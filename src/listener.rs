//! Tunnel listener for accepting incoming tunnel connections.
//!
//! This module provides the [`TunnelListener`] type, which manages
//! WebSocket connections to the tunnel server and accepts incoming connections
//! from remote clients.
//!
//! # Architecture
//!
//! The listener can handle multiple simultaneous connections. Each call to
//! [`TunnelListener::accept()`] establishes (or reuses) a WebSocket connection
//! to the tunnel server and waits for a remote client to connect. Multiple
//! `accept()` calls can be in flight concurrently, allowing the application
//! to handle many tunnel connections simultaneously.
//!
//! When a remote client connects to the tunnel domain, the server sends a
//! `CONNECT` message over the WebSocket. The listener then returns a
//! [`TunnelSink`] and [`TunnelStream`] pair for bidirectional communication.
//!
//! # Connection Recycling
//!
//! After a connection completes (both sink and stream signal completion), the
//! underlying WebSocket can be recycled for subsequent `accept()` calls,
//! avoiding the overhead of establishing new TLS/WebSocket handshakes.
//! A rendezvous channel ensures recycled connections are handed off directly
//! to waiting `accept()` calls.

use crate::bilock_ext::BiLockExt;
use crate::error::TunnelError;
use crate::jwt::{extract_customer_id, JwtManager};
use crate::tunnel_sink::{TunnelSink, TunnelSinkEol, WsBaseSink, WsRawSink};
use crate::tunnel_stream::{TunnelStream, TunnelStreamEol, WsBaseStream};
use bytes::Bytes;
use flume::Receiver;
use futures::lock::BiLock;
use futures::{SinkExt, StreamExt};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::watch;
use tokio::time;
use tokio_tungstenite::tungstenite::protocol::Message;

/// Default tunnel server URL.
const DEFAULT_SERVER_URL: &str = "wss://api.smallware.io/tunnels";

/// Configuration for the tunnel listener.
///
/// This struct holds all the settings needed to establish and maintain
/// tunnel connections.
#[derive(Debug, Clone)]
pub struct TunnelConfig {
    /// The API key (secret) used to sign JWT tokens
    pub key: String,

    /// The key ID for JWT signing (defaults to "default")
    pub key_id: String,

    /// The full tunnel domain name
    /// Format: `<service>-<random>-<customer>.<shard>.smallware.io`
    pub domain: String,

    /// The tunnel server URL (defaults to `wss://api.smallware.io/tunnels`)
    pub server_url: String,

    /// Optional path to a PEM file containing a root CA certificate to trust.
    ///
    /// When set, this CA will be trusted in addition to the system's default
    /// root certificates. This is useful for development or testing against
    /// servers using self-signed certificates.
    pub trust_ca: Option<PathBuf>,
}

impl TunnelConfig {
    /// Creates a new tunnel configuration with default settings.
    ///
    /// # Arguments
    ///
    /// * `key` - The API key (secret) for authentication
    /// * `domain` - The full tunnel domain name
    ///
    /// The key ID defaults to "default" and the server URL defaults to
    /// the production Smallware server.
    pub fn new(key: String, domain: String) -> Self {
        Self {
            key,
            key_id: "default".to_string(),
            domain,
            server_url: DEFAULT_SERVER_URL.to_string(),
            trust_ca: None,
        }
    }

    /// Sets a custom key ID for JWT signing.
    ///
    /// The key ID is included in the JWT header and tells the server
    /// which key to use for verification.
    pub fn with_key_id(mut self, key_id: String) -> Self {
        self.key_id = key_id;
        self
    }

    /// Sets a custom server URL.
    ///
    /// Use this for development or testing against a non-production server.
    pub fn with_server_url(mut self, url: String) -> Self {
        self.server_url = url;
        self
    }

    /// Sets a custom root CA certificate to trust.
    ///
    /// The provided path should point to a PEM file containing one or more
    /// CA certificates. These will be trusted in addition to the system's
    /// default root certificates.
    ///
    /// This is useful for development or testing against servers using
    /// self-signed certificates.
    pub fn with_trust_ca(mut self, path: PathBuf) -> Self {
        self.trust_ca = Some(path);
        self
    }

    /// Extracts the customer ID from the domain.
    pub fn customer_id(&self) -> Result<String, TunnelError> {
        extract_customer_id(&self.domain)
    }
}

/// A recycled connection ready for reuse.
struct RecycledConnection {
    ws_tx: WsRawSink,
    ws_rx: WsBaseStream,
}

/// A listener that accepts incoming tunnel connections.
///
/// `TunnelListener` manages WebSocket connections to the tunnel server and
/// accepts incoming connections from remote clients. It supports multiple
/// concurrent connections and automatic connection recycling.
///
/// # Example
///
/// ```rust,no_run
/// use smallware_tunnel::{TunnelConfig, TunnelListener};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = TunnelConfig::new("api-key".into(), "my-tunnel.t00.smallware.io".into());
/// let listener = TunnelListener::new(config)?;
///
/// loop {
///     let (sink, stream) = listener.accept().await?;
///     tokio::spawn(async move {
///         // Handle the connection using sink and stream
///     });
/// }
/// # }
/// ```
pub struct TunnelListener {
    config: Arc<TunnelConfig>,
    jwt_manager: Arc<JwtManager>,
    /// Rendezvous channel sink to recycle connections
    recycle_tx: flume::Sender<RecycledConnection>,
    /// Rendezvous channel source to receive recycled connections
    recycle_rx: flume::Receiver<RecycledConnection>,
    /// Sender for shutdown events
    shutdown_tx: watch::Sender<bool>,
    /// Receiver for shutdown events
    shutdown_rx: watch::Receiver<bool>,
}

impl TunnelListener {
    /// Creates a new tunnel listener with the given configuration.
    ///
    /// This validates the configuration (extracting the customer ID from the domain)
    /// and sets up the JWT manager for authentication. No network connections are
    /// made until [`accept()`](Self::accept) is called.
    ///
    /// # Errors
    ///
    /// Returns an error if the domain format is invalid and the customer ID
    /// cannot be extracted.
    pub fn new(config: TunnelConfig) -> Result<Self, TunnelError> {
        // Validate configuration by extracting the customer ID from the domain
        let customer_id = config.customer_id()?;

        // Create the JWT manager
        let jwt_manager = Arc::new(JwtManager::new(
            config.key.clone(),
            customer_id,
            config.key_id.clone(),
        ));

        let (recycle_tx, recycle_rx) = flume::bounded::<RecycledConnection>(0);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        Ok(Self {
            config: Arc::new(config),
            jwt_manager,
            recycle_tx,
            recycle_rx,
            shutdown_tx,
            shutdown_rx,
        })
    }

    /// Shuts down the listener.  Existing proxy connections will
    /// remain open, but no new connections will be accepted.
    ///
    /// After calling this method:
    /// - No new connections will be accepted
    /// - `accept()` will return `TunnelError::ListenerClosed`
    pub async fn shutdown(&self) {
        tracing::info!("Shutting down tunnel listener");
        let _ = self.shutdown_tx.send(true);
    }

    /// Accepts an incoming connection from the tunnel server.
    ///
    /// This method either reuses a recycled WebSocket connection or establishes
    /// a new one, then waits for the tunnel server to send a `CONNECT` message
    /// indicating that a remote client has connected.
    ///
    /// Multiple calls to `accept()` can be made concurrently from different tasks.
    /// Each call will handle a separate incoming connection.
    ///
    /// # Returns
    ///
    /// Returns a tuple of ([`TunnelSink`], [`TunnelStream`]) for bidirectional
    /// communication with the remote client:
    /// - `TunnelSink`: Implements `futures::Sink<Bytes>` for sending data
    /// - `TunnelStream`: Implements `futures::Stream<Item = Result<Bytes, TunnelError>>` for receiving data
    ///
    /// # Errors
    ///
    /// - [`TunnelError::ListenerClosed`] if [`shutdown()`](Self::shutdown) was called
    /// - [`TunnelError::ConnectionFailed`] if the WebSocket connection fails
    /// - [`TunnelError::ConnectionClosed`] if the server closes the connection
    /// - [`TunnelError::WebSocketError`] for other WebSocket-level errors
    pub async fn accept(&self) -> Result<(TunnelSink, TunnelStream), TunnelError> {
        let mut shutdown_rx = self.shutdown_rx.clone();
        if *shutdown_rx.borrow_and_update() {
            return Err(TunnelError::ListenerClosed);
        }
        let (ws_tx, ws_rx) = if let Ok(recycled) = self.recycle_rx.try_recv() {
            // Send RESET message to tell the server we're ready for a new proxy client.
            // This must be sent before the server will accept new connections on this WebSocket.
            let reset_msg = Message::Text("RESET".into());
            let mut ws_tx = recycled.ws_tx;
            ws_tx.send(reset_msg).await.map_err(TunnelError::from)?;
            (ws_tx, recycled.ws_rx)
        } else {
            // No recycled connection available, create a new one
            let token = self.jwt_manager.get_token()?;
            // Build the WebSocket URL
            let ws_url = format!("{}/{}", self.config.server_url, self.config.domain);

            tokio::select! {
                _ = util_shutdown(&mut shutdown_rx) => {
                    return Err(TunnelError::ListenerClosed);
                }
                result = connect_websocket(&ws_url, &token, self.config.trust_ca.as_ref()) => {
                    result?
                }
            }
        };

        let (ws_tx1, ws_tx2) = BiLock::new(ws_tx);
        self.wait_for_connection(ws_tx1, ws_tx2, ws_rx).await
    }

    /// Waits for a `CONNECT` message on the WebSocket indicating a client has connected.
    ///
    /// This method handles the WebSocket protocol:
    /// - Sends periodic ping messages to keep the connection alive
    /// - Parses incoming `CONNECT` messages to extract client IP
    /// - Handles `DROP` messages and connection errors
    ///
    /// Once a `CONNECT` is received, it creates the `TunnelSink` and `TunnelStream`
    /// and spawns a background task to monitor them for recycling.
    async fn wait_for_connection(
        &self,
        ws_tx1: WsBaseSink,
        ws_tx2: WsBaseSink,
        mut ws_rx: WsBaseStream,
    ) -> Result<(TunnelSink, TunnelStream), TunnelError> {
        let mut _client_ip: Option<std::net::IpAddr> = None;
        let mut shutdown_rx = self.shutdown_rx.clone();
        loop {
            tokio::select! {
                _ = util_shutdown(&mut shutdown_rx) => {
                    return Err(TunnelError::ListenerClosed);
                },
                // send a ping every minute if we're not already busy sending something else
                _ = time::sleep(time::Duration::from_secs(60)) => {
                    // send keep-alive
                    let ping_msg = Message::Ping(Bytes::new());
                    if let Some(mut guard) = ws_tx1.try_lock() {
                        guard.send(ping_msg).await.map_err(TunnelError::from)?;
                    }
                },
                result = ws_rx.next() => {
                    match result {
                        Some(Ok(Message::Text(text))) => {
                            let text_str = text.to_string();
                            // CONNECT message means a client is connecting
                            if text_str.starts_with("CONNECT: ") {
                                let ip_str = text_str.trim_start_matches("CONNECT:");
                                _client_ip = ip_str.trim().parse().ok();
                                break;
                            } else if text_str.starts_with("DROP: ") {
                            }
                            // Since we haven't got a connect message, any other messages refer to the previous connection on the websocket
                            // Ignore other text messages
                        },
                        Some(Ok(Message::Binary(_))) => {
                            // Unexpected binary data before CONNECT
                            return Err(TunnelError::ProtocolError);
                        },
                        Some(Ok(Message::Close(_))) => {
                            tracing::debug!("WebSocket closed by server");
                            return Err(TunnelError::ConnectionClosed);
                        },
                        Some(Ok(_)) => {
                            // Ignore other messages
                        },
                        Some(Err(e)) => {
                            return Err(e.into());
                        },
                        None => {
                            return Err(TunnelError::ConnectionClosed);
                        }
                    }
                }
            }
        }
        let (recycle_stream_tx, recycle_stream_rx) = flume::bounded::<TunnelStreamEol>(1);
        let (recycle_sink_tx, recycle_sink_rx) = flume::bounded::<TunnelSinkEol>(1);

        let stream = TunnelStream::new(ws_rx, recycle_stream_tx);
        // TODO: set_client_ip not yet implemented
        let sink = TunnelSink::new(ws_tx2, recycle_sink_tx);
        let recycle_tx = self.recycle_tx.clone();
        let shutdown_rx = self.shutdown_rx.clone();
        tokio::spawn(Self::connection_task(
            ws_tx1,
            recycle_sink_rx,
            recycle_stream_rx,
            recycle_tx,
            shutdown_rx,
        ));
        Ok((sink, stream))
    }

    /// Background task that monitors a connection for completion and handles recycling.
    ///
    /// This task:
    /// 1. Waits for both the sink and stream to signal end-of-life (success or failure)
    /// 2. Sends periodic ping messages to keep the WebSocket alive while waiting
    /// 3. If both completed successfully, reunites the BiLock halves and sends the
    ///    recycled connection to the rendezvous channel for reuse
    /// 4. If either failed, discards the connection
    async fn connection_task(
        ws_tx1: WsBaseSink,
        recycle_sink_rx: Receiver<TunnelSinkEol>,
        recycle_stream_rx: Receiver<TunnelStreamEol>,
        recycle_tx: flume::Sender<RecycledConnection>,
        shutdown_rx: watch::Receiver<bool>,
    ) {
        let mut sink_eol: Option<Result<TunnelSinkEol, ()>> = None;
        let mut stream_eol: Option<Result<TunnelStreamEol, ()>> = None;
        while sink_eol.is_none() || stream_eol.is_none() {
            tokio::select! {
                    result = recycle_sink_rx.recv_async(), if sink_eol.is_none() => {
                        match result {
                            Ok(eol) => {sink_eol = Some(Ok(eol));},
                            _ => {sink_eol = Some(Err(()));},
                        }
                    },
                    result = recycle_stream_rx.recv_async(), if stream_eol.is_none() => {
                        match result {
                            Ok(eol) => {stream_eol = Some(Ok(eol));},
                            _ => {stream_eol = Some(Err(()));},
                        }
                    },
                    // send a ping every minute if we're not already busy sending something else
                    _ = time::sleep(time::Duration::from_secs(60)) => {
                        // send keep-alive
                        let ping_msg = Message::Ping(Bytes::new());
                        if let Some(mut guard) = ws_tx1.try_lock() {
                            if guard.send(ping_msg).await.is_err() {
                                return; // connection lost
                            }
                        }
                    },
            }
        }
        let raw_sink = match sink_eol {
            Some(Ok(TunnelSinkEol::Ok(ws_tx2))) => match BiLock::reunite(ws_tx1, ws_tx2) {
                Ok(sink) => sink,
                Err(_) => {
                    return;
                }
            },
            _ => {
                return;
            }
        };
        let raw_stream = match stream_eol {
            Some(Ok(TunnelStreamEol::Ok(ws_rx))) => ws_rx,
            _ => {
                return;
            }
        };
        let mut shutdown_rx = shutdown_rx;
        tokio::select! {
            _ = recycle_tx.send_async(RecycledConnection { ws_tx: raw_sink, ws_rx: raw_stream}) => {},
            _ = time::sleep(time::Duration::from_secs(5)) => {},
            _ = util_shutdown(&mut shutdown_rx) => {
                return;
            }
        }
    }
}

/// Waits until the shutdown signal is received.
///
/// This is a utility function used in `tokio::select!` blocks to cancel
/// operations when the listener is shutting down.
async fn util_shutdown(shutdown_rx: &mut watch::Receiver<bool>) {
    loop {
        if *shutdown_rx.borrow_and_update() {
            break;
        }
        // while this function could be running
        let _ = shutdown_rx.changed().await;
    }
}

/// Establishes a WebSocket connection to the tunnel server.
///
/// This function:
/// 1. Parses the URL and extracts the host
/// 2. Builds an HTTP upgrade request with JWT authorization
/// 3. Performs the WebSocket handshake over TLS
/// 4. Returns the split sink and stream halves
///
/// If `trust_ca` is provided, the specified CA certificate will be trusted
/// in addition to the system's default root certificates.
async fn connect_websocket(
    url: &str,
    token: &str,
    trust_ca: Option<&PathBuf>,
) -> Result<(WsRawSink, WsBaseStream), TunnelError> {
    use tokio_tungstenite::tungstenite::handshake::client::generate_key;

    // Parse the URL
    let uri: http::Uri = url.parse()?;

    let host = uri
        .host()
        .ok_or_else(|| TunnelError::ConfigError(Arc::from("URL missing host")))?;

    // Build the WebSocket request with authorization header
    let request = http::Request::builder()
        .uri(url)
        .header("Host", host)
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", generate_key())
        .header("Authorization", format!("Bearer {}", token))
        .body(())?;

    // Perform WebSocket handshake with TLS
    let ws_stream = if let Some(ca_path) = trust_ca {
        // Build a custom TLS connector that trusts the specified CA
        let connector = build_tls_connector(ca_path)?;
        let (ws_stream, _response) =
            tokio_tungstenite::connect_async_tls_with_config(request, None, false, Some(connector))
                .await?;
        ws_stream
    } else {
        // Use the default connector with system root certificates
        let (ws_stream, _response) = tokio_tungstenite::connect_async(request).await?;
        ws_stream
    };

    Ok(ws_stream.split())
}

/// Builds a TLS connector that trusts the specified CA certificate file
/// in addition to the system's default root certificates.
fn build_tls_connector(ca_path: &PathBuf) -> Result<tokio_tungstenite::Connector, TunnelError> {
    use rustls::pki_types::CertificateDer;
    use std::io::BufReader;

    // Read the CA certificate file
    let ca_file = std::fs::File::open(ca_path).map_err(|e| {
        TunnelError::ConfigError(Arc::from(format!(
            "Failed to open CA file {:?}: {}",
            ca_path, e
        )))
    })?;
    let mut ca_reader = BufReader::new(ca_file);

    // Parse PEM certificates
    let ca_certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut ca_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            TunnelError::ConfigError(Arc::from(format!(
                "Failed to parse CA certificates from {:?}: {}",
                ca_path, e
            )))
        })?;

    if ca_certs.is_empty() {
        return Err(TunnelError::ConfigError(Arc::from(format!(
            "No certificates found in {:?}",
            ca_path
        ))));
    }

    // Build root cert store with system roots plus custom CA
    let mut root_store = rustls::RootCertStore::empty();

    // Add system root certificates
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    // Add custom CA certificates
    for cert in ca_certs {
        root_store.add(cert).map_err(|e| {
            TunnelError::ConfigError(Arc::from(format!("Failed to add CA certificate: {}", e)))
        })?;
    }

    // Build the TLS client config
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(tokio_tungstenite::Connector::Rustls(Arc::new(tls_config)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_new() {
        let config = TunnelConfig::new(
            "key123".to_string(),
            "www-abc-xyz.t00.smallware.io".to_string(),
        );

        assert_eq!(config.key, "key123");
        assert_eq!(config.domain, "www-abc-xyz.t00.smallware.io");
        assert_eq!(config.key_id, "default");
        assert_eq!(config.server_url, DEFAULT_SERVER_URL);
    }

    #[test]
    fn test_config_with_options() {
        let config = TunnelConfig::new(
            "key123".to_string(),
            "www-abc-xyz.t00.smallware.io".to_string(),
        )
        .with_key_id("mykey".to_string())
        .with_server_url("wss://test.example.com/tunnels".to_string());

        assert_eq!(config.key_id, "mykey");
        assert_eq!(config.server_url, "wss://test.example.com/tunnels");
    }

    #[test]
    fn test_config_customer_id() {
        let config = TunnelConfig::new(
            "key".to_string(),
            "www-abc-xyz.t00.smallware.io".to_string(),
        );
        assert_eq!(config.customer_id().unwrap(), "xyz");
    }
}
