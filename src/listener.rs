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
use std::sync::atomic::AtomicBool;
use tokio::sync::watch;
use tokio::time;
use tokio_tungstenite::tungstenite::protocol::Message;

/// Default tunnel server URL.
const DEFAULT_SERVER_URL: &str = "wss://api.smallware.io/tunnels";

/// Configuration for the tunnel listener.
///
/// This struct holds all the settings needed to establish and maintain
/// tunnel connections.
///
/// # Construction
///
/// Use [`TunnelConfig::new()`] to create a configuration, then chain
/// `with_*` methods to customize it:
///
/// ```rust
/// use smallware_tunnel::TunnelConfig;
///
/// // Key format: <keyid>.<secret>
/// // The keyid may contain '.' characters, but the secret cannot.
/// let config = TunnelConfig::new("my-key-id.secret123", "domain.t00.smallware.io")?;
/// # Ok::<(), smallware_tunnel::TunnelError>(())
/// ```
///
/// # Stability
///
/// This struct is marked `#[non_exhaustive]`, meaning new fields may be added
/// in future versions without a breaking change. Always use the constructor
/// and builder methods rather than struct literal syntax.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct TunnelConfig {
    /// The API key (secret) used to sign JWT tokens
    pub key_secret: String,

    /// The key ID for JWT signing
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

/// Parses a combined API key in the format `<keyid>.<secret>`.
///
/// The key ID may contain `.` characters, but the secret cannot.
/// This function splits on the **last** `.` to separate the two parts.
///
/// # Returns
///
/// A tuple of `(key_id, secret)` if the key is valid.
///
/// # Errors
///
/// Returns `TunnelError::InvalidKeyFormat` if the key doesn't contain a `.`.
pub fn parse_key(combined_key: &str) -> Result<(&str, &str), TunnelError> {
    combined_key
        .rfind('.')
        .map(|pos| (&combined_key[..pos], &combined_key[pos + 1..]))
        .ok_or(TunnelError::InvalidKeyFormat)
}

impl TunnelConfig {
    /// Creates a new tunnel configuration with default settings.
    ///
    /// # Arguments
    ///
    /// * `key` - The API key in the format `<keyid>.<secret>`.
    ///           The key ID may contain `.` characters, but the secret cannot.
    /// * `domain` - The full tunnel domain name
    ///
    /// # Errors
    ///
    /// Returns `TunnelError::InvalidKeyFormat` if the key doesn't contain a `.`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use smallware_tunnel::TunnelConfig;
    ///
    /// // Simple key ID
    /// let config = TunnelConfig::new("mykey.secret123", "domain.t00.smallware.io")?;
    ///
    /// // Key ID with dots
    /// let config = TunnelConfig::new("org.team.mykey.secret123", "domain.t00.smallware.io")?;
    /// # Ok::<(), smallware_tunnel::TunnelError>(())
    /// ```
    pub fn new(key: &str, domain: &str) -> Result<Self, TunnelError> {
        let (key_id, secret) = parse_key(key)?;
        Ok(Self {
            key_secret: secret.to_string(),
            key_id: key_id.to_string(),
            domain: domain.to_string(),
            server_url: DEFAULT_SERVER_URL.to_string(),
            trust_ca: None,
        })
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
/// // Key format: <keyid>.<secret>
/// let config = TunnelConfig::new("mykey.secret123", "my-tunnel.t00.smallware.io")?;
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
    shared: Arc<ListenerShared>,
}

struct ListenerShared {
    config: TunnelConfig,
    jwt_manager: JwtManager,
    /// Rendezvous channel sink to recycle connections
    recycle_tx: flume::Sender<RecycledConnection>,
    /// Rendezvous channel source to receive recycled connections
    recycle_rx: flume::Receiver<RecycledConnection>,
    /// Sender for shutdown events
    shutdown_tx: watch::Sender<bool>,
    /// Receiver for shutdown events
    shutdown_rx: watch::Receiver<bool>,
    last_success: AtomicBool,
    retry_state: tokio::sync::Mutex<RetryState>,
}

struct RetryState {
    last_start_millis: i64,
    next_start_millis: i64,
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
        let jwt_manager = JwtManager::new(
            config.key_secret.clone(),
            customer_id,
            config.key_id.clone(),
        );
        let (recycle_tx, recycle_rx) = flume::bounded::<RecycledConnection>(0);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let shared: ListenerShared = ListenerShared {
            config, jwt_manager, recycle_tx, recycle_rx, shutdown_tx, shutdown_rx,
            last_success: AtomicBool::new(false),
            retry_state: tokio::sync::Mutex::new(RetryState {
                last_start_millis: 0,
                next_start_millis: 0,
            }) };

        // Create the JWT manager

        Ok(Self {
            shared: Arc::new(shared),
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
        let _ = self.shared.shutdown_tx.send(true);
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
        let shared = self.shared.clone();
        loop {
            let mut retry_state = shared.retry_state.lock().await;
            let mut now_millis = chrono::Utc::now().timestamp_millis();
            let delay = (retry_state.next_start_millis - now_millis).max(0);

            if delay > 0 {
                tokio::time::sleep(time::Duration::from_millis(delay as u64)).await;
                now_millis = chrono::Utc::now().timestamp_millis();
            }
            let fail_delay = (delay + (delay>>1)).max(1000).min(30000);
            retry_state.last_start_millis = now_millis;
            retry_state.next_start_millis = now_millis + fail_delay;

            let (ws_tx, ws_rx) = match self.connect_or_recycle().await {
                Ok(conn) => conn,
                Err(e) => {
                    // Connection failed, update retry state
                    shared.last_success.store(false, std::sync::atomic::Ordering::SeqCst);
                    if !e.can_retry_accept() {
                        return Err(e);
                    }
                    tracing::info!("WebSocket connect failed. Will retry in {} ms: {}.", fail_delay, e);
                    continue;
                }
            };
            // We have a websocket connection waiting for a CONNECT message
            // If the last connection attempt failed, then wait for a connection inside the lock.
            // If we get a connection,then the other attempts can try without delay.
            if !shared.last_success.load(std::sync::atomic::Ordering::SeqCst) {
                match self.wait_for_connection(ws_tx, ws_rx).await {
                    Ok((sink, stream)) => {
                        // Success, reset retry state
                        shared.last_success.store(true, std::sync::atomic::Ordering::SeqCst);
                        retry_state.next_start_millis = now_millis;
                        return Ok((sink, stream));
                    }
                    Err(e) => {
                        // Failed to get a connection, update retry state
                        shared.last_success.store(false, std::sync::atomic::Ordering::SeqCst);
                        if !e.can_retry_accept() {
                            tracing::info!("tunnel accept failed: {}", &e);
                            return Err(e);
                        }
                        tracing::info!("tunnel accept failed. Will retry: {}", &e);
                    }
                }
                continue;
            }
            // other attempts can try without delay
            retry_state.next_start_millis = now_millis;
            drop(retry_state);
            match self.wait_for_connection(ws_tx, ws_rx).await {
                Ok((sink, stream)) => {
                    return Ok((sink, stream));
                }
                Err(e) => {
                    // Failed to get a connection
                    shared.last_success.store(false, std::sync::atomic::Ordering::SeqCst);
                    if !e.can_retry_accept() {
                        tracing::info!("tunnel accept failed: {}", &e);
                        return Err(e);
                    }
                    tracing::info!("tunnel accept failed. Will retry: {}", &e);
                }
            }
        }
    }


    async fn connect_or_recycle(&self) -> Result<(WsRawSink, WsBaseStream), TunnelError> {
        let shared = self.shared.clone();
        let mut shutdown_rx = shared.shutdown_rx.clone();
        if *shutdown_rx.borrow_and_update() {
            return Err(TunnelError::ListenerClosed);
        }
        let (ws_tx, ws_rx) = if let Ok(recycled) = shared.recycle_rx.try_recv() {
            // Send RESET message to tell the server we're ready for a new proxy client.
            // This must be sent before the server will accept new connections on this WebSocket.
            let reset_msg = Message::Text("RESET".into());
            let mut ws_tx = recycled.ws_tx;
            ws_tx.send(reset_msg).await.map_err(TunnelError::from)?;
            (ws_tx, recycled.ws_rx)
        } else {
            // No recycled connection available, create a new one
            let token = shared.jwt_manager.get_token()?;
            // Build the WebSocket URL
            let ws_url = format!("{}/{}", shared.config.server_url, shared.config.domain);

            tokio::select! {
                _ = util_shutdown(&mut shutdown_rx) => {
                    return Err(TunnelError::ListenerClosed);
                }
                result = connect_websocket(&ws_url, &token, self.shared.config.trust_ca.as_ref()) => {
                    result?
                }
            }
        };
        Ok((ws_tx, ws_rx))
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
        ws_tx: WsRawSink,
        mut ws_rx: WsBaseStream,
    ) -> Result<(TunnelSink, TunnelStream), TunnelError> {
        let mut _client_ip: Option<std::net::IpAddr> = None;
        let shared= self.shared.clone();
        let mut shutdown_rx = shared.shutdown_rx.clone();
        let (ws_tx1, ws_tx2) = BiLock::new(ws_tx);

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
        // TODO: _client_ip is parsed from CONNECT messages for future use (e.g., logging, access control)
        // but is not yet exposed in the public API
        let sink = TunnelSink::new(ws_tx2, recycle_sink_tx);
        let recycle_tx = shared.recycle_tx.clone();
        let shutdown_rx = shared.shutdown_rx.clone();
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
    fn test_parse_key_simple() {
        let (key_id, secret) = parse_key("mykey.secret123").unwrap();
        assert_eq!(key_id, "mykey");
        assert_eq!(secret, "secret123");
    }

    #[test]
    fn test_parse_key_with_dots_in_keyid() {
        // Key ID may contain dots, secret cannot
        let (key_id, secret) = parse_key("org.team.mykey.secret123").unwrap();
        assert_eq!(key_id, "org.team.mykey");
        assert_eq!(secret, "secret123");
    }

    #[test]
    fn test_parse_key_no_dot() {
        let result = parse_key("nosecret");
        assert!(matches!(result, Err(TunnelError::InvalidKeyFormat)));
    }

    #[test]
    fn test_config_new() {
        let config = TunnelConfig::new(
            "mykey.secret123",
            "www-abc-xyz.t00.smallware.io",
        ).unwrap();

        assert_eq!(config.key_secret, "secret123");
        assert_eq!(config.key_id, "mykey");
        assert_eq!(config.domain, "www-abc-xyz.t00.smallware.io");
        assert_eq!(config.server_url, DEFAULT_SERVER_URL);
    }

    #[test]
    fn test_config_with_dotted_keyid() {
        let config = TunnelConfig::new(
            "org.team.key.secret456",
            "www-abc-xyz.t00.smallware.io",
        ).unwrap();

        assert_eq!(config.key_id, "org.team.key");
        assert_eq!(config.key_secret, "secret456");
    }

    #[test]
    fn test_config_with_options() {
        let config = TunnelConfig::new(
            "mykey.secret123",
            "www-abc-xyz.t00.smallware.io",
        )
        .unwrap()
        .with_server_url("wss://test.example.com/tunnels".to_string());

        assert_eq!(config.key_id, "mykey");
        assert_eq!(config.server_url, "wss://test.example.com/tunnels");
    }

    #[test]
    fn test_config_customer_id() {
        let config = TunnelConfig::new(
            "key.secret",
            "www-abc-xyz.t00.smallware.io",
        ).unwrap();
        assert_eq!(config.customer_id().unwrap(), "xyz");
    }

    #[test]
    fn test_config_invalid_key() {
        let result = TunnelConfig::new(
            "invalid-no-dot",
            "www-abc-xyz.t00.smallware.io",
        );
        assert!(result.is_err());
    }
}
