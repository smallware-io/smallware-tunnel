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
use crate::trace_id::{next_trace_id, TraceId};
use crate::tunnel_sink::{TunnelSink, TunnelSinkEol, WsBaseSink, WsRawSink};
use crate::tunnel_stream::{TunnelStream, TunnelStreamEol, WsBaseStream};
use bytes::Bytes;
use flume::Receiver;
use futures::channel::oneshot;
use futures::lock::BiLock;
use futures::{Sink, SinkExt, StreamExt};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tokio::time::{self, timeout};
use tokio_tungstenite::tungstenite::protocol::Message;
use tracing::Instrument;

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

/// Information about a remote connected client
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct TunnelClientInfo{
    pub ip_addr: Option<IpAddr>,
    pub connection_id: TraceId,
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
    /// Tracks whether the most recent connection attempt succeeded.
    ///
    /// This flag controls the concurrency behavior of `accept()`:
    /// - When `false`: Connection attempts are serialized. Only one `accept()` call
    ///   actively attempts a connection at a time, with the `retry_state` lock held
    ///   through both `connect_or_recycle()` and `wait_for_connection()`. This prevents
    ///   multiple callers from hammering the server when it may be experiencing issues.
    /// - When `true`: Connection attempts can proceed concurrently. The lock is released
    ///   before `wait_for_connection()`, allowing multiple WebSocket connections to wait
    ///   for CONNECT messages in parallel.
    ///
    /// The flag is set to `false` on any connection failure and reset to `true` when
    /// a serialized attempt succeeds, signaling that the server is healthy again.
    last_success: AtomicBool,
    /// Controls retry timing and coordinates concurrent `accept()` calls.
    ///
    /// This mutex serves two purposes:
    /// 1. **Backoff coordination**: After a failure, `next_start_millis` is set to a
    ///    future time. All `accept()` calls will sleep until this time, with the lock
    ///    held during the sleep to ensure only one attempt proceeds after the backoff.
    /// 2. **Serialization when failing**: When `last_success` is `false`, the lock is
    ///    held through the entire connection attempt (including `wait_for_connection()`)
    ///    to serialize attempts and prevent overwhelming a potentially struggling server.
    ///
    /// When connections are succeeding (`last_success == true`), the lock is held only
    /// briefly for bookkeeping and released before the potentially long `wait_for_connection()`.
    retry_state: tokio::sync::Mutex<RetryState>,
}

/// Shared state for retry timing across concurrent `accept()` calls.
struct RetryState {
    /// Timestamp when the last connection attempt started (for debugging/metrics).
    last_start_millis: i64,
    /// Earliest time the next connection attempt should start.
    /// Set to a future time after failures to implement exponential backoff.
    /// Reset to the current time on success to allow immediate subsequent attempts.
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
        // Rendezvous channel (capacity 0) for recycling WebSocket connections.
        // When a tunnel session completes successfully, `connection_task` offers the
        // WebSocket for reuse. The zero capacity ensures the handoff is synchronous:
        // if no `accept()` is ready to receive within the timeout, the connection is dropped.
        let (recycle_tx, recycle_rx) = flume::bounded::<RecycledConnection>(0);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let shared: ListenerShared = ListenerShared {
            config,
            jwt_manager,
            recycle_tx,
            recycle_rx,
            shutdown_tx,
            shutdown_rx,
            last_success: AtomicBool::new(false),
            retry_state: tokio::sync::Mutex::new(RetryState {
                last_start_millis: 0,
                next_start_millis: 0,
            }),
        };

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
    /// # Concurrency Model
    ///
    /// The method uses adaptive serialization to balance throughput with server protection:
    ///
    /// - **Normal operation** (`last_success == true`): Multiple `accept()` calls can
    ///   proceed concurrently. Each acquires the retry lock briefly for bookkeeping,
    ///   then releases it before the potentially long wait for a CONNECT message.
    ///
    /// - **After failures** (`last_success == false`): Attempts are serialized. Only one
    ///   `accept()` actively waits for a connection at a time, with the retry lock held
    ///   throughout. This prevents overwhelming a struggling server with parallel retries.
    ///   Once a serialized attempt succeeds, normal concurrent operation resumes.
    ///
    /// - **Backoff**: After failures, an exponential backoff delay (1-30 seconds) is
    ///   enforced. The lock is held during this sleep to ensure all callers respect
    ///   the backoff period.
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
    pub async fn accept(&self) -> Result<(TunnelSink, TunnelStream, TunnelClientInfo), TunnelError> {
        let trace_id = next_trace_id();
        let shared = self.shared.clone();
        async {
            loop {
                // Acquire the retry lock. This lock coordinates backoff timing and, when
                // last_success is false, serializes connection attempts. See field docs
                // for details on when this lock is held vs released.
                let entry_millis = chrono::Utc::now().timestamp_millis();
                let mut retry_state = shared.retry_state.lock().await;
                let mut now_millis = chrono::Utc::now().timestamp_millis();
                if now_millis - entry_millis > 10 {
                    tracing::info!("waited for accept lock: {} ms", now_millis - entry_millis);
                }
                let delay = (retry_state.next_start_millis - now_millis).max(0);

                // Backoff sleep: if a previous attempt set next_start_millis in the future,
                // we sleep here. The lock is intentionally held during this sleep to prevent
                // other callers from bypassing the backoff period.
                if delay > 0 {
                    tracing::info!("accept backoff: {} ms", delay);
                    tokio::time::sleep(time::Duration::from_millis(delay as u64)).await;
                    now_millis = chrono::Utc::now().timestamp_millis();
                }
                // Compute the backoff for the next attempt (in case this one fails).
                // Exponential backoff: 1.5x the previous delay, clamped to 1-30 seconds.
                let fail_delay = (delay + (delay >> 1)).clamp(1000, 30000);
                retry_state.last_start_millis = now_millis;
                retry_state.next_start_millis = now_millis + fail_delay;

                let (ws_tx, ws_rx) = match self.connect_or_recycle().await {
                    Ok(conn) => {
                        tracing::info!(
                            "got server after {} ms",
                            chrono::Utc::now().timestamp_millis() - now_millis
                        );
                        conn
                    }
                    Err(e) => {
                        // Connection failed, update retry state
                        shared
                            .last_success
                            .store(false, std::sync::atomic::Ordering::SeqCst);
                        let connect_delay = chrono::Utc::now().timestamp_millis() - now_millis;
                        if !e.can_retry_accept() {
                            tracing::info!(
                                "Websocket connect failed after {} ms. No retry: {}",
                                connect_delay,
                                e
                            );
                            return Err(e);
                        }
                        tracing::info!(
                            "Websocket connect failed after {} ms. Retry in {}: {}",
                            connect_delay,
                            fail_delay,
                            e
                        );
                        continue;
                    }
                };
                // We now have a fresh WebSocket: either newly connected or recycled with
                // a RESET message just sent. The server should respond with CONNECT promptly
                // once a client connects to the tunnel.
                //
                // Serialization decision: if the previous attempt failed, we hold the lock
                // through wait_for_connection() to serialize attempts. If we succeed here,
                // we signal that the server is healthy (last_success = true) so subsequent
                // callers can proceed concurrently.
                if !shared
                    .last_success
                    .load(std::sync::atomic::Ordering::SeqCst)
                {
                    // SERIALIZED PATH: Hold lock through wait_for_connection.
                    // Only one caller waits for CONNECT at a time until we succeed.
                    tracing::info!("Waiting for connect (blocking)");
                    match self.wait_for_connection(ws_tx, ws_rx).await {
                        Ok((sink, stream, client_info)) => {
                            // Success! Server is healthy. Allow concurrent attempts again.
                            shared
                                .last_success
                                .store(true, std::sync::atomic::Ordering::SeqCst);
                            retry_state.next_start_millis = now_millis;
                            return Ok((sink, stream, client_info));
                        }
                        Err(e) => {
                            shared
                                .last_success
                                .store(false, std::sync::atomic::Ordering::SeqCst);
                            if !e.can_retry_accept() {
                                tracing::info!("tunnel accept failed: {}", &e);
                                return Err(e);
                            }
                            tracing::info!("tunnel accept failed. Will retry: {}", &e);
                        }
                    }
                    continue;
                }
                // CONCURRENT PATH: Release lock before the potentially long wait for CONNECT.
                // Multiple callers can wait on their own WebSocket connections in parallel.
                retry_state.next_start_millis = now_millis;
                drop(retry_state);
                tracing::info!("Waiting for connect (parallel)");
                match self.wait_for_connection(ws_tx, ws_rx).await {
                    Ok((sink, stream, client_info)) => {
                        return Ok((sink, stream, client_info));
                    }
                    Err(e) => {
                        // Failed while in concurrent mode. Mark as failed so the next
                        // attempt will serialize. Note: we don't hold the lock here,
                        // so another caller might already be in wait_for_connection.
                        // That's fine - they'll complete or fail independently.
                        shared
                            .last_success
                            .store(false, std::sync::atomic::Ordering::SeqCst);
                        if !e.can_retry_accept() {
                            tracing::info!("tunnel accept failed: {}", &e);
                            return Err(e);
                        }
                        tracing::info!("tunnel accept failed. Will retry: {}", &e);
                    }
                }
            }
        }
        .instrument(tracing::info_span!("tunnel_accept", accept=%trace_id))
        .await
    }

    /// Obtains a WebSocket connection, either by recycling an existing one or creating new.
    ///
    /// This method first checks the recycle channel for an available connection from a
    /// completed tunnel session. If one is available, it sends a RESET message to signal
    /// the server that we're ready for a new client. If no recycled connection is available,
    /// a new WebSocket connection is established.
    ///
    /// The returned WebSocket is in a "fresh" state: either just connected or just reset.
    /// The server will send a CONNECT message when a client connects to the tunnel.
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
    /// This method should only be called on a "fresh" WebSocket connection:
    /// - A newly established connection (just completed handshake), or
    /// - A recycled connection that just had a RESET message sent
    ///
    /// In either case, the server knows we're ready for a new client and will send
    /// a CONNECT message promptly once a client connects to the tunnel. The 60-second
    /// ping interval is for keep-alive during potentially long waits for clients,
    /// not for failure detection on stale connections.
    ///
    /// This method handles the WebSocket protocol:
    /// - Sends periodic ping messages (every 60s) to keep the connection alive
    /// - Parses incoming `CONNECT` messages to extract client IP
    /// - Ignores stale messages from previous connections on recycled WebSockets
    /// - Handles `DROP` messages and connection errors
    ///
    /// Once a `CONNECT` is received, it creates the `TunnelSink` and `TunnelStream`
    /// and spawns a background task to monitor them for recycling.
    async fn wait_for_connection(
        &self,
        ws_tx: WsRawSink,
        mut ws_rx: WsBaseStream,
    ) -> Result<(TunnelSink, TunnelStream, TunnelClientInfo), TunnelError> {
        let mut client_ip: Option<std::net::IpAddr> = None;
        let mut conn_id: Option<TraceId> = None;
        let shared = self.shared.clone();
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
                            let text_str = text.as_str();
                            tracing::info!("got text: {}", text_str);
                            // CONNECT message means a client is connecting
                            if text_str.starts_with("CONNECT: ") {
                                let mut connect_parts = text_str.trim_start_matches("CONNECT:").split(',');
                                if let Some(ip_str) = connect_parts.next() {
                                    client_ip = ip_str.trim().parse().ok();
                                    if let Some(id_str) = connect_parts.next() {
                                        conn_id = Some(id_str.into());
                                    }
                                }
                                break;
                            } else if text_str.starts_with("DROP: ") {
                            }
                            // Since we haven't got a connect message, any other messages refer to the previous connection on the websocket
                            // Ignore other text messages
                        },
                        Some(Ok(Message::Binary(_))) => {
                            tracing::info!("wait failed: unexpected binary");
                            // Unexpected binary data before CONNECT
                            return Err(TunnelError::ProtocolError);
                        },
                        Some(Ok(Message::Close(_))) => {
                            tracing::info!("wait failed: close message");
                            return Err(TunnelError::ConnectionClosed);
                        },
                        Some(Ok(_)) => {
                            // Ignore other messages
                        },
                        Some(Err(e)) => {
                            tracing::info!("wait failed: {}", e);
                            return Err(e.into());
                        },
                        None => {
                            tracing::info!("wait failed: webSocket closed by server");
                            return Err(TunnelError::ConnectionClosed);
                        }
                    }
                }
            }
        }
        let conn_id = conn_id.unwrap_or_else(|| "?".into());
        let (recycle_stream_tx, recycle_stream_rx) = flume::bounded::<TunnelStreamEol>(1);
        let (recycle_sink_tx, recycle_sink_rx) = flume::bounded::<TunnelSinkEol>(1);
        let (stream_interrupt_tx, stream_interrupt_rx) = oneshot::channel();
        let stream = TunnelStream::new(ws_rx, stream_interrupt_rx, recycle_stream_tx);
        let sink = TunnelSink::new(ws_tx2, recycle_sink_tx);
        let recycle_tx = shared.recycle_tx.clone();
        let shutdown_rx = shared.shutdown_rx.clone();
        tokio::spawn(
            Self::connection_task(
                ws_tx1,
                recycle_sink_rx,
                recycle_stream_rx,
                stream_interrupt_tx,
                recycle_tx,
                shutdown_rx,
            )
            .instrument(tracing::info_span!("connection", conn = %conn_id)),
        );
        Ok((sink, stream, TunnelClientInfo{connection_id: conn_id, ip_addr: client_ip}))
    }

    /// Background task that monitors a connection for completion and handles recycling.
    ///
    /// This task:
    /// 1. Waits for both the sink and stream to signal end-of-life (success or failure)
    /// 2. Sends periodic ping messages to keep the WebSocket alive while waiting
    /// 3. If both completed successfully, reunites the BiLock halves and offers the
    ///    connection to the rendezvous channel for reuse (with 5-second timeout)
    /// 4. If either failed, or if no `accept()` claims the recycled connection within
    ///    the timeout, the WebSocket is dropped
    ///
    /// The rendezvous channel (capacity 0) ensures synchronous handoff: a recycled
    /// connection is only kept alive if an `accept()` call is ready to receive it.
    async fn connection_task(
        ws_tx1: WsBaseSink,
        recycle_sink_rx: Receiver<TunnelSinkEol>,
        recycle_stream_rx: Receiver<TunnelStreamEol>,
        stream_interrupt_tx: oneshot::Sender<()>, // normall drop-signalled
        recycle_tx: flume::Sender<RecycledConnection>,
        shutdown_rx: watch::Receiver<bool>,
    ) {
        let mut sink_eol: Option<TunnelSinkEol> = None;
        let mut stream_eol: Option<TunnelStreamEol> = None;
        // Wait for the caller to finish with its TunnelSink
        while sink_eol.is_none() {
            tokio::select! {
                result = recycle_sink_rx.recv_async() => {
                    match result {
                        Ok(eol) => {sink_eol = Some(eol);},
                        _ => {
                            break;
                        },
                    }
                },
                result = recycle_stream_rx.recv_async(), if stream_eol.is_none() => {
                    match result {
                        Ok(eol) => {stream_eol = Some(eol);},
                        _ => {stream_eol = Some(TunnelStreamEol::Fail);},
                    }
                    if let Some(TunnelStreamEol::Dropped(_)) = &stream_eol {
                        let rsd_msg = Message::Text("RDSD".into());
                        let mut guard = ws_tx1.lock().await;
                        if !checked_send(&mut *guard, rsd_msg).await {
                            return; // connection lost
                        }
                    }
                },
                // send a ping every minute if we're not already busy sending something else
                _ = time::sleep(time::Duration::from_secs(60)) => {
                    // send keep-alive
                    let ping_msg = Message::Ping(Bytes::new());
                    if let Some(mut guard) = ws_tx1.try_lock() {
                        if !checked_send(&mut *guard, ping_msg).await {
                            return; // connection lost
                        }
                    }
                },
            }
        }
        // The writer is done and we have the other half of the write sink
        // back.  Try to put the write sink back together, and make a note
        // pf what we have to do with it.
        let mut send_eof = false;
        let mut send_close = false;
        let mut raw_sink = match sink_eol {
            Some(TunnelSinkEol::Ok(ws_tx2)) => match BiLock::reunite(ws_tx1, ws_tx2) {
                Ok(sink) => sink,
                Err(_) => {
                    return;
                }
            },
            Some(TunnelSinkEol::Dropped(ws_tx2)) => match BiLock::reunite(ws_tx1, ws_tx2) {
                Ok(sink) => {
                    send_eof = true;
                    sink
                }
                Err(_) => {
                    return;
                }
            },
            Some(TunnelSinkEol::Fail(ws_tx2)) => match BiLock::reunite(ws_tx1, ws_tx2) {
                Ok(sink) => {
                    send_close = true;
                    sink
                }
                Err(_) => {
                    return;
                }
            },
            _ => {
                return;
            }
        };
        if send_close {
            // write failed, and connection is not recyclable
            // send a close message to shut down the websocket
            let _ = checked_close(&mut raw_sink).await;
            return;
        }
        if send_eof {
            // write dropped
            let eof_msg = Message::Binary(Bytes::new());
            if !checked_send(&mut raw_sink, eof_msg).await {
                tracing::error!("Send EOF on drop failed");
                return; // connection lost
            }
        }
        // Write side closed done.  Wait for the read stream
        while stream_eol.is_none() {
            tokio::select! {
                result = recycle_stream_rx.recv_async(), if stream_eol.is_none() => {
                    match result {
                        Ok(eol) => {stream_eol = Some(eol);},
                        _ => {stream_eol = Some(TunnelStreamEol::Fail);},
                    }
                    if let Some(TunnelStreamEol::Dropped(_)) = &stream_eol {
                        let rsd_msg = Message::Text("RDSD".into());
                        if !checked_send(&mut raw_sink, rsd_msg).await {
                            return; // connection lost
                        }
                    }
                },
                // send a ping every minute if we're not already busy sending something else
                _ = time::sleep(time::Duration::from_secs(60)) => {
                    // send keep-alive
                    let ping_msg = Message::Ping(Bytes::new());
                    if !checked_send(&mut raw_sink, ping_msg).await {
                        return; // connection lost
                    }
                },
            }
        }
        let raw_stream = match stream_eol {
            Some(TunnelStreamEol::Ok(ws_rx)) => ws_rx,
            Some(TunnelStreamEol::Dropped(ws_rx)) => ws_rx,
            _ => {
                // read stream is not recyclable.
                let _ = checked_close(&mut raw_sink).await;
                let _ = stream_interrupt_tx.send(());
                return;
            }
        };
        // Offer the recycled connection to waiting accept() calls via rendezvous channel.
        // With capacity 0, send_async blocks until a receiver is ready. If no accept()
        // is waiting within 5 seconds, we give up and drop the connection.
        let mut shutdown_rx = shutdown_rx;
        tokio::select! {
            _ = recycle_tx.send_async(RecycledConnection { ws_tx: raw_sink, ws_rx: raw_stream}) => {},
            _ = time::sleep(time::Duration::from_secs(5)) => {},
            _ = util_shutdown(&mut shutdown_rx) => {}
        }
    }
}

async fn checked_send<T: Sink<Message> + Unpin>(sink: &mut T, msg: Message) -> bool {
    let res = timeout(Duration::from_secs(60), sink.send(msg)).await;
    res.is_ok()
}
async fn checked_close<T: Sink<Message> + Unpin>(sink: &mut T) -> bool {
    let res = timeout(Duration::from_secs(60), sink.close()).await;
    res.is_ok()
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
        let config = TunnelConfig::new("mykey.secret123", "www-abc-xyz.t00.smallware.io").unwrap();

        assert_eq!(config.key_secret, "secret123");
        assert_eq!(config.key_id, "mykey");
        assert_eq!(config.domain, "www-abc-xyz.t00.smallware.io");
        assert_eq!(config.server_url, DEFAULT_SERVER_URL);
    }

    #[test]
    fn test_config_with_dotted_keyid() {
        let config =
            TunnelConfig::new("org.team.key.secret456", "www-abc-xyz.t00.smallware.io").unwrap();

        assert_eq!(config.key_id, "org.team.key");
        assert_eq!(config.key_secret, "secret456");
    }

    #[test]
    fn test_config_with_options() {
        let config = TunnelConfig::new("mykey.secret123", "www-abc-xyz.t00.smallware.io")
            .unwrap()
            .with_server_url("wss://test.example.com/tunnels".to_string());

        assert_eq!(config.key_id, "mykey");
        assert_eq!(config.server_url, "wss://test.example.com/tunnels");
    }

    #[test]
    fn test_config_customer_id() {
        let config = TunnelConfig::new("key.secret", "www-abc-xyz.t00.smallware.io").unwrap();
        assert_eq!(config.customer_id().unwrap(), "xyz");
    }

    #[test]
    fn test_config_invalid_key() {
        let result = TunnelConfig::new("invalid-no-dot", "www-abc-xyz.t00.smallware.io");
        assert!(result.is_err());
    }
}
