//! Error types for the Smallware tunnel client.
//!
//! This module defines the error types that can occur when using the tunnel client:
//!
//! - [`TunnelError`]: The main error type encompassing all possible errors
//! - [`Result<T>`]: A convenience type alias for `std::result::Result<T, TunnelError>`

use std::sync::Arc;
use http::StatusCode;
use thiserror::Error;

/// Errors that can occur when using the Smallware tunnel client.
///
/// This enum uses `Arc<str>` for string fields to make cloning cheap,
/// since errors are frequently cloned in async code paths.
///
/// # Stability
///
/// This enum is marked `#[non_exhaustive]`, meaning new variants may be added
/// in future versions without a breaking change. When matching on this enum,
/// always include a wildcard arm (`_`) to handle unknown variants.
#[derive(Error, Debug, Clone)]
#[non_exhaustive]
pub enum TunnelError {
    /// Read stream was dropped before EOF
    #[error("Read stream was dropped before EOF")]
    StreamDropped,

    /// Issue communicating with the remote proxy client
    #[error("Remote error: {0}")]
    RemoteError(Arc<str>),

    /// Failed to connect to the tunnel server.
    ///
    /// This can happen if:
    /// - The server is unreachable
    /// - TLS handshake failed
    /// - WebSocket upgrade was rejected
    #[error("Connection failed: {0}")]
    ConnectionFailed(Arc<str>),

    /// WebSocket protocol error.
    ///
    /// This indicates a problem with the WebSocket connection,
    /// such as receiving an unexpected message type or a protocol violation.
    #[error("WebSocket error: {0}")]
    WebSocketError(Arc<str>),

    /// Authentication error.
    ///
    /// The JWT token was rejected by the server. This can happen if:
    /// - The API key is invalid
    /// - The token has expired
    /// - The domain doesn't match the customer ID
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(Arc<str>),

    /// Invalid domain format.
    ///
    /// The domain must follow the format:
    /// `<service>-<random>-<customer>.<shard>.smallware.io`
    #[error("Invalid domain format: {0}")]
    InvalidDomain(Arc<str>),

    /// The tunnel listener has been closed.
    ///
    /// This error is returned when trying to accept connections
    /// after the listener has been shut down.
    #[error("Tunnel listener is closed")]
    ListenerClosed,

    /// I/O error.
    ///
    /// An underlying I/O operation failed.
    #[error("I/O error: {0}")]
    IoError(Arc<str>),

    /// JWT generation error.
    ///
    /// Failed to generate a JWT token for authentication.
    #[error("JWT error: {0}")]
    JwtError(Arc<str>),

    /// Configuration error.
    ///
    /// The provided configuration is invalid.
    #[error("Configuration error: {0}")]
    ConfigError(Arc<str>),

    /// Invalid key format.
    ///
    /// The API key must be in the format `<keyid>.<secret>`.
    /// The key ID may contain `.` characters, but the secret cannot.
    #[error("Invalid key format: expected '<keyid>.<secret>'")]
    InvalidKeyFormat,

    /// Server returned an error response.
    ///
    /// The server rejected the request with an HTTP error status.
    #[error("Server error: {status} - {message}")]
    ServerError {
        /// HTTP status code
        status: u16,
        /// Error message from server
        message: Arc<str>,
    },

    /// Connection was closed unexpectedly.
    ///
    /// The WebSocket connection was closed before the operation completed.
    #[error("Connection closed unexpectedly")]
    ConnectionClosed,

    /// Operation timed out.
    #[error("Operation timed out")]
    Timeout,

    /// Internal state error.
    ///
    /// This indicates a programming error, such as calling `start_send`
    /// without first calling `poll_ready`.
    #[error("Invalid state")]
    InvalidState,

    /// Tunnel protocol violation.
    ///
    /// The server sent an unexpected message type or the protocol
    /// was not followed correctly.
    #[error("Tunnel protocol violation")]
    ProtocolError,
}

impl TunnelError {
    pub fn can_retry_accept(&self) -> bool {
        matches!(
            self,
            TunnelError::ConnectionFailed(_)
                | TunnelError::WebSocketError(_)
                | TunnelError::Timeout
                | TunnelError::ConnectionClosed
                | TunnelError::ProtocolError
                | TunnelError::RemoteError(_)
                | TunnelError::IoError(_)
                | TunnelError::ServerError { status:_, message:_ }
                | TunnelError::StreamDropped
        )
    }
}

impl From<jsonwebtoken::errors::Error> for TunnelError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        TunnelError::JwtError(Arc::from(err.to_string()))
    }
}

impl From<std::io::Error> for TunnelError {
    fn from(err: std::io::Error) -> Self {
        TunnelError::IoError(Arc::from(err.to_string()))
    }
}

impl From<tokio_tungstenite::tungstenite::Error> for TunnelError {
    fn from(err: tokio_tungstenite::tungstenite::Error) -> Self {
        match &err {
            tokio_tungstenite::tungstenite::Error::Http(res) => {
                if res.status() == StatusCode::FORBIDDEN {
                    return TunnelError::AuthenticationFailed(err.to_string().into())
                }
                TunnelError::ServerError { status: res.status().as_u16(), message: err.to_string().into() }
            },
            _ => TunnelError::WebSocketError(Arc::from(err.to_string()))
        }
    }
}

impl From<http::uri::InvalidUri> for TunnelError {
    fn from(err: http::uri::InvalidUri) -> Self {
        TunnelError::ConfigError(Arc::from(err.to_string()))
    }
}

impl From<http::Error> for TunnelError {
    fn from(err: http::Error) -> Self {
        TunnelError::ConnectionFailed(Arc::from(err.to_string()))
    }
}
