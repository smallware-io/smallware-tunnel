//! Read half of a tunnel connection.
//!
//! This module provides [`TunnelStream`], which implements `futures::Stream`
//! for receiving data from a remote client through the tunnel.

use bytes::Bytes;
use futures::stream::SplitStream;
use futures::{Stream, StreamExt};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use crate::TunnelError;

/// The underlying WebSocket stream type (read half).
pub type WsBaseStream = SplitStream<WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>>;

/// Signal sent when the stream completes, indicating whether the connection
/// can be recycled.
pub(crate) enum TunnelStreamEol {
    /// Stream completed successfully; the WebSocket can be recycled.
    Ok(WsBaseStream),
    /// Stream failed; the WebSocket should be discarded.
    Fail,
}

/// The read half of a tunnel connection.
///
/// `TunnelStream` implements `futures::Stream<Item = Result<Bytes, TunnelError>>`,
/// yielding chunks of data received from the remote client.
///
/// # Protocol
///
/// - Binary WebSocket messages are yielded as `Ok(Bytes)`
/// - An empty binary message signals graceful EOF (stream ends with `None`)
/// - Text messages starting with `DROP:` indicate a remote error
/// - Other text messages are ignored (may be control messages for previous connections)
///
/// # Connection Recycling
///
/// When the stream completes (either gracefully or with an error), it signals
/// the background task whether the underlying WebSocket can be recycled:
/// - Graceful EOF (`None`) or `DROP:` message: connection can be recycled
/// - WebSocket error or unexpected close: connection is discarded
///
/// # Example
///
/// ```rust,ignore
/// use futures::StreamExt;
///
/// while let Some(result) = stream.next().await {
///     match result {
///         Ok(data) => println!("Received {} bytes", data.len()),
///         Err(e) => eprintln!("Error: {}", e),
///     }
/// }
/// ```
pub struct TunnelStream {
    /// The underlying WebSocket stream, or the final result if already completed.
    /// - `Ok(stream)`: Active stream, ready to poll
    /// - `Err(Some(result))`: Completed with a final value to return
    /// - `Err(None)`: Completed with EOF
    inner: Result<WsBaseStream, Option<Result<Bytes, TunnelError>>>,
    /// Channel to signal completion status for connection recycling.
    recycler: flume::Sender<TunnelStreamEol>,
}

impl TunnelStream {
    /// Creates a new `TunnelStream` wrapping a WebSocket stream.
    pub(crate) fn new(inner: WsBaseStream, recycler: flume::Sender<TunnelStreamEol>) -> Self {
        Self {
            inner: Ok(inner),
            recycler,
        }
    }

    /// Marks the stream as done (graceful completion) and signals for recycling.
    ///
    /// The `next` parameter is the final value to return from the stream
    /// (typically `None` for EOF or `Some(Err(...))` for a protocol-level error
    /// that still allows recycling).
    fn set_done(
        &mut self,
        next: Option<Result<Bytes, TunnelError>>,
    ) -> Option<Result<Bytes, TunnelError>> {
        // Swap out the inner stream, replacing it with the final result
        let mut inner = Err(next.clone());
        std::mem::swap(&mut self.inner, &mut inner);
        // If we had an active stream, signal that it can be recycled
        if let Ok(inner) = inner {
            let _ = self.recycler.try_send(TunnelStreamEol::Ok(inner));
        }
        next
    }

    /// Marks the stream as failed (non-recoverable error) and signals to discard.
    ///
    /// The connection cannot be recycled after a failure.
    fn set_failed(&mut self, err: TunnelError) -> Option<Result<Bytes, TunnelError>> {
        let mut inner = Err(Some(Err(err.clone())));
        std::mem::swap(&mut self.inner, &mut inner);
        // If we had an active stream, signal that it should be discarded
        if let Ok(_) = inner {
            let _ = self.recycler.try_send(TunnelStreamEol::Fail);
        }
        Some(Err(err))
    }
}

impl Drop for TunnelStream {
    fn drop(&mut self) {
        // If dropped while the stream is still active (not completed),
        // signal failure so the connection is not recycled
        if self.inner.is_ok() {
            let _ = self.recycler.try_send(TunnelStreamEol::Fail);
        }
    }
}

impl Stream for TunnelStream {
    type Item = Result<Bytes, TunnelError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        // If already completed, return the cached final result
        let inner = match &mut this.inner {
            Ok(s) => s,
            Err(e) => return Poll::Ready(e.clone()),
        };

        // Poll the underlying WebSocket stream
        match inner.poll_next_unpin(cx) {
            // Binary message: the main data channel
            Poll::Ready(Some(Ok(Message::Binary(bin)))) => {
                if !bin.is_empty() {
                    // Normal data chunk
                    return Poll::Ready(Some(Ok(Bytes::from(bin))));
                }
                // Empty binary message = graceful EOF signal from server
                return Poll::Ready(this.set_done(None));
            }

            // Text message: control/error messages
            Poll::Ready(Some(Ok(Message::Text(txt)))) => {
                let str = txt.as_str();
                if let Some(err) = str.strip_prefix("DROP:") {
                    // Remote client disconnected with an error; connection can still be recycled
                    let err = TunnelError::RemoteError(Arc::from(err.trim()));
                    return Poll::Ready(this.set_done(Some(Err(err))));
                }
                // Other text messages are ignored (may be from previous connection)
            }

            // WebSocket stream ended without graceful EOF
            Poll::Ready(None) => {
                return Poll::Ready(this.set_failed(TunnelError::ConnectionClosed));
            }

            // WebSocket error
            Poll::Ready(Some(Err(wserr))) => {
                let err = TunnelError::from(wserr);
                return Poll::Ready(this.set_failed(err));
            }

            // Other message types (Ping, Pong, Close) are handled by tungstenite
            Poll::Ready(Some(Ok(_))) => {}

            Poll::Pending => return Poll::Pending,
        }

        // The message didn't produce a value (e.g., ignored text message).
        // Wake ourselves to poll again immediately.
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
