//! Write half of a tunnel connection.
//!
//! This module provides [`TunnelSink`], which implements `futures::Sink`
//! for sending data to a remote client through the tunnel.

use bytes::Bytes;
use futures::lock::BiLockGuard;
use futures::{lock::BiLock, stream::SplitSink, Sink, SinkExt};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::net::TcpStream;
use tokio_tungstenite::{tungstenite::Message, MaybeTlsStream, WebSocketStream};

use crate::TunnelError;

/// The underlying WebSocket sink type (write half).
pub(crate) type WsRawSink = SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>;

/// A `BiLock`-protected WebSocket sink, allowing shared access between the
/// listener (for pings) and the tunnel sink (for data).
pub(crate) type WsBaseSink = BiLock<WsRawSink>;

/// Signal sent when the sink completes, indicating whether the connection
/// can be recycled.
pub(crate) enum TunnelSinkEol {
    /// Sink completed successfully; return the BiLock half for recycling.
    Ok(WsBaseSink),
    /// Sink failed; the WebSocket should be discarded.
    Fail,
}

/// The write half of a tunnel connection.
///
/// `TunnelSink` implements `futures::Sink<Bytes, Error = TunnelError>`,
/// allowing data to be sent to the remote client.
///
/// # Protocol
///
/// - Data is sent as binary WebSocket messages
/// - Closing the sink sends an empty binary message as EOF signal
/// - The underlying WebSocket is shared with a background task via `BiLock`,
///   which sends periodic ping messages to keep the connection alive
///
/// # Connection Recycling
///
/// When the sink is closed (via `SinkExt::close()`), it signals the background
/// task whether the underlying WebSocket can be recycled:
/// - Clean close: connection can be recycled
/// - Error during send: connection is discarded
///
/// # Example
///
/// ```rust,ignore
/// use futures::SinkExt;
/// use bytes::Bytes;
///
/// sink.send(Bytes::from("Hello")).await?;
/// sink.send(Bytes::from("World")).await?;
/// sink.close().await?; // Sends EOF and allows recycling
/// ```
pub struct TunnelSink {
    /// The BiLock-protected WebSocket sink, or an error if already completed.
    /// - `Ok(sink)`: Active sink, ready to send
    /// - `Err(result)`: Completed; the result to return for subsequent operations
    inner: Result<WsBaseSink, Result<(), TunnelError>>,
    /// Channel to signal completion status for connection recycling.
    recycler: flume::Sender<TunnelSinkEol>,
    /// Cached lock guard between `poll_ready` and `start_send`.
    ///
    /// # Safety
    ///
    /// This guard borrows from `inner`. We use `'static` lifetime with unsafe
    /// transmute because Rust cannot express self-referential structs. We ensure
    /// safety by always clearing this field before modifying or moving `inner`.
    ready_guard: Option<BiLockGuard<'static, WsRawSink>>,
}

impl TunnelSink {
    /// Creates a new `TunnelSink` wrapping a BiLock-protected WebSocket sink.
    pub(crate) fn new(inner: WsBaseSink, recycler: flume::Sender<TunnelSinkEol>) -> Self {
        Self {
            inner: Ok(inner),
            recycler,
            ready_guard: None,
        }
    }

    /// Marks the sink as done (graceful completion) and signals for recycling.
    ///
    /// Clears any cached guard, sends the BiLock half to the recycler, and
    /// sets the final result for subsequent operations.
    fn set_done(&mut self, next: Result<(), TunnelError>) -> Result<(), TunnelError> {
        // Clear the guard first (required for safety)
        self.ready_guard = None;
        // Swap out the inner sink
        let mut temp = Err(Err(TunnelError::InvalidState));
        std::mem::swap(&mut self.inner, &mut temp);
        // If we had an active sink, signal that it can be recycled
        if let Ok(sink) = temp {
            let _ = self.recycler.try_send(TunnelSinkEol::Ok(sink));
        }
        // Set the final result
        self.inner = Err(next.clone());
        next
    }

    /// Marks the sink as failed (non-recoverable error) and signals to discard.
    ///
    /// The connection cannot be recycled after a failure.
    fn set_failure(&mut self, err: TunnelError) -> Result<(), TunnelError> {
        // Clear the guard first (required for safety)
        self.ready_guard = None;
        // If already in error state, return that error
        if let Err(e) = &self.inner {
            return e.clone();
        }
        // Swap out the inner sink
        let mut temp = Err(Err(err.clone()));
        std::mem::swap(&mut self.inner, &mut temp);
        // Signal that the connection should be discarded
        let _ = self.recycler.try_send(TunnelSinkEol::Fail);
        Err(err)
    }
}

impl Drop for TunnelSink {
    fn drop(&mut self) {
        // If dropped while still active, signal completion to allow recycling
        // (though in practice this means the user didn't call close())
        if self.inner.is_ok() {
            let _ = self.set_done(Err(TunnelError::InvalidState));
        }
    }
}

impl Sink<Bytes> for TunnelSink {
    type Error = TunnelError;

    /// Polls readiness to send data.
    ///
    /// This acquires the BiLock and checks if the underlying WebSocket is ready.
    /// The lock guard is cached for use in `start_send`.
    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), TunnelError>> {
        let this = self.get_mut();
        let inner = match &mut this.inner {
            Ok(inner) => inner,
            Err(err) => return Poll::Ready(err.clone()),
        };
        let mut guard = match this.ready_guard.take() {
            Some(guard) => guard,
            None => match inner.poll_lock(cx) {
                Poll::Ready(guard) => {
                    // SAFETY: The guard borrows from `inner` which lives in this struct.
                    // We ensure the guard is cleared before `inner` is moved or dropped.
                    unsafe {
                        std::mem::transmute::<
                            BiLockGuard<'_, WsRawSink>,
                            BiLockGuard<'static, WsRawSink>,
                        >(guard)
                    }
                }
                Poll::Pending => return Poll::Pending,
            },
        };
        match guard.poll_ready_unpin(cx) {
            Poll::Ready(Ok(())) => {
                this.ready_guard = Some(guard);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(this.set_failure(e.into())),
            Poll::Pending => Poll::Pending,
        }
    }

    /// Begins sending a data chunk.
    ///
    /// Must be called after `poll_ready` returns `Ready(Ok(()))`.
    /// The data is sent as a binary WebSocket message.
    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), TunnelError> {
        let this = self.get_mut();
        // We must have a ready_guard from poll_ready
        let mut guard = match this.ready_guard.take() {
            Some(guard) => guard,
            None => {
                return Err(TunnelError::InvalidState);
            }
        };
        match guard.start_send_unpin(Message::binary(item)) {
            Ok(()) => Ok(()),
            Err(e) => this.set_failure(e.into()),
        }
    }

    /// Flushes any buffered data to the WebSocket.
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        let inner = match &mut this.inner {
            Ok(inner) => inner,
            Err(err) => return Poll::Ready(err.clone()),
        };
        // Track whether we already had a guard (from poll_ready)
        let mut is_ready = false;
        let mut guard = match this.ready_guard.take() {
            Some(guard) => {
                is_ready = true;
                guard
            }
            None => match inner.poll_lock(cx) {
                Poll::Ready(guard) => {
                    // SAFETY: same as poll_ready
                    unsafe {
                        std::mem::transmute::<
                            BiLockGuard<'_, WsRawSink>,
                            BiLockGuard<'static, WsRawSink>,
                        >(guard)
                    }
                }
                Poll::Pending => return Poll::Pending,
            },
        };
        let result = guard.poll_flush_unpin(cx);
        // Restore the guard if we had it from poll_ready
        if is_ready {
            this.ready_guard = Some(guard);
        }
        result.map_err(TunnelError::from)
    }

    /// Closes the sink, sending an EOF signal and allowing connection recycling.
    ///
    /// This sends an empty binary message as the EOF signal, then marks the
    /// sink as complete and signals the background task for recycling.
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        let inner = match &mut this.inner {
            Ok(inner) => inner,
            Err(err) => return Poll::Ready(err.clone()),
        };
        let mut is_ready = false;
        let mut guard = match this.ready_guard.take() {
            Some(guard) => {
                is_ready = true;
                guard
            }
            None => match inner.poll_lock(cx) {
                Poll::Ready(guard) => {
                    // SAFETY: same as poll_ready
                    unsafe {
                        std::mem::transmute::<
                            BiLockGuard<'_, WsRawSink>,
                            BiLockGuard<'static, WsRawSink>,
                        >(guard)
                    }
                }
                Poll::Pending => return Poll::Pending,
            },
        };
        // send EOF
        let ready_result = guard.poll_ready_unpin(cx);
        if ready_result.is_pending() {
            if is_ready {
                this.ready_guard = Some(guard);
            }
            return Poll::Pending;
        }
        let send_result = guard.start_send_unpin(Message::Binary(Bytes::new()));
        drop(guard);
        // successfully closed
        let _ = this.set_done(Err(TunnelError::InvalidState));
        Poll::Ready(send_result.map_err(TunnelError::from))
    }
}
