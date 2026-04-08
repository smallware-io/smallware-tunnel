use std::cell::RefCell;
use std::fmt::{self};
use std::sync::Arc;
use std::task::{Context, Poll};

use futures::{Sink, Stream};
use std::pin::Pin;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use crate::io_sink::IoSink;
use crate::io_stream::IoStream;
use crate::tunnel_protocol::ServerLinks;
use crate::{StatCounter, STAT_COUNT_BYTES_DOWN, STAT_COUNT_BYTES_UP};

/// The underlying WebSocket sink type (write half after split).
pub type WsRawSink =
    futures::stream::SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>;

/// The underlying WebSocket stream type (read half after split).
pub type WsBaseStream = futures::stream::SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>;

/// A [`ServerLinks`] implementation backed by a split WebSocket connection.
///
/// Wraps a [`WsRawSink`] and [`WsBaseStream`] to provide [`IoSink`] and
/// [`IoStream`] interfaces that the tunnel protocol tasks can poll directly.
///
/// The inner sink and stream are held in `Option`s — set to `None` when
/// closed, dropped, or consumed by an error. Closing the sink actually
/// closes the WebSocket write half; dropping the read actually drops
/// the WebSocket read half. Once either half is gone the connection
/// is not recyclable.
///
/// If both halves are still present after the protocol completes (i.e. a
/// clean shutdown without close/drop), [`take`](WsServerLinks::take) can
/// extract them for connection recycling.
pub struct WsServerLinks {
    sink: RefCell<Option<WsRawSink>>,
    stream: RefCell<Option<WsBaseStream>>,
    stat_counter: Arc<dyn StatCounter>,
    buffered: RefCell<Option<Message>>,
}

impl WsServerLinks {
    pub fn new(sink: WsRawSink, stream: WsBaseStream, stat_counter: Arc<dyn StatCounter>) -> Self {
        Self {
            sink: RefCell::new(Some(sink)),
            stream: RefCell::new(Some(stream)),
            stat_counter,
            buffered: RefCell::new(None),
        }
    }

    /// Extracts the underlying WebSocket halves for connection recycling.
    ///
    /// Returns `None` for either half that has already been closed, dropped,
    /// or consumed by an error.
    pub fn take(&self) -> (Option<WsRawSink>, Option<WsBaseStream>) {
        (
            self.sink.borrow_mut().take(),
            self.stream.borrow_mut().take(),
        )
    }
}

impl fmt::Debug for WsServerLinks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WsServerLinks")
            .field("sink", &self.sink.borrow().is_some())
            .field("stream", &self.stream.borrow().is_some())
            .finish()
    }
}

// SAFETY: WsRawSink and WsBaseStream are Send. RefCell is Send when
// its contents are Send. The struct is used inside a ProcMachine which
// guarantees single-threaded access through its lock.
unsafe impl Send for WsServerLinks {}

impl ServerLinks for WsServerLinks {
    fn sink(&self) -> &(impl IoSink<Item = Message> + ?Sized) {
        self
    }
    fn stream(&self) -> &(impl IoStream<Message> + ?Sized) {
        self
    }
}

impl IoSink for WsServerLinks {
    type Error = ();
    type Item = Message;

    fn poll_send_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), ()>> {
        let mut sink = self.sink.borrow_mut();
        let Some(sink) = sink.as_mut() else {
            tracing::error!("Websocket check write after done");
            return Poll::Ready(Err(()));
        };
        Pin::new(sink).poll_ready(cx).map_err(|_| ())
    }

    fn poll_send(&self, cx: &mut Context<'_>, item: &mut Option<Message>) -> Poll<Result<(), ()>> {
        if item.is_none() {
            return Poll::Ready(Ok(()));
        }
        let mut sink = self.sink.borrow_mut();
        let Some(sink) = sink.as_mut() else {
            tracing::error!("Websocket write after done");
            return Poll::Ready(Err(()));
        };
        match Pin::new(&mut *sink).poll_ready(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(_)) => return Poll::Ready(Err(())),
            Poll::Ready(Ok(())) => {}
        }
        let len = match item {
            Some(Message::Binary(bytes)) => Some(bytes.len()),
            _ => None,
        };
        let msg = item.take().unwrap();
        Pin::new(&mut *sink).start_send(msg).map_err(|_| ())?;
        // Best-effort flush to push data to the network. The waker from cx
        // (a protocol task waker) is registered for write-readiness, so the
        // task will be re-polled when the socket can make progress.
        let _ = Pin::new(&mut *sink).poll_flush(cx);
        if let Some(len) = len {
            if len == 0 {
                tracing::debug!("WS UP EOS");
            } else {
                self.stat_counter
                    .stat_count(STAT_COUNT_BYTES_UP, len as i32);
                tracing::debug!("WS UP {}", len);
            }
        }
        Poll::Ready(Ok(()))
    }

    fn poll_flush(&self, cx: &mut Context<'_>) -> Poll<Result<(), ()>> {
        let mut sink = self.sink.borrow_mut();
        let Some(sink) = sink.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        let ret = Pin::new(sink).poll_flush(cx).map_err(|_| ());
        if ret.is_ready() {
            tracing::debug!("WS UP FLUSH");
        }
        ret
    }

    fn poll_close(&self, cx: &mut Context<'_>) -> Poll<Result<(), ()>> {
        let mut sink = self.sink.borrow_mut();
        let Some(sink) = sink.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        match Pin::new(sink).poll_close(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(_) => {
                *self.sink.borrow_mut() = None;
                tracing::debug!("WS UP CLOSE");
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl IoStream<Message> for WsServerLinks {
    fn check_read(&self, cx: &mut Context<'_>) -> Poll<bool> {
        if self.buffered.borrow().is_some() {
            return Poll::Ready(true);
        }
        let mut stream = self.stream.borrow_mut();
        let Some(stream) = stream.as_mut() else {
            return Poll::Ready(false);
        };
        match Pin::new(stream).poll_next(cx) {
            Poll::Ready(Some(Ok(msg))) => {
                *self.buffered.borrow_mut() = Some(msg);
                Poll::Ready(true)
            }
            Poll::Ready(Some(Err(_))) | Poll::Ready(None) => {
                *self.stream.borrow_mut() = None;
                Poll::Ready(false)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_read(&self, cx: &mut Context<'_>) -> Poll<Option<Message>> {
        if let Some(msg) = self.buffered.borrow_mut().take() {
            return Poll::Ready(Some(msg));
        }
        let mut stream = self.stream.borrow_mut();
        let Some(stream) = stream.as_mut() else {
            return Poll::Ready(None);
        };
        match Pin::new(stream).poll_next(cx) {
            Poll::Ready(Some(Ok(msg))) => {
                match &msg {
                    Message::Binary(bytes) => {
                        let len = bytes.len();
                        if len == 0 {
                            tracing::debug!("WS DOWN EOS");
                        } else {
                            self.stat_counter
                                .stat_count(STAT_COUNT_BYTES_DOWN, len as i32);
                            tracing::debug!("WS DOWN {}", len);
                        }
                    }
                    _ => {}
                }
                Poll::Ready(Some(msg))
            }
            Poll::Ready(None) => {
                *self.stream.borrow_mut() = None;
                tracing::debug!("WS DOWN CLOSE");
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(_))) => {
                *self.stream.borrow_mut() = None;
                tracing::error!("Websocket read error");
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn drop_read(&self) {
        self.buffered.borrow_mut().take();
        *self.stream.borrow_mut() = None;
    }
}
