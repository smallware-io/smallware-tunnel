use std::cell::RefCell;
use std::fmt;
use std::task::{Context, Poll};

use futures::{Sink, Stream};
use std::pin::Pin;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use crate::io_sink::IoSink;
use crate::io_stream::IoStream;
use crate::tunnel_protocol::ServerLinks;

/// The underlying WebSocket sink type (write half after split).
pub type WsRawSink = futures::stream::SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>;

/// The underlying WebSocket stream type (read half after split).
pub type WsBaseStream = futures::stream::SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>;

/// A [`ServerLinks`] implementation backed by a split WebSocket connection.
///
/// Wraps a [`WsRawSink`] and [`WsBaseStream`] to provide [`IoSink`] and
/// [`IoStream`] interfaces that the tunnel protocol tasks can poll directly.
///
/// The inner sink and stream are held in `Option`s — set to `None` once
/// closed or dropped, so that the underlying WebSocket halves are released.
pub struct WsServerLinks {
    sink: RefCell<Option<WsRawSink>>,
    stream: RefCell<Option<WsBaseStream>>,
    buffered: RefCell<Option<Message>>,
}

impl WsServerLinks {
    pub fn new(sink: WsRawSink, stream: WsBaseStream) -> Self {
        Self {
            sink: RefCell::new(Some(sink)),
            stream: RefCell::new(Some(stream)),
            buffered: RefCell::new(None),
        }
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
            return Poll::Ready(Err(()));
        };
        Pin::new(sink).poll_ready(cx).map_err(|_| ())
    }

    fn poll_send(
        &self,
        cx: &mut Context<'_>,
        item: &mut Option<Message>,
    ) -> Poll<Result<(), ()>> {
        if item.is_none() {
            return Poll::Ready(Ok(()));
        }
        let mut sink = self.sink.borrow_mut();
        let Some(sink) = sink.as_mut() else {
            return Poll::Ready(Err(()));
        };
        match Pin::new(&mut *sink).poll_ready(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(_)) => return Poll::Ready(Err(())),
            Poll::Ready(Ok(())) => {}
        }
        let msg = item.take().unwrap();
        Pin::new(sink).start_send(msg).map_err(|_| ())?;
        Poll::Ready(Ok(()))
    }

    fn poll_flush(&self, cx: &mut Context<'_>) -> Poll<Result<(), ()>> {
        let mut sink = self.sink.borrow_mut();
        let Some(sink) = sink.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        Pin::new(sink).poll_flush(cx).map_err(|_| ())
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
            Poll::Ready(Some(Ok(msg))) => Poll::Ready(Some(msg)),
            Poll::Ready(Some(Err(_))) | Poll::Ready(None) => {
                *self.stream.borrow_mut() = None;
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
