use std::{pin::Pin, sync::{Arc, Mutex, atomic::{ AtomicU8, Ordering}}, task::{Context, Poll}};

use futures::{Sink, Stream, task::AtomicWaker};

// A single-slot rendezvous between a `Sink` writer and a `Stream` reader.
//
// This is a small, lock-assisted state machine that transfers at most one
// `ITEM` at a time. The writer publishes by calling `start_send`, and the
// reader consumes via `poll_next`. Each side uses an `AtomicWaker` so that
// when it makes progress, it can wake the other side.
//
// The `Mutex<Option<ITEM>>` protects the actual payload. The `state` tracks
// whether the slot is empty/full, flushing, or closed.
pub struct SinkStreamRendezvous<ITEM>
{
  reader: AtomicWaker,
  writer: AtomicWaker,
  state: AtomicU8,
  item: Mutex<Option<ITEM>>,
}

#[derive(Debug)]
pub enum RendezvousWriteError {
    ReaderDropped,
    InvalidState,
}

// External wrapper: a `Sink` backed by a shared rendezvous.
pub struct RendezvousExternalSink<ITEM> {
    inner: Arc<SinkStreamRendezvous<ITEM>>,
    close_on_drop: bool,
}

// External wrapper: a `Stream` backed by a shared rendezvous.
pub struct RendezvousExternalStream<ITEM> {
    inner: Arc<SinkStreamRendezvous<ITEM>>,
    close_on_drop: bool,
}

// State machine (single slot) overview:
// EMPTY -> FULL -> EMPTY ...
// EMPTY_FLUSH / FULL_FLUSH are used to honor `poll_flush`.
// FULL_CLOSED is "one last item then close".
// DONE means the stream is finished.
// DROPPED indicates the reader was dropped.
const RENDEZVOUS_EMPTY: u8 = 0;
const RENDEZVOUS_EMPTY_FLUSH: u8 = 1;
const RENDEZVOUS_FULL: u8 = 2;
const RENDEZVOUS_FULL_FLUSH: u8 = 3;
const RENDEZVOUS_FULL_CLOSED: u8 = 4;
const RENDEZVOUS_DONE: u8 = 5;
const RENDEZVOUS_DROPPED: u8 = 6;

impl<ITEM> SinkStreamRendezvous<ITEM> {
    pub fn new() -> Self {
        Self {
            reader: AtomicWaker::new(),
            writer: AtomicWaker::new(),
            state: AtomicU8::new(RENDEZVOUS_EMPTY),
            item: Mutex::new(None),
        }
    }
    // Reader side: attempt to take the next item.
    //
    // Behavior:
    // - If empty, return Pending.
    // - If full, take the item and transition to the appropriate empty state.
    // - If closed/done, return None.
    pub fn read_poll_next(&self, cx: &mut Context<'_>) -> Poll<Option<ITEM>> {
        self.reader.register(cx.waker());
        let mut guard = self.item.lock().unwrap();
        let st = self.state.load(Ordering::Acquire);
        let nextst = match st {
            RENDEZVOUS_EMPTY | RENDEZVOUS_EMPTY_FLUSH => {
                return Poll::Pending;
            }
            RENDEZVOUS_FULL => RENDEZVOUS_EMPTY,
            RENDEZVOUS_FULL_FLUSH => RENDEZVOUS_EMPTY_FLUSH,
            RENDEZVOUS_FULL_CLOSED => RENDEZVOUS_DONE,
            _ => {
                return Poll::Ready(None);
            },
        };
        let item = guard.take();
        self.state.store(nextst, Ordering::Release);
        self.writer.wake();
        drop(guard);
        if let Some(item) = item {
            return Poll::Ready(Some(item));
        }
        if nextst == RENDEZVOUS_DONE {
            return Poll::Ready(None);
        }
        return Poll::Pending;
    }

    pub fn read_drop(&self) {
        let mut guard = self.item.lock().unwrap();
        let st = self.state.load(Ordering::Acquire);
        match st {
            RENDEZVOUS_DROPPED | RENDEZVOUS_DONE => return,
            _ => {
                self.state.store(RENDEZVOUS_DROPPED, Ordering::Release);
                *guard = None;
                self.writer.wake();
            },
        }
    }

    // Writer side: is the slot available for a new item?
    // Returns Pending while an item is still in flight or during close.
    pub fn write_poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), RendezvousWriteError>> {
        self.writer.register(cx.waker());
        match self.state.load(Ordering::Acquire) {
            RENDEZVOUS_EMPTY | RENDEZVOUS_EMPTY_FLUSH => Poll::Ready(Ok(())),
            RENDEZVOUS_FULL | RENDEZVOUS_FULL_FLUSH | RENDEZVOUS_FULL_CLOSED => Poll::Pending,
            RENDEZVOUS_DROPPED => Poll::Ready(Err(RendezvousWriteError::ReaderDropped)),
            _ => Poll::Ready(Err(RendezvousWriteError::InvalidState)),
        }
    }
    // Writer side: publish a new item into the slot.
    //
    // This only succeeds when the slot is empty (flush state allowed).
    pub fn write_start_send(&self, item: ITEM) -> Result<(), RendezvousWriteError> {
        let mut guard = self.item.lock().unwrap();
        let st = self.state.load(Ordering::Acquire);
        match st {
            RENDEZVOUS_EMPTY | RENDEZVOUS_EMPTY_FLUSH => {
                if self.state.compare_exchange(st, RENDEZVOUS_FULL, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
                    *guard = Some(item);
                    self.state.store(RENDEZVOUS_FULL, Ordering::Release);
                    self.reader.wake();
                    Ok(())
                } else {
                    Err(RendezvousWriteError::InvalidState)
                }
            },
            RENDEZVOUS_DROPPED => Err(RendezvousWriteError::ReaderDropped),
            _ => Err(RendezvousWriteError::InvalidState),
        }
    }
    // Begin a flush. Returns true if flush is complete immediately.
    // If an item is in flight, transitions to a FLUSH state and waits.
    pub fn write_start_flush(&self) -> bool {
        loop {
            let st = self.state.load(Ordering::Acquire);
            match st {
                RENDEZVOUS_EMPTY => {
                    if self.state.compare_exchange(st, RENDEZVOUS_EMPTY_FLUSH, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
                        self.reader.wake();
                        break true;
                    }
                },
                RENDEZVOUS_FULL => {
                    let mut _guard = self.item.lock().unwrap();
                    if self.state.compare_exchange(RENDEZVOUS_FULL, RENDEZVOUS_FULL_FLUSH, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
                        self.reader.wake();
                        break false;
                    }
                },
                RENDEZVOUS_FULL_FLUSH | RENDEZVOUS_FULL_CLOSED=> break false,
                _ => break true,
            }
        }
    }
    // Writer side: wait until the flush completes.
    pub fn write_poll_flush(&self, cx: &mut Context<'_>) -> Poll<Result<(), RendezvousWriteError>> {
        self.writer.register(cx.waker());
        match self.write_start_flush() {
            true => Poll::Ready(Ok(())),
            false => Poll::Pending,
        }
    }
    // Begin closing. If empty, move to DONE. If full, mark FULL_CLOSED so
    // the reader will consume the last item and then finish.
    pub fn write_close(&self) -> bool {
        loop {
            let st = self.state.load(Ordering::Acquire);
            match st {
                RENDEZVOUS_EMPTY | RENDEZVOUS_EMPTY_FLUSH => {
                    if self.state.compare_exchange(st, RENDEZVOUS_DONE, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
                        self.reader.wake();
                        break true;
                    }
                },
                RENDEZVOUS_FULL | RENDEZVOUS_FULL_FLUSH => {
                    let mut _guard = self.item.lock().unwrap();
                    if self.state.compare_exchange(st, RENDEZVOUS_FULL_CLOSED, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
                        self.reader.wake();
                        break false;
                    }
                },
                RENDEZVOUS_FULL_CLOSED => {
                    break false
                },
                _ => break true,
            }
        }
    }
    // Writer side: wait until close is fully observed.
    pub fn write_poll_close(&self, cx: &mut Context<'_>) -> Poll<Result<(), RendezvousWriteError>> {
        self.writer.register(cx.waker());
        match self.write_close() {
            true => Poll::Ready(Ok(())),
            false => Poll::Pending,
        }
    }
}

impl<ITEM> RendezvousExternalSink<ITEM> {
    pub fn new(inner: Arc<SinkStreamRendezvous<ITEM>>, close_on_drop: bool) -> Self {
        Self {
            inner,
            close_on_drop,
        }
    }
}

impl<ITEM> RendezvousExternalStream<ITEM> {
    pub fn new(inner: Arc<SinkStreamRendezvous<ITEM>>, close_on_drop: bool) -> Self {
        Self {
            inner,
            close_on_drop,
        }
    }
}

impl<ITEM> Drop for RendezvousExternalSink<ITEM> {
    fn drop(&mut self) {
        if self.close_on_drop {
            self.inner.write_close();
        }
    }
}

impl<ITEM> Drop for RendezvousExternalStream<ITEM> {
    fn drop(&mut self) {
        if self.close_on_drop {
            self.inner.read_drop();
        }
    }
}

// These wrappers don't contain self-referential data, so it's safe to Unpin them.
impl<ITEM> Unpin for RendezvousExternalSink<ITEM> {}
impl<ITEM> Unpin for RendezvousExternalStream<ITEM> {}

impl<ITEM> Sink<ITEM> for RendezvousExternalSink<ITEM> {
    type Error = RendezvousWriteError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.write_poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: ITEM) -> Result<(), Self::Error> {
        self.inner.write_start_send(item)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.write_poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.write_poll_close(cx)
    }
}

impl<ITEM> Stream for RendezvousExternalStream<ITEM> {
    type Item = ITEM;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<ITEM>> {
        self.inner.read_poll_next(cx)
    }
}

impl<ITEM> Sink<ITEM> for SinkStreamRendezvous<ITEM> {
    type Error = RendezvousWriteError;

    // The `Sink` implementation is just a thin wrapper around the writer-side
    // helper methods above.
    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.write_poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: ITEM) -> Result<(), Self::Error> {
        self.write_start_send(item)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.write_poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.write_poll_close(cx)
    }
}

impl<ITEM> Stream for SinkStreamRendezvous<ITEM> {
    type Item = ITEM;

    // The `Stream` implementation is just a thin wrapper around the reader-side
    // helper method above.
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<ITEM>> {
        self.read_poll_next(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::task::noop_waker;
    use std::sync::atomic::Ordering as AtomicOrdering;
    use std::task::Context;

    fn with_noop_cx<T>(f: impl FnOnce(&mut Context<'_>) -> T) -> T {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        f(&mut cx)
    }

    #[test]
    fn send_receive_single_item() {
        let r = SinkStreamRendezvous::new();

        let pending = with_noop_cx(|cx| r.read_poll_next(cx));
        assert!(matches!(pending, Poll::Pending));

        let ready = with_noop_cx(|cx| r.write_poll_ready(cx));
        assert!(matches!(ready, Poll::Ready(Ok(()))));

        r.write_start_send(42).unwrap();

        let pending = with_noop_cx(|cx| r.write_poll_ready(cx));
        assert!(matches!(pending, Poll::Pending));

        let next = with_noop_cx(|cx| r.read_poll_next(cx));
        assert!(matches!(next, Poll::Ready(Some(42))));

        let ready = with_noop_cx(|cx| r.write_poll_ready(cx));
        assert!(matches!(ready, Poll::Ready(Ok(()))));

        let pending = with_noop_cx(|cx| r.read_poll_next(cx));
        assert!(matches!(pending, Poll::Pending));
    }

    #[test]
    fn flush_on_empty_is_immediate() {
        let r: SinkStreamRendezvous<i32> = SinkStreamRendezvous::new();

        let flushed = with_noop_cx(|cx| r.write_poll_flush(cx));
        assert!(matches!(flushed, Poll::Ready(Ok(()))));

        let ready = with_noop_cx(|cx| r.write_poll_ready(cx));
        assert!(matches!(ready, Poll::Ready(Ok(()))));
    }

    #[test]
    fn flush_waits_for_in_flight_item() {
        let r = SinkStreamRendezvous::new();
        r.write_start_send(7).unwrap();

        let pending = with_noop_cx(|cx| r.write_poll_flush(cx));
        assert!(matches!(pending, Poll::Pending));

        let next = with_noop_cx(|cx| r.read_poll_next(cx));
        assert!(matches!(next, Poll::Ready(Some(7))));

        let flushed = with_noop_cx(|cx| r.write_poll_flush(cx));
        assert!(matches!(flushed, Poll::Ready(Ok(()))));
    }

    #[test]
    fn close_when_empty_finishes_stream() {
        let r: SinkStreamRendezvous<i32> = SinkStreamRendezvous::new();

        let closed = with_noop_cx(|cx| r.write_poll_close(cx));
        assert!(matches!(closed, Poll::Ready(Ok(()))));

        let end = with_noop_cx(|cx| r.read_poll_next(cx));
        assert!(matches!(end, Poll::Ready(None)));
    }

    #[test]
    fn close_after_full_delivers_last_item() {
        let r = SinkStreamRendezvous::new();
        r.write_start_send(11).unwrap();

        let pending = with_noop_cx(|cx| r.write_poll_close(cx));
        assert!(matches!(pending, Poll::Pending));

        let next = with_noop_cx(|cx| r.read_poll_next(cx));
        assert!(matches!(next, Poll::Ready(Some(11))));

        let end = with_noop_cx(|cx| r.read_poll_next(cx));
        assert!(matches!(end, Poll::Ready(None)));

        let closed = with_noop_cx(|cx| r.write_poll_close(cx));
        assert!(matches!(closed, Poll::Ready(Ok(()))));
    }

    #[test]
    fn start_send_on_full_is_invalid_state() {
        let r = SinkStreamRendezvous::new();
        r.write_start_send(1).unwrap();

        let err = r.write_start_send(2).unwrap_err();
        assert!(matches!(err, RendezvousWriteError::InvalidState));
    }

    #[test]
    fn reader_dropped_errors() {
        let r = SinkStreamRendezvous::<i32>::new();
        r.state.store(RENDEZVOUS_DROPPED, AtomicOrdering::Release);

        let ready = with_noop_cx(|cx| r.write_poll_ready(cx));
        assert!(matches!(ready, Poll::Ready(Err(RendezvousWriteError::ReaderDropped))));

        let err = r.write_start_send(1).unwrap_err();
        assert!(matches!(err, RendezvousWriteError::ReaderDropped));
    }
}
