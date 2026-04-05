use std::{
    fmt::Display,
    sync::{
        atomic::{AtomicU8, Ordering},
        Mutex,
    },
    task::{Context, Poll},
};

use futures::task::AtomicWaker;

use crate::{io_sink::IoSink, io_stream::IoStream};

// A single-slot rendezvous exchange between a `Sink` writer and a `Stream` reader.
//
// This is a small, lock-assisted state machine that transfers at most one
// `ITEM` at a time. The writer publishes by calling `start_send`, and the
// reader consumes via `poll_next`. Each side uses an `AtomicWaker` so that
// when it makes progress, it can wake the other side.
//
// The `Mutex<Option<ITEM>>` protects the actual payload. The `state` tracks
// whether the slot is empty/full, flushing, or closed.
#[derive(Debug)]
pub struct IoExchange<ITEM> {
    reader: AtomicWaker,
    writer: AtomicWaker,
    state: AtomicU8,
    item: Mutex<Option<ITEM>>,
}

#[derive(Debug)]
pub enum ExchangeWriteError {
    ReaderDropped,
    InvalidState,
}

impl Display for ExchangeWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExchangeWriteError::ReaderDropped => {
                write!(f, "Write operation failed -- the reader has been dropped.")
            }
            ExchangeWriteError::InvalidState => {
                write!(f, "Write operation failed -- not ready to receive")
            }
        }
    }
}

// State machine (single slot) overview:
// EMPTY -> FULL -> EMPTY ...
// EMPTY_FLUSH / FULL_FLUSH are used to honor `poll_flush`.
// FULL_CLOSED is "one last item then close".
// DONE means the stream is finished.
// DROPPED indicates the reader was dropped.
const EXCH_EMPTY: u8 = 0;
const EXCH_EMPTY_FLUSH: u8 = 1;
const EXCH_FULL: u8 = 2;
const EXCH_FULL_FLUSH: u8 = 3;
const EXCH_FULL_CLOSED: u8 = 4;
const EXCH_DONE: u8 = 5;
const EXCH_DROPPED: u8 = 6;

impl<ITEM: Send> IoExchange<ITEM> {
    pub fn new() -> Self {
        Self {
            reader: AtomicWaker::new(),
            writer: AtomicWaker::new(),
            state: AtomicU8::new(EXCH_EMPTY),
            item: Mutex::new(None),
        }
    }
}
impl<ITEM: Send> IoStream<ITEM> for IoExchange<ITEM> {
    fn check_read(&self, cx: &mut Context<'_>) -> Poll<bool> {
        self.reader.register(cx.waker());
        let guard = self.item.lock().unwrap();
        let st = self.state.load(Ordering::Acquire);
        match st {
            EXCH_EMPTY | EXCH_EMPTY_FLUSH => Poll::Pending,
            EXCH_FULL | EXCH_FULL_CLOSED | EXCH_FULL_FLUSH => Poll::Ready(guard.is_some()),
            _ => Poll::Ready(false),
        }
    }

    // Reader side: attempt to take the next item.
    //
    // Behavior:
    // - If empty, return Pending.
    // - If full, take the item and transition to the appropriate empty state.
    // - If closed/done, return None.
    fn poll_read(&self, cx: &mut Context<'_>) -> Poll<Option<ITEM>> {
        self.reader.register(cx.waker());
        let mut guard = self.item.lock().unwrap();
        let st = self.state.load(Ordering::Acquire);
        let nextst = match st {
            EXCH_EMPTY | EXCH_EMPTY_FLUSH => {
                return Poll::Pending;
            }
            EXCH_FULL => EXCH_EMPTY,
            EXCH_FULL_FLUSH => EXCH_EMPTY_FLUSH,
            EXCH_FULL_CLOSED => EXCH_DONE,
            _ => {
                return Poll::Ready(None);
            }
        };
        let item = guard.take();
        self.state.store(nextst, Ordering::Release);
        self.writer.wake();
        drop(guard);
        if let Some(item) = item {
            return Poll::Ready(Some(item));
        }
        if nextst == EXCH_DONE {
            return Poll::Ready(None);
        }
        return Poll::Pending;
    }

    fn drop_read(&self) {
        let mut guard = self.item.lock().unwrap();
        let st = self.state.load(Ordering::Acquire);
        match st {
            EXCH_DROPPED | EXCH_DONE => return,
            _ => {
                self.state.store(EXCH_DROPPED, Ordering::Release);
                *guard = None;
                self.writer.wake();
            }
        }
    }
}
impl<ITEM: Send> IoSink for IoExchange<ITEM> {
    type Error = ExchangeWriteError;
    type Item = ITEM;
    // Writer side: is the slot available for a new item?
    // Returns Pending while an item is still in flight or during close.
    fn poll_send_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), ExchangeWriteError>> {
        self.writer.register(cx.waker());
        match self.state.load(Ordering::Acquire) {
            EXCH_EMPTY | EXCH_EMPTY_FLUSH => Poll::Ready(Ok(())),
            EXCH_FULL | EXCH_FULL_FLUSH | EXCH_FULL_CLOSED => Poll::Pending,
            EXCH_DROPPED => Poll::Ready(Err(ExchangeWriteError::ReaderDropped)),
            _ => Poll::Ready(Err(ExchangeWriteError::InvalidState)),
        }
    }
    fn poll_send(
        &self,
        cx: &mut Context<'_>,
        item: &mut Option<Self::Item>,
    ) -> Poll<Result<(), ExchangeWriteError>> {
        self.writer.register(cx.waker());
        if item.is_none() {
            return Poll::Ready(Ok(()));
        }
        let mut guard = self.item.lock().unwrap();
        let st = self.state.load(Ordering::Acquire);
        match st {
            EXCH_EMPTY | EXCH_EMPTY_FLUSH => {
                if self
                    .state
                    .compare_exchange(st, EXCH_FULL, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
                {
                    *guard = item.take();
                    self.state.store(EXCH_FULL, Ordering::Release);
                    self.reader.wake();
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Ready(Err(ExchangeWriteError::InvalidState))
                }
            }
            EXCH_FULL | EXCH_FULL_FLUSH | EXCH_FULL_CLOSED => Poll::Pending,
            EXCH_DROPPED => Poll::Ready(Err(ExchangeWriteError::ReaderDropped)),
            _ => Poll::Ready(Err(ExchangeWriteError::InvalidState)),
        }
    }

    fn poll_flush(&self, cx: &mut Context<'_>) -> Poll<Result<(), ExchangeWriteError>> {
        self.writer.register(cx.waker());
        loop {
            let st = self.state.load(Ordering::Acquire);
            match st {
                EXCH_EMPTY => {
                    if self
                        .state
                        .compare_exchange(st, EXCH_EMPTY_FLUSH, Ordering::SeqCst, Ordering::SeqCst)
                        .is_ok()
                    {
                        self.reader.wake();
                        break Poll::Ready(Ok(()));
                    }
                }
                EXCH_FULL => {
                    let mut _guard = self.item.lock().unwrap();
                    if self
                        .state
                        .compare_exchange(
                            EXCH_FULL,
                            EXCH_FULL_FLUSH,
                            Ordering::SeqCst,
                            Ordering::SeqCst,
                        )
                        .is_ok()
                    {
                        self.reader.wake();
                        break Poll::Pending;
                    }
                }
                EXCH_FULL_FLUSH | EXCH_FULL_CLOSED => return Poll::Pending,
                _ => break Poll::Ready(Ok(())),
            };
        }
    }

    fn poll_close(&self, cx: &mut Context<'_>) -> Poll<Result<(), ExchangeWriteError>> {
        self.writer.register(cx.waker());
        loop {
            let st = self.state.load(Ordering::Acquire);
            match st {
                EXCH_EMPTY | EXCH_EMPTY_FLUSH => {
                    if self
                        .state
                        .compare_exchange(st, EXCH_DONE, Ordering::SeqCst, Ordering::SeqCst)
                        .is_ok()
                    {
                        self.reader.wake();
                        break Poll::Ready(Ok(()));
                    }
                }
                EXCH_FULL | EXCH_FULL_FLUSH => {
                    let mut _guard = self.item.lock().unwrap();
                    if self
                        .state
                        .compare_exchange(st, EXCH_FULL_CLOSED, Ordering::SeqCst, Ordering::SeqCst)
                        .is_ok()
                    {
                        self.reader.wake();
                        break Poll::Pending;
                    }
                }
                EXCH_FULL_CLOSED => break Poll::Pending,
                _ => break Poll::Ready(Ok(())),
            }
        }
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
        let r = IoExchange::new();

        let pending = with_noop_cx(|cx| r.poll_read(cx));
        assert!(matches!(pending, Poll::Pending));

        let ready = with_noop_cx(|cx| r.poll_send_ready(cx));
        assert!(matches!(ready, Poll::Ready(Ok(()))));

        match with_noop_cx(|cx| r.poll_send(cx, &mut Some(42))) {
            Poll::Ready(Ok(_)) => (),
            _ => panic!(),
        }

        let pending = with_noop_cx(|cx| r.poll_send_ready(cx));
        assert!(matches!(pending, Poll::Pending));

        let next = with_noop_cx(|cx| r.poll_read(cx));
        assert!(matches!(next, Poll::Ready(Some(42))));

        let ready = with_noop_cx(|cx| r.poll_send_ready(cx));
        assert!(matches!(ready, Poll::Ready(Ok(()))));

        let pending = with_noop_cx(|cx| r.poll_read(cx));
        assert!(matches!(pending, Poll::Pending));
    }

    #[test]
    fn flush_on_empty_is_immediate() {
        let r: IoExchange<i32> = IoExchange::new();

        let flushed = with_noop_cx(|cx| r.poll_flush(cx));
        assert!(matches!(flushed, Poll::Ready(Ok(()))));

        let ready = with_noop_cx(|cx| r.poll_send_ready(cx));
        assert!(matches!(ready, Poll::Ready(Ok(()))));
    }

    #[test]
    fn flush_waits_for_in_flight_item() {
        let r = IoExchange::new();
        match with_noop_cx(|cx| r.poll_send(cx, &mut Some(7))) {
            Poll::Ready(Ok(_)) => (),
            _ => panic!(),
        }

        let pending = with_noop_cx(|cx| r.poll_flush(cx));
        assert!(matches!(pending, Poll::Pending));

        let next = with_noop_cx(|cx| r.poll_read(cx));
        assert!(matches!(next, Poll::Ready(Some(7))));

        let flushed = with_noop_cx(|cx| r.poll_flush(cx));
        assert!(matches!(flushed, Poll::Ready(Ok(()))));
    }

    #[test]
    fn close_when_empty_finishes_stream() {
        let r: IoExchange<i32> = IoExchange::new();

        let closed = with_noop_cx(|cx| r.poll_close(cx));
        assert!(matches!(closed, Poll::Ready(Ok(()))));

        let end = with_noop_cx(|cx| r.poll_read(cx));
        assert!(matches!(end, Poll::Ready(None)));
    }

    #[test]
    fn close_after_full_delivers_last_item() {
        let r = IoExchange::new();
        match with_noop_cx(|cx| r.poll_send(cx, &mut Some(11))) {
            Poll::Ready(Ok(_)) => (),
            _ => panic!(),
        }

        let pending = with_noop_cx(|cx| r.poll_close(cx));
        assert!(matches!(pending, Poll::Pending));

        let next = with_noop_cx(|cx| r.poll_read(cx));
        assert!(matches!(next, Poll::Ready(Some(11))));

        let end = with_noop_cx(|cx| r.poll_read(cx));
        assert!(matches!(end, Poll::Ready(None)));

        let closed = with_noop_cx(|cx| r.poll_close(cx));
        assert!(matches!(closed, Poll::Ready(Ok(()))));
    }

    #[test]
    fn start_send_on_full_is_invalid_state() {
        let r: IoExchange<i32> = IoExchange::new();
        match with_noop_cx(|cx| r.poll_send(cx, &mut Some(1))) {
            Poll::Ready(Ok(_)) => (),
            _ => panic!(),
        }
        match with_noop_cx(|cx| r.poll_send(cx, &mut Some(2))) {
            Poll::Pending => (),
            _ => panic!(),
        }
    }

    #[test]
    fn reader_dropped_errors() {
        let r = IoExchange::<i32>::new();
        r.state.store(EXCH_DROPPED, AtomicOrdering::Release);

        let ready = with_noop_cx(|cx| r.poll_send_ready(cx));
        assert!(matches!(
            ready,
            Poll::Ready(Err(ExchangeWriteError::ReaderDropped))
        ));
        let ready = with_noop_cx(|cx| r.poll_send(cx, &mut Some(1)));
        assert!(matches!(
            ready,
            Poll::Ready(Err(ExchangeWriteError::ReaderDropped))
        ));
    }
}
