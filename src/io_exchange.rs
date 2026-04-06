//! Single-slot rendezvous channel implementing both [`IoSink`] and [`IoStream`].
//!
//! [`IoExchange`] transfers at most one item at a time between a writer
//! (the [`IoSink`] side) and a reader (the [`IoStream`] side). It is the
//! concrete implementation backing the tunnel protocol's data-flow pipes
//! (`down_in`, `down_out`, `up_in`, `up_out`).
//!
//! # State machine
//!
//! The exchange is driven by an atomic `u8` state with the following
//! transitions:
//!
//! ```text
//!   EMPTY ──send──► FULL ──read──► EMPTY  (normal cycle)
//!
//!   EMPTY ──flush──► EMPTY_FLUSH ──reader sees──► EMPTY_FLUSHED
//!   FULL  ──flush──► FULL_FLUSH  ──read──► EMPTY_FLUSH ──reader sees──► EMPTY_FLUSHED
//!
//!   EMPTY* ──close──► DONE
//!   FULL*  ──close──► FULL_CLOSED ──read──► DONE
//!
//!   (any)  ──drop_read──► DROPPED
//! ```
//!
//! "reader sees" means the reader called [`check_read`](IoStream::check_read)
//! or [`poll_read`](IoStream::poll_read) and observed the empty slot, which
//! proves it has consumed everything sent so far.
//!
//! # Synchronization
//!
//! - The `state` field (`AtomicU8`) is the sequencing authority; all
//!   transitions use `SeqCst` compare-exchanges.
//! - The `item` field (`Mutex<Option<ITEM>>`) protects the payload.
//!   The mutex is held during the brief window of placing/taking the item
//!   so that the state transition and the payload swap are atomic together.
//! - `AtomicWaker`s for both sides ensure the other side is notified when
//!   it can make progress.

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

/// A single-slot, lock-assisted rendezvous channel.
///
/// Implements both [`IoSink`] (writer) and [`IoStream`] (reader) using
/// interior mutability, so both halves can be accessed through a shared
/// `&IoExchange` reference.
///
/// # Usage
///
/// The tunnel protocol creates four `IoExchange` instances per connection:
/// two for the downstream (WebSocket ↔ protocol logic) direction and two
/// for the upstream (protocol logic ↔ application) direction.
#[derive(Debug)]
pub struct IoExchange<ITEM> {
    /// Waker for the reader side, notified when an item is placed or the
    /// stream is closed.
    reader: AtomicWaker,
    /// Waker for the writer side, notified when the reader consumes the
    /// item (freeing the slot) or drops.
    writer: AtomicWaker,
    /// Atomic state machine governing the exchange lifecycle.
    state: AtomicU8,
    /// The single-item payload slot, protected by a mutex so that state
    /// transitions and payload swaps happen together.
    item: Mutex<Option<ITEM>>,
}

/// Errors returned by the writer side of an [`IoExchange`].
#[derive(Debug)]
pub enum ExchangeWriteError {
    /// The reader called [`drop_read`](IoStream::drop_read), so no one will
    /// ever consume further items.
    ReaderDropped,
    /// A state transition failed unexpectedly (e.g. concurrent send on a
    /// single-producer channel).
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

// ---------------------------------------------------------------------------
// State constants
// ---------------------------------------------------------------------------

/// Slot is empty, no flush requested.
const EXCH_EMPTY: u8 = 0;
/// Slot is empty, writer has requested a flush but the reader hasn't
/// acknowledged yet.
const EXCH_EMPTY_FLUSH: u8 = 1;
/// Slot is empty and the reader has acknowledged the flush (observed the
/// empty slot after the flush request).
const EXCH_EMPTY_FLUSHED: u8 = 2;
/// Slot contains an item, no flush/close pending.
const EXCH_FULL: u8 = 3;
/// Slot contains an item and a flush has been requested.
const EXCH_FULL_FLUSH: u8 = 4;
/// Slot contains the final item; after the reader takes it the stream ends.
const EXCH_FULL_CLOSED: u8 = 5;
/// Stream is finished — the reader will see `None` from now on.
const EXCH_DONE: u8 = 6;
/// The reader has been dropped; further writes will error.
const EXCH_DROPPED: u8 = 7;

impl<ITEM: Send> IoExchange<ITEM> {
    /// Creates a new, empty exchange in the `EMPTY` state.
    pub fn new() -> Self {
        Self {
            reader: AtomicWaker::new(),
            writer: AtomicWaker::new(),
            state: AtomicU8::new(EXCH_EMPTY),
            item: Mutex::new(None),
        }
    }
}

// ---------------------------------------------------------------------------
// IoStream (reader side)
// ---------------------------------------------------------------------------

impl<ITEM: Send> IoStream<ITEM> for IoExchange<ITEM> {
    fn check_read(&self, cx: &mut Context<'_>) -> Poll<bool> {
        self.reader.register(cx.waker());
        let guard = self.item.lock().unwrap();
        let st = self.state.load(Ordering::Acquire);
        match st {
            // Nothing to read yet.
            EXCH_EMPTY | EXCH_EMPTY_FLUSHED => Poll::Pending,
            EXCH_EMPTY_FLUSH => {
                // The writer wants a flush acknowledgement. Transition to
                // FLUSHED so the writer's next poll_flush sees completion.
                let _ = self.state.compare_exchange(
                    st,
                    EXCH_EMPTY_FLUSHED,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                );
                self.writer.wake();
                Poll::Pending
            }
            // An item is available.
            EXCH_FULL | EXCH_FULL_CLOSED | EXCH_FULL_FLUSH => Poll::Ready(guard.is_some()),
            // DONE or DROPPED — stream is over.
            _ => Poll::Ready(false),
        }
    }

    /// Takes the next item from the exchange.
    ///
    /// State transitions on read:
    /// - `FULL` → `EMPTY` (normal cycle)
    /// - `FULL_FLUSH` → `EMPTY_FLUSH` (item consumed, flush still pending)
    /// - `FULL_CLOSED` → `DONE` (last item consumed, stream ends)
    fn poll_read(&self, cx: &mut Context<'_>) -> Poll<Option<ITEM>> {
        self.reader.register(cx.waker());
        let mut guard = self.item.lock().unwrap();
        let st = self.state.load(Ordering::Acquire);
        let nextst = match st {
            EXCH_EMPTY | EXCH_EMPTY_FLUSHED => {
                return Poll::Pending;
            }
            EXCH_EMPTY_FLUSH => {
                // Acknowledge the flush (reader has seen the empty slot).
                let _ = self.state.compare_exchange(
                    st,
                    EXCH_EMPTY_FLUSHED,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                );
                self.writer.wake();
                return Poll::Pending;
            }
            EXCH_FULL => EXCH_EMPTY,
            EXCH_FULL_FLUSH => EXCH_EMPTY_FLUSH,
            EXCH_FULL_CLOSED => EXCH_DONE,
            // DONE or DROPPED.
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
        // The state said FULL but the item slot was empty — shouldn't happen
        // in correct usage. If we just transitioned to DONE, report end-of-stream;
        // otherwise pend so the caller retries.
        if nextst == EXCH_DONE {
            return Poll::Ready(None);
        }
        Poll::Pending
    }

    fn drop_read(&self) {
        let mut guard = self.item.lock().unwrap();
        let st = self.state.load(Ordering::Acquire);
        match st {
            EXCH_DROPPED | EXCH_DONE => return,
            _ => {
                // Move to DROPPED and discard any in-flight item.
                self.state.store(EXCH_DROPPED, Ordering::Release);
                *guard = None;
                self.writer.wake();
            }
        }
    }
}

// ---------------------------------------------------------------------------
// IoSink (writer side)
// ---------------------------------------------------------------------------

impl<ITEM: Send> IoSink for IoExchange<ITEM> {
    type Error = ExchangeWriteError;
    type Item = ITEM;

    /// Checks whether the slot is empty and ready to accept a new item.
    fn poll_send_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), ExchangeWriteError>> {
        self.writer.register(cx.waker());
        match self.state.load(Ordering::Acquire) {
            // Any empty state means the slot is free.
            EXCH_EMPTY | EXCH_EMPTY_FLUSH | EXCH_EMPTY_FLUSHED => Poll::Ready(Ok(())),
            // Slot occupied — wait for the reader to consume.
            EXCH_FULL | EXCH_FULL_FLUSH | EXCH_FULL_CLOSED => Poll::Pending,
            EXCH_DROPPED => Poll::Ready(Err(ExchangeWriteError::ReaderDropped)),
            _ => Poll::Ready(Err(ExchangeWriteError::InvalidState)),
        }
    }

    /// Places an item into the slot if it is empty.
    ///
    /// Uses a compare-exchange on the state to atomically transition from
    /// an empty state to `FULL`. If the CAS fails (e.g. concurrent writer
    /// or reader-side state change), returns an error.
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
            EXCH_EMPTY | EXCH_EMPTY_FLUSH | EXCH_EMPTY_FLUSHED => {
                if self
                    .state
                    .compare_exchange(st, EXCH_FULL, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
                {
                    *guard = item.take();
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

    /// Requests that the reader acknowledge all previously sent items.
    ///
    /// Flush is a two-phase handshake:
    /// 1. Writer transitions to a `*_FLUSH` state and wakes the reader.
    /// 2. Reader observes the empty slot (via `check_read` or `poll_read`)
    ///    and transitions to `EMPTY_FLUSHED`.
    /// 3. Writer sees `EMPTY_FLUSHED` and returns `Ready`.
    ///
    /// The loop handles CAS retries if the state changes concurrently.
    fn poll_flush(&self, cx: &mut Context<'_>) -> Poll<Result<(), ExchangeWriteError>> {
        self.writer.register(cx.waker());
        loop {
            let st = self.state.load(Ordering::Acquire);
            match st {
                // Already in a flush/close state — wait for reader progress.
                EXCH_EMPTY_FLUSH | EXCH_FULL_FLUSH | EXCH_FULL_CLOSED => {
                    break Poll::Pending;
                }
                // Reader has acknowledged the flush.
                EXCH_EMPTY_FLUSHED => {
                    break Ok(()).into();
                }
                // Slot is empty — request a flush.
                EXCH_EMPTY => {
                    if self
                        .state
                        .compare_exchange(st, EXCH_EMPTY_FLUSH, Ordering::SeqCst, Ordering::SeqCst)
                        .is_ok()
                    {
                        self.reader.wake();
                        break Poll::Pending;
                    }
                    // CAS failed — retry the loop.
                }
                // Item still in flight — mark as flush-pending.
                EXCH_FULL => {
                    // Hold the lock to prevent the reader from consuming the
                    // item between our load and our CAS.
                    let _guard = self.item.lock().unwrap();
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
                    // CAS failed — retry the loop.
                }
                // DONE or DROPPED — nothing left to flush.
                _ => break Ok(()).into(),
            };
        }
    }

    /// Signals that no more items will be sent and waits for close completion.
    ///
    /// If the slot is empty, transitions directly to `DONE`. If an item is
    /// still in flight, transitions to `FULL_CLOSED` so the reader gets the
    /// last item before seeing end-of-stream.
    ///
    /// The loop handles CAS retries.
    fn poll_close(&self, cx: &mut Context<'_>) -> Poll<Result<(), ExchangeWriteError>> {
        self.writer.register(cx.waker());
        loop {
            let st = self.state.load(Ordering::Acquire);
            match st {
                // Empty (any sub-state) — go straight to DONE.
                EXCH_EMPTY | EXCH_EMPTY_FLUSH | EXCH_EMPTY_FLUSHED => {
                    if self
                        .state
                        .compare_exchange(st, EXCH_DONE, Ordering::SeqCst, Ordering::SeqCst)
                        .is_ok()
                    {
                        self.reader.wake();
                        break Ok(()).into();
                    }
                    // CAS failed — retry.
                }
                // Item in flight — mark as "last item, then close".
                EXCH_FULL | EXCH_FULL_FLUSH => {
                    // Hold the lock to prevent the reader from consuming the
                    // item between our load and our CAS.
                    let _guard = self.item.lock().unwrap();
                    if self
                        .state
                        .compare_exchange(st, EXCH_FULL_CLOSED, Ordering::SeqCst, Ordering::SeqCst)
                        .is_ok()
                    {
                        self.reader.wake();
                        break Poll::Pending;
                    }
                    // CAS failed — retry.
                }
                // Already waiting for the reader to take the last item.
                EXCH_FULL_CLOSED => break Poll::Pending,
                // DONE or DROPPED — already finished.
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

    /// Helper: run a closure with a no-op waker context.
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
    fn flush_on_empty_requires_check() {
        let r: IoExchange<i32> = IoExchange::new();

        let flushed = with_noop_cx(|cx| r.poll_flush(cx));
        assert!(matches!(flushed, Poll::Pending));

        let flushed = with_noop_cx(|cx| r.poll_flush(cx));
        assert!(matches!(flushed, Poll::Pending));

        let read = with_noop_cx(|cx| r.check_read(cx));
        assert!(matches!(read, Poll::Pending));

        let flushed = with_noop_cx(|cx| r.poll_flush(cx));
        assert!(matches!(flushed, Poll::Ready(Ok(()))));

        let ready = with_noop_cx(|cx| r.poll_send_ready(cx));
        assert!(matches!(ready, Poll::Ready(Ok(()))));
    }

    #[test]
    fn flush_waits_for_in_flight_item_and_check() {
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
        assert!(matches!(flushed, Poll::Pending));

        let next = with_noop_cx(|cx| r.poll_read(cx));
        assert!(matches!(next, Poll::Pending));

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
