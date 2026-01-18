//! Building blocks for single-producer, single-consumer relationships
//! between asynchronous processes.
//!
//! Each "relationship" is generally protected by a Mutex that
//! Serializes access between the producer and the consumer.
//!
//! There is generally one `Arc` or other cloneable owner for an
//! *entire system*, consisting of many relationships.
//!
//! These tasks interface differently with async tasks:
//! 1. The task's waker is registered when it gets, checks, or tries
//!    something, so that the task will be woken when whatever it looked
//!    at changes materially.
//! 2. A task will typically check lots of things in a loop and then
//!    `yield_once().await;` when it has nothing to do.  It is then
//!     guaranteed to be woken when the same checks might find something.
//!
//! This is a lot simpler than other models for integrating multiple
//! inputs like `tokio::select!`.

// ============================================================================
// YIELD ONCE
// ============================================================================

use coarsetime::Instant;
use std::{
    fmt,
    future::{poll_fn, Future},
    pin::Pin,
    sync::Mutex,
    task::{Context, Poll, Waker},
};

/// A future that will yield exactly once.
/// It returns `Pending` the first time it is polled, and will
/// return `Ready(())` from then on.
pub struct YieldOnce {
    yielded: bool,
}

impl Future for YieldOnce {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.yielded {
            Poll::Ready(())
        } else {
            self.yielded = true;
            // Crucial: Wake the executor so it polls us again!
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

/**
 * Async yield exactly once.  Calling `await` on the returned future
 * will suspend the task until its waker is called.  If the task already
 * an unacknowledged wake, then it's runtime will reschedule it "immediately".
 */
pub fn yield_once() -> YieldOnce {
    YieldOnce { yielded: false }
}

// ============================================================================
// ACCESSOR
// ============================================================================

/// A single-producer, single-consumer accessor for a struct of type T.
///
/// This allows the internal struct to be accessed as either the "producer"
/// or the "consumer" task, and to notify the other task when material
/// changes are mode.
///
/// Accessing the struct registers the task's
/// waker to be notified when the struct is changed by the other party.
///
/// `SpScMutex` is the usual implementation, allowing tasks in different threads
pub trait SpScAccessor<T> {
    /// Access the inner data as the "producer"
    /// The waker from the caller's context will be registered to be woken when the consumer
    /// task makes a change that the producer task should see.
    /// Then, `proc` is called to access the shared data.
    /// If `proc` returns true, then the consumer task's waker is woken.
    fn p<F: FnMut(&mut T) -> bool>(&self, proc: F) -> impl Future<Output = ()>;
    /// Access the inner data as the "producer" in a read-only fashion
    /// The waker from the caller's context will be registered to be woken when the consumer
    /// task makes a change that the producer task should see.
    /// Then, `proc` is called to access the shared data.
    /// This method does not notify the consumer
    fn p_get<RET, F: FnMut(&T) -> RET>(&self, proc: F) -> impl std::future::Future<Output = RET>;
    /// Access the inner data as the "consumer"
    /// The waker from the caller's context will be registered to be woken when the producer
    /// task makes a change that the consumer task should see.
    /// Then, `proc` is called to access the shared data.
    /// If `proc` returns true, then the producer task's waker is woken.
    fn c<F: FnMut(&mut T) -> bool>(&self, proc: F) -> impl std::future::Future<Output = ()>;
    /// Access the inner data as the "consumer" in a read-only fashion
    /// The waker from the caller's context will be registered to be woken when the producer
    /// task makes a change that the consumer task should see.
    /// Then, `proc` is called to access the shared data.
    /// This method does not notify the producer
    fn c_get<RET, F: FnMut(&T) -> RET>(&self, proc: F) -> impl std::future::Future<Output = RET>;
    /// Access the inner data as neither a consumer nor producer.
    /// No wakers will be registered.
    /// `proc` is called to access the shared data, and if it returns true, then both
    /// the producer and consumer tasks are notified.
    fn side_check<F: FnMut(&mut T) -> bool>(&self, proc: F);
}

/// An SpScAccessor that protects the inner data with a Mutex, allowing the
/// consumer and producer task to be in different threads.
#[derive(Debug)]
pub struct SpScMutex<T> {
    inner: Mutex<SpScMutexInner<T>>,
}

#[derive(Debug)]
struct SpScMutexInner<T> {
    p_waker: Waker,
    c_waker: Waker,
    inner: T,
}

impl<T> SpScMutex<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner: Mutex::new(SpScMutexInner {
                p_waker: Waker::noop().clone(),
                c_waker: Waker::noop().clone(),
                inner,
            }),
        }
    }
}

impl<T> SpScAccessor<T> for SpScMutex<T> {
    #[inline]
    async fn p<F: FnMut(&mut T) -> bool>(&self, mut proc: F) {
        let _ = poll_fn(|cx| {
            let mut guard = self.inner.lock().unwrap();
            let w = cx.waker();
            if !guard.p_waker.will_wake(w) {
                guard.p_waker = w.clone();
            }
            if proc(&mut guard.inner) {
                guard.c_waker.wake_by_ref();
            }
            Poll::Ready(())
        })
        .await;
    }
    #[inline]
    async fn p_get<RET, F: FnMut(&T) -> RET>(&self, mut proc: F) -> RET {
        let ret = poll_fn(|cx| {
            let mut guard = self.inner.lock().unwrap();
            let w = cx.waker();
            if !guard.p_waker.will_wake(w) {
                guard.p_waker = w.clone();
            }
            Poll::Ready(proc(&mut guard.inner))
        })
        .await;
        ret
    }
    #[inline]
    async fn c<F: FnMut(&mut T) -> bool>(&self, mut proc: F) {
        let _ = poll_fn(|cx| {
            let mut guard = self.inner.lock().unwrap();
            let w = cx.waker();
            if !guard.c_waker.will_wake(w) {
                guard.c_waker = w.clone();
            }
            if proc(&mut guard.inner) {
                guard.p_waker.wake_by_ref();
            }
            Poll::Ready(())
        })
        .await;
    }
    #[inline]
    async fn c_get<RET, F: FnMut(&T) -> RET>(&self, mut proc: F) -> RET {
        let ret = poll_fn(|cx| {
            let mut guard = self.inner.lock().unwrap();
            let w = cx.waker();
            if !guard.c_waker.will_wake(w) {
                guard.c_waker = w.clone();
            }
            Poll::Ready(proc(&mut guard.inner))
        })
        .await;
        ret
    }

    #[inline]
    fn side_check<F: FnMut(&mut T) -> bool>(&self, mut proc: F) {
        let mut guard = self.inner.lock().unwrap();
        if proc(&mut guard.inner) {
            guard.p_waker.wake_by_ref();
            guard.c_waker.wake_by_ref();
        }
    }
}

// ============================================================================
// ITEM EXCHANGE
// ============================================================================

/// The state of an "item exchange" that allows a single producer to send
/// "things" to a consumer one at a time.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SpScItemState {
    // The consumer is busy and can't receive an item right now.
    Busy,
    // The consumer is waiting for an item.
    Waiting,
    // The producer has provided an item to the consumer, but
    // the consumer hasn't received it yet. There will be an associated
    // item stored.
    Full,
    // The consumer is not accepting any more items
    Closed,
    // The consumer or producer has failed, and no more items can be transferred
    Failed,
}

impl fmt::Display for SpScItemState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let str = match self {
            Self::Busy => "BUSY",
            Self::Waiting => "WAITING",
            Self::Full => "FULL",
            Self::Closed => "CLOSED",
            Self::Failed => "FAILED",
        };
        write!(f, "{}", str)
    }
}

/// An SpScAccessor for a struct representing a SpSc relationship can be
/// used as an item exchange if the struct implements this trait.
pub trait SpScItemInner<T> {
    // Get the `SpScItemState` for the exchange
    fn get_state(&self) -> SpScItemState;
    // Set the `SpScItemSTate` for the exchange. This should perform any
    // Other state changes required for consistency like clearing timeouts, etc.
    fn set_state(&mut self, state: SpScItemState);
    // Access the item storage for the exchange
    fn item_mut(&mut self) -> &mut Option<T>;
    fn get_timeout(&self) -> Option<Instant>;
    fn timeout_mut(&mut self) -> &mut Option<Instant>;
}

/// An "item exchange" based on a shared struct that allows a producer process to write
/// items that a consumer process can then read.
/// This trait manages the changes to the `SpScItemState`, and delegates the data manipulations
pub trait SpScItem<INNER, T> {
    /// Try to read an item from the shared struct
    /// - If the current state is `Busy`, then it transitions to `Waiting`
    /// - If the current state is `Full`, then it transitions to `Busy`, and the item is transferred to `receiver`.
    /// - In all cases, the resulting state is returned.
    fn c_try_read(
        &self,
        receiver: &mut Option<T>,
        timeout: Option<Instant>,
    ) -> impl std::future::Future<Output = SpScItemState>;
    /// Try to write an item into the shared struct
    /// - If the current state is `Full`, then `Busy` is returned.
    /// - If the current state is `Waiting`, then it transitions to `Full`, the item is transferred from `sender`,
    ///   and `Full` is returned.
    /// - In other cases the current state is just returned.
    fn p_try_write(
        &self,
        sender: &mut Option<T>,
        timeout: Option<Instant>,
    ) -> impl std::future::Future<Output = SpScItemState>;
    /// Try to flush any pending output.
    /// - If the current state is `Full` or `Busy`, then the given timeout is establisehd and `Busy` is returned.
    /// - In all other cases, the current state is just returned.
    fn p_try_flush(
        &self,
        timeout: Option<Instant>,
    ) -> impl std::future::Future<Output = SpScItemState>;
    /// Close the exchange.  The state updates as follows:
    /// - Busy -> Closed
    /// - Waiting -> Closed
    /// - Full -> Failed
    /// - Closed -> Closed
    /// - Failed -> Failed
    fn close(&self);
    /// Check timeouts against a given time, and fail operations that have timed out:
    /// If the current state is Busy, Waiting, or Full, with a timeout in place, and `now` is greater than
    /// the timeout deadline, then the state transitions to `Failed` and the producer and consumer are notified.
    fn check_timeouts(&self, now: Instant);
}

impl<INNER, T, ACC> SpScItem<INNER, T> for ACC
where
    INNER: SpScItemInner<T>,
    ACC: SpScAccessor<INNER>,
{
    #[inline]
    async fn c_try_read(
        &self,
        receiver: &mut Option<T>,
        timeout: Option<Instant>,
    ) -> SpScItemState {
        let mut rst = SpScItemState::Failed;
        self.c(|r| {
            let changed = match r.get_state() {
                SpScItemState::Busy => {
                    r.set_state(SpScItemState::Waiting);
                    *r.timeout_mut() = timeout;
                    true
                }
                SpScItemState::Waiting => {
                    let tr = r.timeout_mut();
                    if *tr != timeout {
                        *tr = timeout;
                        true
                    } else {
                        false
                    }
                }
                SpScItemState::Full => {
                    r.set_state(SpScItemState::Busy);
                    *r.timeout_mut() = None;
                    *receiver = r.item_mut().take();
                    true
                }
                SpScItemState::Closed | SpScItemState::Failed => false,
            };
            rst = r.get_state();
            changed
        })
        .await;
        rst
    }

    #[inline]
    async fn p_try_write(&self, sender: &mut Option<T>, timeout: Option<Instant>) -> SpScItemState {
        let mut wst = SpScItemState::Failed;
        self.p(|w| {
            wst = w.get_state();
            match wst {
                SpScItemState::Busy => {
                    let tr = w.timeout_mut();
                    if *tr != timeout {
                        *tr = timeout;
                        true
                    } else {
                        false
                    }
                }
                SpScItemState::Failed | SpScItemState::Closed => false,
                SpScItemState::Waiting => {
                    wst = SpScItemState::Full;
                    *w.timeout_mut() = None;
                    *w.item_mut() = sender.take();
                    true
                }
                SpScItemState::Full => {
                    wst = SpScItemState::Busy;
                    *w.timeout_mut() = timeout;
                    false
                }
            }
        })
        .await;
        wst
    }
    #[inline]
    async fn p_try_flush(&self, timeout: Option<Instant>) -> SpScItemState {
        let mut wst = SpScItemState::Failed;
        self.p(|w| {
            wst = w.get_state();
            match wst {
                SpScItemState::Busy => {
                    let tr = w.timeout_mut();
                    if *tr != timeout {
                        *tr = timeout;
                        true
                    } else {
                        false
                    }
                }
                SpScItemState::Failed | SpScItemState::Closed => false,
                SpScItemState::Waiting => {
                    *w.timeout_mut() = None;
                    true
                }
                SpScItemState::Full => {
                    wst = SpScItemState::Busy;
                    *w.timeout_mut() = timeout;
                    false
                }
            }
        })
        .await;
        wst
    }
    fn close(&self) {
        self.side_check(|x| match x.get_state() {
            SpScItemState::Busy | SpScItemState::Waiting => {
                x.set_state(SpScItemState::Closed);
                true
            }
            SpScItemState::Full => {
                x.set_state(SpScItemState::Failed);
                true
            }
            _ => false,
        });
    }
    fn check_timeouts(&self, now: Instant) {
        self.side_check(|x| match x.get_timeout() {
            Some(deadline) => match deadline < now {
                true => match x.get_state() {
                    SpScItemState::Busy | SpScItemState::Waiting | SpScItemState::Full => {
                        x.set_state(SpScItemState::Failed);
                        true
                    }
                    _ => false,
                },
                false => false,
            },
            _ => false,
        });
    }
}

// ============================================================================
// DEFAULT ITEM EXCHAGNE
// ============================================================================

#[derive(Debug)]
pub struct SimpleSpScItemInner<T> {
    pub state: SpScItemState,
    pub timeout: Option<Instant>,
    pub item: Option<T>,
}

impl<T> Default for SimpleSpScItemInner<T> {
    fn default() -> Self {
        Self {
            state: SpScItemState::Waiting,
            timeout: None,
            item: None,
        }
    }
}

impl<T> SpScItemInner<T> for SimpleSpScItemInner<T> {
    fn get_state(&self) -> SpScItemState {
        self.state
    }

    fn set_state(&mut self, state: SpScItemState) {
        self.state = state;
    }

    fn item_mut(&mut self) -> &mut Option<T> {
        &mut self.item
    }

    fn get_timeout(&self) -> Option<Instant> {
        self.timeout
    }

    fn timeout_mut(&mut self) -> &mut Option<Instant> {
        &mut self.timeout
    }
}
