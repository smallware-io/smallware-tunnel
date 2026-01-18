//! Building blocks for single-producer, single-consumer relationships
//! between asynchronous processes.
//!
//! # Overview
//!
//! This module provides primitives for coordinating data flow between two async tasks:
//! a "producer" that creates data and a "consumer" that processes it. Unlike traditional
//! channel-based approaches (e.g., `mpsc`), these primitives are designed to work with
//! **sans-IO** state machines that are polled synchronously rather than run on an async
//! runtime.
//!
//! # Design Philosophy
//!
//! Each "relationship" between producer and consumer is protected by a Mutex that
//! serializes access between them. There is typically one `Arc` or other cloneable
//! owner for an *entire system*, consisting of many relationships.
//!
//! The integration with async/await is unusual but deliberate:
//!
//! 1. **Waker Registration**: When a task gets, checks, or tries something, its waker
//!    is registered so it will be woken when the data it examined changes materially.
//!
//! 2. **Polling Loop Pattern**: A task typically checks multiple conditions in a loop
//!    and calls `yield_once().await` when it has nothing to do. It is then guaranteed
//!    to be woken when the same checks might find something new.
//!
//! This approach is simpler than other models for integrating multiple inputs like
//! `tokio::select!`, and crucially, it works without a real async runtime - the futures
//! can be polled directly with a custom waker that just sets a flag.
//!
//! # Key Components
//!
//! - [`YieldOnce`] / [`yield_once()`]: A future that yields exactly once, allowing other
//!   tasks to make progress before this task continues.
//!
//! - [`SpScAccessor`] / [`SpScMutex`]: Traits and implementations for accessing shared
//!   state as either the producer or consumer, with automatic waker notification.
//!
//! - [`SpScItemState`] / [`SpScItem`]: A state machine for transferring items one at a
//!   time from producer to consumer, with timeout support.
//!
//! # Example Flow
//!
//! ```text
//! Producer Task                    Consumer Task
//!      |                                |
//!      |-- p_try_write(item) --------->|
//!      |   (state: Waiting -> Full)    |
//!      |                                |
//!      |   <-- consumer waker called --|
//!      |                                |
//!      |                                |-- c_try_read()
//!      |                                |   (state: Full -> Busy)
//!      |   <-- producer waker called --|
//!      |                                |
//! ```

// ============================================================================
// YIELD ONCE
// ============================================================================
//
// The `yield_once()` function creates a future that suspends exactly once.
// This is the fundamental building block for cooperative multitasking within
// a ProcMachine - it allows one task to give up control so other tasks can
// make progress.
//
// In a traditional async runtime, you'd use something like `tokio::task::yield_now()`.
// But since we're running without a real runtime, we need our own version that
// works with our custom polling loop.
//
// The key insight is that when a task has nothing useful to do (e.g., waiting
// for data that isn't available yet), it should call `yield_once().await` to
// let other tasks run. The ProcMachine will poll all tasks in a round-robin
// fashion until all of them are idle (no wakers fired recently).
// ============================================================================

use coarsetime::Instant;
use std::{
    fmt,
    future::{poll_fn, Future},
    pin::Pin,
    sync::Mutex,
    task::{Context, Poll, Waker},
};

/// A future that yields exactly once before completing.
///
/// This is used within the sans-IO state machine to give other tasks a chance
/// to run. When polled:
/// - First poll: Returns `Pending` and schedules itself to be woken immediately
/// - Subsequent polls: Returns `Ready(())`
///
/// The immediate wake is crucial - it ensures the executor knows this task
/// still has work to do, just not right now.
pub struct YieldOnce {
    /// Tracks whether we've already yielded once
    yielded: bool,
}

impl Future for YieldOnce {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.yielded {
            // We've already yielded once; now we're ready to continue
            Poll::Ready(())
        } else {
            // Mark that we're yielding
            self.yielded = true;
            // CRUCIAL: Wake the executor so it polls us again!
            // Without this, the task would be suspended forever since nothing
            // else would wake it. By calling wake_by_ref(), we ensure the
            // ProcMachine's `tick()` will poll us again on the next round.
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

/// Creates a future that yields exactly once before completing.
///
/// Use this when a task has nothing useful to do right now but wants to
/// give other tasks a chance to make progress. After yielding, the task
/// will be polled again.
///
/// # Example
///
/// ```ignore
/// loop {
///     // Try to do something
///     let state = io.channel.c_try_read(&mut data, timeout).await;
///     match state {
///         SpScItemState::Waiting => {
///             // Nothing available yet - let other tasks run
///             yield_once().await;
///             continue;
///         }
///         SpScItemState::Busy => {
///             // Got data! Process it...
///         }
///         // ... handle other states
///     }
/// }
/// ```
pub fn yield_once() -> YieldOnce {
    YieldOnce { yielded: false }
}

// ============================================================================
// ACCESSOR
// ============================================================================
//
// The SpScAccessor trait provides a pattern for two tasks to share data while
// maintaining the invariant that exactly one is the "producer" and one is the
// "consumer". Each side can register its waker to be notified when the other
// side makes a relevant change.
//
// This is different from a traditional channel because:
// 1. Both sides share access to the SAME data structure (not copying through a queue)
// 2. The closure-based API allows complex operations atomically
// 3. The producer/consumer distinction is for notification purposes, not ownership
//
// The key methods are:
// - `p()` / `p_get()`: Access as producer, register producer's waker, optionally notify consumer
// - `c()` / `c_get()`: Access as consumer, register consumer's waker, optionally notify producer
// - `side_check()`: Access from outside (e.g., timeout checker), notify both sides
//
// The bool return value from the closure determines whether to wake the other side:
// - Return `true` if you made a change the other side should see
// - Return `false` if you just read data or made no relevant change
// ============================================================================

/// A single-producer, single-consumer accessor for shared data of type `T`.
///
/// This trait enables two async tasks to coordinate access to shared state while
/// automatically handling waker registration and notification. The "producer" and
/// "consumer" roles are conceptual - both can read and write the data, but each
/// registers a separate waker so they can be notified independently.
///
/// # Waker Semantics
///
/// - When the producer accesses the data via `p()`, it registers its waker. If
///   the closure returns `true`, the consumer's waker is invoked.
/// - When the consumer accesses the data via `c()`, it registers its waker. If
///   the closure returns `true`, the producer's waker is invoked.
/// - This ensures that when one side makes a change, the other side gets a chance
///   to react to it.
///
/// # Implementation
///
/// [`SpScMutex`] is the standard implementation, using a `std::sync::Mutex` to
/// protect the inner data. This allows the producer and consumer to run in
/// different threads.
pub trait SpScAccessor<T> {
    /// Access the inner data as the "producer" (read-write).
    ///
    /// 1. Registers the producer's waker from the current async context
    /// 2. Calls `proc` with mutable access to the shared data
    /// 3. If `proc` returns `true`, wakes the consumer
    ///
    /// # Return Value from Closure
    ///
    /// - `true`: You made a change the consumer should see (e.g., wrote new data)
    /// - `false`: No notification needed (e.g., just checked state)
    fn p<F: FnMut(&mut T) -> bool>(&self, proc: F) -> impl Future<Output = ()>;

    /// Access the inner data as the "producer" (read-only).
    ///
    /// 1. Registers the producer's waker from the current async context
    /// 2. Calls `proc` with shared access to the data
    /// 3. Returns whatever `proc` returns
    ///
    /// This method never notifies the consumer since it's read-only.
    fn p_get<RET, F: FnMut(&T) -> RET>(&self, proc: F) -> impl std::future::Future<Output = RET>;

    /// Access the inner data as the "consumer" (read-write).
    ///
    /// 1. Registers the consumer's waker from the current async context
    /// 2. Calls `proc` with mutable access to the shared data
    /// 3. If `proc` returns `true`, wakes the producer
    ///
    /// # Return Value from Closure
    ///
    /// - `true`: You made a change the producer should see (e.g., consumed data)
    /// - `false`: No notification needed (e.g., just checked state)
    fn c<F: FnMut(&mut T) -> bool>(&self, proc: F) -> impl std::future::Future<Output = ()>;

    /// Access the inner data as the "consumer" (read-only).
    ///
    /// 1. Registers the consumer's waker from the current async context
    /// 2. Calls `proc` with shared access to the data
    /// 3. Returns whatever `proc` returns
    ///
    /// This method never notifies the producer since it's read-only.
    fn c_get<RET, F: FnMut(&T) -> RET>(&self, proc: F) -> impl std::future::Future<Output = RET>;

    /// Access the inner data from outside the producer/consumer relationship.
    ///
    /// This is used for external operations like timeout checking that need to
    /// modify the shared state and notify both sides.
    ///
    /// - Does NOT register any waker (this is not an async method)
    /// - If `proc` returns `true`, wakes BOTH producer and consumer
    fn side_check<F: FnMut(&mut T) -> bool>(&self, proc: F);
}

/// An [`SpScAccessor`] that protects the inner data with a `std::sync::Mutex`.
///
/// This allows the producer and consumer tasks to run in different threads.
/// The mutex is held only for the duration of the closure call, so contention
/// should be minimal as long as closures are quick.
///
/// # Waker Storage
///
/// The struct stores two wakers:
/// - `p_waker`: Waker for the producer task, called when the consumer makes changes
/// - `c_waker`: Waker for the consumer task, called when the producer makes changes
///
/// Wakers are initialized to no-op wakers and updated on each access if the
/// calling task's waker has changed (checked via `will_wake()`).
#[derive(Debug)]
pub struct SpScMutex<T> {
    inner: Mutex<SpScMutexInner<T>>,
}

/// Internal state protected by the mutex.
#[derive(Debug)]
struct SpScMutexInner<T> {
    /// Waker to notify when the consumer makes changes the producer should see
    p_waker: Waker,
    /// Waker to notify when the producer makes changes the consumer should see
    c_waker: Waker,
    /// The actual shared data
    inner: T,
}

impl<T> SpScMutex<T> {
    /// Creates a new `SpScMutex` wrapping the given data.
    ///
    /// Both wakers start as no-op wakers and will be set when the producer
    /// and consumer first access the data.
    pub fn new(inner: T) -> Self {
        Self {
            inner: Mutex::new(SpScMutexInner {
                // Start with no-op wakers - they'll be replaced on first access
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
        // We use poll_fn to get access to the async Context (which contains the waker).
        // The future always returns Ready immediately - we're not actually waiting for
        // anything, just using the async machinery to get the waker.
        let _ = poll_fn(|cx| {
            let mut guard = self.inner.lock().unwrap();

            // Update the producer's waker if it has changed.
            // `will_wake()` is an optimization - if the waker is the same, we skip cloning.
            let w = cx.waker();
            if !guard.p_waker.will_wake(w) {
                guard.p_waker = w.clone();
            }

            // Run the user's closure. If it returns true, wake the consumer.
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

            // Update the producer's waker if it has changed
            let w = cx.waker();
            if !guard.p_waker.will_wake(w) {
                guard.p_waker = w.clone();
            }

            // Run the closure and return its result (read-only, no notification)
            Poll::Ready(proc(&mut guard.inner))
        })
        .await;
        ret
    }

    #[inline]
    async fn c<F: FnMut(&mut T) -> bool>(&self, mut proc: F) {
        let _ = poll_fn(|cx| {
            let mut guard = self.inner.lock().unwrap();

            // Update the consumer's waker if it has changed
            let w = cx.waker();
            if !guard.c_waker.will_wake(w) {
                guard.c_waker = w.clone();
            }

            // Run the user's closure. If it returns true, wake the producer.
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

            // Update the consumer's waker if it has changed
            let w = cx.waker();
            if !guard.c_waker.will_wake(w) {
                guard.c_waker = w.clone();
            }

            // Run the closure and return its result (read-only, no notification)
            Poll::Ready(proc(&mut guard.inner))
        })
        .await;
        ret
    }

    #[inline]
    fn side_check<F: FnMut(&mut T) -> bool>(&self, mut proc: F) {
        // This is called from outside the async context (e.g., for timeout checking).
        // We don't register any waker, but we may wake both sides.
        let mut guard = self.inner.lock().unwrap();
        if proc(&mut guard.inner) {
            // Wake both producer and consumer so they can react to the change
            guard.p_waker.wake_by_ref();
            guard.c_waker.wake_by_ref();
        }
    }
}

// ============================================================================
// ITEM EXCHANGE
// ============================================================================
//
// The "item exchange" is a higher-level abstraction built on top of SpScAccessor.
// It provides a protocol for transferring items one at a time from producer to
// consumer, with timeout support.
//
// The state machine looks like this:
//
//                    +--------+
//                    | Closed |<--------------+
//                    +--------+               |
//                        ^                    |
//                        | (consumer closes   |
//                        |  while Busy/Wait)  |
//                        |                    |
//    +-------+       +--------+           +------+
//    | Busy  |<----->| Waiting|---------->| Full |
//    +-------+       +--------+           +------+
//        ^               ^                    |
//        |               |                    |
//        +---------------+--------------------+
//                        |
//                        v
//                    +--------+
//                    | Failed |
//                    +--------+
//
// State transitions:
// - Busy -> Waiting: Consumer is ready to receive (c_try_read)
// - Waiting -> Full: Producer writes an item (p_try_write)
// - Full -> Busy: Consumer takes the item (c_try_read)
// - Busy/Waiting -> Closed: Clean shutdown (close)
// - Full -> Failed: Close while item pending (data loss)
// - Any -> Failed: Timeout or error
//
// The "Busy" state is important - it indicates the consumer has received an item
// and is processing it. The producer shouldn't write another item until the
// consumer signals it's ready again (moves to Waiting).
// ============================================================================

/// The state of an "item exchange" that transfers items one at a time from
/// producer to consumer.
///
/// This state machine ensures orderly transfer: the producer can't write a new
/// item until the consumer has finished processing the previous one.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SpScItemState {
    /// The consumer is busy processing the last item and can't receive a new one yet.
    /// The producer should wait until the state becomes `Waiting`.
    Busy,

    /// The consumer is waiting for an item. The producer can now write one.
    Waiting,

    /// The producer has provided an item, but the consumer hasn't taken it yet.
    /// The associated item is stored in the exchange.
    Full,

    /// The consumer is not accepting any more items (clean shutdown).
    Closed,

    /// An error occurred (timeout, or close while item pending). No more transfers.
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

/// Trait for the inner data structure used by [`SpScItem`].
///
/// Any struct that holds the state for an item exchange must implement this trait.
/// It provides access to the state, the stored item, and timeout information.
///
/// The trait allows `SpScItem` to be generic over different inner representations,
/// though [`SimpleSpScItemInner`] is the standard implementation.
pub trait SpScItemInner<T> {
    /// Returns the current state of the exchange.
    fn get_state(&self) -> SpScItemState;

    /// Sets the state of the exchange.
    ///
    /// Implementations should perform any additional state changes required for
    /// consistency (like clearing timeouts when transitioning to terminal states).
    fn set_state(&mut self, state: SpScItemState);

    /// Returns a mutable reference to the item storage.
    ///
    /// This is `Option<T>` because the item is only present in the `Full` state.
    fn item_mut(&mut self) -> &mut Option<T>;

    /// Returns the current timeout deadline, if any.
    fn get_timeout(&self) -> Option<Instant>;

    /// Returns a mutable reference to the timeout deadline.
    fn timeout_mut(&mut self) -> &mut Option<Instant>;
}

/// High-level trait for an item exchange channel.
///
/// This trait provides the actual read/write/flush operations for transferring
/// items between producer and consumer. It's implemented generically for any
/// [`SpScAccessor`] whose inner type implements [`SpScItemInner`].
///
/// # Usage Pattern
///
/// **Consumer side** (reading items):
/// ```ignore
/// loop {
///     let mut item: Option<T> = None;
///     match channel.c_try_read(&mut item, timeout).await {
///         SpScItemState::Busy => {
///             // Got an item! It's now in `item`.
///             let data = item.take().unwrap();
///             // Process data...
///         }
///         SpScItemState::Waiting => {
///             // No item available yet, wait and try again
///             yield_once().await;
///         }
///         _ => break, // Closed or Failed
///     }
/// }
/// ```
///
/// **Producer side** (writing items):
/// ```ignore
/// let mut item = Some(data);
/// loop {
///     match channel.p_try_write(&mut item, timeout).await {
///         SpScItemState::Full => {
///             // Item was accepted!
///             break;
///         }
///         SpScItemState::Busy => {
///             // Consumer hasn't taken the last item yet, wait
///             yield_once().await;
///         }
///         _ => return Err(...), // Closed or Failed
///     }
/// }
/// ```
pub trait SpScItem<INNER, T> {
    /// Try to read an item from the exchange (consumer side).
    ///
    /// # State Transitions
    ///
    /// - `Busy` → `Waiting`: Consumer signals it's ready for the next item
    /// - `Waiting` → `Waiting`: Already waiting, no change (timeout may be updated)
    /// - `Full` → `Busy`: Item is transferred to `receiver`, consumer starts processing
    /// - `Closed`/`Failed`: No change
    ///
    /// # Returns
    ///
    /// The resulting state after the operation. Check for `Busy` to confirm an
    /// item was received.
    fn c_try_read(
        &self,
        receiver: &mut Option<T>,
        timeout: Option<Instant>,
    ) -> impl std::future::Future<Output = SpScItemState>;

    /// Try to write an item into the exchange (producer side).
    ///
    /// # State Transitions
    ///
    /// - `Waiting` → `Full`: Item is transferred from `sender`, producer notified
    /// - `Full` → returns `Busy`: Can't write, previous item not consumed yet
    /// - `Busy` → returns `Busy`: Consumer is processing, can't write yet
    /// - `Closed`/`Failed`: No change
    ///
    /// # Returns
    ///
    /// - `Full`: Item was successfully written
    /// - `Busy`: Consumer hasn't consumed the previous item yet (or is processing)
    /// - `Closed`/`Failed`: Channel is closed
    fn p_try_write(
        &self,
        sender: &mut Option<T>,
        timeout: Option<Instant>,
    ) -> impl std::future::Future<Output = SpScItemState>;

    /// Try to flush any pending item (producer side).
    ///
    /// This doesn't write anything new - it just waits for any previously written
    /// item to be consumed. Useful before closing to ensure data isn't lost.
    ///
    /// # Returns
    ///
    /// - `Waiting`: All items have been consumed
    /// - `Busy`: Still waiting for consumer to take/finish the item
    /// - `Closed`/`Failed`: Channel is closed
    fn p_try_flush(
        &self,
        timeout: Option<Instant>,
    ) -> impl std::future::Future<Output = SpScItemState>;

    /// Close the exchange.
    ///
    /// # State Transitions
    ///
    /// - `Busy` → `Closed`: Clean shutdown
    /// - `Waiting` → `Closed`: Clean shutdown
    /// - `Full` → `Failed`: Data loss (item wasn't consumed)
    /// - `Closed` → `Closed`: Already closed
    /// - `Failed` → `Failed`: Already failed
    fn close(&self);

    /// Check if any timeouts have expired and fail the exchange if so.
    ///
    /// This should be called periodically (e.g., on each `tick()`) with the
    /// current time. If a timeout is set and `now` is past the deadline, the
    /// exchange transitions to `Failed` and both sides are notified.
    fn check_timeouts(&self, now: Instant);
}

// Blanket implementation of SpScItem for any SpScAccessor over SpScItemInner.
// This is where the actual state machine logic lives.
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
            // The closure returns true if we made a change the producer should see
            let changed = match r.get_state() {
                SpScItemState::Busy => {
                    // Consumer finished processing, now ready for next item.
                    // Transition: Busy -> Waiting
                    r.set_state(SpScItemState::Waiting);
                    *r.timeout_mut() = timeout;
                    true // Notify producer: we're ready for more
                }
                SpScItemState::Waiting => {
                    // Already waiting. Just update timeout if it changed.
                    let tr = r.timeout_mut();
                    if *tr != timeout {
                        *tr = timeout;
                        true // Timeout changed, notify producer
                    } else {
                        false // No change
                    }
                }
                SpScItemState::Full => {
                    // Producer wrote an item! Take it.
                    // Transition: Full -> Busy
                    r.set_state(SpScItemState::Busy);
                    *r.timeout_mut() = None; // Clear timeout since we got data
                    *receiver = r.item_mut().take(); // Move item to receiver
                    true // Notify producer: we took the item
                }
                // Terminal states: no change
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
                    // Consumer is busy processing. We can't write yet.
                    // Just update the timeout if it changed.
                    let tr = w.timeout_mut();
                    if *tr != timeout {
                        *tr = timeout;
                        true // Timeout changed, notify consumer
                    } else {
                        false // No change
                    }
                }
                // Terminal states: no change
                SpScItemState::Failed | SpScItemState::Closed => false,
                SpScItemState::Waiting => {
                    // Consumer is ready! Write the item.
                    // Transition: Waiting -> Full
                    // Note: We update wst to Full so caller knows we succeeded
                    wst = SpScItemState::Full;
                    *w.timeout_mut() = None; // Clear timeout since write succeeded
                    *w.item_mut() = sender.take(); // Move item from sender to storage
                    true // Notify consumer: we wrote an item
                }
                SpScItemState::Full => {
                    // Consumer hasn't taken the previous item yet.
                    // Report as Busy (we can't write) but set up timeout.
                    wst = SpScItemState::Busy; // Lie to caller: report as Busy
                    *w.timeout_mut() = timeout;
                    false // Don't notify (nothing changed)
                }
            }
        })
        .await;
        wst
    }

    #[inline]
    async fn p_try_flush(&self, timeout: Option<Instant>) -> SpScItemState {
        // Similar to p_try_write but doesn't write anything - just waits for
        // consumer to finish with any pending item.
        let mut wst = SpScItemState::Failed;
        self.p(|w| {
            wst = w.get_state();
            match wst {
                SpScItemState::Busy => {
                    // Consumer is processing. Update timeout if changed.
                    let tr = w.timeout_mut();
                    if *tr != timeout {
                        *tr = timeout;
                        true
                    } else {
                        false
                    }
                }
                // Terminal states: no change
                SpScItemState::Failed | SpScItemState::Closed => false,
                SpScItemState::Waiting => {
                    // Consumer is ready - flush is complete!
                    *w.timeout_mut() = None;
                    true // Notify consumer (though there's nothing to do)
                }
                SpScItemState::Full => {
                    // Consumer hasn't taken the item yet. Report as Busy.
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
        // Close the exchange from outside the async context.
        // This is typically called during shutdown.
        self.side_check(|x| match x.get_state() {
            SpScItemState::Busy | SpScItemState::Waiting => {
                // Clean shutdown - no data loss
                x.set_state(SpScItemState::Closed);
                true // Notify both sides
            }
            SpScItemState::Full => {
                // There's an unconsumed item! This is data loss.
                // Transition to Failed to indicate the error.
                x.set_state(SpScItemState::Failed);
                true // Notify both sides
            }
            // Already in terminal state
            _ => false,
        });
    }

    fn check_timeouts(&self, now: Instant) {
        // Check if any timeout has expired and fail the exchange if so.
        // Called periodically from the main tick() loop.
        self.side_check(|x| match x.get_timeout() {
            Some(deadline) => match deadline < now {
                true => match x.get_state() {
                    // Active states: timeout causes failure
                    SpScItemState::Busy | SpScItemState::Waiting | SpScItemState::Full => {
                        x.set_state(SpScItemState::Failed);
                        true // Notify both sides so they can handle the failure
                    }
                    // Already terminal: no change
                    _ => false,
                },
                false => false, // Timeout not expired yet
            },
            _ => false, // No timeout set
        });
    }
}

// ============================================================================
// DEFAULT ITEM EXCHANGE
// ============================================================================
//
// SimpleSpScItemInner is a straightforward implementation of SpScItemInner.
// It just stores the state, timeout, and item directly. More complex
// implementations could add additional fields for monitoring, debugging, etc.
// ============================================================================

/// A simple implementation of [`SpScItemInner`] for item exchanges.
///
/// This struct holds the state, timeout deadline, and the item being transferred.
/// It's designed to be wrapped in an [`SpScMutex`] and used with the [`SpScItem`]
/// trait.
///
/// # Example
///
/// ```ignore
/// // Create an item exchange for transferring Bytes
/// let exchange: SpScMutex<SimpleSpScItemInner<Bytes>> =
///     SpScMutex::new(SimpleSpScItemInner::default());
///
/// // Now you can use exchange.c_try_read(), exchange.p_try_write(), etc.
/// ```
#[derive(Debug)]
pub struct SimpleSpScItemInner<T> {
    /// Current state of the item exchange
    pub state: SpScItemState,
    /// Optional timeout deadline for the current operation
    pub timeout: Option<Instant>,
    /// The item being transferred (only Some when state is Full)
    pub item: Option<T>,
}

impl<T> Default for SimpleSpScItemInner<T> {
    /// Creates a new exchange in the `Waiting` state (ready to receive).
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
