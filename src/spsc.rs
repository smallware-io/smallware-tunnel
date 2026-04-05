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

use std::{
    future::{poll_fn, Future},
    sync::Mutex,
    task::{Poll, Waker},
};


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
pub trait SpScAccessor {
    /// The inner data type protected by this accessor.
    type Inner;

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
    fn p<F: FnMut(&mut Self::Inner) -> bool>(&self, proc: F) -> impl Future<Output = ()>;

    /// Access the inner data as the "producer" (read-only).
    ///
    /// 1. Registers the producer's waker from the current async context
    /// 2. Calls `proc` with shared access to the data
    /// 3. Returns whatever `proc` returns
    ///
    /// This method never notifies the consumer since it's read-only.
    fn p_get<RET, F: FnMut(&Self::Inner) -> RET>(
        &self,
        proc: F,
    ) -> impl std::future::Future<Output = RET>;

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
    fn c<F: FnMut(&mut Self::Inner) -> bool>(
        &self,
        proc: F,
    ) -> impl std::future::Future<Output = ()>;

    /// Access the inner data as the "consumer" (read-only).
    ///
    /// 1. Registers the consumer's waker from the current async context
    /// 2. Calls `proc` with shared access to the data
    /// 3. Returns whatever `proc` returns
    ///
    /// This method never notifies the producer since it's read-only.
    fn c_get<RET, F: FnMut(&Self::Inner) -> RET>(
        &self,
        proc: F,
    ) -> impl std::future::Future<Output = RET>;

    /// Access the inner data from outside the producer/consumer relationship.
    ///
    /// This is used for external operations like timeout checking that need to
    /// modify the shared state and notify both sides.
    ///
    /// - Does NOT register any waker (this is not an async method)
    /// - If `proc` returns `true`, wakes BOTH producer and consumer
    fn side_check<F: FnMut(&mut Self::Inner) -> bool>(&self, proc: F);
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

impl<T> SpScAccessor for SpScMutex<T> {
    type Inner = T;

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
