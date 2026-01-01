//! Extension trait for `futures::lock::BiLock`.
//!
//! Provides a non-blocking `try_lock` method for `BiLock`, which is not
//! available in the standard `futures` crate API.

use futures::lock::{BiLock, BiLockGuard};
use futures::task::noop_waker;
use std::task::{Context, Poll};

/// Extension trait that adds `try_lock` to `BiLock`.
///
/// `BiLock` from the `futures` crate only provides an async `lock()` method.
/// This trait adds a non-blocking `try_lock()` that returns immediately
/// if the lock is not available.
pub trait BiLockExt<T> {
    /// Attempts to acquire the lock without blocking.
    ///
    /// Returns `Some(guard)` if the lock was acquired, or `None` if
    /// the other half currently holds the lock.
    fn try_lock(&self) -> Option<BiLockGuard<'_, T>>;
}

impl<T> BiLockExt<T> for BiLock<T> {
    fn try_lock(&self) -> Option<BiLockGuard<'_, T>> {
        // Use a no-op waker since we don't need to be woken up
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        match self.poll_lock(&mut cx) {
            Poll::Ready(guard) => Some(guard),
            Poll::Pending => None,
        }
    }
}
