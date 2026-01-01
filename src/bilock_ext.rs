use futures::lock::{BiLock, BiLockGuard};
use futures::task::noop_waker;
use std::task::{Context, Poll};

pub trait BiLockExt<T> {
    fn try_lock(&self) -> Option<BiLockGuard<'_, T>>;
}

impl<T> BiLockExt<T> for BiLock<T> {
    fn try_lock(&self) -> Option<BiLockGuard<'_, T>> {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        match self.poll_lock(&mut cx) {
            Poll::Ready(guard) => Some(guard),
            Poll::Pending => None,
        }
    }
}
