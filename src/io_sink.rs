use std::{
    sync::Arc,
    task::{Context, Poll},
};

/// A variant of the `Sink` interface with internal mutability, allowing it to
/// be used in contexts where the sink is not owned by the caller.
pub trait IoSink<ITEM> : Send {
    type Error;
    fn poll_send_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>>;
    fn start_send(&self, item: ITEM) -> Result<(), Self::Error>;
    fn start_flush(&self) -> bool;
    fn poll_flush(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>>;
    fn send_close(&self) -> bool;
    fn poll_send_close(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>>;
}

pub trait AsSharedSink<ITEM, ERROR> {
    fn as_shared_sink(&self) -> &dyn IoSink<ITEM, Error = ERROR>;
}

pub struct DetachedSharedSink<ITEM, ERROR> {
    inner: Arc<dyn AsSharedSink<ITEM, ERROR>>,
    close_on_drop: bool,
}

impl<ITEM, ERROR> Unpin for DetachedSharedSink<ITEM, ERROR> {}

impl<ITEM, ERROR> DetachedSharedSink<ITEM, ERROR> {
    pub fn new(inner: Arc<dyn AsSharedSink<ITEM, ERROR>>, close_on_drop: bool) -> Self {
        Self {
            inner,
            close_on_drop,
        }
    }
}

impl<ITEM, ERROR> Drop for DetachedSharedSink<ITEM, ERROR> {
    fn drop(&mut self) {
        if self.close_on_drop {
            self.inner.as_shared_sink().send_close();
        }
    }
}

