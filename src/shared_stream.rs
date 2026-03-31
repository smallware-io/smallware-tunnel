use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures::Stream;

/// A variant of the `Stream` interface with internal mutability, allowing it to
/// be used in contexts where the sink is not owned by the caller.
pub trait SharedStream<ITEM> {
    fn poll_read(&self, cx: &mut Context<'_>) -> Poll<Option<ITEM>>;
    fn drop_read(&self);
}

pub trait AsSharedStream<ITEM> {
    fn as_shared_stream(&self) -> &dyn SharedStream<ITEM>;
}

pub struct DetachedSharedStream<ITEM> {
    inner: Arc<dyn AsSharedStream<ITEM>>,
    close_on_drop: bool,
}

impl<ITEM> Unpin for DetachedSharedStream<ITEM> {}

impl<ITEM> DetachedSharedStream<ITEM> {
    pub fn new(inner: Arc<dyn AsSharedStream<ITEM>>, close_on_drop: bool) -> Self {
        Self {
            inner,
            close_on_drop,
        }
    }
}

impl<ITEM> Drop for DetachedSharedStream<ITEM> {
    fn drop(&mut self) {
        if self.close_on_drop {
            self.inner.as_shared_stream().drop_read();
        }
    }
}

impl<ITEM> SharedStream<ITEM> for DetachedSharedStream<ITEM> {
    fn poll_read(&self, cx: &mut Context<'_>) -> Poll<Option<ITEM>> {
        self.inner.as_shared_stream().poll_read(cx)
    }
    fn drop_read(&self) {
        self.inner.as_shared_stream().drop_read();
    }
}

impl<ITEM> Stream for dyn SharedStream<ITEM> {
    type Item = ITEM;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.as_ref().poll_read(cx)
    }
}
