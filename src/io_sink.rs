use std::task::{Context, Poll};

/// A variant of the `Sink` interface with internal mutability, that can be used
/// by callers that don't own it.
/// The interface makes sense for multiple callers, but implementations may still
/// be single-producer.
pub trait IoSink: Send {
    type Error;
    type Item;
    /// Check to see if the sink is ready to receive an item.
    /// If this returns `Poll::Ready(())`, then a subsequent `poll_send` will succeed
    /// immediately unless another caller intervened and changed the state
    fn poll_send_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>>;
    /// Attempt to send an item.  If this returns `Poll::Ready(())`, then the item
    /// is consumed an `item` is changed to `None`.  Otherwise, `item` is unmodified.
    /// If `item` is `None` on entry, then `Poll::Ready(())` is returened immediately.
    fn poll_send(
        &self,
        cx: &mut Context<'_>,
        item: &mut Option<Self::Item>,
    ) -> Poll<Result<(), Self::Error>>;
    /// Signal that any unflushed items should be flushed, and check to see if all
    /// sent items are flushed.  The definition of "flushed" depends on the specific
    /// type of the sink.
    /// Note that for IoExchange, everything is considered "flushed" when the reader
    /// attempts a read that does not return any item.
    fn poll_flush(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>>;
    /// Signal that the sink is done and no further items will be sent, and check
    /// to see if the "close message", if any, has been flushed.
    fn poll_close(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>>;
}
