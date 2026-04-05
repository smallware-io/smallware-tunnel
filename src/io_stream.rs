use std::task::{Context, Poll};

/// A variant of the `Stream` interface with internal mutability, allowing it to
/// be used in contexts where the sink is not owned by the caller.
pub trait IoStream<ITEM> {
    /// If this returs `Ready(true)` or `Ready(false)`, then
    /// `poll_read` would have returned `Ready(Some(...))` or `Ready(None)`, respectively
    fn check_read(&self, cx: &mut Context<'_>) -> Poll<bool>;
    fn poll_read(&self, cx: &mut Context<'_>) -> Poll<Option<ITEM>>;
    fn drop_read(&self);
}
