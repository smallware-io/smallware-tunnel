//! Interior-mutable stream trait for async item consumption.
//!
//! [`IoStream`] is analogous to [`futures::Stream`], but all methods take
//! `&self` instead of `Pin<&mut Self>`. This makes it usable through shared
//! references, matching the design of [`IoSink`](crate::io_sink::IoSink).
//!
//! The trait is implemented by [`IoExchange`](crate::io_exchange::IoExchange),
//! which provides the reader half of a single-slot rendezvous channel.

use std::task::{Context, Poll};

/// A `Stream`-like trait with interior mutability (`&self` receivers).
///
/// Provides async item consumption through shared references. Paired with
/// [`IoSink`](crate::io_sink::IoSink) to form a full duplex channel.
pub trait IoStream<ITEM> {
    /// Checks whether an item is available without consuming it.
    ///
    /// Returns:
    /// - `Poll::Ready(true)` — an item is available; a subsequent
    ///   [`poll_read`](IoStream::poll_read) would return `Poll::Ready(Some(...))`.
    /// - `Poll::Ready(false)` — the stream is finished; a subsequent
    ///   `poll_read` would return `Poll::Ready(None)`.
    /// - `Poll::Pending` — no item is available yet; the waker will be
    ///   notified when the state changes.
    fn check_read(&self, cx: &mut Context<'_>) -> Poll<bool>;

    /// Attempts to read the next item from the stream.
    ///
    /// Returns:
    /// - `Poll::Ready(Some(item))` — an item was consumed.
    /// - `Poll::Ready(None)` — the stream is finished (writer closed).
    /// - `Poll::Pending` — no item is available yet.  The waker will be notified
    ///   when the state changes.
    fn poll_read(&self, cx: &mut Context<'_>) -> Poll<Option<ITEM>>;

    /// Signals that the reader is no longer interested in further items.
    ///
    /// After calling this, the writer side will observe that the reader has
    /// been dropped and will receive appropriate errors on subsequent sends.
    /// Any in-flight item is discarded.
    fn drop_read(&self);
}
