//! Interior-mutable sink trait for async item delivery.
//!
//! [`IoSink`] is analogous to [`futures::Sink`], but all methods take `&self`
//! instead of `Pin<&mut Self>`. This makes it usable through shared references
//! (e.g. behind an `Arc` or embedded in a struct that multiple tasks can
//! access). The trade-off is that implementations must handle their own
//! synchronization.
//!
//! The trait is implemented by [`IoExchange`](crate::io_exchange::IoExchange),
//! which provides a single-slot rendezvous channel between a writer and a reader.

use std::task::{Context, Poll};

/// A `Sink`-like trait with interior mutability (`&self` receivers).
///
/// All methods take `&self`, enabling use from contexts that only have a
/// shared reference to the sink. Implementations must be `Send` so the sink
/// can be shared across tasks.
///
/// # Protocol
///
/// The expected calling pattern mirrors [`futures::Sink`]:
///
/// 1. [`poll_send_ready`](IoSink::poll_send_ready) — wait for capacity.
/// 2. [`poll_send`](IoSink::poll_send) — submit an item.
/// 3. Optionally [`poll_flush`](IoSink::poll_flush) — ensure delivery.
/// 4. [`poll_close`](IoSink::poll_close) — signal end-of-stream.
///
/// Multiple callers may share the `&self` reference, but individual
/// implementations (e.g. `IoExchange`) may still be single-producer.
pub trait IoSink: Send {
    /// The error type returned by sink operations.
    type Error;
    /// The type of items accepted by the sink.
    type Item;

    /// Checks whether the sink is ready to accept an item.
    ///
    /// Returns `Poll::Ready(Ok(()))` when a subsequent [`poll_send`](IoSink::poll_send)
    /// is expected to succeed immediately, assuming no other caller intervenes.
    /// Returns `Poll::Pending` when the sink is full or busy.
    fn poll_send_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>>;

    /// Attempts to send an item into the sink.
    ///
    /// If the item is successfully consumed, `*item` is set to `None` and
    /// `Poll::Ready(Ok(()))` is returned. If the sink is not ready, `*item`
    /// is left unchanged and `Poll::Pending` is returned.
    ///
    /// If `item` is `None` on entry, returns `Poll::Ready(Ok(()))` immediately
    /// (no-op send).
    fn poll_send(
        &self,
        cx: &mut Context<'_>,
        item: &mut Option<Self::Item>,
    ) -> Poll<Result<(), Self::Error>>;

    /// Requests that any buffered items be delivered, and checks progress.
    ///
    /// The definition of "flushed" is implementation-specific. For
    /// [`IoExchange`](crate::io_exchange::IoExchange), flushing completes when
    /// the reader has consumed the in-flight item and then performed a read
    /// that observes the empty slot (confirming it has seen all sent data).
    ///
    /// Returns `Poll::Ready(Ok(()))` once the flush is acknowledged.
    fn poll_flush(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>>;

    /// Signals that no further items will be sent and waits for the close
    /// handshake to complete.
    ///
    /// After closing, the reader will eventually observe end-of-stream. If an
    /// item is still in flight, the close is deferred until the reader consumes
    /// it.
    ///
    /// Returns `Poll::Ready(Ok(()))` once the close is fully acknowledged.
    fn poll_close(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>>;
}
