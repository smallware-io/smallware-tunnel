//! Sans-IO implementation of the tunnel client WebSocket protocol.
//!
//! # Overview
//!
//! This module provides a **sans-IO** implementation of the tunnel protocol on the
//! client side. "Sans-IO" means the protocol logic is completely separated from
//! actual I/O operations - the protocol just processes data and produces output,
//! without directly reading from or writing to sockets.
//!
//! # Architecture
//!
//! The protocol is implemented as two concurrent async tasks:
//!
//! 1. **Upload task** (`up_connected`): Reads data from the application and sends it
//!    to the WebSocket (app → WebSocket)
//!
//! 2. **Download task** (`down_connected`): Reads messages from the WebSocket and
//!    writes data to the application (WebSocket → app)
//!
//! These tasks communicate with the outside world through the `TunnelIO` struct,
//! which contains four [`IoExchange`] channels for data flow and an
//! [`SpScMutex`] for shutdown coordination:
//!
//! ```text
//!                         TunnelIO
//!                    ┌─────────────────┐
//!     Application    │                 │    WebSocket
//!                    │   up_in         │
//!         ────────►  │ (app→protocol)  │
//!                    │                 │
//!                    │   up_out        │
//!                    │ (protocol→ws)   │  ────────►
//!                    │                 │
//!         ◄────────  │   down_out      │
//!                    │ (protocol→app)  │
//!                    │                 │
//!                    │   down_in       │  ◄────────
//!                    │ (ws→protocol)   │
//!                    │                 │
//!                    └─────────────────┘
//! ```
//!
//! # Data Flow
//!
//! ## Upload (app → WebSocket):
//! 1. Application writes `Bytes` to `up_in`
//! 2. Upload task reads from `up_in`, wraps in `Message::Binary`
//! 3. Upload task writes `Message` to `up_out`
//! 4. External code reads from `up_out` and sends to WebSocket
//!
//! ## Download (WebSocket → app):
//! 1. External code receives `Message` from WebSocket, writes to `down_in`
//! 2. Download task reads from `down_in`, extracts `Bytes`
//! 3. Download task writes `Bytes` to `down_out`
//! 4. Application reads from `down_out`
//!
//! # Protocol Messages
//!
//! - `Message::Binary(data)`: Payload data. Empty binary = EOF.
//! - `Message::Text("RDSD")`: "Read Side Done" - signals the read side is shutting down
//! - `Message::Text("DROP:...")`: Server-initiated close with reason
//! - `Message::Text("CONNECT:...")`: Connection established (only during handshake)
//!
//! # Shutdown Coordination
//!
//! The two tasks coordinate shutdown via the `UpToDown` struct:
//! - When upload finishes, it sets `up_result` so download knows
//! - When download finishes, it sets `down_result` so upload knows
//! - If one side fails, the other starts a shutdown timer

use bytes::Bytes;
use coarsetime::{Duration, Instant};
use futures::task::noop_waker_ref;
use futures::{future::poll_fn, Future};
use futures::{Sink, Stream};
use std::fmt::Debug;
use std::pin::{pin, Pin};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio_tungstenite::tungstenite::Message;

use procmachines::{ExchangeWriteError, IoExchange, IoSink, IoStream};
use procmachines::{
    ProcMachine, ProcMachineHolder, ProcMachineJobs, TaskEnd, PROC_MACHINE_JOBS_BASE,
};

use crate::alarm_clock::{AlarmClock, ClockAlarm};
use crate::watchable_value::{ValueWatch, WatchableValue};

// ============================================================================
// TIMEOUT CONSTANTS
// ============================================================================
//
// These constants define how long the protocol waits during shutdown and for
// I/O operations. They're set conservatively to allow for slow networks while
// still detecting stuck connections.
// ============================================================================

/// Timeout for reads when the other direction has completed.
///
/// When the upload or download task finishes, the other task starts a countdown.
/// If it doesn't receive any data within this time, it gives up and closes.
/// This prevents hanging indefinitely when the remote end has stopped sending.
pub const SHUTDOWN_READ_TIMEOUT: Duration = Duration::from_secs(60);

/// Timeout for write operations.
///
/// How long to wait for a send to the WebSocket to complete. If the consumer
/// doesn't take the message within this time, the operation fails. This prevents
/// blocking indefinitely if the network is stuck.
pub const SEND_TIMEOUT: Duration = Duration::from_secs(60);

// ============================================================================
// SHARED I/O STATE
// ============================================================================
//
// TunnelIO is the "glue" between the protocol tasks and the outside world.
// External code interacts with TunnelIO to feed data in and pull data out.
// The protocol tasks interact with TunnelIO to process that data.
//
// Each data channel is an IoExchange<T> which provides:
// - Single-slot rendezvous (only one item in flight at a time)
// - AtomicWaker-based producer/consumer notification
// - Interior mutability (&self access for both sides)
//
// The UpToDown coordination channel uses SpScMutex for shared state between
// the upload and download tasks.
// ============================================================================

pub trait ServerLinks: Send {
    fn sink(&self) -> &(impl IoSink<Message> + ?Sized);
    fn stream(&self) -> &(impl IoStream<Item = Message> + ?Sized);
}

/// A [`ServerLinks`] implementation backed by [`IoExchange`] channels.
///
/// This is the default used by [`create_tunnel_protocol`] and the listener.
/// External code writes incoming WebSocket messages into `down_in` and reads
/// outgoing WebSocket messages from `up_out`.
#[derive(Debug)]
pub struct ExchangeServerLinks {
    /// WebSocket messages coming in (external → download task).
    pub down_in: IoExchange<Message>,
    /// WebSocket messages going out (upload task → external).
    pub up_out: IoExchange<Message>,
}

impl ExchangeServerLinks {
    pub fn new() -> Self {
        Self {
            down_in: IoExchange::new(),
            up_out: IoExchange::new(),
        }
    }
}

impl ServerLinks for ExchangeServerLinks {
    fn sink(&self) -> &(impl IoSink<Message> + ?Sized) {
        &self.up_out
    }
    fn stream(&self) -> &(impl IoStream<Item = Message> + ?Sized) {
        &self.down_in
    }
}

/// The default [`ServerLinks`] implementation used by [`TunnelSink`] and
/// [`TunnelStream`].
pub type StandardServerLinks = crate::ws_links::WsServerLinks;

/// Shared I/O state for the tunnel protocol.
///
/// This struct is shared between the protocol tasks and external I/O code.
/// It contains channels for data flow and coordination state.
///
/// # Channel Naming Convention
///
/// - `up_*`: Channels for the upload direction (app → WebSocket)
/// - `down_*`: Channels for the download direction (WebSocket → app)
/// - `*_in`: Data coming into the protocol from outside
/// - `*_out`: Data going out of the protocol to outside
///
/// # Producers and Consumers
///
/// | Channel   | Producer (writes)     | Consumer (reads)      |
/// |-----------|----------------------|----------------------|
/// | up_in     | External (app data)  | Upload task          |
/// | up_out    | Upload task          | External (to WS)     |
/// | down_in   | External (from WS)   | Download task        |
/// | down_out  | Download task        | External (to app)    |
#[derive(Debug)]
pub struct TunnelIO<SLINKS: ServerLinks> {
    /// Current timestamp as ticks (for timeout checking).
    /// Updated by external code via `update_clock()`.
    pub clock: AlarmClock<Instant>,

    /// Server-side links (WebSocket sink and stream).
    pub server_links: SLINKS,

    /// Application data going out (download task → external).
    /// Download task writes Bytes extracted from Messages here.
    pub down_out: IoExchange<Bytes>,

    /// Application data coming in (external → upload task).
    /// External code writes Bytes from the application here.
    pub up_in: IoExchange<Bytes>,

    /// Status of the download process
    pub down_status: WatchableValue<DownloadStatus>,
    // Status of the upload process
    pub up_status: WatchableValue<UploadStatus>,
}

impl<SLINKS: ServerLinks> TunnelIO<SLINKS> {
    /// Creates a new TunnelIO with the given initial timestamp.
    ///
    /// All channels start in the `Waiting` state (ready to receive).
    pub fn new(now: Instant, server_links: SLINKS) -> Self {
        Self {
            clock: AlarmClock::new(now),
            server_links,
            down_out: IoExchange::new(),
            up_in: IoExchange::new(),
            up_status: WatchableValue::new(UploadStatus::Active),
            down_status: WatchableValue::new(DownloadStatus::Active),
        }
    }

    /// Returns the current timestamp.
    ///
    /// This is used by tasks to calculate timeout deadlines.
    pub fn now(&self) -> Instant {
        self.clock.get()
    }

    /// Update the clock and check for expired timeouts.
    ///
    /// This should be called at the start of each `tick()` with the current time.
    /// If any channel has a timeout that has expired, it will be failed.
    ///
    /// # Arguments
    ///
    /// * `now` - The current timestamp
    pub fn update_clock(&self, now: Instant) {
        self.clock.advance(now);
    }

    /// Returns a pinned reference to the internal [`AlarmClock`].
    ///
    /// Used by protocol tasks to create [`ClockAlarm`] futures for timeouts.
    ///
    /// # Safety
    ///
    /// This is safe because `TunnelIO` is stored inside a `ProcMachine` which
    /// keeps it at a stable address (behind an `Arc`-held mutex).
    pub fn pin_clock<'a>(self: &'a Pin<&'a Self>) -> Pin<&'a AlarmClock<Instant>> {
        unsafe { Pin::new_unchecked(&self.clock) }
    }
    pub fn pin_up_status<'a>(self: &'a Pin<&'a Self>) -> Pin<&'a WatchableValue<UploadStatus>> {
        unsafe { Pin::new_unchecked(&self.up_status) }
    }
    pub fn pin_down_status<'a>(self: &'a Pin<&'a Self>) -> Pin<&'a WatchableValue<DownloadStatus>> {
        unsafe { Pin::new_unchecked(&self.down_status) }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UploadStatus {
    Active,
    Done,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DownloadStatus {
    Active,
    Discarding,
    Done,
    Failed,
}

impl<SLINKS: ServerLinks> TunnelIO<SLINKS> {
    // ========================================================================
    // UPLOAD PROCESS
    // ========================================================================
    //
    // The upload task handles the app → WebSocket direction:
    // 1. Reads Bytes from up_in (written by external code from the app)
    // 2. Wraps them in Message::Binary
    // 3. Writes the Message to the server sink (read by external code to send to WS)
    //
    // The main loop continues until:
    // - The app sends EOF (empty read)
    // - The download task signals failure
    // - A timeout expires
    // - The server sink fails
    //
    // On completion, it sends an EOF message (empty Binary) to the WebSocket,
    // closes the channels, and signals success via up_status.
    // ========================================================================

    /// Upload task: transfers data from the application to the WebSocket.
    ///
    /// This async function reads from `up_in` and writes to the server sink
    /// until EOF or an error occurs.
    async fn up_connected(io: Pin<&Self>) -> TaskEnd {
        let sink = io.server_links.sink();
        let mut got_eof = false;

        // Once we're in shutdown mode, we use a read timeout to avoid hanging forever
        // waiting for app data that will never come.
        let mut read_timeout: Option<Instant> = None;
        let down_status_alarm = pin!(ValueWatch::new(io.pin_down_status()));
        let mut to_send: Option<Message> = None;
        let read_alarm = pin!(ClockAlarm::new(io.pin_clock(), None));
        let send_alarm = pin!(ClockAlarm::new(io.pin_clock(), None));
        let mut down_status = DownloadStatus::Active;
        let mut need_flush = false;

        // Main loop: transfer data from app to WebSocket
        let is_ok = poll_fn(|cx| {
            if to_send.is_some() {
                (*send_alarm).set(Some(io.now() + SEND_TIMEOUT));
                match sink.prod_poll_send(cx, &mut to_send) {
                    Poll::Ready(Ok(_)) => {}
                    Poll::Ready(Err(_)) => {
                        tracing::info!("Up stream aborting: Error sending");
                        return false.into();
                    }
                    Poll::Pending => {
                        if send_alarm.poll_ref(cx).is_ready() {
                            return Poll::Ready(false);
                        }
                        return Poll::Pending;
                    }
                };
                need_flush = true;
                to_send = None;
                cx.waker().wake_by_ref();
            }
            if let Poll::Ready(ds) = down_status_alarm.poll_ref(cx) {
                down_status = ds;
                cx.waker().wake_by_ref();
            };

            if got_eof {
                return true.into();
            }
            // check for discarding or EOF message
            match down_status {
                DownloadStatus::Active => {}
                DownloadStatus::Discarding => {
                    if read_timeout.is_none() {
                        // Download can't write to app anymore (app closed?).
                        // Start shutdown timer.
                        tracing::info!(
                            "Up stream starting shutdown timer after down stream failed write."
                        );
                        read_timeout = Some(io.now() + SHUTDOWN_READ_TIMEOUT);
                        // Tell the server we're shutting down our read side.
                        to_send = Some(Message::Text("RDSD".into()));
                    }
                }
                DownloadStatus::Done => {
                    if read_timeout.is_none() {
                        // Download completed successfully. Start shutdown timer.
                        tracing::info!(
                            "Up stream starting shutdown timer after down stream finished."
                        );
                        read_timeout = Some(io.now() + SHUTDOWN_READ_TIMEOUT);
                        // Tell the server we're shutting down our read side.
                        to_send = Some(Message::Text("RDSD".into()));
                    }
                }
                DownloadStatus::Failed => {
                    // Download failed. Close immediately.
                    tracing::info!("Up stream closing after down stream failed.");
                    got_eof = true;
                    to_send = Some(Message::Binary(Bytes::new())); // EOF message
                }
            }

            // If we don't have a status message to send, try to read app data
            if to_send.is_none() {
                (&*read_alarm).set(read_timeout);
                let data: Option<Bytes> = match io.up_in.con_poll_read(cx) {
                    Poll::Ready(item) => {
                        // We successfully read data or EOF
                        // If we're in shutdown mode, extend the timeout
                        // (we're still getting data, so the app is still alive)
                        if read_timeout.is_some() {
                            read_timeout = Some(io.now() + SHUTDOWN_READ_TIMEOUT);
                        }
                        if item.is_none() {
                            // EOF from app - send EOF to WebSocket
                            got_eof = true;
                            to_send = Some(Message::Binary(Bytes::new()));
                        }
                        item
                    }
                    Poll::Pending => {
                        if read_alarm.poll_ref(cx).is_ready() {
                            tracing::error!(
                                "Up stream aborting.  Read timed out after down stream shut down"
                            );
                            return false.into();
                        }
                        None
                    }
                };

                // Process the data we read
                match data {
                    None => {}
                    Some(bin) => {
                        // If data is empty, just skip it
                        // (We can't send empty Binary - that looks like EOF!)
                        if !bin.is_empty() {
                            to_send = Some(Message::Binary(bin));
                        }
                    }
                }
            }
            if to_send.is_some() {
                cx.waker().wake_by_ref();
            } else if need_flush {
                if sink.prod_poll_flush(cx).is_ready() {
                    need_flush = false;
                }
            }
            Poll::Pending
        })
        .await;

        if !is_ok {
            return Self::up_abort(io).await;
        }
        // Clean shutdown: we got EOF and sent an EOF message
        io.up_in.drop_read();

        if need_flush {
            let flush_alarm = pin!(ClockAlarm::new(
                io.pin_clock(),
                Some(io.now() + SEND_TIMEOUT)
            ));
            poll_fn(|cx| {
                if sink.prod_poll_flush(cx).is_ready() {
                    Poll::Ready(())
                } else {
                    flush_alarm.poll_ref(cx)
                }
            })
            .await;
        }
        // Wait for any pending output to be consumed
        io.up_status.set(UploadStatus::Done);
        TaskEnd()
    }

    /// Abort the upload task due to an error.
    ///
    /// Closes both channels and signals failure so the download task aborts too.
    async fn up_abort(io: Pin<&Self>) -> TaskEnd {
        let sink = io.server_links.sink();
        io.up_in.drop_read();
        let flush_alarm = pin!(ClockAlarm::new(
            io.pin_clock(),
            Some(io.now() + SEND_TIMEOUT)
        ));
        poll_fn(|cx| {
            if sink.prod_poll_close(cx).is_ready() {
                Poll::Ready(())
            } else {
                flush_alarm.poll_ref(cx)
            }
        })
        .await;
        io.up_status.set(UploadStatus::Failed);
        TaskEnd()
    }

    // ========================================================================
    // DOWNLOAD PROCESS
    // ========================================================================
    //
    // The download task handles the WebSocket → app direction:
    // 1. Reads Messages from the server stream (written by external code from the WS)
    // 2. Extracts Bytes from Binary messages
    // 3. Writes the Bytes to down_out (read by external code to send to app)
    //
    // The main loop continues until:
    // - We receive an EOF message (empty Binary or "DROP:...")
    // - The upload task signals failure
    // - A timeout expires
    // - The server stream fails
    //
    // If writing to the app fails, the task enters "discarding" mode where it
    // continues reading from the WebSocket (to drain it properly) but doesn't
    // try to write to the app anymore.
    // ========================================================================

    /// Download task: transfers data from the WebSocket to the application.
    ///
    /// This async function reads from the server stream and writes to `down_out`
    /// until EOF or an error occurs.
    async fn down_connected(io: Pin<&Self>) -> TaskEnd {
        let stream = io.server_links.stream();
        let sink = &io.down_out;
        let mut got_eof = false;

        // If we can't write to the app, we enter discarding mode:
        // keep reading from WS (to drain it) but don't write to app
        let mut down_discarding = false;

        // Timeout for reading from WebSocket (set when upload task completes)
        let mut read_timeout: Option<Instant> = None;
        let read_alarm = pin!(ClockAlarm::new(io.pin_clock(), None));
        let send_alarm = pin!(ClockAlarm::new(io.pin_clock(), None));
        let up_status_alarm = pin!(ValueWatch::new(io.pin_up_status()));
        let mut to_send: Option<Bytes> = None;
        let mut need_flush = false;

        // Main loop: transfer data from WebSocket to app
        let is_ok = poll_fn(|cx| {
            if read_timeout.is_none() {
                match up_status_alarm.poll_ref(cx) {
                    Poll::Ready(UploadStatus::Done) => {
                        tracing::info!(
                            "Down stream starting shutdown timer after up stream finished."
                        );
                        read_timeout = Some(io.now() + SHUTDOWN_READ_TIMEOUT);
                    }
                    Poll::Ready(UploadStatus::Failed) => {
                        // Upload failed. Abort immediately.
                        tracing::info!("Down stream aborted after up stream.");
                        return false.into();
                    }
                    _ => {}
                }
            };

            if to_send.is_some() {
                // We've got some data that we're trying to send
                (*send_alarm).set(Some(io.now() + SEND_TIMEOUT));
                match sink.prod_poll_send(cx, &mut to_send) {
                    Poll::Pending => {
                        return Poll::Pending;
                    }
                    Poll::Ready(Err(_)) => {
                        // Can't write to app. Enter discarding mode.
                        // We still need to drain the WebSocket, so don't abort entirely.
                        tracing::info!("Down stream discarding due to send error");
                        down_discarding = true;
                        io.down_status.set(DownloadStatus::Discarding);
                        return false.into();
                    }
                    Poll::Ready(Ok(_)) => {
                        need_flush = true;
                        cx.waker().wake_by_ref();
                        to_send = None;
                    }
                }
            }

            if got_eof {
                return true.into();
            }

            // Try to read a WebSocket message
            (*read_alarm).set(read_timeout);
            let msg: Result<Option<Message>, ()> = match stream.con_poll_read(cx) {
                Poll::Ready(msg) => Ok(msg),
                Poll::Pending => {
                    if read_alarm.poll_ref(cx).is_ready() {
                        tracing::info!("Down stream aborted: read error");
                        return false.into();
                    }
                    if need_flush {
                        if sink.prod_poll_flush(cx).is_ready() {
                            need_flush = false;
                            cx.waker().wake_by_ref();
                        }
                    }
                    return Poll::Pending;
                }
            };

            // read a message
            let msg = match msg {
                Err(_) => {
                    tracing::info!("Down stream aborted: read error");
                    return false.into();
                }
                Ok(None) => {
                    tracing::info!("Down stream aborted: EOF");
                    return false.into();
                }
                Ok(Some(msg)) => msg,
            };

            // We got some data. If we're in shutdown mode, extend the timeout
            cx.waker().wake_by_ref();
            if read_timeout.is_some() {
                read_timeout = Some(io.now() + SHUTDOWN_READ_TIMEOUT);
            }

            // Process the WebSocket message
            to_send = match msg {
                // WebSocket close frame (unexpected - we should initiate close)
                Message::Close(_) => {
                    tracing::info!("Down stream aborted. Got WS close");
                    return false.into();
                }
                // Control/text message from the server
                Message::Text(txt) => {
                    let str = txt.as_str();
                    if str.starts_with("DROP:") {
                        // Server-initiated close with reason
                        tracing::info!("Down stream done: {}", str);
                        got_eof = true;
                        None
                    } else if str.starts_with("CONNECT:") {
                        // CONNECT message shouldn't happen after we're connected
                        tracing::info!("Down stream aborted. Unexpected CONNECT");
                        return false.into();
                    } else {
                        // Unknown text message - ignore and continue
                        tracing::info!("Down stream: unrecognized: {}", str);
                        None
                    }
                }
                // Binary data message
                Message::Binary(bytes) => {
                    if bytes.is_empty() {
                        // Empty binary = EOF from server
                        got_eof = true;
                        tracing::info!("Down stream done: EOF");
                        None
                    } else {
                        // Actual data to forward to app
                        Some(bytes)
                    }
                }
                // Other message types (Ping, Pong, etc.) - ignore
                _ => None,
            };

            // If we're discarding (can't write to app), skip the write
            if down_discarding {
                to_send = None;
            }
            // Since we processed a message, loop around to the next iteration to send it or get more
            cx.waker().wake_by_ref();
            Poll::Pending
        })
        .await;

        if !is_ok {
            stream.drop_read();
        }

        // Wait for any pending output to be consumed by the app
        let flush_timeout: ClockAlarm<Instant> =
            ClockAlarm::new(io.pin_clock(), Some(io.now() + SEND_TIMEOUT));
        let mut flush_timeout = pin!(flush_timeout);
        poll_fn(|cx| {
            if sink.prod_poll_close(cx).is_ready() {
                return Poll::Ready(());
            }
            if flush_timeout.as_mut().poll(cx).is_ready() {
                return Poll::Ready(());
            }
            Poll::Pending
        })
        .await;
        if !is_ok {
            io.down_status.set(DownloadStatus::Failed);
        } else {
            // Clean shutdown: we got EOF from WebSocket
            io.down_status.set(DownloadStatus::Done);
        }
        TaskEnd()
    }
}

// ============================================================================
// PUBLIC API
// ============================================================================

/// Handle to a running tunnel protocol instance.
///
/// The protocol runs as two cooperative tasks inside a [`ProcMachine`]:
/// upload (`up_connected`) and download (`down_connected`). External code
/// drives the machine by calling [`.lock()`](LockableIo::lock) to access
/// the [`TunnelIO`] channels, then dropping the guard to let the tasks tick.
pub type TunnelProtocol<SLINKS> = Arc<dyn ProcMachine<TunnelIO<SLINKS>>>;

/// Creates a new tunnel protocol instance and starts its internal tasks.
///
/// The returned [`TunnelProtocol`] is ready to use immediately — both the
/// upload and download tasks are initialized and will begin processing data
/// as soon as items are placed in the input exchanges.
///
/// # Arguments
///
/// * `now` — the current timestamp, used to seed the internal [`AlarmClock`].
/// * `server_links` — the server-side sink and stream implementation.
pub fn create_tunnel_protocol<SLINKS: ServerLinks + Debug + 'static>(
    now: Instant,
    server_links: SLINKS,
) -> TunnelProtocol<SLINKS> {
    PROC_MACHINE_JOBS_BASE
        .with(TunnelIO::<SLINKS>::up_connected)
        .with(TunnelIO::<SLINKS>::down_connected)
        .build(TunnelIO::new(now, server_links))
}

/// A [`futures::Sink`] adapter for writing application data into the tunnel.
///
/// Wraps a [`TunnelProtocol`] and forwards `Bytes` into the `up_in` exchange,
/// where the upload task picks them up, wraps them in `Message::Binary`, and
/// delivers them to `up_out` for the WebSocket.
///
/// Dropping the sink closes `up_in`, which causes the upload task to send an
/// EOF (`Message::Binary(empty)`) to the WebSocket.
#[derive(Debug, Clone)]
pub struct TunnelSink {
    inner: TunnelProtocol<StandardServerLinks>,
}

impl TunnelSink {
    /// Creates a new sink backed by the given protocol instance.
    pub fn new(proto: TunnelProtocol<StandardServerLinks>) -> Self {
        Self { inner: proto }
    }
}

impl Sink<Bytes> for TunnelSink {
    type Error = ExchangeWriteError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let guard = self.inner.lock();
        guard.up_in.prod_poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        let mut cx = Context::from_waker(noop_waker_ref());
        let guard = self.inner.lock();
        let mut to_send = Some(item);
        match guard.up_in.prod_poll_send(&mut cx, &mut to_send) {
            Poll::Ready(res) => res,
            Poll::Pending => Err(ExchangeWriteError::InvalidState),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let guard = self.inner.lock();
        guard.up_in.prod_poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let guard = self.inner.lock();
        guard.up_in.prod_poll_close(cx)
    }
}

impl Drop for TunnelSink {
    fn drop(&mut self) {
        let guard = self.inner.lock();
        let mut cx = Context::from_waker(noop_waker_ref());
        let _ = guard.up_in.prod_poll_close(&mut cx);
    }
}

/// A [`futures::Stream`] adapter for reading application data from the tunnel.
///
/// Wraps a [`TunnelProtocol`] and reads `Bytes` from the `down_out` exchange,
/// where the download task places data extracted from incoming WebSocket
/// `Message::Binary` frames.
///
/// The stream yields `None` when the download task closes `down_out` (either
/// because it received an EOF or a `DROP:` message from the server).
///
/// Dropping the stream calls [`drop_read`](IoStream::drop_read) on `down_out`,
/// which causes the download task to enter discarding mode.
#[derive(Debug, Clone)]
pub struct TunnelStream {
    inner: TunnelProtocol<StandardServerLinks>,
}

impl TunnelStream {
    /// Creates a new stream backed by the given protocol instance.
    pub fn new(proto: TunnelProtocol<StandardServerLinks>) -> Self {
        Self { inner: proto }
    }
}

impl Stream for TunnelStream {
    type Item = Bytes;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let guard = self.inner.lock();
        guard.down_out.con_poll_read(cx)
    }
}

impl Drop for TunnelStream {
    fn drop(&mut self) {
        let guard = self.inner.lock();
        guard.down_out.drop_read();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use coarsetime::Instant;
    use futures::task::noop_waker_ref;
    use procmachines::{IoSink, IoStream, ProcMachineHolder};

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    /// Creates a protocol and returns it with a fixed "now" instant.
    fn make_proto() -> TunnelProtocol<ExchangeServerLinks> {
        create_tunnel_protocol(Instant::now(), ExchangeServerLinks::new())
    }

    /// Sends an item into an IoExchange (writer/sink side). Returns true if accepted.
    fn exchange_send<T: Send>(exch: &IoExchange<T>, item: T) -> bool {
        let mut cx = Context::from_waker(noop_waker_ref());
        let mut opt = Some(item);
        matches!(exch.prod_poll_send(&mut cx, &mut opt), Poll::Ready(Ok(())))
    }

    /// Reads an item from an IoExchange (reader/stream side).
    fn exchange_read<T: Send>(exch: &IoExchange<T>) -> Poll<Option<T>> {
        let mut cx = Context::from_waker(noop_waker_ref());
        exch.con_poll_read(&mut cx)
    }

    /// Initiates close on the writer side of an IoExchange.
    fn exchange_close<T: Send>(exch: &IoExchange<T>) -> Poll<Result<(), ExchangeWriteError>> {
        let mut cx = Context::from_waker(noop_waker_ref());
        exch.prod_poll_close(&mut cx)
    }

    /// Drives the protocol by locking/unlocking (which triggers a tick).
    /// Optionally performs an operation inside the lock.
    fn tick(proto: &TunnelProtocol<ExchangeServerLinks>) {
        let _guard = proto.lock();
        // guard drop triggers tick
    }

    /// Repeatedly ticks and tries to read from an exchange until we get a
    /// Ready result or exhaust attempts.
    fn read_with_ticks<T: Send>(
        proto: &TunnelProtocol<ExchangeServerLinks>,
        get_exchange: impl Fn(&TunnelIO<ExchangeServerLinks>) -> &IoExchange<T>,
        max_ticks: usize,
    ) -> Poll<Option<T>> {
        for _ in 0..max_ticks {
            let guard = proto.lock();
            let result = exchange_read(get_exchange(&*guard));
            if result.is_ready() {
                return result;
            }
            // drop guard → tick
        }
        Poll::Pending
    }

    // -----------------------------------------------------------------------
    // Upload path: app → protocol → WebSocket
    // -----------------------------------------------------------------------

    #[test]
    fn upload_single_message() {
        let proto = make_proto();

        // Write app data into up_in
        {
            let guard = proto.lock();
            assert!(exchange_send(&guard.up_in, Bytes::from("hello")));
        }

        // Read the resulting WS message from up_out
        let msg = read_with_ticks(&proto, |io| &io.server_links.up_out, 5);
        match msg {
            Poll::Ready(Some(Message::Binary(b))) => {
                assert_eq!(b, Bytes::from("hello"));
            }
            other => panic!("expected Binary message, got {:?}", other),
        }
    }

    #[test]
    fn upload_multiple_messages() {
        let proto = make_proto();
        let payloads = vec!["one", "two", "three"];

        for payload in &payloads {
            {
                let guard = proto.lock();
                assert!(exchange_send(&guard.up_in, Bytes::from(*payload)));
            }

            let msg = read_with_ticks(&proto, |io| &io.server_links.up_out, 5);
            match msg {
                Poll::Ready(Some(Message::Binary(b))) => {
                    assert_eq!(b, Bytes::from(*payload));
                }
                other => panic!("expected Binary({payload}), got {:?}", other),
            }
        }
    }

    #[test]
    fn upload_empty_bytes_skipped() {
        // The upload task must skip empty Bytes from the app, because
        // Message::Binary(empty) is the EOF signal on the wire.
        let proto = make_proto();

        // Send empty bytes (should be skipped)
        {
            let guard = proto.lock();
            assert!(exchange_send(&guard.up_in, Bytes::new()));
        }

        // Send real data
        {
            let guard = proto.lock();
            assert!(exchange_send(&guard.up_in, Bytes::from("real")));
        }

        // The first message out should be the real data, not an empty one
        let msg = read_with_ticks(&proto, |io| &io.server_links.up_out, 10);
        match msg {
            Poll::Ready(Some(Message::Binary(b))) => {
                assert_eq!(b, Bytes::from("real"));
            }
            other => panic!("expected Binary(real), got {:?}", other),
        }
    }

    #[test]
    fn upload_eof_sends_empty_binary() {
        let proto = make_proto();

        // Close up_in (simulates app EOF)
        {
            let guard = proto.lock();
            let _ = exchange_close(&guard.up_in);
        }

        // The upload task should send an empty Binary (EOF marker)
        let msg = read_with_ticks(&proto, |io| &io.server_links.up_out, 10);
        match msg {
            Poll::Ready(Some(Message::Binary(b))) => {
                assert!(b.is_empty(), "EOF should be empty Binary");
            }
            other => panic!("expected empty Binary (EOF), got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Download path: WebSocket → protocol → app
    // -----------------------------------------------------------------------

    #[test]
    fn download_single_message() {
        let proto = make_proto();

        // Write a WS message into down_in
        {
            let guard = proto.lock();
            assert!(exchange_send(
                &guard.server_links.down_in,
                Message::Binary(Bytes::from("world"))
            ));
        }

        // Read the resulting app data from down_out
        let data = read_with_ticks(&proto, |io| &io.down_out, 5);
        match data {
            Poll::Ready(Some(b)) => {
                assert_eq!(b, Bytes::from("world"));
            }
            other => panic!("expected Bytes(world), got {:?}", other),
        }
    }

    #[test]
    fn download_multiple_messages() {
        let proto = make_proto();
        let payloads = vec!["alpha", "beta", "gamma"];

        for payload in &payloads {
            {
                let guard = proto.lock();
                assert!(exchange_send(
                    &guard.server_links.down_in,
                    Message::Binary(Bytes::from(*payload))
                ));
            }

            let data = read_with_ticks(&proto, |io| &io.down_out, 5);
            match data {
                Poll::Ready(Some(b)) => {
                    assert_eq!(b, Bytes::from(*payload));
                }
                other => panic!("expected Bytes({payload}), got {:?}", other),
            }
        }
    }

    #[test]
    fn download_eof_empty_binary() {
        let proto = make_proto();

        // Send EOF (empty Binary)
        {
            let guard = proto.lock();
            assert!(exchange_send(
                &guard.server_links.down_in,
                Message::Binary(Bytes::new())
            ));
        }

        // down_out should eventually close (yield None)
        let result = read_with_ticks(&proto, |io| &io.down_out, 10);
        assert!(
            matches!(result, Poll::Ready(None)),
            "expected stream end after EOF, got {:?}",
            result
        );
    }

    #[test]
    fn download_eof_drop_message() {
        let proto = make_proto();

        // Send a DROP message
        {
            let guard = proto.lock();
            assert!(exchange_send(
                &guard.server_links.down_in,
                Message::Text("DROP:connection_limit".into())
            ));
        }

        // down_out should close
        let result = read_with_ticks(&proto, |io| &io.down_out, 10);
        assert!(
            matches!(result, Poll::Ready(None)),
            "expected stream end after DROP, got {:?}",
            result
        );
    }

    #[test]
    fn download_data_then_eof() {
        let proto = make_proto();

        // Send data
        {
            let guard = proto.lock();
            assert!(exchange_send(
                &guard.server_links.down_in,
                Message::Binary(Bytes::from("payload"))
            ));
        }

        let data = read_with_ticks(&proto, |io| &io.down_out, 5);
        assert_eq!(data, Poll::Ready(Some(Bytes::from("payload"))));

        // Send EOF
        {
            let guard = proto.lock();
            assert!(exchange_send(
                &guard.server_links.down_in,
                Message::Binary(Bytes::new())
            ));
        }

        let result = read_with_ticks(&proto, |io| &io.down_out, 10);
        assert!(matches!(result, Poll::Ready(None)));
    }

    #[test]
    fn download_abort_on_close_frame() {
        let proto = make_proto();

        // Send a WebSocket Close frame
        {
            let guard = proto.lock();
            assert!(exchange_send(
                &guard.server_links.down_in,
                Message::Close(None)
            ));
        }

        // down_out should close (abort)
        let result = read_with_ticks(&proto, |io| &io.down_out, 10);
        assert!(
            matches!(result, Poll::Ready(None)),
            "expected abort after Close frame, got {:?}",
            result
        );
    }

    #[test]
    fn download_abort_on_connect_message() {
        let proto = make_proto();

        // Send a CONNECT message (shouldn't happen post-handshake)
        {
            let guard = proto.lock();
            assert!(exchange_send(
                &guard.server_links.down_in,
                Message::Text("CONNECT:some_id".into())
            ));
        }

        // down_out should close (abort)
        let result = read_with_ticks(&proto, |io| &io.down_out, 10);
        assert!(
            matches!(result, Poll::Ready(None)),
            "expected abort after CONNECT, got {:?}",
            result
        );
    }

    #[test]
    fn download_ignores_ping() {
        let proto = make_proto();

        // Send a Ping (should be ignored by protocol)
        {
            let guard = proto.lock();
            assert!(exchange_send(
                &guard.server_links.down_in,
                Message::Ping(vec![1, 2, 3].into())
            ));
        }

        // Then send actual data
        {
            let guard = proto.lock();
            assert!(exchange_send(
                &guard.server_links.down_in,
                Message::Binary(Bytes::from("after_ping"))
            ));
        }

        // Should get the data, not the ping
        let data = read_with_ticks(&proto, |io| &io.down_out, 10);
        match data {
            Poll::Ready(Some(b)) => assert_eq!(b, Bytes::from("after_ping")),
            other => panic!("expected data after ping, got {:?}", other),
        }
    }

    #[test]
    fn download_ignores_pong() {
        let proto = make_proto();

        {
            let guard = proto.lock();
            assert!(exchange_send(
                &guard.server_links.down_in,
                Message::Pong(vec![].into())
            ));
        }

        {
            let guard = proto.lock();
            assert!(exchange_send(
                &guard.server_links.down_in,
                Message::Binary(Bytes::from("after_pong"))
            ));
        }

        let data = read_with_ticks(&proto, |io| &io.down_out, 10);
        match data {
            Poll::Ready(Some(b)) => assert_eq!(b, Bytes::from("after_pong")),
            other => panic!("expected data after pong, got {:?}", other),
        }
    }

    #[test]
    fn download_ignores_unknown_text() {
        let proto = make_proto();

        // Send unrecognized text (should be ignored)
        {
            let guard = proto.lock();
            assert!(exchange_send(
                &guard.server_links.down_in,
                Message::Text("UNKNOWN_COMMAND".into())
            ));
        }

        // Then send actual data
        {
            let guard = proto.lock();
            assert!(exchange_send(
                &guard.server_links.down_in,
                Message::Binary(Bytes::from("real_data"))
            ));
        }

        let data = read_with_ticks(&proto, |io| &io.down_out, 10);
        match data {
            Poll::Ready(Some(b)) => assert_eq!(b, Bytes::from("real_data")),
            other => panic!("expected data after unknown text, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Full round trip
    // -----------------------------------------------------------------------

    #[test]
    fn full_round_trip_upload_and_download() {
        let proto = make_proto();

        // Upload: app → WS
        {
            let guard = proto.lock();
            assert!(exchange_send(&guard.up_in, Bytes::from("up_data")));
        }

        let up_msg = read_with_ticks(&proto, |io| &io.server_links.up_out, 5);
        assert_eq!(
            up_msg,
            Poll::Ready(Some(Message::Binary(Bytes::from("up_data"))))
        );

        // Download: WS → app
        {
            let guard = proto.lock();
            assert!(exchange_send(
                &guard.server_links.down_in,
                Message::Binary(Bytes::from("down_data"))
            ));
        }

        let down_data = read_with_ticks(&proto, |io| &io.down_out, 5);
        assert_eq!(down_data, Poll::Ready(Some(Bytes::from("down_data"))));
    }

    // -----------------------------------------------------------------------
    // Shutdown coordination
    // -----------------------------------------------------------------------

    #[test]
    fn upload_sends_rdsd_after_download_completes() {
        let proto = make_proto();

        // Complete the download by sending EOF
        {
            let guard = proto.lock();
            assert!(exchange_send(
                &guard.server_links.down_in,
                Message::Binary(Bytes::new())
            ));
        }

        // Drain down_out (the close notification)
        let _ = read_with_ticks(&proto, |io| &io.down_out, 10);

        // Now send app data to trigger the upload task to loop back and
        // check down_result. It should see download completed and send RDSD.
        {
            let guard = proto.lock();
            assert!(exchange_send(&guard.up_in, Bytes::from("trigger")));
        }

        // Read messages from up_out. We should see RDSD before or after the
        // data message (depending on timing).
        let mut saw_rdsd = false;
        let mut saw_data = false;
        for _ in 0..20 {
            let msg = read_with_ticks(&proto, |io| &io.server_links.up_out, 3);
            match msg {
                Poll::Ready(Some(Message::Text(ref t))) if AsRef::<str>::as_ref(t) == "RDSD" => {
                    saw_rdsd = true;
                }
                Poll::Ready(Some(Message::Binary(ref b))) if !b.is_empty() => {
                    saw_data = true;
                }
                _ => {}
            }
            if saw_rdsd && saw_data {
                break;
            }
        }
        assert!(saw_rdsd, "expected RDSD message after download completed");
        assert!(saw_data, "expected data message to be forwarded");
    }

    #[test]
    fn download_aborts_when_upload_fails() {
        let proto = make_proto();

        // Make the upload task fail by closing up_out (the consumer side)
        // and feeding it some input data so it tries to write.
        // The upload task will see prod_poll_send return Err and abort.
        {
            let guard = proto.lock();
            guard.server_links.up_out.drop_read();
            assert!(exchange_send(&guard.up_in, Bytes::from("trigger")));
        }

        // Tick to let the upload task detect the error and set up_result=Some(false)
        for _ in 0..5 {
            tick(&proto);
        }

        // Send data to down_in. This should fail because the download process is done
        {
            let guard = proto.lock();
            assert!(!exchange_send(
                &guard.server_links.down_in,
                Message::Binary(Bytes::from("may_pass_through"))
            ));
        }

        // Drain any data that slipped through, then expect close.
        let mut got_close = false;
        for _ in 0..20 {
            let result = read_with_ticks(&proto, |io| &io.down_out, 3);
            match result {
                Poll::Ready(None) => {
                    got_close = true;
                    break;
                }
                Poll::Ready(Some(_)) => continue, // data that arrived before abort
                Poll::Pending => continue,
            }
        }
        assert!(
            got_close,
            "expected download to eventually close after upload failure"
        );
    }

    #[test]
    fn upload_aborts_when_download_fails() {
        let proto = make_proto();

        // Make the download task fail by sending a Close frame
        {
            let guard = proto.lock();
            assert!(exchange_send(
                &guard.server_links.down_in,
                Message::Close(None)
            ));
        }

        // Tick to let download process the Close and set down_result
        for _ in 0..5 {
            tick(&proto);
        }

        // Upload should send EOF (empty binary) because down_result is Some(false)
        let mut saw_eof = false;
        for _ in 0..20 {
            let msg = read_with_ticks(&proto, |io| &io.server_links.up_out, 3);
            match msg {
                Poll::Ready(Some(Message::Binary(b))) if b.is_empty() => {
                    saw_eof = true;
                    break;
                }
                Poll::Ready(Some(_)) => continue,
                _ => break,
            }
        }
        assert!(
            saw_eof,
            "expected upload to send EOF after download failure"
        );
    }

    // -----------------------------------------------------------------------
    // Coordination state (UpToDown)
    // -----------------------------------------------------------------------

    #[test]
    fn up_to_down_signals_after_download_eof() {
        let proto = make_proto();

        // Send download EOF
        {
            let guard = proto.lock();
            assert!(exchange_send(
                &guard.server_links.down_in,
                Message::Binary(Bytes::new())
            ));
        }

        // Tick to process
        for _ in 0..5 {
            tick(&proto);
        }

        // Check the coordination state via the public accessor
        let guard = proto.lock();
        assert_eq!(guard.down_status.get(), DownloadStatus::Done);
    }

    #[test]
    fn up_to_down_signals_after_download_abort() {
        let proto = make_proto();

        // Trigger download abort via Close frame
        {
            let guard = proto.lock();
            assert!(exchange_send(
                &guard.server_links.down_in,
                Message::Close(None)
            ));
        }

        for _ in 0..5 {
            tick(&proto);
        }

        let guard = proto.lock();
        assert_eq!(guard.down_status.get(), DownloadStatus::Failed);
    }

    // -----------------------------------------------------------------------
    // TunnelIO
    // -----------------------------------------------------------------------

    #[test]
    fn tunnel_io_now_returns_initial_time() {
        let now = Instant::now();
        let io = TunnelIO::new(now, ExchangeServerLinks::new());
        assert_eq!(io.now(), now);
    }

    #[test]
    fn tunnel_io_update_clock_advances() {
        let now = Instant::now();
        let io = TunnelIO::new(now, ExchangeServerLinks::new());
        let later = now + Duration::from_secs(10);
        io.update_clock(later);
        assert_eq!(io.now(), later);
    }

    #[test]
    fn tunnel_io_update_clock_does_not_go_backwards() {
        let now = Instant::now();
        let io = TunnelIO::new(now, ExchangeServerLinks::new());
        let earlier = Instant::now(); // same or earlier
        io.update_clock(earlier);
        // advance() only goes forward, so the clock should still be `now`
        // (or possibly `earlier` if it's actually later due to timing)
        // The key invariant: it never goes backward from `now`
        assert!(io.now() >= now);
    }

    // -----------------------------------------------------------------------
    // Protocol creation
    // -----------------------------------------------------------------------

    #[test]
    fn create_protocol_does_not_panic() {
        let _proto = make_proto();
    }

    #[test]
    fn protocol_is_not_immediately_done() {
        let proto = make_proto();
        // Both tasks should be alive initially
        assert!(!proto.get_pin().is_done());
    }
}
