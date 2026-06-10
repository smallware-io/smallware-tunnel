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
use futures::{Future, future::poll_fn};
use parking_lot::{Mutex, RawMutex};
use std::cell::Cell;
use std::fmt::Debug;
use std::net::IpAddr;
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio_tungstenite::tungstenite::Message;

use procmachines::{
    AlarmClock, ClockAlarm, IoError, IoPort, IoReader, IoSink, IoStream, IoWriter,
    ProcMachineFutures, ProcMachineImpl, RefLockable, ValueWatch, WatchableValue,
};
use procmachines::{PROC_MACHINE_BUILDER, ProcMachine, ProcMachineJobs, TaskEnd};

use crate::error::TunnelError;
use crate::trace_id::TraceId;

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

pub(crate) trait ServerLinks: Send {
    fn sink(&self) -> &(impl IoSink<Message> + ?Sized);
    fn stream(&self) -> &(impl IoStream<Item = Message> + ?Sized);
}

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
pub(crate) struct TunnelIO<SLINKS: ServerLinks> {
    /// Current timestamp as ticks (for timeout checking).
    /// Updated by external code via `update_clock()`.
    pub clock: AlarmClock<RawMutex, Instant>,

    /// Information about the connected client
    pub client_info: TunnelClientInfo,

    /// Server-side links (WebSocket sink and stream).
    pub server_links: SLINKS,

    /// Application data going out (download task → external).
    /// Download task writes Bytes extracted from Messages here.
    /// Connected externally to an [`IoWriter`] (e.g. an [`IoBytesExchange`]).
    pub down_out: IoPort<Arc<Mutex<dyn IoWriter<Error = IoError> + Send>>>,

    /// Application data coming in (external → upload task).
    /// Connected externally to an [`IoReader`] (e.g. an [`IoBytesExchange`]).
    pub up_in: IoPort<Arc<Mutex<dyn IoReader<Error = IoError> + Send>>>,
    pub bytes_uploaded: Cell<u64>,
    pub bytes_downloaded: Cell<u64>,

    /// Status of the download process
    pub down_status: WatchableValue<RawMutex, DownloadStatus>,
    // Status of the upload process
    pub up_status: WatchableValue<RawMutex, UploadStatus>,
}

impl<SLINKS: ServerLinks + Debug> Debug for TunnelIO<SLINKS> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunnelIO")
            .field("server_links", &self.server_links)
            .field("up_status", &self.up_status)
            .field("down_status", &self.down_status)
            .finish_non_exhaustive()
    }
}

impl<SLINKS: ServerLinks> TunnelIO<SLINKS> {
    /// Creates a new TunnelIO with the given initial timestamp.
    ///
    /// All channels start in the `Waiting` state (ready to receive).
    pub fn new(now: Instant, server_links: SLINKS, client_info: TunnelClientInfo) -> Self {
        Self {
            clock: AlarmClock::new(now),
            server_links,
            client_info,
            down_out: IoPort::new(),
            up_in: IoPort::new(),
            bytes_downloaded: Cell::new(0),
            bytes_uploaded: Cell::new(0),
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

    /// Returns a pinned reference to the internal [`AlarmClock`].
    ///
    /// Used by protocol tasks to create [`ClockAlarm`] futures for timeouts.
    ///
    /// # Safety
    ///
    /// This is safe because `TunnelIO` is stored inside a `ProcMachine` which
    /// keeps it at a stable address (behind an `Arc`-held mutex).
    pub fn pin_clock<'a>(self: &'a Pin<&'a Self>) -> Pin<&'a AlarmClock<RawMutex, Instant>> {
        unsafe { Pin::new_unchecked(&self.clock) }
    }
    pub fn pin_up_status<'a>(
        self: &'a Pin<&'a Self>,
    ) -> Pin<&'a WatchableValue<RawMutex, UploadStatus>> {
        unsafe { Pin::new_unchecked(&self.up_status) }
    }
    pub fn pin_down_status<'a>(
        self: &'a Pin<&'a Self>,
    ) -> Pin<&'a WatchableValue<RawMutex, DownloadStatus>> {
        unsafe { Pin::new_unchecked(&self.down_status) }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum UploadStatus {
    Active,
    Done,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum DownloadStatus {
    Active,
    Discarding,
    Done,
    Failed,
}

impl<SLINKS: ServerLinks> TunnelIO<SLINKS> {
    fn get_stats(&self) -> TunnelConnectionStats {
        TunnelConnectionStats {
            bytes_downloaded: self.bytes_downloaded.get(),
            bytes_uploaded: self.bytes_uploaded.get(),
        }
    }
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
                match sink.prod_poll_send(cx, &mut to_send) {
                    Poll::Ready(Ok(_)) => {}
                    Poll::Ready(Err(_)) => {
                        tracing::info!("Up stream aborting: Error sending");
                        return false.into();
                    }
                    Poll::Pending => {
                        if send_alarm.alarm_poll(cx).is_ready() {
                            return Poll::Ready(false);
                        }
                        return Poll::Pending;
                    }
                };
                need_flush = true;
                to_send = None;
                cx.waker().wake_by_ref();
            }
            if let Poll::Ready(ds) = down_status_alarm.watch_poll(cx) {
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

            (*send_alarm).set_alarm(Some(io.now() + SEND_TIMEOUT));
            if to_send.is_some() {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }

            // We don't have a status message to send, so try to read app data
            (*read_alarm).set_alarm(read_timeout);
            let data: Option<Bytes> = match io.up_in.con_poll_read(cx, 65536) {
                Poll::Ready(Ok(item)) => {
                    // We successfully read data or EOF
                    // If we're in shutdown mode, extend the timeout
                    // (we're still getting data, so the app is still alive)
                    if read_timeout.is_some() {
                        read_timeout = Some(io.now() + SHUTDOWN_READ_TIMEOUT);
                    }
                    if item.is_none() {
                        // EOF from app - send EOF to WebSocket
                        if read_timeout.is_some() {
                            read_timeout = Some(io.now() + SHUTDOWN_READ_TIMEOUT);
                        }
                        got_eof = true;
                        to_send = Some(Message::Binary(Bytes::new()));
                    }
                    item
                }
                Poll::Ready(Err(_)) => {
                    tracing::error!("Up stream aborting: Error reading from app");
                    return false.into();
                }
                Poll::Pending => {
                    if read_alarm.alarm_poll(cx).is_ready() {
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
                        io.bytes_uploaded
                            .set(io.bytes_uploaded.get() + (bin.len() as u64));
                        to_send = Some(Message::Binary(bin));
                    }
                }
            }
            if to_send.is_some() {
                cx.waker().wake_by_ref();
            } else if need_flush && sink.prod_poll_flush(cx).is_ready() {
                need_flush = false;
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
                    flush_alarm.alarm_poll(cx)
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
                flush_alarm.alarm_poll(cx)
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
        let writer = &io.down_out;
        let mut got_eof = false;

        // If we can't write to the app, we enter discarding mode:
        // keep reading from WS (to drain it) but don't write to app
        let mut down_discarding = false;

        // Timeout for reading from WebSocket (set when upload task completes)
        let mut read_timeout: Option<Instant> = None;
        let read_alarm = pin!(ClockAlarm::new(io.pin_clock(), None));
        let send_alarm = pin!(ClockAlarm::new(io.pin_clock(), None));
        let up_status_alarm = pin!(ValueWatch::new(io.pin_up_status()));
        let mut send_bytes: Bytes = Bytes::new();
        let mut need_flush = false;

        // Main loop: transfer data from WebSocket to app
        let is_ok = poll_fn(|cx| {
            if read_timeout.is_none() {
                match up_status_alarm.watch_poll(cx) {
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

            if !send_bytes.is_empty() {
                // We've got some data that we're trying to send
                match writer.prod_poll_write(cx, &mut send_bytes) {
                    Poll::Pending => {
                        if send_alarm.alarm_poll(cx).is_ready() {
                            tracing::info!("Down stream discarding due to send timeout");
                            down_discarding = true;
                            io.down_status.set(DownloadStatus::Discarding);
                            return false.into();
                        }
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
                        if send_bytes.is_empty() {
                            need_flush = true;
                        } else {
                            (*send_alarm).set_alarm(Some(io.now() + SEND_TIMEOUT));
                            cx.waker().wake_by_ref();
                            return Poll::Pending;
                        }
                    }
                }
            }

            if got_eof {
                return true.into();
            }

            // Try to read a WebSocket message
            (*read_alarm).set_alarm(read_timeout);
            let msg: Result<Option<Message>, ()> = match stream.con_poll_read(cx) {
                Poll::Ready(Ok(msg)) => Ok(msg),
                Poll::Ready(Err(_)) => {
                    tracing::info!("Down stream aborted: read error");
                    return false.into();
                }
                Poll::Pending => {
                    if read_alarm.alarm_poll(cx).is_ready() {
                        tracing::info!("Down stream aborted: read error");
                        return false.into();
                    }
                    if need_flush && writer.prod_poll_flush(cx).is_ready() {
                        need_flush = false;
                        cx.waker().wake_by_ref();
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
            match msg {
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
                    } else if str.starts_with("CONNECT:") {
                        // CONNECT message shouldn't happen after we're connected
                        tracing::info!("Down stream aborted. Unexpected CONNECT");
                        return false.into();
                    } else {
                        // Unknown text message - ignore and continue
                        tracing::info!("Down stream: unrecognized: {}", str);
                    }
                }
                // Binary data message
                Message::Binary(bytes) => {
                    if bytes.is_empty() {
                        // Empty binary = EOF from server
                        got_eof = true;
                        tracing::info!("Down stream done: EOF");
                    } else if !down_discarding {
                        io.bytes_downloaded
                            .set(io.bytes_downloaded.get() + (bytes.len() as u64));
                        // Actual data to forward to app
                        send_bytes = bytes;
                    }
                }
                // Other message types (Ping, Pong, etc.) - ignore
                _ => {}
            };

            // Since we processed a message, loop around to the next iteration to send it or get more
            (*send_alarm).set_alarm(Some(io.now() + SEND_TIMEOUT));
            cx.waker().wake_by_ref();
            Poll::Pending
        })
        .await;

        if !is_ok {
            stream.drop_read();
        }

        // Wait for any pending output to be consumed by the app
        let flush_timeout: ClockAlarm<RawMutex, Instant> =
            ClockAlarm::new(io.pin_clock(), Some(io.now() + SEND_TIMEOUT));
        let mut flush_timeout = pin!(flush_timeout);
        poll_fn(|cx| {
            if writer.prod_poll_close(cx).is_ready() {
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

/// Information about a remote connected client
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct TunnelClientInfo {
    pub ip_addr: Option<IpAddr>,
    pub connection_id: TraceId,
}

/// Statistics from a completed tunnel forwarding session.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct TunnelConnectionStats {
    /// Bytes received from the tunnel and sent to the local service
    pub bytes_downloaded: u64,
    /// Bytes received from the local service and sent to the tunnel
    pub bytes_uploaded: u64,
}

/// A connection to a tunnel client.  When a caller receives one of these, it
/// is in a state that is waiting for I/O to be connected to the input and output
/// ports.  The caller MUST connect I/O, or the protocol will not finish until
/// it times out.
pub trait TunnelConnection: Send + Sync {
    fn client_info(&self) -> &TunnelClientInfo;

    /// Connect the protocol's I/O channels to the given reader and writer.
    fn connect_io(
        &self,
        download: Arc<Mutex<dyn IoWriter<Error = IoError> + Send>>,
        upload: Arc<Mutex<dyn IoReader<Error = IoError> + Send>>,
    ) -> Result<(), TunnelError>;
    fn get_stats(&self) -> TunnelConnectionStats;
    fn join(self: Arc<Self>) -> TunnelConnectionJoin;
}

pub(crate) trait TunnelConnectionPrivate: TunnelConnection {
    fn as_arc_connection(self: Arc<Self>) -> Arc<dyn TunnelConnection>;
    fn poll(&self, cx: &mut Context<'_>) -> Poll<()>;
    fn can_recycle(&self) -> bool;
    fn get_up_status(&self) -> &WatchableValue<RawMutex, UploadStatus>;
    fn get_down_status(&self) -> &WatchableValue<RawMutex, DownloadStatus>;
}

pub(crate) trait TunnelConnectionImpl<SLINKS: ServerLinks + Debug + 'static>:
    TunnelConnectionPrivate
{
    fn get_io(&self) -> &TunnelIO<SLINKS>;
}

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
pub(crate) fn create_tunnel_protocol<SLINKS: ServerLinks + Debug + 'static>(
    now: Instant,
    server_links: SLINKS,
    client_info: TunnelClientInfo,
) -> Arc<dyn TunnelConnectionImpl<SLINKS>> {
    let conn: Arc<ProcMachineImpl<RawMutex, TunnelIO<SLINKS>, _>> = PROC_MACHINE_BUILDER
        .with(TunnelIO::<SLINKS>::up_connected)
        .with(TunnelIO::<SLINKS>::down_connected)
        .build_std(TunnelIO::new(now, server_links, client_info));
    conn
}

pub struct TunnelConnectionJoin {
    d_watch: ValueWatch<'static, RawMutex, DownloadStatus>,
    u_watch: ValueWatch<'static, RawMutex, UploadStatus>,
    // MUST DROP AFTER WATCHES
    pm: Arc<dyn TunnelConnectionPrivate>,
    progress: Cell<u32>,
}

impl Future for TunnelConnectionJoin {
    type Output = TunnelConnectionStats;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };
        if this.progress.get() < 1 {
            let p = unsafe { Pin::new_unchecked(&mut this.d_watch) };
            match p.watch_poll(cx) {
                Poll::Ready(DownloadStatus::Done)
                | Poll::Ready(DownloadStatus::Discarding)
                | Poll::Ready(DownloadStatus::Failed) => {}
                _ => return Poll::Pending,
            }
            this.progress.set(1);
        }
        if this.progress.get() < 2 {
            let p = unsafe { Pin::new_unchecked(&mut this.u_watch) };
            match p.watch_poll(cx) {
                Poll::Pending | Poll::Ready(UploadStatus::Active) => return Poll::Pending,
                _ => {}
            }
            this.progress.set(2);
        }
        Poll::Ready(this.pm.get_stats())
    }
}

impl<SLINKS: ServerLinks + Debug + 'static, F: ProcMachineFutures + 'static> TunnelConnection
    for ProcMachineImpl<RawMutex, TunnelIO<SLINKS>, F>
{
    fn client_info(&self) -> &TunnelClientInfo {
        let ptr: *const TunnelClientInfo = &self.lock_ref().client_info;
        // SAFETY: All instances of Self are held by an Arc and never moved, so the address of client_info is stable.
        unsafe { &*ptr }
    }

    fn connect_io(
        &self,
        download: Arc<Mutex<dyn IoWriter<Error = IoError> + Send>>,
        upload: Arc<Mutex<dyn IoReader<Error = IoError> + Send>>,
    ) -> Result<(), TunnelError> {
        let mut guard = self.lock_ref();
        guard
            .down_out
            .connect(download)
            .map_err(|()| TunnelError::InvalidState)?;
        guard
            .up_in
            .connect(upload)
            .map_err(|()| TunnelError::InvalidState)?;
        Ok(())
    }

    fn get_stats(&self) -> TunnelConnectionStats {
        let guard = self.lock_ref();
        guard.get_stats()
    }

    fn join(self: Arc<Self>) -> TunnelConnectionJoin {
        let a = self.clone();
        // SAFETY: All instances of Self are held by an Arc and never moved, and
        // TunnelConnectionJoin will hold the arc longer than the pin
        let pd = unsafe {
            let p: *const WatchableValue<RawMutex, DownloadStatus> = self.get_down_status();
            Pin::new_unchecked(&*p)
        };
        // SAFETY: All instances of Self are held by an Arc and never moved, and
        // TunnelConnectionJoin will hold the arc longer than the pin
        let pu = unsafe {
            let p: *const WatchableValue<RawMutex, UploadStatus> = self.get_up_status();
            Pin::new_unchecked(&*p)
        };
        TunnelConnectionJoin {
            d_watch: ValueWatch::new(pd),
            u_watch: ValueWatch::new(pu),
            progress: Cell::new(0),
            pm: a,
        }
    }
}

impl<SLINKS: ServerLinks + Debug + 'static, F: ProcMachineFutures + 'static> TunnelConnectionPrivate
    for ProcMachineImpl<RawMutex, TunnelIO<SLINKS>, F>
{
    fn as_arc_connection(self: Arc<Self>) -> Arc<dyn TunnelConnection> {
        self
    }
    fn poll(&self, cx: &mut Context<'_>) -> Poll<()> {
        {
            let g = self.lock_ref();
            g.clock.advance(coarsetime::Instant::now());
        }
        self.external_poll(cx)
    }
    fn can_recycle(&self) -> bool {
        let g = self.lock_ref();
        g.up_status.get() == UploadStatus::Done && g.down_status.get() == DownloadStatus::Done
    }

    fn get_up_status(&self) -> &WatchableValue<RawMutex, UploadStatus> {
        let ptr: *const TunnelIO<SLINKS> = &*self.lock_ref();
        // SAFETY: All instances in held by Arc
        unsafe { &(*ptr).up_status }
    }

    fn get_down_status(&self) -> &WatchableValue<RawMutex, DownloadStatus> {
        let ptr: *const TunnelIO<SLINKS> = &*self.lock_ref();
        // SAFETY: All instances in held by Arc
        unsafe { &(*ptr).down_status }
    }
}

impl<SLINKS: ServerLinks + Debug + 'static, F: ProcMachineFutures + 'static>
    TunnelConnectionImpl<SLINKS> for ProcMachineImpl<RawMutex, TunnelIO<SLINKS>, F>
{
    fn get_io(&self) -> &TunnelIO<SLINKS> {
        let g = self.lock_ref();
        let ptr: *const TunnelIO<SLINKS> = &*g;
        // SAFETY: The ProcMachine guarantees that the TunnelIO is at a stable address and that the lock_ref() guard keeps it alive while we're using the pointer.
        unsafe { &*ptr }
    }
}

#[cfg(test)]
mod tests {
    use std::task::Context;
    type TunnelProtocol<SLINKS> = Arc<dyn ProcMachine<IO = TunnelIO<SLINKS>>>;

    /// A [`ServerLinks`] implementation backed by [`IoExchange`] channels.
    ///
    /// This is the default used by [`create_tunnel_protocol`] and the listener.
    /// External code writes incoming WebSocket messages into `down_in` and reads
    /// outgoing WebSocket messages from `up_out`.
    #[derive(Debug)]
    pub(crate) struct ExchangeServerLinks {
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

    use super::*;
    use coarsetime::Instant;
    use futures::task::noop_waker_ref;
    use procmachines::{IoBytesExchange, IoExchange, IoSink, IoStream, RefLockable};

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    /// The exchanges connected to a protocol for the duration of a test.
    struct TestRig {
        proto: TunnelProtocol<ExchangeServerLinks>,
        up_in: Arc<Mutex<IoBytesExchange>>,
        down_out: Arc<Mutex<IoBytesExchange>>,
    }

    /// Creates a protocol and connects exchanges for `up_in` and `down_out`.
    ///
    /// Builds the protocol as a concrete [`ProcMachine`] (rather than going
    /// through [`create_tunnel_protocol`], which returns an opaque
    /// [`TunnelConnection`]) so the tests can `lock_ref()` to inspect the
    /// internal [`TunnelIO`] channels.
    fn make_proto() -> TestRig {
        let client_info = TunnelClientInfo {
            connection_id: "test_client".into(),
            ip_addr: None,
        };
        let proto: TunnelProtocol<ExchangeServerLinks> = PROC_MACHINE_BUILDER
            .with(TunnelIO::<ExchangeServerLinks>::up_connected)
            .with(TunnelIO::<ExchangeServerLinks>::down_connected)
            .build_std(TunnelIO::new(
                Instant::now(),
                ExchangeServerLinks::new(),
                client_info,
            ));
        let up_in = Arc::new(Mutex::new(IoBytesExchange::new()));
        let down_out = Arc::new(Mutex::new(IoBytesExchange::new()));
        {
            let mut guard = proto.lock_ref();
            guard.up_in.connect(up_in.clone()).unwrap();
            guard.down_out.connect(down_out.clone()).unwrap();
        }
        TestRig {
            proto,
            up_in,
            down_out,
        }
    }

    /// Sends an item into an IoExchange (writer/sink side). Returns true if accepted.
    fn exchange_send<T: Send>(exch: &IoExchange<T>, item: T) -> bool {
        let mut cx = Context::from_waker(noop_waker_ref());
        let mut opt = Some(item);
        matches!(exch.prod_poll_send(&mut cx, &mut opt), Poll::Ready(Ok(())))
    }

    /// Writes Bytes into an IoBytesExchange (writer side). Returns true if the
    /// full payload was accepted.
    fn bytes_send<T: RefLockable<Target = IoBytesExchange>>(exch: &T, item: Bytes) -> bool {
        let mut cx = Context::from_waker(noop_waker_ref());
        let mut data = item;
        let was_len = data.len();
        let guard = exch.lock_ref();
        match guard.prod_poll_write(&mut cx, &mut data) {
            Poll::Ready(Ok(n)) => n == was_len && data.is_empty(),
            _ => false,
        }
    }

    /// Reads a chunk of Bytes from an IoBytesExchange (reader side).
    fn bytes_read<T: RefLockable<Target = IoBytesExchange>>(exch: &T) -> Poll<Option<Bytes>> {
        let mut cx = Context::from_waker(noop_waker_ref());
        let guard = exch.lock_ref();
        match guard.con_poll_read(&mut cx, usize::MAX) {
            Poll::Ready(Ok(opt)) => Poll::Ready(opt),
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(_)) => unreachable!(),
        }
    }

    /// Initiates close on the writer side of an IoBytesExchange.
    fn bytes_close<T: RefLockable<Target = IoBytesExchange>>(
        exch: &T,
    ) -> Poll<Result<(), IoError>> {
        let mut cx = Context::from_waker(noop_waker_ref());
        exch.lock_ref().prod_poll_close(&mut cx)
    }

    /// Drives the protocol by locking/unlocking (which triggers a tick).
    fn tick(proto: &TunnelProtocol<ExchangeServerLinks>) {
        let _guard = proto.lock_ref();
        // guard drop triggers tick
    }

    /// Repeatedly ticks and tries to read from a Message IoExchange until we
    /// get a Ready result or exhaust attempts.
    fn read_message_with_ticks(
        proto: &TunnelProtocol<ExchangeServerLinks>,
        get_exchange: impl Fn(&TunnelIO<ExchangeServerLinks>) -> &IoExchange<Message>,
        max_ticks: usize,
    ) -> Poll<Result<Option<Message>, IoError>> {
        for _ in 0..max_ticks {
            let guard = proto.lock_ref();
            let result = {
                let mut cx = Context::from_waker(noop_waker_ref());
                get_exchange(&guard).con_poll_read(&mut cx)
            };
            if result.is_ready() {
                return result;
            }
            // drop guard → tick
        }
        Poll::Pending
    }

    /// Repeatedly ticks the protocol and tries to read bytes from the given
    /// `IoBytesExchange` until we get a Ready result or exhaust attempts.
    fn read_bytes_with_ticks<T: RefLockable<Target = IoBytesExchange>>(
        proto: &TunnelProtocol<ExchangeServerLinks>,
        exch: &T,
        max_ticks: usize,
    ) -> Poll<Option<Bytes>> {
        for _ in 0..max_ticks {
            let _guard = proto.lock_ref();
            let result = bytes_read(exch);
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
        let rig = make_proto();

        // Write app data into up_in
        assert!(bytes_send(&rig.up_in, Bytes::from("hello")));

        // Read the resulting WS message from up_out
        let msg = read_message_with_ticks(&rig.proto, |io| &io.server_links.up_out, 5);
        match msg {
            Poll::Ready(Ok(Some(Message::Binary(b)))) => {
                assert_eq!(b, Bytes::from("hello"));
            }
            other => panic!("expected Binary message, got {:?}", other),
        }
    }

    #[test]
    fn upload_multiple_messages() {
        let rig = make_proto();
        let payloads = vec!["one", "two", "three"];

        for payload in &payloads {
            assert!(bytes_send(&rig.up_in, Bytes::from(*payload)));

            let msg = read_message_with_ticks(&rig.proto, |io| &io.server_links.up_out, 5);
            match msg {
                Poll::Ready(Ok(Some(Message::Binary(b)))) => {
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
        // (IoBytesExchange::prod_poll_write is itself a no-op for empty input,
        // so the protocol task never sees the empty chunk.)
        let rig = make_proto();

        // "Send" empty bytes (no-op).
        assert!(bytes_send(&rig.up_in, Bytes::new()));

        // Send real data
        assert!(bytes_send(&rig.up_in, Bytes::from("real")));

        // The first message out should be the real data, not an empty one
        let msg = read_message_with_ticks(&rig.proto, |io| &io.server_links.up_out, 10);
        match msg {
            Poll::Ready(Ok(Some(Message::Binary(b)))) => {
                assert_eq!(b, Bytes::from("real"));
            }
            other => panic!("expected Binary(real), got {:?}", other),
        }
    }

    #[test]
    fn upload_eof_sends_empty_binary() {
        let rig = make_proto();

        // Close up_in (simulates app EOF)
        let _ = bytes_close(&rig.up_in);

        // The upload task should send an empty Binary (EOF marker)
        let msg = read_message_with_ticks(&rig.proto, |io| &io.server_links.up_out, 10);
        match msg {
            Poll::Ready(Ok(Some(Message::Binary(b)))) => {
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
        let rig = make_proto();

        // Write a WS message into down_in
        {
            let guard = rig.proto.lock_ref();
            assert!(exchange_send(
                &guard.server_links.down_in,
                Message::Binary(Bytes::from("world"))
            ));
        }

        // Read the resulting app data from down_out
        let data = read_bytes_with_ticks(&rig.proto, &rig.down_out, 5);
        match data {
            Poll::Ready(Some(b)) => {
                assert_eq!(b, Bytes::from("world"));
            }
            other => panic!("expected Bytes(world), got {:?}", other),
        }
    }

    #[test]
    fn download_multiple_messages() {
        let rig = make_proto();
        let payloads = vec!["alpha", "beta", "gamma"];

        for payload in &payloads {
            {
                let guard = rig.proto.lock_ref();
                assert!(exchange_send(
                    &guard.server_links.down_in,
                    Message::Binary(Bytes::from(*payload))
                ));
            }

            let data = read_bytes_with_ticks(&rig.proto, &rig.down_out, 5);
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
        let rig = make_proto();

        // Send EOF (empty Binary)
        {
            let guard = rig.proto.lock_ref();
            assert!(exchange_send(
                &guard.server_links.down_in,
                Message::Binary(Bytes::new())
            ));
        }

        // down_out should eventually close (yield None)
        let result = read_bytes_with_ticks(&rig.proto, &rig.down_out, 10);
        assert!(
            matches!(result, Poll::Ready(None)),
            "expected stream end after EOF, got {:?}",
            result
        );
    }

    #[test]
    fn download_eof_drop_message() {
        let rig = make_proto();

        // Send a DROP message
        {
            let guard = rig.proto.lock_ref();
            assert!(exchange_send(
                &guard.server_links.down_in,
                Message::Text("DROP:connection_limit".into())
            ));
        }

        // down_out should close
        let result = read_bytes_with_ticks(&rig.proto, &rig.down_out, 10);
        assert!(
            matches!(result, Poll::Ready(None)),
            "expected stream end after DROP, got {:?}",
            result
        );
    }

    #[test]
    fn download_data_then_eof() {
        let rig = make_proto();

        // Send data
        {
            let guard = rig.proto.lock_ref();
            assert!(exchange_send(
                &guard.server_links.down_in,
                Message::Binary(Bytes::from("payload"))
            ));
        }

        let data = read_bytes_with_ticks(&rig.proto, &rig.down_out, 5);
        assert_eq!(data, Poll::Ready(Some(Bytes::from("payload"))));

        // Send EOF
        {
            let guard = rig.proto.lock_ref();
            assert!(exchange_send(
                &guard.server_links.down_in,
                Message::Binary(Bytes::new())
            ));
        }

        let result = read_bytes_with_ticks(&rig.proto, &rig.down_out, 10);
        assert!(matches!(result, Poll::Ready(None)));
    }

    #[test]
    fn download_abort_on_close_frame() {
        let rig = make_proto();

        // Send a WebSocket Close frame
        {
            let guard = rig.proto.lock_ref();
            assert!(exchange_send(
                &guard.server_links.down_in,
                Message::Close(None)
            ));
        }

        // down_out should close (abort)
        let result = read_bytes_with_ticks(&rig.proto, &rig.down_out, 10);
        assert!(
            matches!(result, Poll::Ready(None)),
            "expected abort after Close frame, got {:?}",
            result
        );
    }

    #[test]
    fn download_abort_on_connect_message() {
        let rig = make_proto();

        // Send a CONNECT message (shouldn't happen post-handshake)
        {
            let guard = rig.proto.lock_ref();
            assert!(exchange_send(
                &guard.server_links.down_in,
                Message::Text("CONNECT:some_id".into())
            ));
        }

        // down_out should close (abort)
        let result = read_bytes_with_ticks(&rig.proto, &rig.down_out, 10);
        assert!(
            matches!(result, Poll::Ready(None)),
            "expected abort after CONNECT, got {:?}",
            result
        );
    }

    #[test]
    fn download_ignores_ping() {
        let rig = make_proto();

        // Send a Ping (should be ignored by protocol)
        {
            let guard = rig.proto.lock_ref();
            assert!(exchange_send(
                &guard.server_links.down_in,
                Message::Ping(vec![1, 2, 3].into())
            ));
        }

        // Then send actual data
        {
            let guard = rig.proto.lock_ref();
            assert!(exchange_send(
                &guard.server_links.down_in,
                Message::Binary(Bytes::from("after_ping"))
            ));
        }

        // Should get the data, not the ping
        let data = read_bytes_with_ticks(&rig.proto, &rig.down_out, 10);
        match data {
            Poll::Ready(Some(b)) => assert_eq!(b, Bytes::from("after_ping")),
            other => panic!("expected data after ping, got {:?}", other),
        }
    }

    #[test]
    fn download_ignores_pong() {
        let rig = make_proto();

        {
            let guard = rig.proto.lock_ref();
            assert!(exchange_send(
                &guard.server_links.down_in,
                Message::Pong(vec![].into())
            ));
        }

        {
            let guard = rig.proto.lock_ref();
            assert!(exchange_send(
                &guard.server_links.down_in,
                Message::Binary(Bytes::from("after_pong"))
            ));
        }

        let data = read_bytes_with_ticks(&rig.proto, &rig.down_out, 10);
        match data {
            Poll::Ready(Some(b)) => assert_eq!(b, Bytes::from("after_pong")),
            other => panic!("expected data after pong, got {:?}", other),
        }
    }

    #[test]
    fn download_ignores_unknown_text() {
        let rig = make_proto();

        // Send unrecognized text (should be ignored)
        {
            let guard = rig.proto.lock_ref();
            assert!(exchange_send(
                &guard.server_links.down_in,
                Message::Text("UNKNOWN_COMMAND".into())
            ));
        }

        // Then send actual data
        {
            let guard = rig.proto.lock_ref();
            assert!(exchange_send(
                &guard.server_links.down_in,
                Message::Binary(Bytes::from("real_data"))
            ));
        }

        let data = read_bytes_with_ticks(&rig.proto, &rig.down_out, 10);
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
        let rig = make_proto();

        // Upload: app → WS
        assert!(bytes_send(&rig.up_in, Bytes::from("up_data")));

        let up_msg = read_message_with_ticks(&rig.proto, |io| &io.server_links.up_out, 5);
        assert_eq!(
            up_msg,
            Poll::Ready(Ok(Some(Message::Binary(Bytes::from("up_data")))))
        );

        // Download: WS → app
        {
            let guard = rig.proto.lock_ref();
            assert!(exchange_send(
                &guard.server_links.down_in,
                Message::Binary(Bytes::from("down_data"))
            ));
        }

        let down_data = read_bytes_with_ticks(&rig.proto, &rig.down_out, 5);
        assert_eq!(down_data, Poll::Ready(Some(Bytes::from("down_data"))));
    }

    // -----------------------------------------------------------------------
    // Shutdown coordination
    // -----------------------------------------------------------------------

    #[test]
    fn upload_sends_rdsd_after_download_completes() {
        let rig = make_proto();

        // Complete the download by sending EOF
        {
            let guard = rig.proto.lock_ref();
            assert!(exchange_send(
                &guard.server_links.down_in,
                Message::Binary(Bytes::new())
            ));
        }

        // Drain down_out (the close notification)
        let _ = read_bytes_with_ticks(&rig.proto, &rig.down_out, 10);

        // Now send app data to trigger the upload task to loop back and
        // check down_result. It should see download completed and send RDSD.
        assert!(bytes_send(&rig.up_in, Bytes::from("trigger")));

        // Read messages from up_out. We should see RDSD before or after the
        // data message (depending on timing).
        let mut saw_rdsd = false;
        let mut saw_data = false;
        for _ in 0..20 {
            let msg = read_message_with_ticks(&rig.proto, |io| &io.server_links.up_out, 3);
            match msg {
                Poll::Ready(Ok(Some(Message::Text(ref t))))
                    if AsRef::<str>::as_ref(t) == "RDSD" =>
                {
                    saw_rdsd = true;
                }
                Poll::Ready(Ok(Some(Message::Binary(ref b)))) if !b.is_empty() => {
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
        let rig = make_proto();

        // Make the upload task fail by closing up_out (the consumer side)
        // and feeding it some input data so it tries to write.
        // The upload task will see prod_poll_send return Err and abort.
        {
            let guard = rig.proto.lock_ref();
            guard.server_links.up_out.drop_read();
        }
        assert!(bytes_send(&rig.up_in, Bytes::from("trigger")));

        // Tick to let the upload task detect the error and set up_result=Some(false)
        for _ in 0..5 {
            tick(&rig.proto);
        }

        // Send data to down_in. This should fail because the download process is done
        {
            let guard = rig.proto.lock_ref();
            assert!(!exchange_send(
                &guard.server_links.down_in,
                Message::Binary(Bytes::from("may_pass_through"))
            ));
        }

        // Drain any data that slipped through, then expect close.
        let mut got_close = false;
        for _ in 0..20 {
            let result = read_bytes_with_ticks(&rig.proto, &rig.down_out, 3);
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
        let rig = make_proto();

        // Make the download task fail by sending a Close frame
        {
            let guard = rig.proto.lock_ref();
            assert!(exchange_send(
                &guard.server_links.down_in,
                Message::Close(None)
            ));
        }

        // Tick to let download process the Close and set down_result
        for _ in 0..5 {
            tick(&rig.proto);
        }

        // Upload should send EOF (empty binary) because down_result is Some(false)
        let mut saw_eof = false;
        for _ in 0..20 {
            let msg = read_message_with_ticks(&rig.proto, |io| &io.server_links.up_out, 3);
            match msg {
                Poll::Ready(Ok(Some(Message::Binary(b)))) if b.is_empty() => {
                    saw_eof = true;
                    break;
                }
                Poll::Ready(Ok(Some(_))) => continue,
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
        let rig = make_proto();

        // Send download EOF
        {
            let guard = rig.proto.lock_ref();
            assert!(exchange_send(
                &guard.server_links.down_in,
                Message::Binary(Bytes::new())
            ));
        }

        // Tick to process
        for _ in 0..5 {
            tick(&rig.proto);
        }

        // Check the coordination state via the public accessor
        let guard = rig.proto.lock_ref();
        assert_eq!(guard.down_status.get(), DownloadStatus::Done);
    }

    #[test]
    fn up_to_down_signals_after_download_abort() {
        let rig = make_proto();

        // Trigger download abort via Close frame
        {
            let guard = rig.proto.lock_ref();
            assert!(exchange_send(
                &guard.server_links.down_in,
                Message::Close(None)
            ));
        }

        for _ in 0..5 {
            tick(&rig.proto);
        }

        let guard = rig.proto.lock_ref();
        assert_eq!(guard.down_status.get(), DownloadStatus::Failed);
    }

    // -----------------------------------------------------------------------
    // TunnelIO
    // -----------------------------------------------------------------------

    #[test]
    fn tunnel_io_now_returns_initial_time() {
        let now = Instant::now();
        let client_info = TunnelClientInfo {
            connection_id: "test_client".into(),
            ip_addr: None,
        };
        let io = TunnelIO::new(now, ExchangeServerLinks::new(), client_info);
        assert_eq!(io.now(), now);
    }

    #[test]
    fn tunnel_io_update_clock_advances() {
        let now = Instant::now();
        let client_info = TunnelClientInfo {
            connection_id: "test_client".into(),
            ip_addr: None,
        };
        let io = TunnelIO::new(now, ExchangeServerLinks::new(), client_info);
        let later = now + Duration::from_secs(10);
        io.clock.advance(later);
        assert_eq!(io.now(), later);
    }

    #[test]
    fn tunnel_io_update_clock_does_not_go_backwards() {
        let now = Instant::now();
        let client_info = TunnelClientInfo {
            connection_id: "test_client".into(),
            ip_addr: None,
        };
        let io = TunnelIO::new(now, ExchangeServerLinks::new(), client_info);
        let earlier = Instant::now(); // same or earlier
        io.clock.advance(earlier);
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
        let _rig = make_proto();
    }

    #[test]
    fn protocol_is_not_immediately_done() {
        let rig = make_proto();
        // Both tasks should be alive initially
        assert!(!rig.proto.is_done());
    }
}
