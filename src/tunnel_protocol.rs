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
//! which contains several `SpScMutex` channels for exchanging data:
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
use std::pin::{pin, Pin};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio_tungstenite::tungstenite::Message;

use crate::alarms::{AlarmClock, ClockAlarm};
use crate::io_exchange::{ExchangeWriteError, IoExchange};
use crate::io_sink::IoSink;
use crate::io_stream::IoStream;
use crate::proc_machines::*;
use crate::spsc::*;

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
// Each channel is an SpScMutex<SimpleSpScItemInner<T>> which provides:
// - Single-item buffering (only one item in flight at a time)
// - Producer/consumer waker coordination
// - Timeout support
// ============================================================================

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
pub struct TunnelIO {
    /// Current timestamp as ticks (for timeout checking).
    /// Updated by external code via `update_clock()`.
    pub clock: AlarmClock<Instant>,

    /// WebSocket messages coming in (external → download task).
    /// External code writes Messages received from the WebSocket here.
    pub down_in: IoExchange<Message>,

    /// Application data going out (download task → external).
    /// Download task writes Bytes extracted from Messages here.
    pub down_out: IoExchange<Bytes>,

    /// Application data coming in (external → upload task).
    /// External code writes Bytes from the application here.
    pub up_in: IoExchange<Bytes>,

    /// WebSocket messages going out (upload task → external).
    /// Upload task writes Messages to be sent to the WebSocket here.
    pub up_out: IoExchange<Message>,

    /// Coordination state between upload and download tasks.
    /// Used to signal when one task completes or fails.
    pub up_to_down: SpScMutex<UpToDown>,
}

impl TunnelIO {
    /// Creates a new TunnelIO with the given initial timestamp.
    ///
    /// All channels start in the `Waiting` state (ready to receive).
    pub fn new(now: Instant) -> Self {
        Self {
            clock: AlarmClock::new(now),
            down_in: IoExchange::new(),
            down_out: IoExchange::new(),
            up_in: IoExchange::new(),
            up_out: IoExchange::new(),
            up_to_down: SpScMutex::new(UpToDown::default()),
        }
    }

    /// Returns the current timestamp.
    ///
    /// This is used by tasks to calculate timeout deadlines.
    pub fn now(&self) -> Instant {
        *self.clock.get()
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

    pub fn pin_clock<'a>(self: &'a Pin<&'a Self>) -> Pin<&'a AlarmClock<Instant>> {
        unsafe { Pin::<&'a AlarmClock<Instant>>::new_unchecked(&(*self).clock) }
    }
}

/// Coordination state between the upload and download tasks.
///
/// This struct is shared (via SpScMutex) between the two tasks so they can
/// coordinate shutdown. When one task finishes or fails, it updates this
/// state so the other task knows to start its shutdown sequence.
#[derive(Debug, Clone, Default)]
pub struct UpToDown {
    /// Result of the upload task: Some(true) = success, Some(false) = failure, None = still running
    up_result: Option<bool>,

    /// True if the download task has given up on writing to the app (e.g., app closed).
    /// The upload task checks this to know if it should start its shutdown timer.
    down_discarding: bool,

    /// Result of the download task: Some(true) = success, Some(false) = failure, None = still running
    down_result: Option<bool>,
}

// ============================================================================
// UPLOAD PROCESS
// ============================================================================
//
// The upload task handles the app → WebSocket direction:
// 1. Reads Bytes from up_in (written by external code from the app)
// 2. Wraps them in Message::Binary
// 3. Writes the Message to up_out (read by external code to send to WS)
//
// The main loop continues until:
// - The app sends EOF (empty read)
// - The download task signals failure
// - A timeout expires
// - The up_out channel fails
//
// On completion, it sends an EOF message (empty Binary) to the WebSocket,
// closes the channels, and signals success via up_to_down.up_result.
// ============================================================================

/// Upload task: transfers data from the application to the WebSocket.
///
/// This async function reads from `up_in` and writes to `up_out` until EOF
/// or an error occurs. It coordinates with the download task via `up_to_down`.
async fn up_connected(io: Pin<&TunnelIO>) -> TaskEnd {
    let mut got_eof = false;

    // Once we're in shutdown mode, we use a read timeout to avoid hanging forever
    // waiting for app data that will never come.
    let mut read_timeout: Option<Instant> = None;

    // Main loop: transfer data from app to WebSocket
    while !got_eof {
        // Message to send to the WebSocket (if any)
        let mut to_send: Option<Message> = None;

        // Check if the download task has completed or failed.
        // If so, we need to start our shutdown sequence.
        let (down_result, down_discarding) = io
            .up_to_down
            .p_get(|r| (r.down_result, r.down_discarding))
            .await;
        match down_result {
            Some(true) => {
                if read_timeout.is_none() {
                    // Download completed successfully. Start shutdown timer.
                    tracing::info!("Up stream starting shutdown timer after down stream finished.");
                    read_timeout = Some(io.now() + SHUTDOWN_READ_TIMEOUT);
                    // Tell the server we're shutting down our read side.
                    to_send = Some(Message::Text("RDSD".into()));
                }
            }
            Some(false) => {
                // Download failed. Close immediately.
                tracing::info!("Up stream closing after down stream failed.");
                got_eof = true;
                to_send = Some(Message::Binary(Bytes::new())); // EOF message
            }
            _ => {
                // Download still running, but check if it gave up on writing
                if down_discarding && read_timeout.is_none() {
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
        }

        // If we don't have a shutdown message to send, try to read app data
        if to_send.is_none() {
            let mut data: Option<Bytes> = None;
            let read_alarm = pin!(ClockAlarm::new(io.pin_clock(), read_timeout));
            let err: Option<&str> = poll_fn(|cx| {
                match io.up_in.poll_read(cx) {
                    Poll::Ready(item) => {
                        // Got data! We'll process it below.
                        data = item;
                        return Poll::Ready(None);
                    }
                    Poll::Pending => {
                        // No data available yet. Check if output is still valid before yielding.
                        match io.up_out.poll_send_ready(cx) {
                            Poll::Ready(Err(_)) => {
                                return Poll::Ready(Some(
                                    "Up stream aborting: output channel closed while waiting",
                                ))
                            }
                            _ => (),
                        };
                        if read_alarm.poll_ref(cx).is_ready() {
                            return Some(
                                "Up stream aborting.  Read timed out after down stream shut down",
                            )
                            .into();
                        }
                    }
                };
                Poll::Pending
            })
            .await;
            if let Some(err) = err {
                tracing::info!(err);
                return up_abort(io).await;
            }
            // We successfully read data or EOF
            // If we're in shutdown mode, extend the timeout
            // (we're still getting data, so the app is still alive)
            if read_timeout.is_some() {
                read_timeout = Some(io.now() + SHUTDOWN_READ_TIMEOUT);
            }

            // Process the data we read
            match data {
                None => {
                    // EOF from app - send EOF to WebSocket
                    got_eof = true;
                    to_send = Some(Message::Binary(Bytes::new()));
                }
                Some(bin) => {
                    if bin.is_empty() {
                        // Empty data is not EOF, just skip it.
                        // (We can't send empty Binary - that looks like EOF!)
                        continue;
                    }
                    to_send = Some(Message::Binary(bin));
                }
            }
        }

        // We have a message to send - write it to up_out
        let send_timeout = pin!(ClockAlarm::new(
            io.pin_clock(),
            Some(io.now() + SEND_TIMEOUT)
        ));
        let ok = poll_fn(|cx| {
            match io.up_out.poll_send(cx, &mut to_send) {
                Poll::Ready(Ok(_)) => return Poll::Ready(true),
                Poll::Ready(Err(_)) => return Poll::Ready(false),
                Poll::Pending => (),
            };
            if send_timeout.poll_ref(cx).is_ready() {
                return Poll::Ready(false);
            }
            Poll::Pending
        })
        .await;
        if !ok {
            // Can't write - abort the whole upload task
            tracing::info!("Up stream aborting: Error sending");
            return up_abort(io).await;
        }
    }

    // Clean shutdown: we got EOF and sent an EOF message
    io.up_in.drop_read();

    // Wait for any pending output to be consumed
    let flush_timeout = pin!(ClockAlarm::new(
        io.pin_clock(),
        Some(io.now() + SEND_TIMEOUT)
    ));
    poll_fn(|cx| {
        if io.up_out.poll_close(cx).is_ready() {
            Poll::Ready(())
        } else {
            flush_timeout.poll_ref(cx)
        }
    })
    .await;
    io.up_to_down.side_check(|x: &mut UpToDown| {
        x.up_result = Some(true); // Signal success
        true
    });
    TaskEnd()
}

/// Abort the upload task due to an error.
///
/// Closes both channels and signals failure so the download task aborts too.
async fn up_abort(io: Pin<&TunnelIO>) -> TaskEnd {
    let mut cx = Context::from_waker(noop_waker_ref());
    io.up_in.drop_read();
    let _ = io.up_out.poll_close(&mut cx);
    io.up_to_down.side_check(|x: &mut UpToDown| {
        x.up_result = Some(false); // Signal failure - download should abort
        true
    });
    TaskEnd()
}

// ============================================================================
// DOWNLOAD PROCESS
// ============================================================================
//
// The download task handles the WebSocket → app direction:
// 1. Reads Messages from down_in (written by external code from the WS)
// 2. Extracts Bytes from Binary messages
// 3. Writes the Bytes to down_out (read by external code to send to app)
//
// The main loop continues until:
// - We receive an EOF message (empty Binary or "DROP:...")
// - The upload task signals failure
// - A timeout expires
// - The down_in channel fails
//
// If writing to the app fails, the task enters "discarding" mode where it
// continues reading from the WebSocket (to drain it properly) but doesn't
// try to write to the app anymore.
// ============================================================================

/// Download task: transfers data from the WebSocket to the application.
///
/// This async function reads from `down_in` and writes to `down_out` until EOF
/// or an error occurs. It coordinates with the upload task via `up_to_down`.
async fn down_connected(io: Pin<&TunnelIO>) -> TaskEnd {
    let mut got_eof = false;

    // If we can't write to the app, we enter discarding mode:
    // keep reading from WS (to drain it) but don't write to app
    let mut down_discarding = false;

    // Timeout for reading from WebSocket (set when upload task completes)
    let mut read_timeout: Option<Instant> = None;

    // Main loop: transfer data from WebSocket to app
    while !got_eof {
        // Check if the upload task has completed or failed
        if read_timeout.is_none() {
            let up_result = io.up_to_down.c_get(|r| r.up_result).await;
            match up_result {
                Some(true) => {
                    // Upload completed successfully. Start shutdown timer.
                    tracing::info!("Down stream starting shutdown timer after up stream finished.");
                    read_timeout = Some(io.now() + SHUTDOWN_READ_TIMEOUT);
                }
                Some(false) => {
                    // Upload failed. Abort immediately.
                    tracing::info!("Down stream aborted after up stream.");
                    return down_abort(io).await;
                }
                _ => {
                    // Upload still running, continue normally
                }
            }
        }

        // Try to read a WebSocket message
        let msg: Result<Option<Message>, ()> = {
            let read_timeout = ClockAlarm::new(io.pin_clock(), read_timeout);
            let mut read_timeout = pin!(read_timeout);
            poll_fn(|cx| {
                if let Poll::Ready(msg) = io.down_in.poll_read(cx) {
                    // got a message
                    return Result::Ok(msg).into();
                }
                if read_timeout.as_mut().poll(cx).is_ready() {
                    return Result::Err(()).into();
                }
                Poll::Pending
            })
            .await
        };
        let msg = match msg {
            Err(_) => {
                tracing::info!("Down stream aborted: read error");
                return down_abort(io).await;
            }
            Ok(None) => {
                tracing::info!("Down stream aborted: EOF");
                return down_abort(io).await;
            }
            Ok(Some(msg)) => msg,
        };

        // If we got data and we're in shutdown mode, extend the timeout
        if read_timeout.is_some() {
            read_timeout = Some(io.now() + SHUTDOWN_READ_TIMEOUT);
        }

        // Process the WebSocket message
        let mut to_send: Option<Bytes> = match msg {
            // WebSocket close frame (unexpected - we should initiate close)
            Message::Close(_) => {
                tracing::info!("Down stream aborted. Got WS close");
                return down_abort(io).await;
            }
            // Control/text message from the server
            Message::Text(txt) => {
                let str = txt.as_str();
                if str.starts_with("DROP:") {
                    // Server-initiated close with reason
                    tracing::info!("Down stream done: {}", str);
                    got_eof = true;
                    // Fall through to send loop (with to_send = None, which is EOF)
                    None
                } else if str.starts_with("CONNECT:") {
                    // CONNECT message shouldn't happen after we're connected
                    tracing::info!("Down stream aborted. Unexpected CONNECT");
                    return down_abort(io).await;
                } else {
                    // Unknown text message - ignore and continue
                    tracing::info!("Down stream: unrecognized: {}", str);
                    continue;
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
            _ => {
                continue;
            }
        };

        // If we're discarding (can't write to app), skip the write
        if down_discarding {
            continue;
        }

        // Write data to the app (if we have any)
        if to_send.is_some() {
            let send_timeout = ClockAlarm::new(io.pin_clock(), Some(io.now() + SEND_TIMEOUT));
            let mut send_timeout = pin!(send_timeout);
            let ok = poll_fn(|cx| {
                if let Poll::Ready(result) = io.down_out.poll_send(cx, &mut to_send) {
                    return result.is_ok().into();
                }
                if send_timeout.as_mut().poll(cx).is_ready() {
                    return false.into();
                }
                Poll::Pending
            })
            .await;
            if !ok {
                // Can't write to app. Enter discarding mode.
                // We still need to drain the WebSocket, so don't abort entirely.
                tracing::info!("Down stream discarding due to send error");
                io.up_to_down
                    .c(|r| {
                        r.down_discarding = true;
                        true
                    })
                    .await;
                down_discarding = true;
            }
        }
    }

    // Clean shutdown: we got EOF from WebSocket
    io.down_in.drop_read();
    io.up_to_down.side_check(|x: &mut UpToDown| {
        x.down_result = Some(true); // Signal success
        true
    });

    // Wait for any pending output to be consumed by the app
    let flush_timeout: ClockAlarm<Instant> =
        ClockAlarm::new(io.pin_clock(), Some(io.now() + SEND_TIMEOUT));
    let mut flush_timeout = pin!(flush_timeout);
    poll_fn(|cx| {
        if io.down_out.poll_close(cx).is_ready() {
            return Poll::Ready(());
        }
        if flush_timeout.as_mut().poll(cx).is_ready() {
            return Poll::Ready(());
        }
        Poll::Pending
    })
    .await;
    TaskEnd()
}

/// Abort the download task due to an error.
///
/// Closes both channels and signals failure via down_result.
async fn down_abort(io: Pin<&TunnelIO>) -> TaskEnd {
    let mut cx = Context::from_waker(noop_waker_ref());
    io.down_in.drop_read();
    let _ = io.down_out.poll_close(&mut cx);
    io.up_to_down.side_check(|x: &mut UpToDown| {
        x.down_result = Some(false); // Signal failure
        true
    });
    TaskEnd()
}

// ============================================================================
// PUBLIC API
// ============================================================================

pub type TunnelProtocol = Arc<dyn ProcMachine<TunnelIO>>;
pub fn create_tunnel_protocol(now: Instant) -> TunnelProtocol {
    let arc = PROC_MACHINE_JOBS_BASE
        .with(up_connected)
        .with(down_connected)
        .build(TunnelIO::new(now));
    arc
}

#[derive(Debug, Clone)]
pub struct TunnelSink {
    inner: TunnelProtocol,
}

impl TunnelSink {
    pub fn new(proto: TunnelProtocol) -> Self {
        Self { inner: proto }
    }
}

impl Sink<Bytes> for TunnelSink {
    type Error = ExchangeWriteError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let guard = self.inner.lock();
        guard.up_in.poll_send_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        let mut cx = Context::from_waker(noop_waker_ref());
        let guard = self.inner.lock();
        let mut to_send = Some(item);
        match guard.up_in.poll_send(&mut cx, &mut to_send) {
            Poll::Ready(res) => res,
            Poll::Pending => Err(ExchangeWriteError::InvalidState),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let guard = self.inner.lock();
        guard.up_in.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let guard = self.inner.lock();
        guard.up_in.poll_close(cx)
    }
}

impl Drop for TunnelSink {
    fn drop(&mut self) {
        let guard = self.inner.lock();
        let mut cx = Context::from_waker(noop_waker_ref());
        let _ = guard.up_in.poll_close(&mut cx);
    }
}

#[derive(Debug, Clone)]
pub struct TunnelStream {
    inner: TunnelProtocol,
}

impl TunnelStream {
    pub fn new(proto: TunnelProtocol) -> Self {
        Self { inner: proto }
    }
}

impl Stream for TunnelStream {
    type Item = Bytes;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let guard = self.inner.lock();
        guard.down_out.poll_read(cx)
    }
}

impl Drop for TunnelStream {
    fn drop(&mut self) {
        let guard = self.inner.lock();
        guard.down_out.drop_read();
    }
}
