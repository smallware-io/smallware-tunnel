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
//!
//! # Usage
//!
//! ```ignore
//! // Create the protocol
//! let protocol = TunnelProtocol::new(Instant::now());
//!
//! // In your I/O loop:
//! loop {
//!     // Feed data from WebSocket into down_in
//!     // Feed data from app into up_in
//!     // Read from up_out to send to WebSocket
//!     // Read from down_out to send to app
//!
//!     // Advance the protocol
//!     if !protocol.tick(Instant::now()) {
//!         break; // Protocol completed
//!     }
//! }
//! ```

use bytes::Bytes;
use coarsetime::{Duration, Instant};
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio_tungstenite::tungstenite::Message;

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
    pub now_ticks: AtomicU64,

    /// WebSocket messages coming in (external → download task).
    /// External code writes Messages received from the WebSocket here.
    pub down_in: SpScMutex<SimpleSpScItemInner<Message>>,

    /// Application data going out (download task → external).
    /// Download task writes Bytes extracted from Messages here.
    pub down_out: SpScMutex<SimpleSpScItemInner<Bytes>>,

    /// Application data coming in (external → upload task).
    /// External code writes Bytes from the application here.
    pub up_in: SpScMutex<SimpleSpScItemInner<Bytes>>,

    /// WebSocket messages going out (upload task → external).
    /// Upload task writes Messages to be sent to the WebSocket here.
    pub up_out: SpScMutex<SimpleSpScItemInner<Message>>,

    /// Coordination state between upload and download tasks.
    /// Used to signal when one task completes or fails.
    pub up_to_down: SpScMutex<UpToDown>,
}

impl TunnelIO {
    /// Creates a new TunnelIO with the given initial timestamp.
    ///
    /// All channels start in the `Waiting` state (ready to receive).
    pub fn new(now: &Instant) -> Self {
        Self {
            now_ticks: AtomicU64::new(now.as_ticks()),
            down_in: SpScMutex::new(SimpleSpScItemInner::default()),
            down_out: SpScMutex::new(SimpleSpScItemInner::default()),
            up_in: SpScMutex::new(SimpleSpScItemInner::default()),
            up_out: SpScMutex::new(SimpleSpScItemInner::default()),
            up_to_down: SpScMutex::new(UpToDown::default()),
        }
    }

    /// Returns the current timestamp.
    ///
    /// This is used by tasks to calculate timeout deadlines.
    pub fn now(&self) -> Instant {
        Instant::from_ticks(self.now_ticks.load(Ordering::SeqCst))
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
        let now_ticks = now.as_ticks();
        let old_ticks = self.now_ticks.fetch_max(now.as_ticks(), Ordering::SeqCst);
        // Only check timeouts if time actually advanced
        if old_ticks < now_ticks {
            self.down_in.check_timeouts(now);
            self.down_out.check_timeouts(now);
            self.up_in.check_timeouts(now);
            self.up_out.check_timeouts(now);
        }
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
async fn up_connected(io_val: Arc<TunnelIO>) -> TaskEnd {
    let io = io_val.as_ref();
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
            let rst = io.up_in.c_try_read(&mut data, read_timeout).await;
            match rst {
                SpScItemState::Busy => {
                    // Got data! We'll process it below.
                }
                SpScItemState::Waiting => {
                    // No data available yet. Check if output is still valid before yielding.
                    let out_state = io.up_out.p_get(|w| w.get_state()).await;
                    if out_state == SpScItemState::Closed || out_state == SpScItemState::Failed {
                        // Output channel is closed - abort
                        tracing::info!("Up stream aborting: output channel closed while waiting");
                        return up_abort(io).await;
                    }
                    yield_once().await;
                    continue;
                }
                _ => {
                    // Channel closed or failed. Treat as EOF.
                    tracing::info!("Up stream closing: {}", rst);
                    got_eof = true;
                    // Fall through to send EOF message
                }
            }

            // If we successfully read and we're in shutdown mode, extend the timeout
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
        let send_timeout = Some(io.now() + SEND_TIMEOUT);
        loop {
            let wst = io.up_out.p_try_write(&mut to_send, send_timeout).await;
            match wst {
                SpScItemState::Busy => {
                    // Consumer hasn't taken the previous message yet. Wait.
                    yield_once().await;
                }
                SpScItemState::Full => {
                    // Message accepted! Continue to next iteration.
                    break;
                }
                SpScItemState::Closed | SpScItemState::Waiting | SpScItemState::Failed => {
                    // Can't write - abort the whole upload task
                    tracing::info!("Up stream aborting: Error sending: {}", wst);
                    return up_abort(io).await;
                }
            }
        }
    }

    // Clean shutdown: we got EOF and sent an EOF message
    io.up_in.close();

    // Wait for any pending output to be consumed
    let flush_timeout = Some(io.now() + SEND_TIMEOUT);
    io.up_to_down.side_check(|x: &mut UpToDown| {
        x.up_result = Some(true); // Signal success
        true
    });
    while io.up_out.p_try_flush(flush_timeout).await == SpScItemState::Busy {
        yield_once().await;
    }

    io.up_out.close();
    TaskEnd()
}

/// Abort the upload task due to an error.
///
/// Closes both channels and signals failure so the download task aborts too.
async fn up_abort(io: &TunnelIO) -> TaskEnd {
    io.up_in.close();
    io.up_out.close();
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
async fn down_connected(io_val: Arc<TunnelIO>) -> TaskEnd {
    let io = io_val.as_ref();
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
        let mut msg: Option<Message> = None;
        let rst = io.down_in.c_try_read(&mut msg, read_timeout).await;
        match rst {
            SpScItemState::Busy => {
                // Got a message! Process it below.
            }
            SpScItemState::Waiting => {
                // No message available yet. Yield and try again.
                yield_once().await;
                continue;
            }
            _ => {
                // Channel closed or failed. Abort.
                tracing::info!("Down stream aborted: {}", rst);
                return down_abort(io).await;
            }
        }

        // If we got data and we're in shutdown mode, extend the timeout
        if read_timeout.is_some() {
            read_timeout = Some(io.now() + SHUTDOWN_READ_TIMEOUT);
        }

        // Process the WebSocket message
        let mut to_send: Option<Bytes> = None;
        match msg {
            // WebSocket close frame (unexpected - we should initiate close)
            None | Some(Message::Close(_)) => {
                tracing::info!("Down stream aborted. Got WS close");
                return down_abort(io).await;
            }
            // Control/text message from the server
            Some(Message::Text(txt)) => {
                let str = txt.as_str();
                if str.starts_with("DROP:") {
                    // Server-initiated close with reason
                    tracing::info!("Down stream done: {}", str);
                    got_eof = true;
                    // Fall through to send loop (with to_send = None, which is EOF)
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
            Some(Message::Binary(bytes)) => {
                if bytes.is_empty() {
                    // Empty binary = EOF from server
                    got_eof = true;
                    tracing::info!("Down stream done: EOF");
                    to_send = None;
                } else {
                    // Actual data to forward to app
                    to_send = Some(bytes);
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
        let send_timeout = Some(io.now() + SEND_TIMEOUT);
        loop {
            let wst = io.down_out.p_try_write(&mut to_send, send_timeout).await;
            match wst {
                SpScItemState::Busy => {
                    // Consumer hasn't taken the previous data yet. Wait.
                    yield_once().await;
                }
                SpScItemState::Full => {
                    // Data accepted! Continue to next iteration.
                    break;
                }
                SpScItemState::Closed | SpScItemState::Waiting | SpScItemState::Failed => {
                    // Can't write to app. Enter discarding mode.
                    // We still need to drain the WebSocket, so don't abort entirely.
                    tracing::info!("Down stream discarding: {}", wst);
                    io.up_to_down
                        .c(|r| {
                            r.down_discarding = true;
                            true
                        })
                        .await;
                    down_discarding = true;
                    break;
                }
            }
        }
    }

    // Clean shutdown: we got EOF from WebSocket
    io.down_in.close();
    io.up_to_down.side_check(|x: &mut UpToDown| {
        x.down_result = Some(true); // Signal success
        true
    });

    // Wait for any pending output to be consumed by the app
    let flush_timeout = Some(io.now() + SEND_TIMEOUT);
    while io.down_out.p_try_flush(flush_timeout).await == SpScItemState::Busy {
        yield_once().await;
    }

    io.down_out.close();
    TaskEnd()
}

/// Abort the download task due to an error.
///
/// Closes both channels and signals failure via down_result.
async fn down_abort(io: &TunnelIO) -> TaskEnd {
    io.down_in.close();
    io.down_out.close();
    io.up_to_down.side_check(|x: &mut UpToDown| {
        x.down_result = Some(false); // Signal failure
        true
    });
    TaskEnd()
}

// ============================================================================
// PUBLIC API
// ============================================================================

/// The main tunnel protocol state machine.
///
/// This struct combines the I/O state (`TunnelIO`) with the procedural state
/// machine (`ProcMachine`) that runs the upload and download tasks.
///
/// # Usage
///
/// ```ignore
/// // Create the protocol
/// let protocol = TunnelProtocol::new(Instant::now());
///
/// // Get access to the I/O channels
/// let io = protocol.io();
///
/// // In your main I/O loop:
/// loop {
///     // Feed incoming WebSocket messages into the protocol
///     if let Some(msg) = ws.try_recv() {
///         io.down_in.p_try_write(&mut Some(msg), timeout).await;
///     }
///
///     // Feed outgoing data from app into the protocol
///     if let Some(data) = app.try_read() {
///         io.up_in.p_try_write(&mut Some(data), timeout).await;
///     }
///
///     // Get outgoing WebSocket messages from the protocol
///     let mut msg = None;
///     if io.up_out.c_try_read(&mut msg, None).await == SpScItemState::Busy {
///         ws.send(msg.take().unwrap()).await;
///     }
///
///     // Get data to send to the app
///     let mut data = None;
///     if io.down_out.c_try_read(&mut data, None).await == SpScItemState::Busy {
///         app.write(data.take().unwrap()).await;
///     }
///
///     // Advance the protocol state machine
///     if !protocol.tick(Instant::now()) {
///         break; // Protocol completed
///     }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct TunnelProtocol {
    /// Shared I/O state for data exchange with external code
    io: Arc<TunnelIO>,
    /// The procedural state machine running upload and download tasks
    pm: Arc<dyn ProcMachine>,
}

impl TunnelProtocol {
    /// Creates a new tunnel protocol instance.
    ///
    /// # Arguments
    ///
    /// * `now` - The current timestamp (used for timeout calculations)
    ///
    /// # Returns
    ///
    /// A new `TunnelProtocol` with both upload and download tasks ready to run.
    pub fn new(now: Instant) -> Self {
        // Create shared I/O state
        let io = Arc::new(TunnelIO::new(&now));

        // Create the procedural state machine with two tasks:
        // - up_connected: handles app → WebSocket
        // - down_connected: handles WebSocket → app
        let pm = create_proc_machine2(up_connected(io.clone()), down_connected(io.clone()));

        Self { io, pm }
    }

    /// Returns a reference to the shared I/O state.
    ///
    /// Use this to interact with the protocol's channels for feeding data
    /// in and pulling data out.
    pub fn io(&self) -> &Arc<TunnelIO> {
        &self.io
    }

    /// Advance the protocol by updating the clock and polling the tasks.
    ///
    /// This method should be called repeatedly in your I/O loop. It:
    /// 1. Updates the internal clock and checks for expired timeouts
    /// 2. Polls all async tasks until they're all idle
    ///
    /// # Arguments
    ///
    /// * `now` - The current timestamp
    ///
    /// # Returns
    ///
    /// * `true` - Protocol is still running, call `tick()` again later
    /// * `false` - Protocol has completed (both tasks finished)
    pub fn tick(&self, now: Instant) -> bool {
        self.io.update_clock(now);
        self.pm.tick()
    }

    /// Returns a reference to the upload input channel (app → protocol).
    ///
    /// This is used by TunnelSink to write data.
    pub fn up_in(&self) -> &SpScMutex<SimpleSpScItemInner<Bytes>> {
        &self.io.up_in
    }

    /// Returns a reference to the download output channel (protocol → app).
    ///
    /// This is used by TunnelStream to read data.
    pub fn down_out(&self) -> &SpScMutex<SimpleSpScItemInner<Bytes>> {
        &self.io.down_out
    }
}

/// Implement ProcMachine for TunnelProtocol so it can be used with SpScItemSink/Stream.
impl ProcMachine for TunnelProtocol {
    fn tick(&self) -> bool {
        self.io.update_clock(Instant::now());
        self.pm.tick()
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    // ========================================================================
    // TEST HELPERS
    // ========================================================================

    /// A test harness for driving the TunnelProtocol in a sans-io manner.
    ///
    /// The key insight is that we need to interleave I/O operations with ticks,
    /// and collect output messages as they become available (before channels close).
    struct TestHarness {
        protocol: TunnelProtocol,
        now: Instant,
        /// Messages collected from up_out (to WebSocket)
        ws_out_msgs: Vec<Message>,
        /// Data collected from down_out (to app)
        app_out_data: Vec<Option<Bytes>>,
    }

    impl TestHarness {
        fn new() -> Self {
            let now = Instant::now();
            let mut h = Self {
                protocol: TunnelProtocol::new(now),
                now,
                ws_out_msgs: Vec::new(),
                app_out_data: Vec::new(),
            };
            // Initial tick to register task wakers with SpScAccessor channels.
            // Without this, the wakers would be noop_waker and external writes
            // wouldn't wake the tasks.
            h.tick();
            h
        }

        fn io(&self) -> &Arc<TunnelIO> {
            self.protocol.io()
        }

        /// Drain all available output from both output channels
        fn drain_outputs(&mut self) {
            // Drain WebSocket output (up_out)
            loop {
                let mut item = None;
                let state = block_on(self.io().up_out.c_try_read(&mut item, None));
                match state {
                    SpScItemState::Busy => {
                        if let Some(msg) = item {
                            self.ws_out_msgs.push(msg);
                        }
                    }
                    _ => break,
                }
            }

            // Drain app output (down_out)
            loop {
                let mut item = None;
                let state = block_on(self.io().down_out.c_try_read(&mut item, None));
                match state {
                    SpScItemState::Busy => {
                        self.app_out_data.push(item);
                    }
                    _ => break,
                }
            }
        }

        /// Tick the protocol and drain any output
        fn tick(&mut self) -> bool {
            let result = self.protocol.tick(self.now);
            self.drain_outputs();
            result
        }

        /// Tick multiple times, draining output each time
        fn tick_n(&mut self, n: usize) -> bool {
            let mut result = true;
            for _ in 0..n {
                result = self.tick();
                if !result {
                    break;
                }
            }
            result
        }

        /// Advance time by the given duration and tick
        fn advance_and_tick(&mut self, duration: Duration) -> bool {
            self.now += duration;
            self.tick()
        }

        /// Write data from "app" into the upload channel
        fn app_write(&mut self, data: Bytes) -> SpScItemState {
            let mut item = Some(data);
            let result = block_on(self.io().up_in.p_try_write(&mut item, None));
            // Tick to process the write
            self.tick();
            result
        }
        fn app_write_eof(&mut self) -> SpScItemState {
            let mut item: Option<Bytes> = None;
            let result = block_on(self.io().up_in.p_try_write(&mut item, None));
            // Tick to process the write
            self.tick();
            result
        }

        /// Close the app's upload channel (simulate app EOF)
        fn app_close_upload(&mut self) {
            self.io().up_in.close();
            self.tick();
        }

        /// Close the app's download channel (simulate app closed for reading)
        fn app_close_download(&mut self) {
            self.io().down_out.close();
            self.tick();
        }

        /// Write a WebSocket message into the download channel
        fn ws_write(&mut self, msg: Message) -> SpScItemState {
            let mut item = Some(msg);
            let result = block_on(self.io().down_in.p_try_write(&mut item, None));
            // Tick to process the write
            self.tick();
            result
        }

        /// Close the WebSocket input channel
        fn ws_close_input(&mut self) {
            self.io().down_in.close();
            self.tick();
        }

        /// Close the WebSocket output channel
        fn ws_close_output(&mut self) {
            self.io().up_out.close();
            self.tick();
        }

        /// Get collected WebSocket output messages
        fn take_ws_msgs(&mut self) -> Vec<Message> {
            std::mem::take(&mut self.ws_out_msgs)
        }

        /// Get collected app output data
        fn take_app_data(&mut self) -> Vec<Option<Bytes>> {
            std::mem::take(&mut self.app_out_data)
        }

        /// Run until protocol completes or max iterations
        fn run_to_completion(&mut self, max_iters: usize) -> bool {
            for _ in 0..max_iters {
                if !self.tick() {
                    return true; // Completed
                }
            }
            false // Did not complete
        }
    }

    /// Block on a future using a no-op waker (for testing SpScItem operations).
    fn block_on<F: Future>(fut: F) -> F::Output {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut fut = std::pin::pin!(fut);
        loop {
            match fut.as_mut().poll(&mut cx) {
                Poll::Ready(val) => return val,
                Poll::Pending => {}
            }
        }
    }

    /// Create a no-op waker for testing
    fn noop_waker() -> Waker {
        const VTABLE: RawWakerVTable = RawWakerVTable::new(
            |_| RawWaker::new(std::ptr::null(), &VTABLE),
            |_| {},
            |_| {},
            |_| {},
        );
        unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) }
    }

    // ========================================================================
    // BASIC DATA TRANSFER TESTS
    // ========================================================================

    /// Test basic upload: app sends data, it appears on WebSocket
    #[test]
    fn test_upload_single_message() {
        let mut h = TestHarness::new();

        // App writes data - don't use c_get here as it would overwrite the task's waker!
        let data = Bytes::from_static(b"hello");
        h.app_write(data.clone());

        // Check WebSocket received the message
        let msgs = h.take_ws_msgs();
        assert_eq!(msgs.len(), 1);
        match &msgs[0] {
            Message::Binary(b) => assert_eq!(b, &data),
            _ => panic!("Expected binary message, got {:?}", msgs[0]),
        }
    }

    /// Test basic download: WebSocket sends data, it appears on app
    #[test]
    fn test_download_single_message() {
        let mut h = TestHarness::new();

        // WebSocket writes data
        let data = Bytes::from_static(b"world");
        h.ws_write(Message::Binary(data.clone()));

        // Check app received the data
        let app_data = h.take_app_data();
        assert_eq!(app_data.len(), 1);
        assert_eq!(app_data[0], Some(data));
    }

    /// Test multiple messages in both directions
    #[test]
    fn test_bidirectional_transfer() {
        let mut h = TestHarness::new();

        // Send 3 messages in each direction
        for i in 0..3 {
            let up_data = Bytes::from(format!("up{}", i));
            let down_data = Bytes::from(format!("down{}", i));

            // App writes
            h.app_write(up_data.clone());

            // WebSocket writes
            h.ws_write(Message::Binary(down_data.clone()));

            // Check WebSocket output
            let ws_msgs = h.take_ws_msgs();
            assert!(
                ws_msgs
                    .iter()
                    .any(|m| matches!(m, Message::Binary(b) if *b == up_data)),
                "Expected up_data in ws_msgs"
            );

            // Check app output
            let app_data = h.take_app_data();
            assert!(
                app_data.iter().any(|d| *d == Some(down_data.clone())),
                "Expected down_data in app_data"
            );
        }
    }

    // ========================================================================
    // EOF AND SHUTDOWN TESTS
    // ========================================================================

    /// Test clean shutdown: app closes upload, WebSocket receives EOF
    #[test]
    fn test_app_eof_sends_ws_eof() {
        let mut h = TestHarness::new();

        // App closes its upload
        h.app_close_upload();

        // WebSocket should receive an empty binary (EOF)
        let msgs = h.take_ws_msgs();
        assert!(
            msgs.iter()
                .any(|m| matches!(m, Message::Binary(b) if b.is_empty())),
            "Expected empty binary EOF message, got {:?}",
            msgs
        );
    }

    /// Test clean shutdown: WebSocket sends EOF (empty binary), app receives None
    #[test]
    fn test_ws_eof_forwards_to_app() {
        let mut h = TestHarness::new();

        // WebSocket sends EOF
        h.ws_write(Message::Binary(Bytes::new()));

        // App should receive None (EOF signal)
        let app_data = h.take_app_data();
        assert!(
            app_data.iter().any(|d| d.is_none()),
            "Expected None (EOF) in app_data, got {:?}",
            app_data
        );
    }

    /// Test DROP message from server triggers EOF
    #[test]
    fn test_drop_message_triggers_eof() {
        let mut h = TestHarness::new();

        // Server sends DROP
        h.ws_write(Message::Text("DROP: connection closed by remote".into()));

        // Tick a few more times to let it settle
        h.tick_n(5);

        // App should receive EOF (None)
        let app_data = h.take_app_data();
        // DROP causes EOF which means None is written to down_out
        assert!(
            app_data.iter().any(|d| d.is_none()),
            "Expected None (EOF) after DROP message, got {:?}",
            app_data
        );
    }

    /// Test full clean shutdown sequence
    #[test]
    fn test_full_clean_shutdown() {
        let mut h = TestHarness::new();

        // 1. App closes upload
        h.app_close_upload();

        // 2. Check EOF was sent to WebSocket
        let ws_msgs = h.take_ws_msgs();
        assert!(
            ws_msgs
                .iter()
                .any(|m| matches!(m, Message::Binary(b) if b.is_empty())),
            "Expected EOF message"
        );

        // 3. WebSocket sends EOF back
        h.ws_write(Message::Binary(Bytes::new()));

        // 4. Run to completion
        assert!(h.run_to_completion(20), "Protocol should have completed");
    }

    // ========================================================================
    // ERROR HANDLING TESTS
    // ========================================================================

    /// Test CONNECT message after connection is established (should abort)
    #[test]
    fn test_unexpected_connect_aborts() {
        let mut h = TestHarness::new();

        // Send unexpected CONNECT
        h.ws_write(Message::Text("CONNECT:foo".into()));

        // The protocol should eventually terminate (download task aborts)
        assert!(
            h.run_to_completion(20),
            "Protocol should terminate after unexpected CONNECT"
        );
    }

    /// Test WebSocket close frame causes abort
    #[test]
    fn test_ws_close_frame_aborts() {
        let mut h = TestHarness::new();

        // Send close frame
        h.ws_write(Message::Close(None));

        // Should terminate
        assert!(
            h.run_to_completion(20),
            "Protocol should terminate after close frame"
        );
    }

    /// Test WebSocket input channel closing causes abort
    #[test]
    fn test_ws_input_close_aborts_download() {
        let mut h = TestHarness::new();

        // Close WebSocket input
        h.ws_close_input();

        // Should terminate eventually
        assert!(
            h.run_to_completion(30),
            "Protocol should terminate after ws_input close"
        );
    }

    /// Test WebSocket output channel closing aborts upload
    #[test]
    fn test_ws_output_close_aborts_upload() {
        let mut h = TestHarness::new();

        // App writes some data
        h.app_write(Bytes::from_static(b"test"));

        // Close WebSocket output before it can be fully processed
        h.ws_close_output();

        // Tick to let protocol react
        h.tick_n(10);

        // Protocol should terminate
        assert!(
            h.run_to_completion(30),
            "Protocol should terminate after ws_output close"
        );
    }

    // ========================================================================
    // DISCARDING MODE TESTS
    // ========================================================================

    /// Test download enters discarding mode when app closes down_out
    #[test]
    fn test_download_discarding_mode() {
        let mut h = TestHarness::new();

        // Send some data from WebSocket
        h.ws_write(Message::Binary(Bytes::from_static(b"data1")));

        // App reads it (drain outputs already does this)
        let app_data = h.take_app_data();
        assert!(app_data
            .iter()
            .any(|d| *d == Some(Bytes::from_static(b"data1"))));

        // App closes its read side
        h.app_close_download();

        // WebSocket sends more data (should be discarded)
        h.ws_write(Message::Binary(Bytes::from_static(b"data2")));

        // Send EOF from WebSocket (download process finished)
        h.ws_write(Message::Binary(Bytes::new()));

        h.app_write_eof();

        // Should eventually complete
        assert!(
            h.run_to_completion(30),
            "Protocol should complete in discarding mode"
        );
    }

    // ========================================================================
    // TIMEOUT TESTS
    // ========================================================================

    /// Test that read timeout triggers after one side completes
    #[test]
    fn test_shutdown_read_timeout() {
        let mut h = TestHarness::new();

        // App closes upload (sends EOF to WebSocket)
        h.app_close_upload();

        // Verify EOF was sent
        let ws_msgs = h.take_ws_msgs();
        assert!(ws_msgs
            .iter()
            .any(|m| matches!(m, Message::Binary(b) if b.is_empty())));

        // Now WebSocket should be sending data to app, but we don't send EOF back.
        // The upload task has finished, so download task should have started a timeout.

        // Advance time past the shutdown timeout
        for _ in 0..70 {
            h.advance_and_tick(Duration::from_secs(1));
        }

        // Protocol should eventually terminate due to timeout
        assert!(
            h.run_to_completion(20),
            "Protocol should terminate due to timeout"
        );
    }

    /// Test that send timeout causes abort
    #[test]
    fn test_send_timeout() {
        let mut h = TestHarness::new();

        // Write data but don't drain outputs (simulate slow consumer)
        {
            let mut item = Some(Bytes::from_static(b"test1"));
            block_on(h.io().up_in.p_try_write(&mut item, None));
        }
        // Don't call tick() which would drain outputs

        // Manually tick without draining
        h.protocol.tick(h.now);

        // Write more data
        {
            let mut item = Some(Bytes::from_static(b"test2"));
            block_on(h.io().up_in.p_try_write(&mut item, None));
        }

        // Advance time past the send timeout without consuming
        for _ in 0..70 {
            h.now += Duration::from_secs(1);
            h.protocol.tick(h.now);
        }

        // Now drain and check protocol terminates
        h.drain_outputs();
        assert!(
            h.run_to_completion(20),
            "Protocol should fail due to send timeout"
        );
    }

    // ========================================================================
    // EDGE CASE TESTS
    // ========================================================================

    /// Test empty data from app is ignored (not sent as EOF)
    #[test]
    fn test_empty_app_data_ignored() {
        let mut h = TestHarness::new();

        // App writes empty data
        h.app_write(Bytes::new());

        // WebSocket should NOT have received an empty binary (that would be EOF)
        let ws_msgs = h.take_ws_msgs();
        assert!(
            !ws_msgs
                .iter()
                .any(|m| matches!(m, Message::Binary(b) if b.is_empty())),
            "Empty app data should be ignored, not sent as EOF"
        );

        // Now write real data
        h.app_write(Bytes::from_static(b"real"));

        // Should get the real data
        let ws_msgs = h.take_ws_msgs();
        assert!(
            ws_msgs
                .iter()
                .any(|m| matches!(m, Message::Binary(b) if b.as_ref() == b"real")),
            "Expected real data message"
        );
    }

    /// Test unknown text messages are ignored
    #[test]
    fn test_unknown_text_message_ignored() {
        let mut h = TestHarness::new();

        // Send unknown text message
        h.ws_write(Message::Text("UNKNOWN:something".into()));

        // App should not have received anything
        let app_data = h.take_app_data();
        assert!(app_data.is_empty(), "Unknown messages should be ignored");

        // Protocol should still be running
        assert!(h.tick(), "Protocol should still be running");
    }

    /// Test Ping/Pong messages are ignored
    #[test]
    fn test_ping_pong_ignored() {
        let mut h = TestHarness::new();

        // Send Ping
        h.ws_write(Message::Ping(Bytes::from_static(b"ping")));

        // App should not have received anything
        let app_data = h.take_app_data();
        assert!(app_data.is_empty(), "Ping should be ignored");

        // Send Pong
        h.ws_write(Message::Pong(Bytes::from_static(b"pong")));

        // Still nothing
        let app_data = h.take_app_data();
        assert!(app_data.is_empty(), "Pong should be ignored");
    }

    /// Test RDSD message is sent when download completes first
    #[test]
    fn test_rdsd_sent_on_download_complete() {
        let mut h = TestHarness::new();

        // WebSocket sends EOF
        h.ws_write(Message::Binary(Bytes::new()));

        // Keep ticking - upload task should notice download finished and send RDSD
        h.tick_n(10);

        // Check if RDSD was sent
        let ws_msgs = h.take_ws_msgs();
        assert!(
            ws_msgs
                .iter()
                .any(|m| matches!(m, Message::Text(t) if t.as_str() == "RDSD")),
            "RDSD message should have been sent, got {:?}",
            ws_msgs
        );
    }

    // ========================================================================
    // STRESS TESTS
    // ========================================================================

    /// Test many messages in sequence
    #[test]
    fn test_many_messages() {
        let mut h = TestHarness::new();

        for i in 0..100 {
            let data = Bytes::from(format!("message{}", i));

            // Write from app
            h.app_write(data.clone());

            // Verify WebSocket received it
            let ws_msgs = h.take_ws_msgs();
            assert!(
                ws_msgs
                    .iter()
                    .any(|m| matches!(m, Message::Binary(b) if *b == data)),
                "Expected message {} in ws_msgs",
                i
            );
        }
    }

    /// Test rapid back-and-forth
    #[test]
    fn test_rapid_bidirectional() {
        let mut h = TestHarness::new();

        for i in 0..50 {
            // App sends
            let up = Bytes::from(format!("up{}", i));
            h.app_write(up.clone());

            // WebSocket sends
            let down = Bytes::from(format!("down{}", i));
            h.ws_write(Message::Binary(down.clone()));

            // Verify both directions
            let ws_msgs = h.take_ws_msgs();
            let app_data = h.take_app_data();

            assert!(
                ws_msgs
                    .iter()
                    .any(|m| matches!(m, Message::Binary(b) if *b == up)),
                "Expected up{} in ws_msgs",
                i
            );
            assert!(
                app_data.iter().any(|d| *d == Some(down.clone())),
                "Expected down{} in app_data",
                i
            );
        }
    }

    // ========================================================================
    // COORDINATION TESTS
    // ========================================================================

    /// Test that download failure causes upload to close
    #[test]
    fn test_download_failure_closes_upload() {
        let mut h = TestHarness::new();

        // Close WebSocket input (causes download to fail)
        h.ws_close_input();

        // Protocol should terminate
        assert!(
            h.run_to_completion(30),
            "Protocol should have terminated after download failure"
        );
    }

    /// Test that upload abort is signaled to download
    #[test]
    fn test_upload_abort_signals_download() {
        let mut h = TestHarness::new();

        // Write data from app
        h.app_write(Bytes::from_static(b"test"));

        // Close WebSocket output (causes upload to fail when trying to send more)
        h.ws_close_output();

        // Write more to trigger failure
        {
            let mut item = Some(Bytes::from_static(b"more"));
            block_on(h.io().up_in.p_try_write(&mut item, None));
        }
        h.tick_n(10);

        // Download should eventually notice and terminate
        assert!(
            h.run_to_completion(30),
            "Protocol should have completed after upload abort"
        );
    }

    // ========================================================================
    // BUG REGRESSION TESTS
    // ========================================================================

    /// Regression test: down_result=Some(false) should set got_eof=true
    /// (Previously this caused infinite EOF messages)
    #[test]
    fn test_download_failure_doesnt_cause_infinite_eof() {
        let mut h = TestHarness::new();

        // Close WebSocket input to make download fail
        h.ws_close_input();

        // Run for a bit
        h.tick_n(20);

        // Count EOF messages sent to WebSocket
        let ws_msgs = h.take_ws_msgs();
        let eof_count = ws_msgs
            .iter()
            .filter(|m| matches!(m, Message::Binary(b) if b.is_empty()))
            .count();

        // Should only have at most one EOF message
        assert!(
            eof_count <= 1,
            "Should have at most 1 EOF message, got {}",
            eof_count
        );
    }

    /// Regression test: up_connected should flush up_out, not down_out
    #[test]
    fn test_upload_flushes_correct_channel() {
        let mut h = TestHarness::new();

        // Send some data through upload
        h.app_write(Bytes::from_static(b"test"));

        // Close app upload
        h.app_close_upload();

        // All messages should be on the WebSocket side
        let ws_msgs = h.take_ws_msgs();
        assert!(ws_msgs.len() >= 2, "Should have data + EOF messages");

        // Check we got the data message
        assert!(
            ws_msgs
                .iter()
                .any(|m| matches!(m, Message::Binary(b) if b.as_ref() == b"test")),
            "Should have data message"
        );

        // Check we got EOF
        assert!(
            ws_msgs
                .iter()
                .any(|m| matches!(m, Message::Binary(b) if b.is_empty())),
            "Should have EOF message"
        );
    }
}
