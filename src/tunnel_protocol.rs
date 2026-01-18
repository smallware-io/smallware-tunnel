//! Sans-IO implementation of the tunnel client WebSocket protocol.
//!
//! # Overview
//!
//! This module provides a **sans-io** (sans I/O) implementation of the tunnel protocol
//! on the client side.
//!
//! Rather than implementing the state machine as an explicitly, however (programming with
//! only gotos), this module implements the state machine as a pair of interaction async
//! functions that are polled with a noop waker.

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

/// If one direction is dead, this is the read timeout in the other direction.
pub const SHUTDOWN_READ_TIMEOUT: Duration = Duration::from_secs(60);

/// How long to wait for a send to the WebSocket to complete.
/// If exceeded, the protocol will fail the current operation.
pub const SEND_TIMEOUT: Duration = Duration::from_secs(60);

// ============================================================================
// SHARED I/O STATE
// ============================================================================

#[derive(Debug)]
pub struct TunnelIO {
    pub now_ticks: AtomicU64,
    // One accessor for each pair-wise relationship
    pub down_in: SpScMutex<SimpleSpScItemInner<Message>>,
    pub down_out: SpScMutex<SimpleSpScItemInner<Bytes>>,
    pub up_in: SpScMutex<SimpleSpScItemInner<Bytes>>,
    pub up_out: SpScMutex<SimpleSpScItemInner<Message>>,
    pub up_to_down: SpScMutex<UpToDown>,
}

impl TunnelIO {
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
    pub fn now(&self) -> Instant {
        Instant::from_ticks(self.now_ticks.load(Ordering::SeqCst))
    }
    /**
     * Update `now_ticks` and check timeouts
     */
    pub fn update_clock(&self, now: Instant) {
        let now_ticks = now.as_ticks();
        let old_ticks = self.now_ticks.fetch_max(now.as_ticks(), Ordering::SeqCst);
        if old_ticks < now_ticks {
            self.down_in.check_timeouts(now);
            self.down_out.check_timeouts(now);
            self.up_in.check_timeouts(now);
            self.up_out.check_timeouts(now);
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct UpToDown {
    up_result: Option<bool>,
    down_discarding: bool,
    down_result: Option<bool>,
}

// ============================================================================
// UPLOAD PROCESS
// ============================================================================

async fn up_connected(io_val: Arc<TunnelIO>) -> TaskEnd {
    let io = io_val.as_ref();
    let mut got_eof = false;

    // Transfer from app to websocket until the stream
    let mut read_timeout: Option<Instant> = None;
    while !got_eof {
        // This will be the message to send
        let mut to_send: Option<Message> = None;

        // When the download process completes, we start using a read timeout
        if read_timeout.is_none() {
            let (down_result, down_discarding) = io
                .up_to_down
                .p_get(|r| (r.down_result, r.down_discarding))
                .await;
            match down_result {
                Some(true) => {
                    tracing::info!("Up stream starting shutdown timer after down stream finished.");
                    read_timeout = Some(io.now() + SHUTDOWN_READ_TIMEOUT);
                }
                Some(false) => {
                    tracing::info!("Up stream closing after down stream failed.");
                    // TODO maybe make another kind of EOF message
                    to_send = Some(Message::Binary(Bytes::new()));
                }
                _ => {
                    if down_discarding {
                        tracing::info!(
                            "Up stream starting shutdown timer after down stream failed write."
                        );
                        read_timeout = Some(io.now() + SHUTDOWN_READ_TIMEOUT);
                    }
                }
            }
            if read_timeout.is_some() {
                // If we set the read timeout, we should let the server know so it can pass it along
                to_send = Some(Message::Text("RDSD".into()));
            }
        }

        if to_send.is_none() {
            // Try to read some data
            let mut data: Option<Bytes> = None;
            let rst = io.up_in.c_try_read(&mut data, read_timeout).await;
            match rst {
                // Success
                SpScItemState::Busy => {}
                // Wait
                SpScItemState::Waiting => {
                    yield_once().await;
                    continue;
                }
                // Abort (Full is impossible)
                _ => {
                    tracing::info!("Up stream closing: {}", rst);
                    got_eof = true;
                    // TODO maybe make another kind of EOF message
                    // For now we fall through and let data == None => EOF
                }
            }
            // We read something
            if read_timeout.is_some() {
                // extend timeout
                read_timeout = Some(io.now() + SHUTDOWN_READ_TIMEOUT);
            }
            // Make the upload message
            match data {
                None => {
                    // EOF
                    got_eof = true;
                    to_send = Some(Message::Binary(Bytes::new()));
                    // fall to send loop
                }
                Some(bin) => {
                    if bin.is_empty() {
                        //We don't send a WS message for no data. It would look like EOF.
                        //Ignore it
                        continue;
                    }
                    to_send = Some(Message::Binary(bin));
                }
            }
        }

        // Guaranteed we have something to send
        let send_timeout = Some(io.now() + SEND_TIMEOUT);
        loop {
            let wst = io.up_out.p_try_write(&mut to_send, send_timeout).await;
            match wst {
                SpScItemState::Busy => {
                    yield_once().await;
                }
                SpScItemState::Full => {
                    // Send complete. Yay!
                    break;
                }
                SpScItemState::Closed | SpScItemState::Waiting | SpScItemState::Failed => {
                    tracing::info!("Up stream aborting: Error sending: {}", wst);
                    return up_abort(io).await;
                }
            }
        }
        // item sent
    }
    // We got on EOF, and sent an EOF message of some kind
    io.up_in.close();
    // Flush any pending message
    let flush_timeout = Some(io.now() + SEND_TIMEOUT);
    io.up_to_down.side_check(|x: &mut UpToDown| {x.up_result = Some(true); true});
    while io.down_out.p_try_flush(flush_timeout).await == SpScItemState::Busy {
        yield_once().await;
    }
    io.up_out.close();
    TaskEnd()
}

async fn up_abort(io: &TunnelIO) -> TaskEnd {
    io.up_in.close();
    io.up_out.close();
    io.up_to_down.side_check(|x: &mut UpToDown| {x.up_result = Some(true); true});
    TaskEnd()
}

// ============================================================================
// DOWNLOAD PROCESS
// ============================================================================

async fn down_connected(io_val: Arc<TunnelIO>) -> TaskEnd {
    let io = io_val.as_ref();
    let mut got_eof = false;
    let mut down_discarding = false;
    let mut read_timeout: Option<Instant> = None;

    // Transfer from websocket to app untile we get an EOF indication - either a `DROP: ...` text
    // message, or an empty binary message
    while !got_eof {
        // When the upload process completes, we start using a read timeout
        if read_timeout.is_none() {
            let up_result = io.up_to_down.c_get(|r| r.up_result).await;
            match up_result {
                Some(true) => {
                    tracing::info!("Down stream starting shutdown timer after up stream finished.");
                    read_timeout = Some(io.now() + SHUTDOWN_READ_TIMEOUT);
                }
                Some(false) => {
                    tracing::info!("Down stream aborted after up stream.");
                    return down_abort(io).await;
                }
                _ => {}
            }
        }
        // Try to read a message
        let mut msg: Option<Message> = None;
        let rst = io.down_in.c_try_read(&mut msg, read_timeout).await;
        match rst {
            // Success
            SpScItemState::Busy => {}
            // Wait
            SpScItemState::Waiting => {
                yield_once().await;
                continue;
            }
            // Abort (Full is impossible)
            _ => {
                tracing::info!("Down stream aborted: {}", rst);
                return down_abort(io).await;
            }
        }

        // We read something
        if read_timeout.is_some() {
            // extend timeout
            read_timeout = Some(io.now() + SHUTDOWN_READ_TIMEOUT);
        }
        // Process it
        let mut to_send: Option<Bytes> = None;
        match msg {
            // Unexpected websocket close (normally, our side closes it)
            None | Some(Message::Close(_)) => {
                tracing::info!("Down stream aborted. Got WS close");
                return down_abort(io).await;
            }
            // Control message
            Some(Message::Text(txt)) => {
                let str = txt.as_str();
                if str.starts_with("DROP:") {
                    tracing::info!("Down stream done: {}", str);
                    got_eof = true;
                    // fall out to send loop
                } else if str.starts_with("CONNECT:") {
                    tracing::info!("Down stream aborted. Unexpected CONNECT");
                    return down_abort(io).await;
                } else {
                    tracing::info!("Down stream: unrecognized: {}", str);
                    continue;
                }
            }
            // Data message
            Some(Message::Binary(bytes)) => {
                to_send = match bytes.is_empty() {
                    true => {
                        got_eof = true;
                        tracing::info!("Down stream done: EOF");
                        None
                    }
                    false => Some(bytes),
                };
                // fall out to send
            }
            _ => {
                // Nothing to send
                continue;
            }
        };

        // We got something to send
        if down_discarding {
            continue;
        }

        let send_timeout = Some(io.now() + SEND_TIMEOUT);
        loop {
            let wst = io.down_out.p_try_write(&mut to_send, send_timeout).await;
            match wst {
                SpScItemState::Busy => {
                    yield_once().await;
                }
                SpScItemState::Full => {
                    // Send complete. Yay!
                    break;
                }
                SpScItemState::Closed | SpScItemState::Waiting | SpScItemState::Failed => {
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
        // send done
    }
    // We sent an EOF
    io.down_in.close();
    io.up_to_down.side_check(|x: &mut UpToDown| {
        x.down_result = Some(true);
        true
    });
    // flush any pending output
    let flush_timeout = Some(io.now() + SEND_TIMEOUT);
    while io.down_out.p_try_flush(flush_timeout).await == SpScItemState::Busy {
        yield_once().await;
    }
    io.down_out.close();
    TaskEnd()
}

async fn down_abort(io: &TunnelIO) -> TaskEnd {
    io.down_in.close();
    io.down_out.close();
    io.up_to_down.side_check(|x: &mut UpToDown| {
        x.down_result = Some(false);
        true
    });
    TaskEnd()
}

#[derive(Debug, Clone)]
pub struct TunnelProtocol {
    io: Arc<TunnelIO>,
    pm: Arc<dyn ProcMachine>,
}

impl TunnelProtocol {
    pub fn new(now: Instant) -> Self {
        let io = Arc::new(TunnelIO::new(&now));
        let pm = create_proc_machine2(up_connected(io.clone()), down_connected(io.clone()));
        Self {
            io,
            pm
        }
    }

    /**
     * Advance the clock inside the protocol and execute all pending work
     */
    pub fn tick(&self, now: Instant) -> bool {
        self.io.update_clock(now);
        self.pm.tick()
    }
}
