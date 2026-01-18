//! Components for building "procedural state machines" (ProcMachines).
//!
//! # Overview
//!
//! This module provides a lightweight executor for running multiple async tasks
//! **without a real async runtime** like Tokio. Instead, the tasks are polled
//! synchronously via a single `tick()` method, making this a "sans-IO" approach.
//!
//! The key insight is that Rust's async/await is just syntactic sugar for state
//! machines. By providing our own polling mechanism, we can use async functions
//! to express complex state machine logic while maintaining full control over
//! when and how execution happens.
//!
//! # Why "Procedural State Machines"?
//!
//! Traditional state machines are defined with explicit states and transitions
//! (essentially programming with gotos). Async functions let us write the same
//! logic procedurally - the compiler transforms our sequential code into a state
//! machine automatically.
//!
//! For example, instead of:
//! ```ignore
//! enum State { WaitingForData, ProcessingData, SendingResponse }
//! fn step(&mut self, event: Event) -> Option<Action> {
//!     match (&self.state, event) {
//!         (State::WaitingForData, Event::DataReceived(d)) => { ... }
//!         ...
//!     }
//! }
//! ```
//!
//! We can write:
//! ```ignore
//! async fn run(io: &IO) {
//!     loop {
//!         let data = io.read().await;    // "WaitingForData"
//!         process(&data);                 // "ProcessingData"
//!         io.write(response).await;       // "SendingResponse"
//!     }
//! }
//! ```
//!
//! # How It Works
//!
//! 1. **Custom Wakers**: Each task gets a waker that just sets an `AtomicBool` flag.
//!    When something calls `waker.wake()`, it sets the flag indicating the task
//!    should be polled again.
//!
//! 2. **Pointer Tagging**: To support multiple wakers per ProcMachine with a single
//!    Arc, we use pointer tagging. The low 3 bits of the Arc pointer (which are
//!    always zero due to alignment) encode which task (0-7) the waker is for.
//!
//! 3. **Round-Robin Polling**: The `tick()` method polls all tasks repeatedly until
//!    they're all idle (no wakers fired) or all done (returned `Ready`).
//!
//! 4. **Idle Detection**: We track consecutive idle polls. Once all tasks have been
//!    idle for a full round, `tick()` returns - the caller should wait for external
//!    events before calling `tick()` again.
//!
//! # Usage
//!
//! ```ignore
//! // Create async functions for your tasks
//! async fn task_a(io: Arc<MyIO>) -> TaskEnd { ... }
//! async fn task_b(io: Arc<MyIO>) -> TaskEnd { ... }
//!
//! // Combine them into a ProcMachine
//! let machine = create_proc_machine2(task_a(io.clone()), task_b(io.clone()));
//!
//! // Drive the state machine externally
//! loop {
//!     // Wait for external events (network I/O, timers, etc.)
//!     let event = wait_for_event();
//!
//!     // Feed event into shared state
//!     io.handle_event(event);
//!
//!     // Advance the state machine
//!     if !machine.tick() {
//!         break; // All tasks completed
//!     }
//! }
//! ```

use std::fmt;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, RawWaker, RawWakerVTable, Waker};

// ============================================================================
// PROCEDURAL STATE MACHINES
// ============================================================================

// ============================================================================
// MULTI-WAKER SUPPORT VIA POINTER TAGGING
// ============================================================================
//
// We need a way for each task within a ProcMachine to have its own Waker.
// The naive approach would be to allocate a separate Arc for each task's waker
// data, but that's wasteful when all tasks share the same ProcMachine.
//
// Instead, we use "pointer tagging": Since the ProcMachine structs are aligned
// to at least 8 bytes, the low 3 bits of any pointer to them are always zero.
// We can use those 3 bits to encode which task (0-7) the waker is for.
//
// When a waker is invoked:
// 1. Extract the tag (task index) from the low 3 bits
// 2. Clear the tag to get the real pointer
// 3. Call the appropriate task's wake method
//
// This is a common technique in lock-free data structures and GC implementations.
// ============================================================================

/// Trait for types that can dispatch wakes to multiple tasks (up to 8).
///
/// Types implementing this trait MUST have `#[repr(align(8))]` or greater
/// alignment to ensure the low 3 bits of their address are available for tagging.
trait MultiWake: Send + Sync {
    /// Wake the task at index `n` (0-7).
    fn wake(&self, n: u8);
}

/// Creates a Waker that targets a specific task index on a MultiWake-capable Arc.
///
/// # Arguments
///
/// * `target` - The Arc containing the ProcMachine
/// * `n` - The task index (0-7)
///
/// # Safety Requirements
///
/// The type T must have alignment of at least 8 bytes (use `#[repr(align(8))]`).
fn get_multi_waker<T: MultiWake + 'static>(target: &Arc<T>, n: u8) -> Waker {
    // Step 1: Convert Arc to raw pointer.
    // This increments the reference count (via clone) so the Arc stays alive.
    let ptr = Arc::into_raw(target.clone()) as *const ();

    // Step 2: Tag the pointer using the bottom 3 bits.
    // Masking n with 0x7 ensures we only use 3 bits (indices 0-7).
    // This works because the pointer is 8-byte aligned, so bits 0-2 are always 0.
    let tagged_ptr = ((ptr as usize) | (n as usize & 0x7)) as *const ();

    // Step 3: Construct the Waker using our custom vtable.
    // The vtable functions know how to unpack the tag and dispatch to the right task.
    unsafe { Waker::from_raw(RawWaker::new(tagged_ptr, multi_waker_vtable::<T>())) }
}

// --- Pointer Unpacking Logic ---

/// Extract the real pointer and task index from a tagged pointer.
///
/// Returns (real_pointer, task_index).
fn unpack_multi_waker<T>(ptr: *const ()) -> (*const T, u8) {
    let addr = ptr as usize;
    let tag = (addr & 0x7) as u8;        // Extract low 3 bits as task index
    let real_ptr = (addr & !0x7) as *const T;  // Clear low 3 bits to get real address
    (real_ptr, tag)
}

// --- Generic VTable Generator ---

/// Returns the vtable for wakers targeting type T.
///
/// The vtable defines how to clone, wake, and drop the waker.
fn multi_waker_vtable<T: MultiWake + 'static>() -> &'static RawWakerVTable {
    &RawWakerVTable::new(
        multi_waker_clone_raw::<T>,      // clone
        multi_wake_raw::<T>,             // wake (consumes waker)
        multi_wake_by_ref_raw::<T>,      // wake_by_ref (doesn't consume)
        multi_waker_drop_raw::<T>,       // drop
    )
}

// --- Waker VTable Implementation Functions ---

/// Clone the waker: increment Arc reference count, preserve the tag.
unsafe fn multi_waker_clone_raw<T: MultiWake + 'static>(ptr: *const ()) -> RawWaker {
    let (real_ptr, _) = unpack_multi_waker::<T>(ptr);
    // Increment the Arc's reference count (don't take ownership)
    Arc::increment_strong_count(real_ptr);
    // Return a new RawWaker with the same tagged pointer
    RawWaker::new(ptr, multi_waker_vtable::<T>())
}

/// Wake and consume the waker: call wake() and decrement Arc reference count.
unsafe fn multi_wake_raw<T: MultiWake + 'static>(ptr: *const ()) {
    let (real_ptr, n) = unpack_multi_waker::<T>(ptr);
    // Reconstruct the Arc (takes ownership of one reference)
    let arc = Arc::from_raw(real_ptr);
    // Dispatch wake to the appropriate task
    arc.wake(n);
    // Arc is dropped here, decrementing the reference count
}

/// Wake without consuming the waker: call wake() but don't decrement count.
unsafe fn multi_wake_by_ref_raw<T: MultiWake + 'static>(ptr: *const ()) {
    let (real_ptr, n) = unpack_multi_waker::<T>(ptr);
    // Just borrow the target, don't take ownership
    let target = &*real_ptr;
    target.wake(n);
}

/// Drop the waker: decrement Arc reference count.
unsafe fn multi_waker_drop_raw<T: MultiWake + 'static>(ptr: *const ()) {
    let (real_ptr, _) = unpack_multi_waker::<T>(ptr);
    // Reconstruct and immediately drop the Arc to decrement reference count
    drop(Arc::from_raw(real_ptr));
}

// ============================================================================
// PUBLIC INTERFACE
// ============================================================================

/// Trait for a procedural state machine that can be advanced synchronously.
///
/// Implementations hold one or more async tasks that are polled together.
/// The `tick()` method drives all tasks forward until they're idle or complete.
pub trait ProcMachine: Send + Sync + std::fmt::Debug {
    /// Advance the state machine by polling all tasks.
    ///
    /// This method will poll tasks repeatedly in round-robin fashion until:
    /// - All tasks are idle (no wakers fired recently), or
    /// - All tasks are complete
    ///
    /// # Returns
    ///
    /// - `true`: At least one task is still active (not completed)
    /// - `false`: All tasks have completed
    ///
    /// The caller should wait for external events (I/O, timers) before calling
    /// `tick()` again when it returns `true`.
    fn tick(&self) -> bool;
}

/// Marker type returned by async tasks when they complete.
///
/// Tasks in a ProcMachine must return `TaskEnd` to signal completion.
/// This is just a unit type - the interesting work happens via side effects
/// on shared state (e.g., the IO struct).
pub struct TaskEnd();

// ============================================================================
// SINGLE TASK WRAPPER
// ============================================================================
//
// ProcMachineTask wraps a single async future and provides:
// 1. A signal flag (AtomicBool) that the waker sets when the task should be polled
// 2. Storage for the future and its waker
// 3. The tick() logic for polling the future
// ============================================================================

/// Wrapper for a single async task within a ProcMachine.
///
/// This struct holds the future to be polled, its waker, and a signal flag
/// that indicates whether the task has been woken (and should be polled again).
struct ProcMachineTask<FUT>
where
    FUT: Future<Output = TaskEnd> + Send,
{
    /// Signal flag: set to `true` by the waker, cleared on poll.
    /// If `false` when we go to poll, the task is considered "idle".
    sig: AtomicBool,

    /// The future and its waker, or None if the task has completed.
    /// Protected by a Mutex to allow safe access from multiple threads
    /// (though typically only one thread polls at a time).
    fut: Mutex<Option<(Waker, FUT)>>,
}

impl<FUT> ProcMachineTask<FUT>
where
    FUT: Future<Output = TaskEnd> + Send,
{
    /// Creates a new task wrapper (uninitialized - call `init()` to set the future).
    pub fn new() -> Self {
        ProcMachineTask {
            sig: AtomicBool::new(false),
            fut: Mutex::new(None),
        }
    }

    /// Poll this task and update the idle/done counters.
    ///
    /// # Arguments
    ///
    /// * `idle_and_done_count` - Tuple of (consecutive_idle_count, consecutive_done_count)
    ///
    /// # Counter Logic
    ///
    /// - If the task was NOT signaled (idle): increment idle count, reset done count
    /// - If the task was polled and returned Pending: reset both counts (made progress)
    /// - If the task was polled and returned Ready: remove it, increment both counts
    /// - If the task was already done (None): increment both counts
    ///
    /// The outer `tick()` loop uses these counters to detect when all tasks are
    /// idle (idle_count >= num_tasks) or all done (done_count >= num_tasks).
    pub fn tick(&self, idle_and_done_count: &mut (u8, u8)) {
        // Check and clear the signal flag atomically.
        // If it was false, this task is idle (wasn't woken since last poll).
        if !self.sig.swap(false, Ordering::SeqCst) {
            // Task is idle - increment idle count, reset done count
            // (can't be "done" if we're counting idle)
            *idle_and_done_count = (idle_and_done_count.0 + 1, 0);
        }

        let mut guard = self.fut.lock().unwrap();
        if let Some((w, f)) = guard.as_mut() {
            // Task exists and hasn't completed yet - poll it.
            // SAFETY: We never move the future after init(), so Pin is safe.
            let pinned = unsafe { std::pin::Pin::new_unchecked(f) };
            let mut cx = Context::from_waker(&w);

            if pinned.poll(&mut cx).is_ready() {
                // Task completed! Remove it from storage.
                *guard = None;
            };

            // We polled the task, so reset both counters (we made progress).
            *idle_and_done_count = (0, 0)
        } else {
            // Task has already completed (fut is None).
            // Increment both idle and done counts.
            *idle_and_done_count = (idle_and_done_count.0 + 1, idle_and_done_count.1 + 1);
        }
    }

    /// Initialize this task with a waker and future.
    ///
    /// Called once during ProcMachine creation.
    pub fn init(&self, w: Waker, f: FUT) {
        self.fut.lock().unwrap().replace((w, f));
    }

    /// Signal this task to be polled again.
    ///
    /// Called by the waker when something wants this task to run.
    fn wake(&self) {
        self.sig.store(true, Ordering::SeqCst);
    }
}

// ============================================================================
// PROCEDURAL STATE MACHINE IMPLEMENTATIONS
// ============================================================================
//
// Below are implementations for ProcMachine with 1-8 tasks.
// They all follow the same pattern:
//
// 1. Struct definition with #[repr(align(8))] for pointer tagging support
// 2. Debug impl (just prints the type name)
// 3. MultiWake impl that dispatches wake(n) to the appropriate task
// 4. create_proc_machineN() factory function
// 5. ProcMachine::tick() impl
//
// The tick() implementation:
// - Uses a (idle_count, done_count) tuple to track progress
// - Loops, polling each task in sequence
// - After polling all tasks, if idle_count >= N, all tasks are idle → return
// - After all tasks complete, done_count >= N → return false
// - Otherwise, keep looping until idle
//
// The pattern is repetitive because Rust doesn't have variadic generics.
// A macro could reduce boilerplate, but explicit code is clearer.
// ============================================================================

// ============================================================================
// PROCEDURAL STATE MACHINE WITH 8 TASKS
// ============================================================================

/// ProcMachine holding 8 async tasks.
///
/// Uses `#[repr(align(8))]` to ensure pointer tagging works correctly.
#[repr(align(8))]
struct ProcMachine8<A, B, C, D, E, F, G, H>
where
    A: Future<Output = TaskEnd> + Send + 'static,
    B: Future<Output = TaskEnd> + Send + 'static,
    C: Future<Output = TaskEnd> + Send + 'static,
    D: Future<Output = TaskEnd> + Send + 'static,
    E: Future<Output = TaskEnd> + Send + 'static,
    F: Future<Output = TaskEnd> + Send + 'static,
    G: Future<Output = TaskEnd> + Send + 'static,
    H: Future<Output = TaskEnd> + Send + 'static,
{
    a: ProcMachineTask<A>,
    b: ProcMachineTask<B>,
    c: ProcMachineTask<C>,
    d: ProcMachineTask<D>,
    e: ProcMachineTask<E>,
    f: ProcMachineTask<F>,
    g: ProcMachineTask<G>,
    h: ProcMachineTask<H>,
}

impl<A, B, C, D, E, F, G, H> std::fmt::Debug for ProcMachine8<A, B, C, D, E, F, G, H>
where
    A: Future<Output = TaskEnd> + Send + 'static,
    B: Future<Output = TaskEnd> + Send + 'static,
    C: Future<Output = TaskEnd> + Send + 'static,
    D: Future<Output = TaskEnd> + Send + 'static,
    E: Future<Output = TaskEnd> + Send + 'static,
    F: Future<Output = TaskEnd> + Send + 'static,
    G: Future<Output = TaskEnd> + Send + 'static,
    H: Future<Output = TaskEnd> + Send + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<ProcMachine8>")
    }
}

impl<A, B, C, D, E, F, G, H> MultiWake for ProcMachine8<A, B, C, D, E, F, G, H>
where
    A: Future<Output = TaskEnd> + Send + 'static,
    B: Future<Output = TaskEnd> + Send + 'static,
    C: Future<Output = TaskEnd> + Send + 'static,
    D: Future<Output = TaskEnd> + Send + 'static,
    E: Future<Output = TaskEnd> + Send + 'static,
    F: Future<Output = TaskEnd> + Send + 'static,
    G: Future<Output = TaskEnd> + Send + 'static,
    H: Future<Output = TaskEnd> + Send + 'static,
{
    fn wake(&self, n: u8) {
        match n {
            0 => self.a.wake(),
            1 => self.b.wake(),
            2 => self.c.wake(),
            3 => self.d.wake(),
            4 => self.e.wake(),
            5 => self.f.wake(),
            6 => self.g.wake(),
            7 => self.h.wake(),
            _ => (),
        }
    }
}
/// Creates a ProcMachine with 8 async tasks.
///
/// Each task is initialized with its own waker (using pointer tagging) so that
/// when code inside the task calls `.await`, the correct task gets woken.
///
/// # Returns
///
/// An `Arc<dyn ProcMachine>` that can be driven by calling `tick()`.
pub fn create_proc_machine8<A, B, C, D, E, F, G, H>(
    a: A,
    b: B,
    c: C,
    d: D,
    e: E,
    f: F,
    g: G,
    h: H,
) -> Arc<dyn ProcMachine>
where
    A: Future<Output = TaskEnd> + Send + 'static,
    B: Future<Output = TaskEnd> + Send + 'static,
    C: Future<Output = TaskEnd> + Send + 'static,
    D: Future<Output = TaskEnd> + Send + 'static,
    E: Future<Output = TaskEnd> + Send + 'static,
    F: Future<Output = TaskEnd> + Send + 'static,
    G: Future<Output = TaskEnd> + Send + 'static,
    H: Future<Output = TaskEnd> + Send + 'static,
{
    // Create the ProcMachine with empty task slots
    let ret = Arc::new(ProcMachine8 {
        a: ProcMachineTask::new(),
        b: ProcMachineTask::new(),
        c: ProcMachineTask::new(),
        d: ProcMachineTask::new(),
        e: ProcMachineTask::new(),
        f: ProcMachineTask::new(),
        g: ProcMachineTask::new(),
        h: ProcMachineTask::new(),
    });
    // Initialize each task with its future and a tagged waker.
    // The waker's tag (0-7) identifies which task to wake.
    ret.a.init(get_multi_waker(&ret, 0), a);
    ret.b.init(get_multi_waker(&ret, 1), b);
    ret.c.init(get_multi_waker(&ret, 2), c);
    ret.d.init(get_multi_waker(&ret, 3), d);
    ret.e.init(get_multi_waker(&ret, 4), e);
    ret.f.init(get_multi_waker(&ret, 5), f);
    ret.g.init(get_multi_waker(&ret, 6), g);
    ret.h.init(get_multi_waker(&ret, 7), h);
    ret
}

impl<A, B, C, D, E, F, G, H> ProcMachine for ProcMachine8<A, B, C, D, E, F, G, H>
where
    A: Future<Output = TaskEnd> + Send + 'static,
    B: Future<Output = TaskEnd> + Send + 'static,
    C: Future<Output = TaskEnd> + Send + 'static,
    D: Future<Output = TaskEnd> + Send + 'static,
    E: Future<Output = TaskEnd> + Send + 'static,
    F: Future<Output = TaskEnd> + Send + 'static,
    G: Future<Output = TaskEnd> + Send + 'static,
    H: Future<Output = TaskEnd> + Send + 'static,
{
    fn tick(&self) -> bool {
        // counts.0 = consecutive idle task count (how many tasks in a row were idle)
        // counts.1 = consecutive done task count (how many tasks in a row were completed)
        //
        // When counts.0 reaches 8, all tasks are idle → return to let caller wait for events
        // When counts.1 reaches 8, all tasks are done → return false (machine complete)
        let mut counts: (u8, u8) = (0, 0);
        loop {
            // Poll each task. The tick() method updates counts based on task state.
            // After each task, check if we've seen 8 consecutive idle tasks.
            self.a.tick(&mut counts);
            if counts.0 >= 8 {
                break;
            }
            self.b.tick(&mut counts);
            if counts.0 >= 8 {
                break;
            }
            self.c.tick(&mut counts);
            if counts.0 >= 8 {
                break;
            }
            self.d.tick(&mut counts);
            if counts.0 >= 8 {
                break;
            }
            self.e.tick(&mut counts);
            if counts.0 >= 8 {
                break;
            }
            self.f.tick(&mut counts);
            if counts.0 >= 8 {
                break;
            }
            self.g.tick(&mut counts);
            if counts.0 >= 8 {
                break;
            }
            self.h.tick(&mut counts);
            if counts.0 >= 8 {
                break;
            }
            // Loop continues - some task made progress, keep polling
        }
        // Return true if any task is still running (done_count < 8)
        counts.1 < 8
    }
}

// ============================================================================
// PROCEDURAL STATE MACHINE WITH 7 TASKS
// ============================================================================
// Same pattern as ProcMachine8, but with 7 tasks.

#[repr(align(8))]
struct ProcMachine7<A, B, C, D, E, F, G>
where
    A: Future<Output = TaskEnd> + Send + 'static,
    B: Future<Output = TaskEnd> + Send + 'static,
    C: Future<Output = TaskEnd> + Send + 'static,
    D: Future<Output = TaskEnd> + Send + 'static,
    E: Future<Output = TaskEnd> + Send + 'static,
    F: Future<Output = TaskEnd> + Send + 'static,
    G: Future<Output = TaskEnd> + Send + 'static,
{
    a: ProcMachineTask<A>,
    b: ProcMachineTask<B>,
    c: ProcMachineTask<C>,
    d: ProcMachineTask<D>,
    e: ProcMachineTask<E>,
    f: ProcMachineTask<F>,
    g: ProcMachineTask<G>,
}

impl<A, B, C, D, E, F, G> std::fmt::Debug for ProcMachine7<A, B, C, D, E, F, G>
where
    A: Future<Output = TaskEnd> + Send + 'static,
    B: Future<Output = TaskEnd> + Send + 'static,
    C: Future<Output = TaskEnd> + Send + 'static,
    D: Future<Output = TaskEnd> + Send + 'static,
    E: Future<Output = TaskEnd> + Send + 'static,
    F: Future<Output = TaskEnd> + Send + 'static,
    G: Future<Output = TaskEnd> + Send + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<ProcMachine7>")
    }
}

impl<A, B, C, D, E, F, G> MultiWake for ProcMachine7<A, B, C, D, E, F, G>
where
    A: Future<Output = TaskEnd> + Send + 'static,
    B: Future<Output = TaskEnd> + Send + 'static,
    C: Future<Output = TaskEnd> + Send + 'static,
    D: Future<Output = TaskEnd> + Send + 'static,
    E: Future<Output = TaskEnd> + Send + 'static,
    F: Future<Output = TaskEnd> + Send + 'static,
    G: Future<Output = TaskEnd> + Send + 'static,
{
    fn wake(&self, n: u8) {
        match n {
            0 => self.a.wake(),
            1 => self.b.wake(),
            2 => self.c.wake(),
            3 => self.d.wake(),
            4 => self.e.wake(),
            5 => self.f.wake(),
            6 => self.g.wake(),
            _ => (),
        }
    }
}
pub fn create_proc_machine7<A, B, C, D, E, F, G>(
    a: A,
    b: B,
    c: C,
    d: D,
    e: E,
    f: F,
    g: G,
) -> Arc<dyn ProcMachine>
where
    A: Future<Output = TaskEnd> + Send + 'static,
    B: Future<Output = TaskEnd> + Send + 'static,
    C: Future<Output = TaskEnd> + Send + 'static,
    D: Future<Output = TaskEnd> + Send + 'static,
    E: Future<Output = TaskEnd> + Send + 'static,
    F: Future<Output = TaskEnd> + Send + 'static,
    G: Future<Output = TaskEnd> + Send + 'static,
{
    let ret = Arc::new(ProcMachine7 {
        a: ProcMachineTask::new(),
        b: ProcMachineTask::new(),
        c: ProcMachineTask::new(),
        d: ProcMachineTask::new(),
        e: ProcMachineTask::new(),
        f: ProcMachineTask::new(),
        g: ProcMachineTask::new(),
    });
    ret.a.init(get_multi_waker(&ret, 0), a);
    ret.b.init(get_multi_waker(&ret, 1), b);
    ret.c.init(get_multi_waker(&ret, 2), c);
    ret.d.init(get_multi_waker(&ret, 3), d);
    ret.e.init(get_multi_waker(&ret, 4), e);
    ret.f.init(get_multi_waker(&ret, 5), f);
    ret.g.init(get_multi_waker(&ret, 6), g);
    ret
}

impl<A, B, C, D, E, F, G> ProcMachine for ProcMachine7<A, B, C, D, E, F, G>
where
    A: Future<Output = TaskEnd> + Send + 'static,
    B: Future<Output = TaskEnd> + Send + 'static,
    C: Future<Output = TaskEnd> + Send + 'static,
    D: Future<Output = TaskEnd> + Send + 'static,
    E: Future<Output = TaskEnd> + Send + 'static,
    F: Future<Output = TaskEnd> + Send + 'static,
    G: Future<Output = TaskEnd> + Send + 'static,
{
    fn tick(&self) -> bool {
        let mut counts: (u8, u8) = (0, 0);
        loop {
            self.a.tick(&mut counts);
            if counts.0 >= 7 {
                break;
            }
            self.b.tick(&mut counts);
            if counts.0 >= 7 {
                break;
            }
            self.c.tick(&mut counts);
            if counts.0 >= 7 {
                break;
            }
            self.d.tick(&mut counts);
            if counts.0 >= 7 {
                break;
            }
            self.e.tick(&mut counts);
            if counts.0 >= 7 {
                break;
            }
            self.f.tick(&mut counts);
            if counts.0 >= 7 {
                break;
            }
            self.g.tick(&mut counts);
            if counts.0 >= 7 {
                break;
            }
        }
        counts.1 < 7
    }
}

// ============================================================================
// PROCEDURAL STATE MACHINE WITH 6 TASKS
// ============================================================================
// Same pattern as ProcMachine8, but with 6 tasks.

#[repr(align(8))]
struct ProcMachine6<A, B, C, D, E, F>
where
    A: Future<Output = TaskEnd> + Send + 'static,
    B: Future<Output = TaskEnd> + Send + 'static,
    C: Future<Output = TaskEnd> + Send + 'static,
    D: Future<Output = TaskEnd> + Send + 'static,
    E: Future<Output = TaskEnd> + Send + 'static,
    F: Future<Output = TaskEnd> + Send + 'static,
{
    a: ProcMachineTask<A>,
    b: ProcMachineTask<B>,
    c: ProcMachineTask<C>,
    d: ProcMachineTask<D>,
    e: ProcMachineTask<E>,
    f: ProcMachineTask<F>,
}

impl<A, B, C, D, E, F> std::fmt::Debug for ProcMachine6<A, B, C, D, E, F>
where
    A: Future<Output = TaskEnd> + Send + 'static,
    B: Future<Output = TaskEnd> + Send + 'static,
    C: Future<Output = TaskEnd> + Send + 'static,
    D: Future<Output = TaskEnd> + Send + 'static,
    E: Future<Output = TaskEnd> + Send + 'static,
    F: Future<Output = TaskEnd> + Send + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<ProcMachine6>")
    }
}

impl<A, B, C, D, E, F> MultiWake for ProcMachine6<A, B, C, D, E, F>
where
    A: Future<Output = TaskEnd> + Send + 'static,
    B: Future<Output = TaskEnd> + Send + 'static,
    C: Future<Output = TaskEnd> + Send + 'static,
    D: Future<Output = TaskEnd> + Send + 'static,
    E: Future<Output = TaskEnd> + Send + 'static,
    F: Future<Output = TaskEnd> + Send + 'static,
{
    fn wake(&self, n: u8) {
        match n {
            0 => self.a.wake(),
            1 => self.b.wake(),
            2 => self.c.wake(),
            3 => self.d.wake(),
            4 => self.e.wake(),
            5 => self.f.wake(),
            _ => (),
        }
    }
}
pub fn create_proc_machine6<A, B, C, D, E, F>(
    a: A,
    b: B,
    c: C,
    d: D,
    e: E,
    f: F,
) -> Arc<dyn ProcMachine>
where
    A: Future<Output = TaskEnd> + Send + 'static,
    B: Future<Output = TaskEnd> + Send + 'static,
    C: Future<Output = TaskEnd> + Send + 'static,
    D: Future<Output = TaskEnd> + Send + 'static,
    E: Future<Output = TaskEnd> + Send + 'static,
    F: Future<Output = TaskEnd> + Send + 'static,
{
    let ret = Arc::new(ProcMachine6 {
        a: ProcMachineTask::new(),
        b: ProcMachineTask::new(),
        c: ProcMachineTask::new(),
        d: ProcMachineTask::new(),
        e: ProcMachineTask::new(),
        f: ProcMachineTask::new(),
    });
    ret.a.init(get_multi_waker(&ret, 0), a);
    ret.b.init(get_multi_waker(&ret, 1), b);
    ret.c.init(get_multi_waker(&ret, 2), c);
    ret.d.init(get_multi_waker(&ret, 3), d);
    ret.e.init(get_multi_waker(&ret, 4), e);
    ret.f.init(get_multi_waker(&ret, 5), f);
    ret
}

impl<A, B, C, D, E, F> ProcMachine for ProcMachine6<A, B, C, D, E, F>
where
    A: Future<Output = TaskEnd> + Send + 'static,
    B: Future<Output = TaskEnd> + Send + 'static,
    C: Future<Output = TaskEnd> + Send + 'static,
    D: Future<Output = TaskEnd> + Send + 'static,
    E: Future<Output = TaskEnd> + Send + 'static,
    F: Future<Output = TaskEnd> + Send + 'static,
{
    fn tick(&self) -> bool {
        let mut counts: (u8, u8) = (0, 0);
        loop {
            self.a.tick(&mut counts);
            if counts.0 >= 6 {
                break;
            }
            self.b.tick(&mut counts);
            if counts.0 >= 6 {
                break;
            }
            self.c.tick(&mut counts);
            if counts.0 >= 6 {
                break;
            }
            self.d.tick(&mut counts);
            if counts.0 >= 6 {
                break;
            }
            self.e.tick(&mut counts);
            if counts.0 >= 6 {
                break;
            }
            self.f.tick(&mut counts);
            if counts.0 >= 6 {
                break;
            }
        }
        counts.1 < 6
    }
}

// ============================================================================
// PROCEDURAL STATE MACHINE WITH 5 TASKS
// ============================================================================
// Same pattern as ProcMachine8, but with 5 tasks.

#[repr(align(8))]
struct ProcMachine5<A, B, C, D, E>
where
    A: Future<Output = TaskEnd> + Send + 'static,
    B: Future<Output = TaskEnd> + Send + 'static,
    C: Future<Output = TaskEnd> + Send + 'static,
    D: Future<Output = TaskEnd> + Send + 'static,
    E: Future<Output = TaskEnd> + Send + 'static,
{
    a: ProcMachineTask<A>,
    b: ProcMachineTask<B>,
    c: ProcMachineTask<C>,
    d: ProcMachineTask<D>,
    e: ProcMachineTask<E>,
}

impl<A, B, C, D, E> std::fmt::Debug for ProcMachine5<A, B, C, D, E>
where
    A: Future<Output = TaskEnd> + Send + 'static,
    B: Future<Output = TaskEnd> + Send + 'static,
    C: Future<Output = TaskEnd> + Send + 'static,
    D: Future<Output = TaskEnd> + Send + 'static,
    E: Future<Output = TaskEnd> + Send + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<ProcMachine5>")
    }
}

impl<A, B, C, D, E> MultiWake for ProcMachine5<A, B, C, D, E>
where
    A: Future<Output = TaskEnd> + Send + 'static,
    B: Future<Output = TaskEnd> + Send + 'static,
    C: Future<Output = TaskEnd> + Send + 'static,
    D: Future<Output = TaskEnd> + Send + 'static,
    E: Future<Output = TaskEnd> + Send + 'static,
{
    fn wake(&self, n: u8) {
        match n {
            0 => self.a.wake(),
            1 => self.b.wake(),
            2 => self.c.wake(),
            3 => self.d.wake(),
            4 => self.e.wake(),
            _ => (),
        }
    }
}
pub fn create_proc_machine5<A, B, C, D, E>(a: A, b: B, c: C, d: D, e: E) -> Arc<dyn ProcMachine>
where
    A: Future<Output = TaskEnd> + Send + 'static,
    B: Future<Output = TaskEnd> + Send + 'static,
    C: Future<Output = TaskEnd> + Send + 'static,
    D: Future<Output = TaskEnd> + Send + 'static,
    E: Future<Output = TaskEnd> + Send + 'static,
{
    let ret = Arc::new(ProcMachine5 {
        a: ProcMachineTask::new(),
        b: ProcMachineTask::new(),
        c: ProcMachineTask::new(),
        d: ProcMachineTask::new(),
        e: ProcMachineTask::new(),
    });
    ret.a.init(get_multi_waker(&ret, 0), a);
    ret.b.init(get_multi_waker(&ret, 1), b);
    ret.c.init(get_multi_waker(&ret, 2), c);
    ret.d.init(get_multi_waker(&ret, 3), d);
    ret.e.init(get_multi_waker(&ret, 4), e);
    ret
}

impl<A, B, C, D, E> ProcMachine for ProcMachine5<A, B, C, D, E>
where
    A: Future<Output = TaskEnd> + Send + 'static,
    B: Future<Output = TaskEnd> + Send + 'static,
    C: Future<Output = TaskEnd> + Send + 'static,
    D: Future<Output = TaskEnd> + Send + 'static,
    E: Future<Output = TaskEnd> + Send + 'static,
{
    fn tick(&self) -> bool {
        let mut counts: (u8, u8) = (0, 0);
        loop {
            self.a.tick(&mut counts);
            if counts.0 >= 5 {
                break;
            }
            self.b.tick(&mut counts);
            if counts.0 >= 5 {
                break;
            }
            self.c.tick(&mut counts);
            if counts.0 >= 5 {
                break;
            }
            self.d.tick(&mut counts);
            if counts.0 >= 5 {
                break;
            }
            self.e.tick(&mut counts);
            if counts.0 >= 5 {
                break;
            }
        }
        counts.1 < 5
    }
}

// ============================================================================
// PROCEDURAL STATE MACHINE WITH 4 TASKS
// ============================================================================
// Same pattern as ProcMachine8, but with 4 tasks.

#[repr(align(8))]
struct ProcMachine4<A, B, C, D>
where
    A: Future<Output = TaskEnd> + Send + 'static,
    B: Future<Output = TaskEnd> + Send + 'static,
    C: Future<Output = TaskEnd> + Send + 'static,
    D: Future<Output = TaskEnd> + Send + 'static,
{
    a: ProcMachineTask<A>,
    b: ProcMachineTask<B>,
    c: ProcMachineTask<C>,
    d: ProcMachineTask<D>,
}


impl<A, B, C, D> std::fmt::Debug for ProcMachine4<A, B, C, D>
where
    A: Future<Output = TaskEnd> + Send + 'static,
    B: Future<Output = TaskEnd> + Send + 'static,
    C: Future<Output = TaskEnd> + Send + 'static,
    D: Future<Output = TaskEnd> + Send + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<ProcMachine4>")
    }
}

impl<A, B, C, D> MultiWake for ProcMachine4<A, B, C, D>
where
    A: Future<Output = TaskEnd> + Send + 'static,
    B: Future<Output = TaskEnd> + Send + 'static,
    C: Future<Output = TaskEnd> + Send + 'static,
    D: Future<Output = TaskEnd> + Send + 'static,
{
    fn wake(&self, n: u8) {
        match n {
            0 => self.a.wake(),
            1 => self.b.wake(),
            2 => self.c.wake(),
            3 => self.d.wake(),
            _ => (),
        }
    }
}
pub fn create_proc_machine4<A, B, C, D>(a: A, b: B, c: C, d: D) -> Arc<dyn ProcMachine>
where
    A: Future<Output = TaskEnd> + Send + 'static,
    B: Future<Output = TaskEnd> + Send + 'static,
    C: Future<Output = TaskEnd> + Send + 'static,
    D: Future<Output = TaskEnd> + Send + 'static,
{
    let ret = Arc::new(ProcMachine4 {
        a: ProcMachineTask::new(),
        b: ProcMachineTask::new(),
        c: ProcMachineTask::new(),
        d: ProcMachineTask::new(),
    });
    ret.a.init(get_multi_waker(&ret, 0), a);
    ret.b.init(get_multi_waker(&ret, 1), b);
    ret.c.init(get_multi_waker(&ret, 2), c);
    ret.d.init(get_multi_waker(&ret, 3), d);
    ret
}

impl<A, B, C, D> ProcMachine for ProcMachine4<A, B, C, D>
where
    A: Future<Output = TaskEnd> + Send + 'static,
    B: Future<Output = TaskEnd> + Send + 'static,
    C: Future<Output = TaskEnd> + Send + 'static,
    D: Future<Output = TaskEnd> + Send + 'static,
{
    fn tick(&self) -> bool {
        let mut counts: (u8, u8) = (0, 0);
        loop {
            self.a.tick(&mut counts);
            if counts.0 >= 4 {
                break;
            }
            self.b.tick(&mut counts);
            if counts.0 >= 4 {
                break;
            }
            self.c.tick(&mut counts);
            if counts.0 >= 4 {
                break;
            }
            self.d.tick(&mut counts);
            if counts.0 >= 4 {
                break;
            }
        }
        counts.1 < 4
    }
}

// ============================================================================
// PROCEDURAL STATE MACHINE WITH 3 TASKS
// ============================================================================
// Same pattern as ProcMachine8, but with 3 tasks.

#[repr(align(8))]
struct ProcMachine3<A, B, C>
where
    A: Future<Output = TaskEnd> + Send + 'static,
    B: Future<Output = TaskEnd> + Send + 'static,
    C: Future<Output = TaskEnd> + Send + 'static,
{
    a: ProcMachineTask<A>,
    b: ProcMachineTask<B>,
    c: ProcMachineTask<C>,
}

impl<A, B, C> std::fmt::Debug for ProcMachine3<A, B, C>
where
    A: Future<Output = TaskEnd> + Send + 'static,
    B: Future<Output = TaskEnd> + Send + 'static,
    C: Future<Output = TaskEnd> + Send + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<ProcMachine3>")
    }
}

impl<A, B, C> MultiWake for ProcMachine3<A, B, C>
where
    A: Future<Output = TaskEnd> + Send + 'static,
    B: Future<Output = TaskEnd> + Send + 'static,
    C: Future<Output = TaskEnd> + Send + 'static,
{
    fn wake(&self, n: u8) {
        match n {
            0 => self.a.wake(),
            1 => self.b.wake(),
            2 => self.c.wake(),
            _ => (),
        }
    }
}
pub fn create_proc_machine3<A, B, C>(a: A, b: B, c: C) -> Arc<dyn ProcMachine>
where
    A: Future<Output = TaskEnd> + Send + 'static,
    B: Future<Output = TaskEnd> + Send + 'static,
    C: Future<Output = TaskEnd> + Send + 'static,
{
    let ret = Arc::new(ProcMachine3 {
        a: ProcMachineTask::new(),
        b: ProcMachineTask::new(),
        c: ProcMachineTask::new(),
    });
    ret.a.init(get_multi_waker(&ret, 0), a);
    ret.b.init(get_multi_waker(&ret, 1), b);
    ret.c.init(get_multi_waker(&ret, 2), c);
    ret
}

impl<A, B, C> ProcMachine for ProcMachine3<A, B, C>
where
    A: Future<Output = TaskEnd> + Send + 'static,
    B: Future<Output = TaskEnd> + Send + 'static,
    C: Future<Output = TaskEnd> + Send + 'static,
{
    fn tick(&self) -> bool {
        let mut counts: (u8, u8) = (0, 0);
        loop {
            self.a.tick(&mut counts);
            if counts.0 >= 3 {
                break;
            }
            self.b.tick(&mut counts);
            if counts.0 >= 3 {
                break;
            }
            self.c.tick(&mut counts);
            if counts.0 >= 3 {
                break;
            }
        }
        counts.1 < 3
    }
}

// ============================================================================
// PROCEDURAL STATE MACHINE WITH 2 TASKS
// ============================================================================
// Same pattern as ProcMachine8, but with 2 tasks.
// This is the most commonly used variant (e.g., upload + download tasks).

#[repr(align(8))]
struct ProcMachine2<A, B>
where
    A: Future<Output = TaskEnd> + Send + 'static,
    B: Future<Output = TaskEnd> + Send + 'static,
{
    a: ProcMachineTask<A>,
    b: ProcMachineTask<B>,
}

impl<A, B> std::fmt::Debug for ProcMachine2<A, B>
where
    A: Future<Output = TaskEnd> + Send + 'static,
    B: Future<Output = TaskEnd> + Send + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<ProcMachine2>")
    }
}

impl<A, B> MultiWake for ProcMachine2<A, B>
where
    A: Future<Output = TaskEnd> + Send + 'static,
    B: Future<Output = TaskEnd> + Send + 'static,
{
    fn wake(&self, n: u8) {
        match n {
            0 => self.a.wake(),
            1 => self.b.wake(),
            _ => (),
        }
    }
}
/// Creates a ProcMachine with 2 async tasks.
///
/// This is the most commonly used factory. For example, `TunnelProtocol` uses
/// this to run the upload and download tasks concurrently.
///
/// # Example
///
/// ```ignore
/// let machine = create_proc_machine2(
///     upload_task(io.clone()),
///     download_task(io.clone()),
/// );
///
/// while machine.tick() {
///     // Wait for I/O events, then tick again
/// }
/// ```
pub fn create_proc_machine2<A, B>(a: A, b: B) -> Arc<dyn ProcMachine>
where
    A: Future<Output = TaskEnd> + Send + 'static,
    B: Future<Output = TaskEnd> + Send + 'static,
{
    let ret = Arc::new(ProcMachine2 {
        a: ProcMachineTask::new(),
        b: ProcMachineTask::new(),
    });
    ret.a.init(get_multi_waker(&ret, 0), a);
    ret.b.init(get_multi_waker(&ret, 1), b);
    ret
}

impl<A, B> ProcMachine for ProcMachine2<A, B>
where
    A: Future<Output = TaskEnd> + Send + 'static,
    B: Future<Output = TaskEnd> + Send + 'static,
{
    fn tick(&self) -> bool {
        let mut counts: (u8, u8) = (0, 0);
        loop {
            self.a.tick(&mut counts);
            if counts.0 >= 2 {
                break;
            }
            self.b.tick(&mut counts);
            if counts.0 >= 2 {
                break;
            }
        }
        counts.1 < 2
    }
}

// ============================================================================
// PROCEDURAL STATE MACHINE WITH 1 TASK
// ============================================================================
// Same pattern as ProcMachine8, but with just 1 task.
// Useful when a single complex async state machine is sufficient.

#[repr(align(8))]
struct ProcMachine1<A>
where
    A: Future<Output = TaskEnd> + Send + 'static,
{
    a: ProcMachineTask<A>,
}


impl<A> std::fmt::Debug for ProcMachine1<A>
where
    A: Future<Output = TaskEnd> + Send + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<ProcMachine1>")
    }
}

impl<A> MultiWake for ProcMachine1<A>
where
    A: Future<Output = TaskEnd> + Send + 'static,
{
    fn wake(&self, n: u8) {
        match n {
            0 => self.a.wake(),
            _ => (),
        }
    }
}
pub fn create_proc_machine1<A>(a: A) -> Arc<dyn ProcMachine>
where
    A: Future<Output = TaskEnd> + Send + 'static,
{
    let ret = Arc::new(ProcMachine1 {
        a: ProcMachineTask::new(),
    });
    ret.a.init(get_multi_waker(&ret, 0), a);
    ret
}

impl<A> ProcMachine for ProcMachine1<A>
where
    A: Future<Output = TaskEnd> + Send + 'static,
{
    fn tick(&self) -> bool {
        let mut counts: (u8, u8) = (0, 0);
        loop {
            self.a.tick(&mut counts);
            if counts.0 >= 1 {
                break;
            }
        }
        counts.1 < 1
    }
}
