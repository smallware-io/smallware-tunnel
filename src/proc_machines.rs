//! Procedural state machines driven by cooperative async tasks.
//!
//! A **ProcMachine** bundles one or more `async fn` tasks together with a
//! shared IO struct, runs them cooperatively under a single mutex, and
//! exposes the IO struct to external code through a guard-based API.
//!
//! # Motivation
//!
//! Traditional sans-IO protocol implementations are written as explicit state
//! machines: an enum of states, a `poll`-style driver, and manual
//! save/restore of intermediate variables across yield points. This is
//! correct but painful to write and read.
//!
//! ProcMachines let you write the same logic as straight-line `async` code
//! (loops, branches, `.await`) while retaining the benefits of sans-IO:
//!
//! - **No runtime dependency.** Tasks are polled synchronously; there is no
//!   executor, no spawning, no `Send + 'static` requirement beyond what the
//!   task closures themselves need.
//! - **Deterministic scheduling.** All tasks run under one mutex, so there
//!   are no data races and the polling order is fully controlled.
//! - **External clock.** Timeouts use an [`AlarmClock`](crate::alarms::AlarmClock)
//!   advanced by the caller, making the protocol testable without real time.
//!
//! # Architecture
//!
//! ```text
//!  External code               ProcMachine (behind Arc)
//! ┌────────────┐      lock()  ┌──────────────────────────────┐
//! │            │─────────────►│  Mutex<ProcMachineInner>     │
//! │            │  IoGuard     │  ┌────────────────────────┐  │
//! │ reads/writes◄────────────►│  │ IO struct              │  │
//! │ to IO      │  Deref       │  ├────────────────────────┤  │
//! │            │              │  │ Future 1 (task A)      │  │
//! │            │◄─────────────│  │ Future 2 (task B)      │  │
//! │            │  drop guard  │  │ ...                    │  │
//! │            │  → tick()    │  │ alive_mask: u32        │  │
//! └────────────┘              │  └────────────────────────┘  │
//!                             │  wake_mask: AtomicU32        │
//!                             └──────────────────────────────┘
//! ```
//!
//! 1. External code calls [`LockableIo::lock`] to obtain an [`IoGuard`].
//! 2. Through the guard it reads/writes the IO struct (e.g. feeding data
//!    into an [`IoExchange`](crate::io_exchange::IoExchange)).
//! 3. When the guard is dropped, [`ProcMachineImpl::unsafe_unlock_io`] calls
//!    [`tick`](ProcMachineInner::tick), which polls every task whose waker
//!    has fired since the last tick.
//! 4. Tasks run until they all return `Pending`, then control returns to the
//!    caller.
//!
//! # Wake mechanism
//!
//! Each task gets its own [`Waker`] via the [multi-waker system](#multi-waker-support).
//! When a task registers a waker with an IO primitive (e.g. `IoExchange`)
//! and that primitive later calls `wake()`, the corresponding bit is set in
//! the shared `wake_mask: AtomicU32`. The next [`tick`](ProcMachineInner::tick)
//! intersects `wake_mask` with `alive_mask` to determine which tasks to poll.
//!
//! # Building a ProcMachine
//!
//! Use the builder pattern starting from [`PROC_MACHINE_JOBS_BASE`]:
//!
//! ```rust,ignore
//! let proto = PROC_MACHINE_JOBS_BASE
//!     .with(task_a)   // async fn task_a(io: Pin<&'static MyIO>) -> TaskEnd
//!     .with(task_b)
//!     .build(MyIO::new());
//! ```
//!
//! Each `.with()` appends a task, building a compile-time linked list of
//! futures ([`ProcMachineFuturesExtension`] chain). The `.build()` call
//! allocates the `Arc<ProcMachineImpl>`, pins the IO, initialises the
//! futures, and performs the first tick.

use bytemuck::{allocation::TransparentWrapperAlloc, TransparentWrapper};
use core::fmt::Debug;
use parking_lot::{lock_api::RawMutex as _, Mutex};
use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::task::{Context, Wake, Waker};

// ============================================================================
// PUBLIC INTERFACE
// ============================================================================

/// A procedural state machine that advances synchronously.
///
/// External code interacts with the machine by locking the IO struct (via
/// [`LockableIo::lock`]) and reading/writing its fields. Internal tasks
/// advance automatically when the lock is released.
///
/// Implemented by [`ProcMachineImpl`]; callers work with
/// `Arc<dyn ProcMachine<IO>>` (type-aliased as e.g. `TunnelProtocol`).
pub trait ProcMachine<IO: Send + Debug>: Send + Sync + core::fmt::Debug {
    /// Returns `true` when every internal task has completed.
    ///
    /// Also ticks the machine, so any pending wakes are processed first.
    fn is_done(&self) -> bool;

    /// Acquires the inner mutex and returns a raw pointer to the IO struct.
    ///
    /// # Safety
    ///
    /// - `&self` must be pinned by an `Arc` (guaranteed by the
    ///   [`ProcMachineImpl`] constructor).
    /// - The caller **must** call [`unsafe_unlock_io`](ProcMachine::unsafe_unlock_io)
    ///   exactly once after the critical section, and must not use the
    ///   returned pointer after that call.
    unsafe fn unsafe_lock_io(&self) -> *mut IO;

    /// Ticks the machine and releases the inner mutex.
    ///
    /// # Safety
    ///
    /// - Must be called exactly once after a corresponding
    ///   [`unsafe_lock_io`](ProcMachine::unsafe_lock_io).
    /// - No references derived from the pointer returned by `unsafe_lock_io`
    ///   may be used after this call.
    unsafe fn unsafe_unlock_io(&self);
}

/// Extension trait on `Arc<dyn ProcMachine<IO>>` providing safe lock access.
pub trait LockableIo<IO: Send + Debug> {
    /// Locks the machine and returns an [`IoGuard`] that derefs to the IO
    /// struct. When the guard is dropped the machine ticks.
    fn lock(&self) -> IoGuard<IO>;
}

impl<IO> LockableIo<IO> for Arc<dyn ProcMachine<IO>>
where
    IO: Send + Debug,
{
    #[inline(always)]
    fn lock(&self) -> IoGuard<IO> {
        IoGuard::new(self.clone())
    }
}

/// RAII guard providing `&IO` / `&mut IO` access to a locked [`ProcMachine`].
///
/// Created by [`LockableIo::lock`]. Dropping the guard calls
/// [`unsafe_unlock_io`](ProcMachine::unsafe_unlock_io), which ticks the
/// machine (polling any tasks whose wakers fired during the critical
/// section).
///
/// The guard is `!Send` because `ptr` is a raw pointer, which is correct —
/// a mutex guard should not be sent to another thread.
pub struct IoGuard<IO: Send + Debug> {
    holder: Arc<dyn ProcMachine<IO>>,
    ptr: *mut IO,
}

impl<IO> IoGuard<IO>
where
    IO: Send + Debug,
{
    /// Acquires the lock and creates a new guard.
    pub fn new(holder: Arc<dyn ProcMachine<IO>>) -> Self {
        let ptr = unsafe { holder.unsafe_lock_io() };
        Self { holder, ptr }
    }
}

impl<IO> Drop for IoGuard<IO>
where
    IO: Send + Debug,
{
    /// Ticks the machine and releases the lock.
    #[inline]
    fn drop(&mut self) {
        unsafe {
            self.holder.unsafe_unlock_io();
        }
    }
}

impl<IO> Deref for IoGuard<IO>
where
    IO: Send + Debug,
{
    type Target = IO;
    #[inline]
    fn deref(&self) -> &IO {
        unsafe { &*self.ptr }
    }
}

impl<IO> DerefMut for IoGuard<IO>
where
    IO: Send + Debug,
{
    #[inline]
    fn deref_mut(&mut self) -> &mut IO {
        unsafe { &mut *self.ptr }
    }
}

// ============================================================================
// TASK AND FUTURES MACHINERY
// ============================================================================
//
// Tasks are `async fn(Pin<&'static IO>) -> TaskEnd`. They are stored as
// type-erased futures inside a compile-time linked list built from
// ProcMachineFuturesBase (empty) and ProcMachineFuturesExtension (one task
// + the rest).
//
// The linked list is *not* a runtime linked list — it is a nested struct
// whose shape is fully known at compile time. This means polling the list
// is a static chain of monomorphised function calls with no indirection.
//
// Each extension layer has a DEPTH constant (1-based) that doubles as:
//   - The bit index in alive_mask / wake_mask (1 << DEPTH)
//   - The task index passed to get_multi_waker for Waker creation
//
// Depth 0 is the base (no task). Real tasks start at depth 1.
// ============================================================================

/// Marker type returned by async tasks when they complete.
///
/// The actual result of a task is communicated via side effects on the
/// shared IO struct (e.g. setting a field in [`UpToDown`](crate::tunnel_protocol::UpToDown)).
pub struct TaskEnd();

/// Trait for the compile-time linked list of futures inside a ProcMachine.
///
/// Each node knows how many tasks are in the chain ([`DEPTH`](Self::DEPTH)),
/// can poll them selectively via a bitmask, and returns an updated bitmask
/// indicating which tasks are still alive.
pub trait ProcMachineFutures: Send {
    /// Number of tasks in this chain (0 for the base, N for N tasks).
    const DEPTH: u8;

    /// Polls every task whose bit is set in `depth_mask`.
    ///
    /// Returns a bitmask with a bit set for every task that is still alive
    /// (i.e. has a future and has not yet returned `Ready`).
    fn poll<T: MultiWake + 'static>(self: &mut Self, waker: &Arc<T>, depth_mask: u32) -> u32;

    /// Creates an uninitialised instance (futures are `None`).
    fn new() -> Self;
}

/// Base case: an empty chain with no tasks.
pub struct ProcMachineFuturesBase();

impl ProcMachineFutures for ProcMachineFuturesBase {
    const DEPTH: u8 = 0;

    #[inline(always)]
    fn poll<T: MultiWake + 'static>(self: &mut Self, _waker: &Arc<T>, _depth_mask: u32) -> u32 {
        0 // no tasks → nothing alive
    }

    #[inline(always)]
    fn new() -> Self {
        ProcMachineFuturesBase()
    }
}

/// One task appended to a `PREV` chain.
///
/// The future is `Option<FUT>` — `Some` while the task is alive, `None`
/// after it completes.
pub struct ProcMachineFuturesExtension<
    PREV: ProcMachineFutures,
    FUT: Future<Output = TaskEnd> + Send + 'static,
> {
    prev: PREV,
    fut: Option<FUT>,
}

impl<PREV: ProcMachineFutures, FUT: Future<Output = TaskEnd> + Send + 'static> ProcMachineFutures
    for ProcMachineFuturesExtension<PREV, FUT>
{
    const DEPTH: u8 = PREV::DEPTH + 1;

    #[inline(always)]
    fn new() -> Self {
        Self {
            prev: PREV::new(),
            fut: None,
        }
    }

    #[inline(always)]
    fn poll<T: MultiWake + 'static>(self: &mut Self, waker: &Arc<T>, depth_mask: u32) -> u32 {
        // Poll all tasks in the chain before this one.
        let parent_result = self.prev.poll(waker, depth_mask);

        match &mut self.fut {
            // Task already completed — propagate parent result unchanged.
            None => parent_result,
            Some(fut) => {
                if (depth_mask & (1 << Self::DEPTH)) == 0 {
                    // This task is idle (its waker hasn't fired) — skip
                    // polling, but keep its bit in the alive mask so future
                    // wakes can reach it.
                    return parent_result | (1 << Self::DEPTH);
                }

                // Create a Waker for this task's depth index. Uses the
                // runtime match in get_multi_waker because Rust doesn't
                // permit generic `Self` in anonymous const expressions.
                // Since Self::DEPTH is a compile-time constant, LLVM
                // constant-folds the match after monomorphisation.
                let waker = get_multi_waker(waker, Self::DEPTH);

                // SAFETY: The future lives inside ProcMachineInner, which
                // is inside a Mutex inside an Arc. It is never moved once
                // initialised, so the Pin invariant holds.
                let p = unsafe { std::pin::Pin::new_unchecked(fut) };
                let mut cx = Context::from_waker(&waker);

                if p.poll(&mut cx).is_ready() {
                    // Task completed — drop the future. Its bit is absent
                    // from the returned mask, so it won't be polled again.
                    self.fut = None;
                    parent_result
                } else {
                    // Task still pending — include parent_result so sibling
                    // tasks stay in alive_mask, and set this task's own bit
                    // (matching the waker index from get_multi_waker).
                    parent_result | (1 << Self::DEPTH)
                }
            }
        }
    }
}

// ============================================================================
// JOB BUILDER
// ============================================================================
//
// ProcMachineJobs is the *builder* side: it collects task constructor
// functions and, on .build(), allocates the ProcMachineImpl, creates the
// futures, and performs the initial tick.
//
// Like ProcMachineFutures, it is a compile-time linked list
// (ProcMachineJobsBase + ProcMachineJobsExtension).
// ============================================================================

/// Builder trait for assembling tasks into a [`ProcMachine`].
///
/// Start from [`PROC_MACHINE_JOBS_BASE`] and chain `.with(task_fn)` calls
/// to add tasks, then call `.build(io)` to produce the final
/// `Arc<dyn ProcMachine<IO>>`.
pub trait ProcMachineJobs<IO: Send + Debug + 'static> {
    /// Number of tasks registered so far.
    const DEPTH: u8;

    /// The corresponding futures storage type.
    type FUTURES: ProcMachineFutures;

    /// Initialises the futures by calling each task's constructor with the
    /// pinned IO reference.
    fn init(&self, io: Pin<&'static IO>, futures: &mut Self::FUTURES);

    /// Appends a new task and returns an extended builder.
    fn with<FUT: Future<Output = TaskEnd> + Send + 'static>(
        self: Self,
        proc: fn(Pin<&'static IO>) -> FUT,
    ) -> impl ProcMachineJobs<IO>;

    /// Consumes the builder, allocates the ProcMachine, and returns it.
    fn build(self, io: IO) -> Arc<dyn ProcMachine<IO>>
    where
        Self: Sized + 'static,
    {
        ProcMachineImpl::new(io, self)
    }
}

/// Empty builder — no tasks registered yet.
///
/// Use [`PROC_MACHINE_JOBS_BASE`] for the singleton instance.
#[derive(Debug, Clone, Copy)]
pub struct ProcMachineJobsBase();

impl<IO: Send + Debug + 'static> ProcMachineJobs<IO> for ProcMachineJobsBase {
    const DEPTH: u8 = 0;
    type FUTURES = ProcMachineFuturesBase;

    fn init(&self, _io: Pin<&'static IO>, _futures: &mut Self::FUTURES) {}

    fn with<FUT: Future<Output = TaskEnd> + Send + 'static>(
        self: Self,
        proc: fn(Pin<&'static IO>) -> FUT,
    ) -> impl ProcMachineJobs<IO> {
        ProcMachineJobsExtension { prev: self, proc }
    }
}

/// Builder with one additional task appended to a `PREV` builder.
pub struct ProcMachineJobsExtension<
    IO: Send + Debug + 'static,
    PREV: ProcMachineJobs<IO>,
    FUT: Future<Output = TaskEnd> + Send + 'static,
> {
    prev: PREV,
    /// Constructor function: given a pinned IO ref, returns the task future.
    proc: fn(Pin<&'static IO>) -> FUT,
}

impl<
        IO: Send + Debug,
        PREV: ProcMachineJobs<IO>,
        FUT: Future<Output = TaskEnd> + Send + 'static,
    > ProcMachineJobs<IO> for ProcMachineJobsExtension<IO, PREV, FUT>
{
    const DEPTH: u8 = PREV::DEPTH + 1;
    type FUTURES = ProcMachineFuturesExtension<PREV::FUTURES, FUT>;

    fn init(&self, io: Pin<&'static IO>, futures: &mut Self::FUTURES) {
        // Initialise all previous tasks first, then our own.
        self.prev.init(io, &mut futures.prev);
        futures.fut = Some((self.proc)(io));
    }

    fn with<FUT2: Future<Output = TaskEnd> + Send + 'static>(
        self: Self,
        proc: fn(Pin<&'static IO>) -> FUT2,
    ) -> impl ProcMachineJobs<IO> {
        ProcMachineJobsExtension { prev: self, proc }
    }
}

// ============================================================================
// PROC MACHINE IMPLEMENTATION
// ============================================================================
//
// ProcMachineInner holds the actual state: the IO struct, the futures, and
// the alive_mask. It lives behind a parking_lot::Mutex inside an Arc.
//
// ProcMachineImpl is the Arc-allocated outer shell that also holds the
// wake_mask (atomic, accessed outside the lock) and a raw self-pointer
// (raw_arc) used to reconstruct an Arc<Self> in trait-object methods.
// ============================================================================

/// The mutex-protected interior: IO + futures + alive tracking.
#[derive(Debug)]
struct ProcMachineInner<IO: Send + Debug, FUTURES: ProcMachineFutures> {
    futures: FUTURES,
    io: IO,
    /// Bitmask of tasks that have not yet completed. Bit `n` corresponds to
    /// the task at depth `n`. Updated after every `poll` call.
    alive_mask: u32,
}

impl<IO: Send + Debug, FUTURES: ProcMachineFutures> ProcMachineInner<IO, FUTURES> {
    fn new(io: IO) -> Self {
        Self {
            io,
            futures: FUTURES::new(),
            alive_mask: 0,
        }
    }

    /// Repeatedly polls tasks until no more wakes are pending.
    ///
    /// Each iteration atomically swaps `wake_mask` to 0 (claiming all
    /// pending wakes), intersects with `alive_mask` to get the set of
    /// tasks to poll, and polls them. If any task wakes another task
    /// *synchronously* during its poll (e.g. by writing to an IoExchange),
    /// the new wake bit lands in `wake_mask` and is picked up on the next
    /// loop iteration.
    ///
    /// Returns `true` if any tasks are still alive.
    fn tick<T: MultiWake + 'static>(&mut self, waker: &Arc<T>, wake_mask: &AtomicU32) -> bool {
        loop {
            let mask = self.alive_mask & wake_mask.swap(0, Ordering::SeqCst);
            if mask == 0 {
                break;
            }
            self.alive_mask = self.futures.poll(waker, mask);
        }
        self.alive_mask != 0
    }
}

/// Singleton starting point for the builder pattern.
///
/// ```rust,ignore
/// let machine = PROC_MACHINE_JOBS_BASE
///     .with(my_task)
///     .build(MyIO::new());
/// ```
pub static PROC_MACHINE_JOBS_BASE: ProcMachineJobsBase = ProcMachineJobsBase();

/// The concrete `ProcMachine` implementation, allocated inside an `Arc`.
///
/// # Layout
///
/// - `inner`: Mutex-protected [`ProcMachineInner`] (IO + futures + alive_mask).
/// - `wake_mask`: Atomic bitmask of pending wakes. Lives *outside* the mutex
///   so that [`MultiWake::wake`] can set bits without acquiring the lock
///   (wakes may fire from any thread or from inside a poll).
/// - `raw_arc`: Raw self-pointer set once during construction. Used by
///   trait-object methods ([`is_done`](ProcMachine::is_done),
///   [`unsafe_unlock_io`](ProcMachine::unsafe_unlock_io)) to reconstruct
///   a temporary `Arc<Self>` needed by [`tick`](ProcMachineInner::tick).
///
/// # Safety
///
/// `raw_arc` is a `*const Self` (not `Send`), hence the manual
/// `unsafe impl Send + Sync`. This is sound because `raw_arc` is
/// immutable after construction and always points to the Arc's own
/// allocation, which is guaranteed to be alive while any `&self` exists.
struct ProcMachineImpl<IO: Send + Debug, FUTURES: ProcMachineFutures + 'static> {
    inner: Mutex<ProcMachineInner<IO, FUTURES>>,
    wake_mask: AtomicU32,
    raw_arc: *const Self,
}

// SAFETY: All mutable state is behind the Mutex or is AtomicU32.
// raw_arc is immutable after construction and points to the Arc's own
// allocation (which is alive while any reference exists).
unsafe impl<IO: Send + Debug, FUTURES: ProcMachineFutures + 'static> Send
    for ProcMachineImpl<IO, FUTURES>
{
}
unsafe impl<IO: Send + Debug, FUTURES: ProcMachineFutures + 'static> Sync
    for ProcMachineImpl<IO, FUTURES>
{
}

impl<IO: Send + Debug, FUTURES: ProcMachineFutures> core::fmt::Debug
    for ProcMachineImpl<IO, FUTURES>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let guard = self.inner.lock();
        f.debug_struct("ProcMachineImpl")
            .field("io", &guard.io)
            .field("alive_mask", &guard.alive_mask)
            .finish()
    }
}

/// [`MultiWake`] impl: sets the task's bit in `wake_mask` via CAS loop.
///
/// This is called from [`Waker::wake`] on any thread, potentially while
/// the mutex is held (e.g. a task writes to an IoExchange, which wakes
/// the reader's waker synchronously). Because `wake_mask` is atomic and
/// lives outside the mutex, this never deadlocks.
impl<IO: Send + Debug, FUTURES: ProcMachineFutures + 'static> MultiWake
    for ProcMachineImpl<IO, FUTURES>
{
    fn wake(&self, n: u8) {
        loop {
            let old = self.wake_mask.load(Ordering::SeqCst);
            let new = old | (1 << n);
            if new == old {
                break; // Bit already set — nothing to do.
            }
            if self
                .wake_mask
                .compare_exchange(old, new, Ordering::SeqCst, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
            // CAS failed (another thread modified wake_mask) — retry.
        }
    }
}

impl<IO: Send + Debug + 'static, FUTURES: ProcMachineFutures + 'static>
    ProcMachineImpl<IO, FUTURES>
{
    /// Allocates the ProcMachine, initialises futures, and performs the
    /// first tick.
    ///
    /// # Lifetime extension
    ///
    /// Task futures receive `Pin<&'static IO>`, but the IO actually lives
    /// inside the Arc-held Mutex. This is sound because:
    /// 1. The IO is only accessed through futures stored in the same struct.
    /// 2. Futures are only polled while the mutex is held.
    /// 3. The Arc ensures the allocation is never freed while references
    ///    exist.
    fn new<JOBS: ProcMachineJobs<IO, FUTURES = FUTURES>>(io: IO, jobs: JOBS) -> Arc<Self> {
        let mut ret = Arc::new(Self {
            inner: Mutex::new(ProcMachineInner::new(io)),
            wake_mask: AtomicU32::new(0),
            raw_arc: std::ptr::null(),
        });
        // Store a raw self-pointer for later Arc reconstruction in
        // trait-object methods. Safe because we are the sole owner
        // (Arc::get_mut succeeds).
        Arc::get_mut(&mut ret).unwrap().raw_arc = Arc::as_ptr(&ret);
        {
            let mut guard = ret.inner.lock();
            let ProcMachineInner {
                io,
                futures,
                alive_mask: _,
            } = &mut *guard;
            // SAFETY: Extend the IO lifetime to 'static. The IO lives
            // inside the Arc and is only accessed by futures that are also
            // inside the Arc, polled under the mutex. See doc comment above.
            let io = unsafe { Pin::new_unchecked(&*(io as *const IO)) };
            jobs.init(io, futures);
            // Initial poll with all bits set to discover which tasks are
            // alive, then tick to process any that were immediately ready.
            guard.alive_mask = futures.poll(&ret, 0xFFFFFFFF);
            guard.tick(&ret, &ret.wake_mask);
        }
        ret
    }
}

impl<IO: Send + Debug + 'static, FUTURES: ProcMachineFutures + 'static> ProcMachine<IO>
    for ProcMachineImpl<IO, FUTURES>
{
    fn is_done(&self) -> bool {
        // Reconstruct a temporary Arc<Self> for tick(). The
        // increment_strong_count / from_raw pair ensures the ref count
        // nets to zero when the temporary is dropped at the end.
        let arc: Arc<Self> = unsafe {
            Arc::increment_strong_count(self.raw_arc);
            Arc::from_raw(self.raw_arc)
        };
        let mut guard = self.inner.lock();
        !guard.tick(&arc, &self.wake_mask)
    }

    unsafe fn unsafe_lock_io(&self) -> *mut IO {
        // Acquire the raw mutex (not through MutexGuard, because we need
        // to release it in a separate call — unsafe_unlock_io).
        self.inner.raw().lock();
        let inner_ptr = self.inner.data_ptr();
        unsafe { &mut (*inner_ptr).io }
    }

    unsafe fn unsafe_unlock_io(&self) {
        // Reconstruct a temporary Arc for tick (same pattern as is_done).
        let arc: Arc<Self> = unsafe {
            Arc::increment_strong_count(self.raw_arc);
            Arc::from_raw(self.raw_arc)
        };
        // Tick while still holding the lock — this processes any wakes
        // that occurred during the critical section.
        let inner_ptr = self.inner.data_ptr();
        (*inner_ptr).tick(&arc, &self.wake_mask);
        // Now release the raw mutex.
        self.inner.raw().unlock();
    }
}

// ============================================================================
// MULTI-WAKER SUPPORT
// ============================================================================
//
// Each task needs its own Waker so that when an IO primitive (e.g.
// IoExchange) calls wake(), only the relevant task is scheduled for
// polling — not all of them.
//
// The naive approach (one Arc per waker) would mean extra allocations.
// Instead, we use bytemuck's TransparentWrapper to reinterpret the
// ProcMachineImpl Arc as an Arc<MultiwakeWrapper<_, N>> for each const
// N. Because MultiwakeWrapper is #[repr(transparent)], this is a
// zero-cost pointer cast. Each N gets its own Wake vtable that routes
// to MultiWake::wake(N).
//
// The result: every task gets a distinct Waker backed by the same Arc
// allocation, with no extra heap allocations.
// ============================================================================

/// Trait for types that can be woken by task index.
///
/// Implemented by [`ProcMachineImpl`] to set the corresponding bit in
/// `wake_mask`.
pub trait MultiWake: Send + Sync {
    /// Signal that the task at index `n` (0–31) should be polled.
    fn wake(&self, n: u8);
}

/// Zero-cost wrapper that routes [`Wake::wake`] to [`MultiWake::wake(N)`].
///
/// `#[repr(transparent)]` guarantees the same layout as `T`, so
/// `Arc<MultiwakeWrapper<T, N>>` and `Arc<T>` are interchangeable via
/// [`TransparentWrapperAlloc::wrap_arc`].
#[derive(TransparentWrapper)]
#[repr(transparent)]
struct MultiwakeWrapper<T: MultiWake, const N: u8>(T);

impl<T, const N: u8> Wake for MultiwakeWrapper<T, N>
where
    T: MultiWake,
{
    fn wake(self: Arc<Self>) {
        self.0.wake(N);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.wake(N);
    }
}

impl<T: MultiWake + 'static, const N: u8> MultiwakeWrapper<T, N> {
    /// Reinterprets `Arc<T>` as `Arc<MultiwakeWrapper<T, N>>` (zero-cost)
    /// and converts it to a [`Waker`].
    fn get_waker(target: Arc<T>) -> Waker {
        let wrapper = Self::wrap_arc(target);
        Waker::from(wrapper)
    }
}

/// Maps a runtime task index to a statically-typed [`Waker`] backed by the
/// corresponding `MultiwakeWrapper<T, N>`.
///
/// Each const generic `N` produces a distinct `MultiwakeWrapper` type with
/// its own [`Wake`] impl, so every task index gets a unique vtable that
/// routes [`Waker::wake()`] to [`MultiWake::wake(n)`] on the shared
/// `Arc<T>`.
///
/// # Why a match instead of a const generic call?
///
/// Rust does not allow generic `Self` types in anonymous const expressions,
/// so callers like [`ProcMachineFuturesExtension::poll`] cannot write
/// `MultiwakeWrapper::<T, { Self::DEPTH }>` directly. This function bridges
/// the gap: the caller passes the depth as a plain `u8`, and the match
/// converts it to the corresponding const-generic instantiation.
///
/// Because every call site passes a value derived from an associated const
/// (`Self::DEPTH`), LLVM sees through the match after monomorphisation and
/// constant-folds it to a direct call — no branch at runtime. Only the arms
/// actually used by a given ProcMachine are monomorphised into the binary.
fn get_multi_waker<T: MultiWake + 'static>(target: &Arc<T>, n: u8) -> Waker {
    match n {
        0 => MultiwakeWrapper::<T, 0>::get_waker(target.clone()),
        1 => MultiwakeWrapper::<T, 1>::get_waker(target.clone()),
        2 => MultiwakeWrapper::<T, 2>::get_waker(target.clone()),
        3 => MultiwakeWrapper::<T, 3>::get_waker(target.clone()),
        4 => MultiwakeWrapper::<T, 4>::get_waker(target.clone()),
        5 => MultiwakeWrapper::<T, 5>::get_waker(target.clone()),
        6 => MultiwakeWrapper::<T, 6>::get_waker(target.clone()),
        7 => MultiwakeWrapper::<T, 7>::get_waker(target.clone()),
        8 => MultiwakeWrapper::<T, 8>::get_waker(target.clone()),
        9 => MultiwakeWrapper::<T, 9>::get_waker(target.clone()),
        10 => MultiwakeWrapper::<T, 10>::get_waker(target.clone()),
        11 => MultiwakeWrapper::<T, 11>::get_waker(target.clone()),
        12 => MultiwakeWrapper::<T, 12>::get_waker(target.clone()),
        13 => MultiwakeWrapper::<T, 13>::get_waker(target.clone()),
        14 => MultiwakeWrapper::<T, 14>::get_waker(target.clone()),
        15 => MultiwakeWrapper::<T, 15>::get_waker(target.clone()),
        16 => MultiwakeWrapper::<T, 16>::get_waker(target.clone()),
        17 => MultiwakeWrapper::<T, 17>::get_waker(target.clone()),
        18 => MultiwakeWrapper::<T, 18>::get_waker(target.clone()),
        19 => MultiwakeWrapper::<T, 19>::get_waker(target.clone()),
        20 => MultiwakeWrapper::<T, 20>::get_waker(target.clone()),
        21 => MultiwakeWrapper::<T, 21>::get_waker(target.clone()),
        22 => MultiwakeWrapper::<T, 22>::get_waker(target.clone()),
        23 => MultiwakeWrapper::<T, 23>::get_waker(target.clone()),
        24 => MultiwakeWrapper::<T, 24>::get_waker(target.clone()),
        25 => MultiwakeWrapper::<T, 25>::get_waker(target.clone()),
        26 => MultiwakeWrapper::<T, 26>::get_waker(target.clone()),
        27 => MultiwakeWrapper::<T, 27>::get_waker(target.clone()),
        28 => MultiwakeWrapper::<T, 28>::get_waker(target.clone()),
        29 => MultiwakeWrapper::<T, 29>::get_waker(target.clone()),
        30 => MultiwakeWrapper::<T, 30>::get_waker(target.clone()),
        31 => MultiwakeWrapper::<T, 31>::get_waker(target.clone()),
        _ => panic!("Task index {n} out of range (max 31, limited by u32 wake_mask)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::poll_fn;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use std::task::Poll;

    // -----------------------------------------------------------------------
    // Test IO struct
    // -----------------------------------------------------------------------
    //
    // Tasks suspend by checking a per-slot "gate" flag. External code
    // opens the gate and wakes the stored waker — the next poll sees the
    // open gate and returns Ready, allowing the task to proceed.

    /// Minimal IO struct for testing ProcMachine task scheduling.
    #[derive(Debug)]
    struct TestIO {
        /// Counter incremented by tasks to prove they ran.
        counter: AtomicU32,
        /// Bitfield: bit N is set when task N has completed.
        completed: AtomicU32,
        /// Per-slot gate + waker state.  Protected by the ProcMachine
        /// mutex (accessed through Pin<&TestIO>, which is only valid
        /// while the mutex is held).
        slots: std::sync::Mutex<Vec<Slot>>,
    }

    /// Per-task suspend/resume state.
    #[derive(Default, Debug)]
    struct Slot {
        /// When `true`, the next poll of this slot's gate returns `Ready`.
        open: bool,
        /// Waker stored by the task so external code can schedule it.
        waker: Option<Waker>,
    }

    impl TestIO {
        fn new(num_slots: usize) -> Self {
            let mut slots = Vec::with_capacity(num_slots);
            slots.resize_with(num_slots, Slot::default);
            Self {
                counter: AtomicU32::new(0),
                completed: AtomicU32::new(0),
                slots: std::sync::Mutex::new(slots),
            }
        }

        fn counter(&self) -> u32 {
            self.counter.load(Ordering::SeqCst)
        }

        fn completed(&self) -> u32 {
            self.completed.load(Ordering::SeqCst)
        }

        /// Called by a task inside a `poll_fn` to suspend until the gate
        /// is opened.  Returns `Ready` if the gate is already open
        /// (consuming it), or `Pending` after storing the waker.
        fn poll_gate(&self, n: usize, cx: &std::task::Context<'_>) -> Poll<()> {
            let mut slots = self.slots.lock().unwrap();
            if slots[n].open {
                slots[n].open = false; // consume the gate
                Poll::Ready(())
            } else {
                slots[n].waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }

        /// Called by external code (while holding the IoGuard) to open the
        /// gate and wake the corresponding task.
        fn open_gate(&self, n: usize) {
            let mut slots = self.slots.lock().unwrap();
            slots[n].open = true;
            if let Some(w) = slots[n].waker.take() {
                w.wake();
            }
        }
    }

    // -----------------------------------------------------------------------
    // Task functions
    // -----------------------------------------------------------------------

    /// Increments counter once and completes immediately.
    async fn task_immediate(io: Pin<&'static TestIO>) -> TaskEnd {
        io.counter.fetch_add(1, Ordering::SeqCst);
        io.completed.fetch_or(1 << 0, Ordering::SeqCst);
        TaskEnd()
    }

    /// Increments counter, suspends on gate 0, increments again, completes.
    async fn task_suspend_slot0(io: Pin<&'static TestIO>) -> TaskEnd {
        io.counter.fetch_add(1, Ordering::SeqCst);
        poll_fn(|cx| io.poll_gate(0, cx)).await;
        io.counter.fetch_add(1, Ordering::SeqCst);
        io.completed.fetch_or(1 << 0, Ordering::SeqCst);
        TaskEnd()
    }

    /// Adds 10, suspends on gate 1, adds 10, completes.
    async fn task_suspend_slot1(io: Pin<&'static TestIO>) -> TaskEnd {
        io.counter.fetch_add(10, Ordering::SeqCst);
        poll_fn(|cx| io.poll_gate(1, cx)).await;
        io.counter.fetch_add(10, Ordering::SeqCst);
        io.completed.fetch_or(1 << 1, Ordering::SeqCst);
        TaskEnd()
    }

    /// Suspends 3 times on gate 0, incrementing counter each time.
    async fn task_multi_suspend(io: Pin<&'static TestIO>) -> TaskEnd {
        for _ in 0..3 {
            io.counter.fetch_add(1, Ordering::SeqCst);
            poll_fn(|cx| io.poll_gate(0, cx)).await;
        }
        io.counter.fetch_add(1, Ordering::SeqCst);
        io.completed.fetch_or(1 << 0, Ordering::SeqCst);
        TaskEnd()
    }

    /// Suspends on gate 0, then opens gate 1 (cross-task wake), completes.
    async fn task_wakes_other(io: Pin<&'static TestIO>) -> TaskEnd {
        io.counter.fetch_add(1, Ordering::SeqCst);
        poll_fn(|cx| io.poll_gate(0, cx)).await;
        // Synchronously wake the other task.
        io.open_gate(1);
        io.counter.fetch_add(1, Ordering::SeqCst);
        io.completed.fetch_or(1 << 0, Ordering::SeqCst);
        TaskEnd()
    }

    /// Completes immediately without touching IO.
    async fn task_noop(_io: Pin<&'static TestIO>) -> TaskEnd {
        TaskEnd()
    }

    // -----------------------------------------------------------------------
    // Construction and basic lifecycle
    // -----------------------------------------------------------------------

    #[test]
    fn build_single_task_machine() {
        let _machine: Arc<dyn ProcMachine<TestIO>> = PROC_MACHINE_JOBS_BASE
            .with(task_immediate)
            .build(TestIO::new(1));
    }

    #[test]
    fn build_two_task_machine() {
        let _machine: Arc<dyn ProcMachine<TestIO>> = PROC_MACHINE_JOBS_BASE
            .with(task_suspend_slot0)
            .with(task_suspend_slot1)
            .build(TestIO::new(2));
    }

    #[test]
    fn immediate_task_runs_during_build() {
        let machine = PROC_MACHINE_JOBS_BASE
            .with(task_immediate)
            .build(TestIO::new(1));

        let guard = machine.lock();
        assert_eq!(guard.counter(), 1);
        assert_eq!(guard.completed(), 1);
    }

    #[test]
    fn immediate_task_is_done() {
        let machine = PROC_MACHINE_JOBS_BASE
            .with(task_immediate)
            .build(TestIO::new(1));

        assert!(machine.is_done());
    }

    // -----------------------------------------------------------------------
    // Single task with suspend/resume
    // -----------------------------------------------------------------------

    #[test]
    fn suspended_task_is_not_done() {
        let machine = PROC_MACHINE_JOBS_BASE
            .with(task_suspend_slot0)
            .build(TestIO::new(1));

        {
            let guard = machine.lock();
            assert_eq!(guard.counter(), 1); // first half ran
            assert_eq!(guard.completed(), 0);
        }
        assert!(!machine.is_done());
    }

    #[test]
    fn wake_and_resume_single_task() {
        let machine = PROC_MACHINE_JOBS_BASE
            .with(task_suspend_slot0)
            .build(TestIO::new(1));

        // Open the gate and wake the task.
        {
            let guard = machine.lock();
            assert_eq!(guard.counter(), 1);
            guard.open_gate(0);
        }
        // Guard drop → tick → task sees open gate → resumes.

        {
            let guard = machine.lock();
            assert_eq!(guard.counter(), 2);
            assert_eq!(guard.completed(), 1);
        }
        assert!(machine.is_done());
    }

    #[test]
    fn multiple_suspend_resume_cycles() {
        let machine = PROC_MACHINE_JOBS_BASE
            .with(task_multi_suspend)
            .build(TestIO::new(1));

        // Initial: first increment + suspend.
        {
            let guard = machine.lock();
            assert_eq!(guard.counter(), 1);
        }

        // Resume 3 times (the task loops 3 times with a suspend each).
        for expected in [2, 3, 4] {
            {
                let guard = machine.lock();
                guard.open_gate(0);
            }
            {
                let guard = machine.lock();
                assert_eq!(guard.counter(), expected);
            }
        }

        // After 3 resumes, the loop ends and the task completes.
        {
            let guard = machine.lock();
            assert_eq!(guard.completed(), 1);
        }
        assert!(machine.is_done());
    }

    // -----------------------------------------------------------------------
    // Two-task interaction
    // -----------------------------------------------------------------------

    #[test]
    fn two_tasks_run_independently() {
        let machine = PROC_MACHINE_JOBS_BASE
            .with(task_suspend_slot0)
            .with(task_suspend_slot1)
            .build(TestIO::new(2));

        // Both tasks ran their first half: 1 + 10 = 11.
        {
            let guard = machine.lock();
            assert_eq!(guard.counter(), 11);
            assert_eq!(guard.completed(), 0);
        }

        // Wake only task 0.
        {
            let guard = machine.lock();
            guard.open_gate(0);
        }
        {
            let guard = machine.lock();
            assert_eq!(guard.counter(), 12); // +1 from task 0
            assert_eq!(guard.completed(), 1); // only task 0 done
        }

        // Wake task 1.
        {
            let guard = machine.lock();
            guard.open_gate(1);
        }
        {
            let guard = machine.lock();
            assert_eq!(guard.counter(), 22); // +10 from task 1
            assert_eq!(guard.completed(), 3); // both done
        }
        assert!(machine.is_done());
    }

    #[test]
    fn wake_both_tasks_simultaneously() {
        let machine = PROC_MACHINE_JOBS_BASE
            .with(task_suspend_slot0)
            .with(task_suspend_slot1)
            .build(TestIO::new(2));

        {
            let guard = machine.lock();
            guard.open_gate(0);
            guard.open_gate(1);
        }

        {
            let guard = machine.lock();
            assert_eq!(guard.counter(), 22);
            assert_eq!(guard.completed(), 3);
        }
        assert!(machine.is_done());
    }

    #[test]
    fn cross_task_synchronous_wake() {
        // task_wakes_other: suspends on gate 0, then opens gate 1.
        // task_suspend_slot1: suspends on gate 1.
        let machine = PROC_MACHINE_JOBS_BASE
            .with(task_wakes_other)
            .with(task_suspend_slot1)
            .build(TestIO::new(2));

        // Both ran their first half: 1 + 10 = 11.
        {
            let guard = machine.lock();
            assert_eq!(guard.counter(), 11);
        }

        // Open gate 0: task_wakes_other resumes, opens gate 1
        // synchronously. The tick loop picks up the wake for task 1
        // and polls it too, so both complete in one tick cycle.
        {
            let guard = machine.lock();
            guard.open_gate(0);
        }

        {
            let guard = machine.lock();
            assert_eq!(guard.counter(), 22); // 1+1 + 10+10
            assert_eq!(guard.completed(), 3);
        }
        assert!(machine.is_done());
    }

    // -----------------------------------------------------------------------
    // IoGuard behaviour
    // -----------------------------------------------------------------------

    #[test]
    fn guard_deref_provides_io_access() {
        let machine = PROC_MACHINE_JOBS_BASE
            .with(task_immediate)
            .build(TestIO::new(1));

        let guard = machine.lock();
        assert_eq!(guard.counter(), 1);
    }

    #[test]
    fn guard_deref_mut_provides_mutable_access() {
        let machine = PROC_MACHINE_JOBS_BASE
            .with(task_immediate)
            .build(TestIO::new(1));

        {
            let guard = machine.lock();
            guard.counter.store(42, Ordering::SeqCst);
        }

        let guard = machine.lock();
        assert_eq!(guard.counter(), 42);
    }

    #[test]
    fn guard_drop_ticks_machine() {
        let machine = PROC_MACHINE_JOBS_BASE
            .with(task_suspend_slot0)
            .build(TestIO::new(1));

        {
            let guard = machine.lock();
            assert_eq!(guard.counter(), 1);
            guard.open_gate(0);
            // Task is woken but hasn't run — we still hold the lock.
            assert_eq!(guard.counter(), 1);
        }
        // Guard dropped → tick → task resumes.

        let guard = machine.lock();
        assert_eq!(guard.counter(), 2);
    }

    // -----------------------------------------------------------------------
    // is_done semantics
    // -----------------------------------------------------------------------

    #[test]
    fn is_done_false_while_tasks_pending() {
        let machine = PROC_MACHINE_JOBS_BASE
            .with(task_suspend_slot0)
            .with(task_suspend_slot1)
            .build(TestIO::new(2));

        assert!(!machine.is_done());

        // Complete one task — still not done.
        {
            let guard = machine.lock();
            guard.open_gate(0);
        }
        assert!(!machine.is_done());

        // Complete the other.
        {
            let guard = machine.lock();
            guard.open_gate(1);
        }
        assert!(machine.is_done());
    }

    #[test]
    fn is_done_ticks_before_answering() {
        let machine = PROC_MACHINE_JOBS_BASE
            .with(task_suspend_slot0)
            .build(TestIO::new(1));

        {
            let guard = machine.lock();
            guard.open_gate(0);
        }
        // is_done calls tick internally before checking.
        assert!(machine.is_done());
    }

    // -----------------------------------------------------------------------
    // Multi-waker unit tests
    // -----------------------------------------------------------------------

    /// Standalone MultiWake impl for testing get_multi_waker in isolation.
    struct TestMultiWaker {
        woken: AtomicU32,
    }

    impl TestMultiWaker {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                woken: AtomicU32::new(0),
            })
        }
        fn woken_mask(&self) -> u32 {
            self.woken.load(Ordering::SeqCst)
        }
    }

    impl MultiWake for TestMultiWaker {
        fn wake(&self, n: u8) {
            self.woken.fetch_or(1 << n, Ordering::SeqCst);
        }
    }

    #[test]
    fn multi_waker_routes_to_correct_index() {
        let mw = TestMultiWaker::new();

        let w0 = get_multi_waker(&mw, 0);
        let w3 = get_multi_waker(&mw, 3);
        let w7 = get_multi_waker(&mw, 7);

        w0.wake_by_ref();
        assert_eq!(mw.woken_mask(), 1 << 0);

        w3.wake_by_ref();
        assert_eq!(mw.woken_mask(), (1 << 0) | (1 << 3));

        w7.wake_by_ref();
        assert_eq!(mw.woken_mask(), (1 << 0) | (1 << 3) | (1 << 7));
    }

    #[test]
    fn multi_waker_high_indices() {
        let mw = TestMultiWaker::new();

        let w31 = get_multi_waker(&mw, 31);
        w31.wake_by_ref();
        assert_eq!(mw.woken_mask(), 1 << 31);

        let w16 = get_multi_waker(&mw, 16);
        w16.wake_by_ref();
        assert_eq!(mw.woken_mask(), (1 << 31) | (1 << 16));
    }

    #[test]
    #[should_panic(expected = "out of range")]
    fn multi_waker_index_32_panics() {
        let mw = TestMultiWaker::new();
        let _w = get_multi_waker(&mw, 32);
    }

    #[test]
    fn multi_waker_wake_is_idempotent() {
        let mw = TestMultiWaker::new();
        let w = get_multi_waker(&mw, 5);
        w.wake_by_ref();
        w.wake_by_ref();
        w.wake_by_ref();
        assert_eq!(mw.woken_mask(), 1 << 5);
    }

    #[test]
    fn multi_waker_different_indices_independent() {
        let mw = TestMultiWaker::new();
        for i in 0..8 {
            let w = get_multi_waker(&mw, i);
            w.wake_by_ref();
        }
        assert_eq!(mw.woken_mask(), 0xFF);
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn zero_work_task_completes_at_build() {
        let machine = PROC_MACHINE_JOBS_BASE
            .with(task_noop)
            .build(TestIO::new(0));

        assert!(machine.is_done());
        let guard = machine.lock();
        assert_eq!(guard.counter(), 0);
    }

    #[test]
    fn mix_immediate_and_suspended_tasks() {
        let machine = PROC_MACHINE_JOBS_BASE
            .with(task_immediate)
            .with(task_suspend_slot1)
            .build(TestIO::new(2));

        {
            let guard = machine.lock();
            assert_eq!(guard.counter(), 11); // 1 + 10
            assert_eq!(guard.completed(), 1); // only task 0
        }
        assert!(!machine.is_done());

        {
            let guard = machine.lock();
            guard.open_gate(1);
        }
        {
            let guard = machine.lock();
            assert_eq!(guard.counter(), 21);
            assert_eq!(guard.completed(), 3);
        }
        assert!(machine.is_done());
    }

    #[test]
    fn repeated_lock_unlock_without_wakes() {
        let machine = PROC_MACHINE_JOBS_BASE
            .with(task_suspend_slot0)
            .build(TestIO::new(1));

        for _ in 0..10 {
            let guard = machine.lock();
            assert_eq!(guard.counter(), 1); // no change
        }
        assert!(!machine.is_done());
    }

    #[test]
    fn debug_format_shows_io_and_alive_mask() {
        let machine = PROC_MACHINE_JOBS_BASE
            .with(task_suspend_slot0)
            .build(TestIO::new(1));

        let dbg = format!("{:?}", machine);
        assert!(dbg.contains("ProcMachineImpl"));
        assert!(dbg.contains("alive_mask"));
    }
}
