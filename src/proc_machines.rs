//! Components for building "procedural state machines" (ProcMachines).
//!
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
// PROCEDURAL STATE MACHINES
// ============================================================================

// ============================================================================
// PUBLIC INTERFACE
// ============================================================================

/// Trait for a procedural state machine that advances synchronously
///
/// Communication with the ProcMachine is done via an IO struct, which can be accessed
/// via the `txn()` method, or using the `lock` method on the ProcMachine's Arc
/// (which provides a temporary guard that holds a lock on the ProcMachine's internal state).
pub trait ProcMachine<IO: Send + Debug>: Send + Sync + core::fmt::Debug {
    // TODO external waking internal task
    fn is_done(&self) -> bool;
    // UNSAFE: &self must be pinned by an Arc.  ProcMachineImpl constructor ensures this
    // UNSAFE: Caller must ensure that the lock is released by calling unsafe_unlock_io() after the critical section.
    unsafe fn unsafe_lock_io(&self) -> *mut IO;
    // UNSAFE: &self must be pinned by an Arc.  ProcMachineImpl constructor ensures this
    // UNSAFE: Caller must ensure that this is called after the critical section protected by unsafe_lock_io(),
    // and that no references to the locked IO are used after this is called.
    unsafe fn unsafe_unlock_io(&self);
}

/// This trait is implemented on Arc<dyn ProcMachine<IO>> to provide safe access to the IO struct
pub trait LockableIo<IO: Send + Debug> {
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

pub struct IoGuard<IO: Send + Debug> {
    holder: Arc<dyn ProcMachine<IO>>,
    ptr: *mut IO,
}

impl<IO> IoGuard<IO>
where
    IO: Send + Debug,
{
    pub fn new(holder: Arc<dyn ProcMachine<IO>>) -> Self {
        let ptr = unsafe { holder.unsafe_lock_io() };
        Self {
            holder: holder.clone(),
            ptr,
        }
    }
}

impl<IO> Drop for IoGuard<IO>
where
    IO: Send + Debug,
{
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
// FACTORY IMPLEMENTATION
// ============================================================================

/// Marker type returned by async tasks when they complete.
///
/// Tasks in a ProcMachine must return `TaskEnd` to signal completion.
/// This is just a unit type - the interesting work happens via side effects
/// on shared state (e.g., the IO struct).
pub struct TaskEnd();

pub trait ProcMachineFutures: Send {
    const DEPTH: u8;
    /// Polls the futures in this ProcMachine and returns a bitmask of which tasks are still active.
    fn poll<T: MultiWake + 'static>(self: &mut Self, waker: &Arc<T>, depth_mask: u32) -> u32;
    fn new() -> Self;
}

pub struct ProcMachineFuturesBase();

impl ProcMachineFutures for ProcMachineFuturesBase {
    const DEPTH: u8 = 0;
    #[inline(always)]
    fn poll<T: MultiWake + 'static>(self: &mut Self, _waker: &Arc<T>, _depth_mask: u32) -> u32 {
        0
    }
    #[inline(always)]
    fn new() -> Self {
        ProcMachineFuturesBase()
    }
}

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
        let parent_result = self.prev.poll(waker, depth_mask);
        match &mut self.fut {
            None => parent_result,
            Some(fut) => {
                if (depth_mask & (1 << Self::DEPTH)) == 0 {
                    // This task is idle - skip polling
                    return self.prev.poll(waker, depth_mask) | (1 << Self::DEPTH);
                }
                // TODO do this at compile time
                let waker = get_multi_waker(waker, Self::DEPTH);
                let p = unsafe { std::pin::Pin::new_unchecked(fut) };
                let mut cx = Context::from_waker(&waker);
                if p.poll(&mut cx).is_ready() {
                    // Task completed! Remove it from storage.
                    self.fut = None;
                    parent_result
                } else {
                    // Task still pending - return bitmask with this task's bit set
                    1 << PREV::DEPTH
                }
            }
        }
    }
}

pub trait ProcMachineJobs<IO: Send + Debug + 'static> {
    const DEPTH: u8;
    type FUTURES: ProcMachineFutures;
    fn init(&self, io: Pin<&'static IO>, futures: &mut Self::FUTURES);
    fn with<FUT: Future<Output = TaskEnd> + Send + 'static>(
        self: Self,
        proc: fn(Pin<&'static IO>) -> FUT,
    ) -> impl ProcMachineJobs<IO>;
    fn build(self, io: IO) -> Arc<dyn ProcMachine<IO>>
    where
        Self: Sized + 'static,
    {
        ProcMachineImpl::new(io, self)
    }
}

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

pub struct ProcMachineJobsExtension<
    IO: Send + Debug + 'static,
    PREV: ProcMachineJobs<IO>,
    FUT: Future<Output = TaskEnd> + Send + 'static,
> {
    prev: PREV,
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

#[derive(Debug)]
struct ProcMachineInner<IO: Send + Debug, FUTURES: ProcMachineFutures> {
    futures: FUTURES,
    io: IO,
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
    fn tick<T: MultiWake + 'static>(&mut self, waker: &Arc<T>, wake_mask: &AtomicU32) -> bool {
        loop {
            let mask = self.alive_mask & wake_mask.swap(0, Ordering::SeqCst);
            if mask == 0 {
                break; // No tasks to wake, we're idle
            }
            self.alive_mask = self.futures.poll(waker, mask);
        }
        self.alive_mask != 0
    }
}

pub static PROC_MACHINE_JOBS_BASE: ProcMachineJobsBase = ProcMachineJobsBase();

unsafe impl<IO: Send + Debug, FUTURES: ProcMachineFutures + 'static> Send
    for ProcMachineImpl<IO, FUTURES>
{
}
unsafe impl<IO: Send + Debug, FUTURES: ProcMachineFutures + 'static> Sync
    for ProcMachineImpl<IO, FUTURES>
{
}

struct ProcMachineImpl<IO: Send + Debug, FUTURES: ProcMachineFutures + 'static> {
    inner: Mutex<ProcMachineInner<IO, FUTURES>>,
    wake_mask: AtomicU32,
    raw_arc: *const Self,
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

impl<IO: Send + Debug, FUTURES: ProcMachineFutures + 'static> MultiWake
    for ProcMachineImpl<IO, FUTURES>
{
    fn wake(&self, n: u8) {
        loop {
            let old = self.wake_mask.load(Ordering::SeqCst);
            let new = old | (1 << n);
            if new == old {
                break; // Already set, no need to wake again
            }
            if self
                .wake_mask
                .compare_exchange(old, new, Ordering::SeqCst, Ordering::Relaxed)
                .is_ok()
            {
                break; // Successfully set the bit
            }
        }
    }
}

impl<IO: Send + Debug + 'static, FUTURES: ProcMachineFutures + 'static>
    ProcMachineImpl<IO, FUTURES>
{
    fn new<JOBS: ProcMachineJobs<IO, FUTURES = FUTURES>>(io: IO, jobs: JOBS) -> Arc<Self> {
        let mut ret = Arc::new(Self {
            inner: Mutex::new(ProcMachineInner::new(io)),
            wake_mask: AtomicU32::new(0),
            raw_arc: std::ptr::null(),
        });
        Arc::get_mut(&mut ret).unwrap().raw_arc = Arc::as_ptr(&ret);
        {
            let mut guard = ret.inner.lock();
            let ProcMachineInner {
                io,
                futures,
                alive_mask: _,
            } = &mut *guard;
            // UNSAFE: We are extending the lifetime of `io` to 'static, but this is safe because
            // it will only be accessed by futures that stored in this object.
            let io = unsafe { Pin::new_unchecked(&*(io as *const IO)) };
            jobs.init(io, futures);
            guard.alive_mask = futures.poll(&ret, 0xFFFFFFFF); // Initial poll to set up wake_mask based on which tasks are active
            guard.tick(&ret, &ret.wake_mask); // Process any tasks that were immediately ready
        }
        ret
    }
}

impl<IO: Send + Debug + 'static, FUTURES: ProcMachineFutures + 'static> ProcMachine<IO>
    for ProcMachineImpl<IO, FUTURES>
{
    fn is_done(&self) -> bool {
        let arc: Arc<Self> = unsafe {
            Arc::increment_strong_count(self.raw_arc);
            Arc::from_raw(self.raw_arc)
        };
        let mut guard = self.inner.lock();
        !guard.tick(&arc, &self.wake_mask)
    }

    unsafe fn unsafe_lock_io(&self) -> *mut IO {
        self.inner.raw().lock();
        let inner_ptr = self.inner.data_ptr();
        let io_ref = unsafe { &mut (*inner_ptr).io };
        io_ref
    }

    unsafe fn unsafe_unlock_io(&self) {
        let arc: Arc<Self> = unsafe {
            Arc::increment_strong_count(self.raw_arc);
            Arc::from_raw(self.raw_arc)
        };
        let inner_ptr = self.inner.data_ptr();
        (*inner_ptr).tick(&arc, &self.wake_mask);
        self.inner.raw().unlock();
    }
}

// ============================================================================
// MULTI-WAKER SUPPORT
// ============================================================================
//
// We need a way for each task within a ProcMachine to have its own Waker.
// The naive approach would be to allocate a separate Arc for each task's waker
// data, but that's wasteful when all tasks share the same ProcMachine.
//
// Instead, use variant vtables to get implement multiple Wakers based on the same
// pointer.

pub trait MultiWake: Send + Sync {
    /// Wake the task at index `n` (0-7).
    fn wake(&self, n: u8);
}

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
    fn get_waker(target: Arc<T>) -> Waker {
        let wrapper = Self::wrap_arc(target);
        Waker::from(wrapper)
    }
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
    match n {
        0 => MultiwakeWrapper::<T, 0>::get_waker(target.clone()),
        1 => MultiwakeWrapper::<T, 1>::get_waker(target.clone()),
        2 => MultiwakeWrapper::<T, 2>::get_waker(target.clone()),
        3 => MultiwakeWrapper::<T, 3>::get_waker(target.clone()),
        4 => MultiwakeWrapper::<T, 4>::get_waker(target.clone()),
        5 => MultiwakeWrapper::<T, 5>::get_waker(target.clone()),
        6 => MultiwakeWrapper::<T, 6>::get_waker(target.clone()),
        7 => MultiwakeWrapper::<T, 7>::get_waker(target.clone()),
        _ => panic!("Only task indices 0-7 are supported for get_multi_waker()"),
    }
}
