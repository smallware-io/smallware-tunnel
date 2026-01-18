//! Components for building "functional state machines"
//! These are synchronous state machines that are implemented
//! one or more async functions that are polled with a noop waker

use std::fmt;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, RawWaker, RawWakerVTable, Waker};

// ============================================================================
// PROCEDURAL STATE MACHINES
// ============================================================================

/// This trait allows up to 8 wakers to dispatch to the same Arc<T>
/// Structs that implement this trait MUST have #[repr(align(8))] or more
trait MultiWake: Send + Sync {
    fn wake(&self, n: u8);
}

/// Creates a Waker that targets a specific index 'n' on a MultiWake-capable Arc.
/// Requires T to have an alignment of at least 8 (providing 3 bits of space).
fn get_multi_waker<T: MultiWake + 'static>(target: &Arc<T>, n: u8) -> Waker {
    // 1. Convert Arc to raw pointer.
    let ptr = Arc::into_raw(target.clone()) as *const ();

    // 2. Tag the pointer using the bottom 3 bits (supporting indices 0-7).
    // Masking n to 0x7 ensures we don't overwrite the actual pointer bits.
    let tagged_ptr = ((ptr as usize) | (n as usize & 0x7)) as *const ();

    // 3. Construct the RawWaker using the generic vtable for T.
    unsafe { Waker::from_raw(RawWaker::new(tagged_ptr, multi_waker_vtable::<T>())) }
}

// --- Pointer Unpacking Logic ---

fn unpack_multi_waker<T>(ptr: *const ()) -> (*const T, u8) {
    let addr = ptr as usize;
    let tag = (addr & 0x7) as u8;
    let real_ptr = (addr & !0x7) as *const T;
    (real_ptr, tag)
}

// --- Generic VTable Generator ---

fn multi_waker_vtable<T: MultiWake + 'static>() -> &'static RawWakerVTable {
    &RawWakerVTable::new(
        multi_waker_clone_raw::<T>,
        multi_wake_raw::<T>,
        multi_wake_by_ref_raw::<T>,
        multi_waker_drop_raw::<T>,
    )
}

// --- Implementation Functions ---

unsafe fn multi_waker_clone_raw<T: MultiWake + 'static>(ptr: *const ()) -> RawWaker {
    let (real_ptr, _) = unpack_multi_waker::<T>(ptr);
    Arc::increment_strong_count(real_ptr);
    RawWaker::new(ptr, multi_waker_vtable::<T>())
}

unsafe fn multi_wake_raw<T: MultiWake + 'static>(ptr: *const ()) {
    let (real_ptr, n) = unpack_multi_waker::<T>(ptr);
    let arc = Arc::from_raw(real_ptr);
    arc.wake(n);
}

unsafe fn multi_wake_by_ref_raw<T: MultiWake + 'static>(ptr: *const ()) {
    let (real_ptr, n) = unpack_multi_waker::<T>(ptr);
    let target = &*real_ptr;
    target.wake(n);
}

unsafe fn multi_waker_drop_raw<T: MultiWake + 'static>(ptr: *const ()) {
    let (real_ptr, _) = unpack_multi_waker::<T>(ptr);
    drop(Arc::from_raw(real_ptr));
}

/// Trait for the state machine that can be "ticked" to make progress.
pub trait ProcMachine: Send + Sync + std::fmt::Debug {
    /// Advance the state machine.
    /// returns true if it's still active
    fn tick(&self) -> bool;
}

pub struct TaskEnd();

struct ProcMachineTask<FUT>
where
    FUT: Future<Output = TaskEnd> + Send,
{
    sig: AtomicBool,
    fut: Mutex<Option<(Waker, FUT)>>,
}

impl<FUT> ProcMachineTask<FUT>
where
    FUT: Future<Output = TaskEnd> + Send,
{
    pub fn new() -> Self {
        ProcMachineTask {
            sig: AtomicBool::new(false),
            fut: Mutex::new(None),
        }
    }
    pub fn tick(&self, idle_and_done_count: &mut (u8, u8)) {
        if !self.sig.swap(false, Ordering::SeqCst) {
            *idle_and_done_count = (idle_and_done_count.0 + 1, 0);
        }
        let mut guard = self.fut.lock().unwrap();
        if let Some((w, f)) = guard.as_mut() {
            let pinned = unsafe { std::pin::Pin::new_unchecked(f) };
            let mut cx = Context::from_waker(&w);
            if pinned.poll(&mut cx).is_ready() {
                *guard = None;
            };
            *idle_and_done_count = (0, 0)
        } else {
            *idle_and_done_count = (idle_and_done_count.0 + 1, idle_and_done_count.1 + 1);
        }
    }
    pub fn init(&self, w: Waker, f: FUT) {
        self.fut.lock().unwrap().replace((w, f));
    }
    fn wake(&self) {
        self.sig.store(true, Ordering::SeqCst);
    }
}

// ============================================================================
// PROCEDURAL STATE MACHINE WITH 8 TASKS
// ============================================================================

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
        let mut counts: (u8, u8) = (0, 0);
        loop {
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
        }
        counts.1 < 8
    }
}

// ============================================================================
// PROCEDURAL STATE MACHINE WITH 7 TASKS
// ============================================================================

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
