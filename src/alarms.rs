//! Alarm clock primitives for async timeout management.
//!
//! This module provides [`AlarmClock`] and [`ClockAlarm`], a pair of types that
//! implement an efficient, mutex-synchronized alarm system built on an intrusive
//! doubly-linked list. An [`AlarmClock`] holds a monotonically increasing clock
//! value, and any number of [`ClockAlarm`] futures can register thresholds to be
//! woken when the clock reaches or exceeds their target.
//!
//! # Architecture
//!
//! Internally, every `AlarmClock` owns a *head* node, and every `ClockAlarm` owns
//! a *leaf* node. The head node contains a [`Mutex`] protecting the current clock
//! value; leaf nodes store their alarm threshold and a [`Waker`] in `UnsafeCell`s,
//! and link/unlink themselves from the head's circular doubly-linked list while the
//! mutex is held.
//!
//! When the clock advances, `set_clock` walks the linked list under the lock and
//! wakes every alarm whose threshold has been met, unlinking them in the process.
//! When a `ClockAlarm` is polled, `check_alarm` checks the threshold under the lock,
//! linking the node into the list if it needs to wait.
//!
//! # Safety
//!
//! The linked-list pointers are raw (`*const AlarmNode<T>`) wrapped in `UnsafeCell`.
//! All mutations go through the head's mutex. `AlarmClock` must be pinned before
//! creating any `ClockAlarm` against it, and `ClockAlarm` must be pinned before
//! polling, because the list stores pointers to the nodes' addresses.
//!
//! `get_clock` and `get_alarm` return references into mutex-protected / `UnsafeCell`
//! storage. They acquire the lock to synchronize, but the returned `&T` outlives the
//! guard. This is sound only because the backing memory is pinned and stable, and
//! callers must not race a read with a concurrent mutation on another thread. In
//! practice the clock value is only mutated from a single task, so this is safe.

use parking_lot::Mutex;
use std::{
    cell::UnsafeCell,
    fmt::Debug,
    future::Future,
    marker::{PhantomData, PhantomPinned},
    pin::Pin,
    task::{Context, Poll, Waker},
};

/// The relative order between a "clock" value and an "alarm" value.
///
/// Returned by a comparison function to tell the alarm machinery what action to take.
#[derive(Clone, Copy, PartialEq, Debug)]
enum AlarmOrder {
    /// The alarm value is unset or invalid — the alarm can never fire.
    Never,
    /// The clock value has reached or exceeded the alarm threshold — fire now.
    Now,
    /// The clock has not yet reached the alarm threshold, but a future advance might.
    Later,
}

// ---------------------------------------------------------------------------
// UnsafeLink — a raw, nullable, interior-mutable pointer to a node
// ---------------------------------------------------------------------------

/// A nullable, interior-mutable pointer used for intrusive linked-list links.
///
/// All reads and writes go through `UnsafeCell`, so they are only safe when the
/// caller holds the head node's mutex (or during single-threaded construction).
struct UnsafeLink<T> {
    inner: UnsafeCell<*const T>,
}

impl<T> UnsafeLink<T> {
    /// Creates a new null link.
    fn new() -> Self {
        Self {
            inner: UnsafeCell::new(std::ptr::null()),
        }
    }

    /// Returns the raw pointer (may be null).
    #[inline(always)]
    fn get(&self) -> *const T {
        unsafe { *self.inner.get() }
    }

    /// Dereferences the pointer, returning `None` if null.
    ///
    /// # Safety
    ///
    /// The pointee must be alive and the caller must hold the head mutex.
    /// The returned reference lifetime is *not* tied to any guard.
    #[inline(always)]
    unsafe fn get_ref(&self) -> Option<&T> {
        let p = *self.inner.get();
        if p.is_null() {
            None
        } else {
            Some(&*p)
        }
    }

    /// Stores a raw pointer.
    #[inline(always)]
    fn set(&self, val: *const T) {
        unsafe { *self.inner.get() = val };
    }

    /// Stores a pointer derived from a reference.
    #[inline(always)]
    fn set_ref(&self, val: &T) {
        unsafe { *self.inner.get() = val as *const T };
    }

    /// Returns `true` if the stored pointer is null.
    #[inline(always)]
    fn is_null(&self) -> bool {
        unsafe { (*self.inner.get()).is_null() }
    }

    /// Sets the stored pointer to null.
    #[inline(always)]
    fn clear(&self) {
        unsafe {
            *self.inner.get() = std::ptr::null();
        }
    }
}

// ---------------------------------------------------------------------------
// NodeType — discriminates head nodes (clock owners) from leaf nodes (alarms)
// ---------------------------------------------------------------------------

/// Discriminant for the two kinds of node in the intrusive list.
enum NodeType<T> {
    /// The sentinel head node. Owns the mutex that protects the clock value
    /// and synchronises all list mutations.
    Head {
        mutex: Mutex<T>,
    },
    /// A leaf (alarm) node. Stores the alarm threshold in `val`, a waker to
    /// notify when the alarm fires, and a raw pointer back to the head node
    /// so it can acquire the mutex.
    Node {
        // SAFETY: The `ClockAlarm` constructor ensures that the target (head)
        // is pinned and outlives this node via the `'a` lifetime parameter.
        target: *const AlarmNode<T>,
        val: UnsafeCell<T>,
        waker: UnsafeCell<Option<Waker>>,
    },
}

/// An intrusive doubly-linked list node.
///
/// Both the head (clock) and leaf (alarm) nodes share this structure so they
/// can participate in the same circular linked list.
struct AlarmNode<T> {
    typ: NodeType<T>,
    prev: UnsafeLink<AlarmNode<T>>,
    next: UnsafeLink<AlarmNode<T>>,
    // Nodes must not be moved once linked, because the list stores raw pointers.
    _marker: PhantomPinned,
}

// SAFETY: All mutable state is behind a Mutex or only accessed while the Mutex
// is held. The raw pointers point to pinned, lifetime-guaranteed nodes.
unsafe impl<T: PartialOrd> Send for AlarmNode<T> {}
unsafe impl<T: PartialOrd> Sync for AlarmNode<T> {}

impl<T> NodeType<T> {
    /// Returns `true` if this is the head (clock) node.
    fn is_head(&self) -> bool {
        matches!(self, NodeType::Head { .. })
    }

    /// Acquires the head mutex.
    ///
    /// For a `Node`, follows the `target` pointer to the head and locks its mutex.
    /// For a `Head`, locks its own mutex directly.
    fn lock_target(&self) -> parking_lot::MutexGuard<'_, T> {
        match self {
            NodeType::Node { target, .. } => unsafe {
                match &((**target).typ) {
                    NodeType::Node { .. } => {
                        panic!("Node target must be a Head node");
                    }
                    NodeType::Head { mutex } => mutex.lock(),
                }
            },
            NodeType::Head { mutex } => mutex.lock(),
        }
    }

    /// Takes the stored waker (if any) and wakes it.
    ///
    /// # Safety
    ///
    /// Caller must hold the head mutex.
    unsafe fn wake(&self) {
        if let NodeType::Node { waker, .. } = self {
            if let Some(w) = (*waker.get()).take() {
                w.wake();
            }
        }
    }
}

impl<T> AlarmNode<T> {
    /// Creates a new leaf (alarm) node targeting the given pinned head node.
    fn new_node<'a>(target: Pin<&'a AlarmNode<T>>, val: T) -> Self {
        if !target.typ.is_head() {
            panic!("AlarmNode target needs to be a head node")
        }
        Self {
            typ: NodeType::Node {
                target: target.get_ref() as *const AlarmNode<T>,
                val: UnsafeCell::new(val),
                waker: UnsafeCell::new(None),
            },
            prev: UnsafeLink::new(),
            next: UnsafeLink::new(),
            _marker: PhantomPinned,
        }
    }

    /// Creates a new head (clock) node with the given initial value.
    fn new_head(val: T) -> Self {
        Self {
            typ: NodeType::Head {
                mutex: Mutex::new(val),
            },
            prev: UnsafeLink::new(),
            next: UnsafeLink::new(),
            _marker: PhantomPinned,
        }
    }

    /// Returns `true` if this node is currently part of a linked list.
    ///
    /// A node is considered linked when both `prev` and `next` are non-null.
    ///
    /// # Safety
    ///
    /// Caller must hold the head mutex.
    unsafe fn is_linked(&self) -> bool {
        !self.prev.is_null() && !self.next.is_null()
    }

    /// Removes this node from the linked list.
    ///
    /// If called on the head node, all leaf nodes are unlinked first (the list
    /// is torn down). If the node is not currently linked, this is a no-op.
    ///
    /// # Safety
    ///
    /// Caller must hold the head mutex.
    #[inline(always)]
    unsafe fn unlink(&self) {
        if self.typ.is_head() {
            // Unlinking the head tears down the entire list: walk forward and
            // unlink every leaf until we loop back to the head.
            while !self.next.is_null() && !(*self.next.get()).typ.is_head() {
                (*self.next.get()).unlink();
            }
        }
        if self.is_linked() {
            // Stitch prev and next together, bypassing this node.
            let pn = &*self.prev.get();
            let nn = &*self.next.get();
            pn.next.set_ref(nn);
            nn.prev.set_ref(pn);
        }
        self.prev.clear();
        self.next.clear();
    }

    /// Updates the alarm threshold on a leaf node.
    ///
    /// Acquires the head mutex, compares the new threshold against the current
    /// clock value using `cmp`, and:
    /// - `Never` → unlinks the node (alarm cancelled).
    /// - `Now`   → unlinks and wakes the stored waker (alarm already expired).
    /// - `Later` → leaves the link state unchanged (will fire on a future advance) or
    ///   when polled.
    ///
    /// The threshold value is always written, regardless of order.
    fn set_alarm<F>(&self, cmp: F, val: T)
    where
        F: Fn(&T, &T) -> AlarmOrder,
    {
        let guard = self.typ.lock_target();
        let val_cell = match &self.typ {
            NodeType::Head { .. } => {
                panic!("Cannot set_alarm on a head node");
            }
            NodeType::Node { val, .. } => val,
        };
        unsafe {
            match cmp(&*guard, &val) {
                AlarmOrder::Never => {
                    self.unlink();
                }
                AlarmOrder::Now => {
                    self.unlink();
                    self.typ.wake();
                }
                AlarmOrder::Later => (),
            };
            (*val_cell.get()) = val;
        }
    }

    /// Returns a reference to the alarm threshold value.
    ///
    /// Acquires the head mutex to synchronize, then reads the value.
    ///
    /// # Safety note
    ///
    /// The returned `&T` outlives the lock guard. This is sound because the
    /// backing `UnsafeCell` is in a pinned node with a stable address, and in
    /// practice the value is only mutated under the same lock.
    fn get_alarm(&self) -> &T {
        // Acquire and hold the guard for the duration of the read.
        let _guard = self.typ.lock_target();
        match &self.typ {
            NodeType::Head { .. } => panic!("Cannot get_alarm on a head node"),
            NodeType::Node { val, .. } => unsafe { &*val.get() },
        }
    }

    /// Polls the alarm: checks whether the clock has reached the threshold.
    ///
    /// Returns `true` (ready) if the alarm fires now, `false` (pending) otherwise.
    /// When pending, if the alarm may fire at a later time, then the node is linked
    /// into the head's list so that a future clock change can wake it, and the
    /// provided waker is stored for notification.
    /// 
    /// If the alarm can never fire regardless of how the clock changes, then the node
    /// is unlinked.
    fn check_alarm<F>(self: Pin<&Self>, cx: &Context<'_>, f: F) -> bool
    where
        F: Fn(&T, &T) -> AlarmOrder,
    {
        let guard = self.typ.lock_target();
        let (target, val_cell, waker) = match &self.typ {
            NodeType::Head { .. } => {
                panic!("Cannot check_alarm on a head node");
            }
            NodeType::Node { target, waker, val } => unsafe { (&**target, val, &mut *waker.get()) },
        };
        unsafe {
            let val = &*val_cell.get();
            match f(&*guard, val) {
                AlarmOrder::Never => {
                    // Alarm is disabled Unlink if
                    // we were previously waiting, and return not-ready. The
                    // future will pend forever unless the alarm is re-set.
                    if self.is_linked() {
                        self.unlink();
                    }
                    return false;
                }
                AlarmOrder::Now => {
                    // Clock has already reached the threshold. Unlink (we no
                    // longer need notification) and report ready.
                    if self.is_linked() {
                        self.unlink();
                    }
                    // Wake any previously stored waker (harmless spurious wake
                    // at worst; covers edge cases where an external set() raced).
                    self.typ.wake();
                    return true;
                }
                _ => (),
            };

            // Order is Later — clock hasn't reached our threshold yet.
            // Store / update the waker so set_clock can notify us.
            match waker {
                None => {
                    *waker = Some(cx.waker().clone());
                }
                Some(old_waker) => {
                    let new_waker = cx.waker();
                    if !old_waker.will_wake(new_waker) {
                        *waker = Some(new_waker.clone());
                    }
                }
            }

            // If we're already in the list, nothing more to do — just pend.
            if self.is_linked() {
                return false;
            }

            // Lazily initialise the head's self-link (circular sentinel) the
            // first time any alarm is linked.
            if !target.is_linked() {
                target.next.set_ref(target);
                target.prev.set_ref(target);
            }

            // Insert this node at the tail of the circular list (just before
            // the head). This is O(1) and order doesn't matter since set_clock
            // walks the full list anyway.
            if !self.is_linked() {
                let pn = target.prev.get_ref().unwrap();
                pn.next.set_ref(&*self);
                self.prev.set_ref(pn);
                self.next.set(target);
                target.prev.set_ref(&*self);
            }
        }
        false
    }

    /// Returns a reference to the current clock value.
    ///
    /// Acquires the head mutex to synchronize, then reads the value.
    ///
    /// # Safety note
    ///
    /// The returned `&T` outlives the lock guard. See [`get_alarm`](Self::get_alarm)
    /// for the rationale on why this is acceptable.
    fn get_clock<'a>(&'a self) -> &'a T {
        // Acquire the lock to synchronize-with any concurrent set_clock.
        let guard = self.typ.lock_target();
        unsafe { &*(&*guard as *const T) }
    }

    /// Sets the clock value and wakes any alarms whose thresholds are now met.
    ///
    /// If `advance_only` is `true`, the clock is only updated when `val` is
    /// strictly greater than the current value (i.e., the comparison function
    /// returns `Later`). Returns `false` if the update was suppressed.
    ///
    /// After updating, walks the linked alarm list under the lock and wakes
    /// every node whose threshold the new value reaches.
    fn set_clock<F>(&self, val: T, cmp: F, advance_only: bool) -> bool
    where
        F: Fn(&T, &T) -> AlarmOrder,
    {
        if !self.typ.is_head() {
            panic!("Can only set_clock on a head node");
        }
        let mut guard = self.typ.lock_target();

        // For advance_only, `cmp(current, new)` returns Later when new > current
        // (the "clock" hasn't reached the "alarm" yet, meaning the new value is
        // ahead). Any other result means new <= current, so we skip the update.
        let order = cmp(&*guard, &val);
        if advance_only && order != AlarmOrder::Later {
            return false;
        }
        *guard = val;
        unsafe {
            // If no alarms are linked, we're done.
            if !self.is_linked() {
                return true;
            }
            // Walk the circular list starting from the first node after head.
            // We advance `pn` *before* potentially unlinking the current node,
            // since unlink invalidates the current node's next pointer.
            let mut pn = self.next.get();
            while !(*pn).typ.is_head() {
                let n = &*pn;
                pn = n.next.get();
                if let NodeType::Node { val, waker, .. } = &n.typ {
                    match cmp(&*guard, &*val.get()) {
                        AlarmOrder::Never => {
                            // Shouldn't happen (node wouldn't be linked with a
                            // Never threshold), but defensively clean up.
                            n.unlink();
                        }
                        AlarmOrder::Now => {
                            n.unlink();
                            if let Some(w) = (*waker.get()).take() {
                                w.wake();
                            }
                        }
                        AlarmOrder::Later => (),
                    }
                }
            }
        }
        true
    }
}

impl<T> Drop for AlarmNode<T> {
    fn drop(&mut self) {
        // Acquire the head mutex and unlink ourselves so no dangling pointers
        // remain in the list. For a head node this tears down the entire list.
        unsafe {
            let _guard = self.typ.lock_target();
            self.unlink();
        };
    }
}

// ===========================================================================
// AlarmClock and ClockAlarm
//
// Public API: alarms triggered when a monotonically increasing value meets or
// exceeds the alarm threshold.
// ===========================================================================

/// Comparison function for [`AlarmClock`] / [`ClockAlarm`].
///
/// Interprets `clock` and `alarm` as `Option<T>` where:
/// - `alarm = None` → `Never`  (no threshold set, alarm disabled)
/// - `clock = None` → `Later`  (clock not started, may fire later)
/// - `clock >= alarm` → `Now`  (threshold reached)
/// - otherwise → `Later`
fn alarm_clock_order<T: PartialOrd>(clock: &Option<T>, alarm: &Option<T>) -> AlarmOrder {
    match alarm {
        None => AlarmOrder::Never,
        Some(a) => match clock {
            None => AlarmOrder::Later,
            Some(c) => {
                if *c >= *a {
                    AlarmOrder::Now
                } else {
                    AlarmOrder::Later
                }
            }
        },
    }
}

/// A shared, monotonically-increasing clock that can wake [`ClockAlarm`] futures.
///
/// The clock value is protected by a mutex and can be read or advanced from any
/// thread. When the value advances past an alarm's threshold, the alarm's waker
/// is invoked, causing the corresponding future to resolve.
///
/// # Pinning
///
/// An `AlarmClock` must be pinned (e.g. via [`pin!`](std::pin::pin) or
/// [`Box::pin`]) before any [`ClockAlarm`] can be created against it, because
/// alarms store raw pointers back to the clock's internal node.
///
/// # Example
///
/// ```rust,ignore
/// use std::pin::pin;
/// use smallware_tunnel::alarms::{AlarmClock, ClockAlarm};
///
/// let clock = pin!(AlarmClock::new(0u64));
/// let alarm = pin!(ClockAlarm::new(clock.as_ref(), Some(10)));
///
/// // Later, when time advances:
/// clock.set(10);
/// // `alarm` will resolve on next poll.
/// ```
pub struct AlarmClock<T: PartialOrd> {
    head: AlarmNode<Option<T>>,
}

impl<T: PartialOrd> AlarmClock<T> {
    /// Creates a new alarm clock with the given initial value.
    pub fn new(val: T) -> Self {
        Self {
            head: AlarmNode::new_head(Some(val)),
        }
    }

    /// Sets the clock to `val` unconditionally, waking any alarms whose
    /// thresholds are now met.
    ///
    /// Unlike [`advance`](Self::advance), this allows setting the clock to a
    /// value less than or equal to the current value.
    #[inline(always)]
    pub fn set(&self, val: T) {
        self.head.set_clock(Some(val), alarm_clock_order, false);
    }

    /// Returns a reference to the current clock value.
    ///
    /// # Note
    ///
    /// The returned reference is synchronized via an internal lock acquire, but
    /// the lock is not held for the lifetime of the reference. This is safe when
    /// the clock is only mutated from a single task (the typical usage pattern).
    // TODO more safety
    #[inline(always)]
    pub fn get(&self) -> &T {
        self.head.get_clock().as_ref().unwrap()
    }

    /// Advances the clock to `val` only if `val` is strictly greater than the
    /// current value.
    ///
    /// Returns `true` if the clock was updated, `false` if `val` was not greater.
    /// Any alarms whose thresholds are now met are woken.
    #[inline(always)]
    pub fn advance(&self, val: T) -> bool {
        self.head.set_clock(Some(val), alarm_clock_order, true)
    }
}

impl<T: PartialOrd + Debug> Debug for AlarmClock<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let g = self.head.typ.lock_target();
        f.debug_struct("AlarmClock").field("val", &*g).finish()
    }
}

/// A future that resolves when an [`AlarmClock`]'s value reaches a threshold.
///
/// Created via [`ClockAlarm::new`] with a reference to a pinned `AlarmClock`.
/// The alarm threshold can be changed at any time via [`set`](Self::set), and
/// setting it to `None` disables the alarm (the future will pend indefinitely).
///
/// `ClockAlarm` implements [`Future`], resolving to `()` when the clock value
/// is `>=` the threshold. It also provides [`poll_ref`](Self::poll_ref) for
/// polling through a `Pin<&mut Self>` without consuming the future.
///
/// # Pinning
///
/// The `ClockAlarm` must be pinned before polling, because it participates in
/// an intrusive linked list via raw pointers.
///
/// # Lifetime
///
/// The `'a` lifetime ties this alarm to its parent clock, ensuring the clock
/// is not dropped while alarms reference it.
pub struct ClockAlarm<'a, T: PartialOrd> {
    node: AlarmNode<Option<T>>,
    _lifetime: PhantomData<&'a AlarmClock<T>>,
}

impl<'a, T: PartialOrd> ClockAlarm<'a, T> {
    /// Creates a new alarm against the given pinned clock.
    ///
    /// `wake_at` is the threshold value; the alarm fires when the clock reaches
    /// or exceeds it. Pass `None` to create a disabled alarm that can be armed
    /// later via [`set`](Self::set).
    pub fn new(clock: Pin<&'a AlarmClock<T>>, wake_at: Option<T>) -> Self {
        let head_pin = unsafe { Pin::new_unchecked(&clock.head) };
        Self {
            node: AlarmNode::new_node(head_pin, wake_at),
            _lifetime: PhantomData,
        }
    }

    /// Changes the alarm threshold.
    ///
    /// If the new threshold is already met by the current clock value, the
    /// stored waker is invoked immediately. If set to `None`, the alarm is
    /// disabled and unlinked from the notification list.
    pub fn set(&self, wake_at: Option<T>) {
        self.node.set_alarm(alarm_clock_order, wake_at);
    }

    /// Returns the current alarm threshold, or `None` if disabled.
    pub fn get(&self) -> Option<&T> {
        self.node.get_alarm().as_ref()
    }

    /// Polls the alarm without consuming the pin.
    ///
    /// This is useful when you need to poll the alarm from a `select!` or
    /// similar combinator that provides `&Pin<&mut Self>` rather than
    /// consuming the `Pin<&mut Self>`.
    ///
    /// Returns [`Poll::Ready`] if the clock has reached the threshold,
    /// [`Poll::Pending`] otherwise.
    pub fn poll_ref(self: &Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<()> {
        let node_pin = unsafe { Pin::new_unchecked(&self.node) };
        match node_pin.check_alarm(cx, alarm_clock_order) {
            true => Poll::Ready(()),
            false => Poll::Pending,
        }
    }
}

impl<'a, T: PartialOrd> Future for ClockAlarm<'a, T> {
    type Output = ();

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.poll_ref(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::pin;
    use std::sync::Arc;
    use std::task::{Wake, Waker};
    use std::sync::atomic::{AtomicUsize, Ordering};

    // -----------------------------------------------------------------------
    // Test waker that counts wake() calls
    // -----------------------------------------------------------------------
    struct TestWaker {
        wake_count: AtomicUsize,
    }

    impl TestWaker {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                wake_count: AtomicUsize::new(0),
            })
        }

        fn count(&self) -> usize {
            self.wake_count.load(Ordering::SeqCst)
        }
    }

    impl Wake for TestWaker {
        fn wake(self: Arc<Self>) {
            self.wake_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Helper: poll a ClockAlarm and return the Poll result.
    fn poll_alarm<T: PartialOrd>(
        alarm: &mut Pin<&mut ClockAlarm<'_, T>>,
        waker: &Waker,
    ) -> Poll<()> {
        let mut cx = Context::from_waker(waker);
        alarm.as_mut().poll(&mut cx)
    }

    /// Helper: call AlarmClock::set through a Pin<&mut AlarmClock> without
    /// accidentally hitting Pin::set (which expects a whole AlarmClock value).
    fn clock_set(clock: &Pin<&mut AlarmClock<u64>>, val: u64) {
        clock.as_ref().get_ref().set(val);
    }

    /// Helper: call ClockAlarm::set through a Pin<&mut ClockAlarm>.
    fn alarm_set(alarm: &Pin<&mut ClockAlarm<'_, u64>>, val: Option<u64>) {
        alarm.as_ref().get_ref().set(val);
    }

    // -----------------------------------------------------------------------
    // AlarmOrder tests
    // -----------------------------------------------------------------------

    #[test]
    fn alarm_clock_order_none_alarm_is_never() {
        assert_eq!(
            alarm_clock_order::<u64>(&Some(10), &None),
            AlarmOrder::Never
        );
        assert_eq!(
            alarm_clock_order::<u64>(&None, &None),
            AlarmOrder::Never
        );
    }

    #[test]
    fn alarm_clock_order_none_clock_is_later() {
        assert_eq!(
            alarm_clock_order::<u64>(&None, &Some(10)),
            AlarmOrder::Later
        );
    }

    #[test]
    fn alarm_clock_order_clock_ge_alarm_is_now() {
        assert_eq!(
            alarm_clock_order(&Some(10u64), &Some(10)),
            AlarmOrder::Now
        );
        assert_eq!(
            alarm_clock_order(&Some(15u64), &Some(10)),
            AlarmOrder::Now
        );
    }

    #[test]
    fn alarm_clock_order_clock_lt_alarm_is_later() {
        assert_eq!(
            alarm_clock_order(&Some(5u64), &Some(10)),
            AlarmOrder::Later
        );
    }

    // -----------------------------------------------------------------------
    // AlarmClock basic tests
    // -----------------------------------------------------------------------

    #[test]
    fn alarm_clock_new_and_get() {
        let clock = AlarmClock::new(42u64);
        assert_eq!(*clock.get(), 42);
    }

    #[test]
    fn alarm_clock_set() {
        let clock = AlarmClock::new(0u64);
        clock.set(100);
        assert_eq!(*clock.get(), 100);
        // set allows going backwards
        clock.set(50);
        assert_eq!(*clock.get(), 50);
    }

    #[test]
    fn alarm_clock_advance_only_forward() {
        let clock = AlarmClock::new(10u64);
        // Advance to a larger value succeeds
        assert!(clock.advance(20));
        assert_eq!(*clock.get(), 20);
        // Advance to same value fails
        assert!(!clock.advance(20));
        assert_eq!(*clock.get(), 20);
        // Advance to smaller value fails
        assert!(!clock.advance(5));
        assert_eq!(*clock.get(), 20);
    }

    #[test]
    fn alarm_clock_debug() {
        let clock = AlarmClock::new(99u64);
        let dbg = format!("{:?}", clock);
        assert!(dbg.contains("AlarmClock"));
        assert!(dbg.contains("99"));
    }

    // -----------------------------------------------------------------------
    // ClockAlarm creation and get/set
    // -----------------------------------------------------------------------

    #[test]
    fn clock_alarm_new_and_get() {
        let clock = pin!(AlarmClock::new(0u64));
        let alarm = ClockAlarm::new(clock.as_ref(), Some(10));
        assert_eq!(alarm.get(), Some(&10));
    }

    #[test]
    fn clock_alarm_new_none_threshold() {
        let clock = pin!(AlarmClock::new(0u64));
        let alarm = ClockAlarm::new(clock.as_ref(), None);
        assert_eq!(alarm.get(), None);
    }

    #[test]
    fn clock_alarm_set_threshold() {
        let clock = pin!(AlarmClock::new(0u64));
        let alarm = ClockAlarm::new(clock.as_ref(), Some(10));
        alarm.set(Some(20));
        assert_eq!(alarm.get(), Some(&20));
        alarm.set(None);
        assert_eq!(alarm.get(), None);
    }

    // -----------------------------------------------------------------------
    // Polling tests
    // -----------------------------------------------------------------------

    #[test]
    fn poll_pending_when_clock_below_threshold() {
        let clock = pin!(AlarmClock::new(0u64));
        let alarm = ClockAlarm::new(clock.as_ref(), Some(10));
        let mut alarm = pin!(alarm);
        let tw = TestWaker::new();
        let waker = Waker::from(tw.clone());

        assert_eq!(poll_alarm(&mut alarm, &waker), Poll::Pending);
    }

    #[test]
    fn poll_ready_when_clock_at_threshold() {
        let clock = pin!(AlarmClock::new(10u64));
        let alarm = ClockAlarm::new(clock.as_ref(), Some(10));
        let mut alarm = pin!(alarm);
        let tw = TestWaker::new();
        let waker = Waker::from(tw.clone());

        assert_eq!(poll_alarm(&mut alarm, &waker), Poll::Ready(()));
    }

    #[test]
    fn poll_ready_when_clock_above_threshold() {
        let clock = pin!(AlarmClock::new(20u64));
        let alarm = ClockAlarm::new(clock.as_ref(), Some(10));
        let mut alarm = pin!(alarm);
        let tw = TestWaker::new();
        let waker = Waker::from(tw.clone());

        assert_eq!(poll_alarm(&mut alarm, &waker), Poll::Ready(()));
    }

    #[test]
    fn poll_pending_when_threshold_is_none() {
        let clock = pin!(AlarmClock::new(100u64));
        let alarm = ClockAlarm::new(clock.as_ref(), None);
        let mut alarm = pin!(alarm);
        let tw = TestWaker::new();
        let waker = Waker::from(tw.clone());

        // Even with a large clock value, None threshold means Never → Pending
        assert_eq!(poll_alarm(&mut alarm, &waker), Poll::Pending);
    }

    // -----------------------------------------------------------------------
    // Wake notification tests
    // -----------------------------------------------------------------------

    #[test]
    fn advance_clock_wakes_alarm() {
        let clock = pin!(AlarmClock::new(0u64));
        let alarm = ClockAlarm::new(clock.as_ref(), Some(10));
        let mut alarm = pin!(alarm);
        let tw = TestWaker::new();
        let waker = Waker::from(tw.clone());

        // First poll: pending, registers waker
        assert_eq!(poll_alarm(&mut alarm, &waker), Poll::Pending);
        assert_eq!(tw.count(), 0);

        // Advance clock past threshold
        clock_set(&clock, 10);

        // Waker should have been called
        assert_eq!(tw.count(), 1);

        // Next poll: ready
        assert_eq!(poll_alarm(&mut alarm, &waker), Poll::Ready(()));
    }

    #[test]
    fn advance_clock_below_threshold_does_not_wake() {
        let clock = pin!(AlarmClock::new(0u64));
        let alarm = ClockAlarm::new(clock.as_ref(), Some(10));
        let mut alarm = pin!(alarm);
        let tw = TestWaker::new();
        let waker = Waker::from(tw.clone());

        assert_eq!(poll_alarm(&mut alarm, &waker), Poll::Pending);

        // Advance, but not enough
        clock_set(&clock, 5);
        assert_eq!(tw.count(), 0);

        // Still pending
        assert_eq!(poll_alarm(&mut alarm, &waker), Poll::Pending);
    }

    #[test]
    fn set_alarm_to_already_passed_value_wakes() {
        let clock = pin!(AlarmClock::new(50u64));
        let alarm = ClockAlarm::new(clock.as_ref(), Some(100));
        let mut alarm = pin!(alarm);
        let tw = TestWaker::new();
        let waker = Waker::from(tw.clone());

        // Poll to register the waker
        assert_eq!(poll_alarm(&mut alarm, &waker), Poll::Pending);
        assert_eq!(tw.count(), 0);

        // Change the alarm threshold to something already passed
        alarm_set(&alarm, Some(30));

        // set_alarm with Now should have woken us
        assert_eq!(tw.count(), 1);

        // Next poll should be ready
        assert_eq!(poll_alarm(&mut alarm, &waker), Poll::Ready(()));
    }

    #[test]
    fn set_alarm_to_none_does_not_wake() {
        let clock = pin!(AlarmClock::new(50u64));
        let alarm = ClockAlarm::new(clock.as_ref(), Some(100));
        let mut alarm = pin!(alarm);
        let tw = TestWaker::new();
        let waker = Waker::from(tw.clone());

        assert_eq!(poll_alarm(&mut alarm, &waker), Poll::Pending);

        // Disable the alarm
        alarm_set(&alarm, None);
        // Never → no wake
        assert_eq!(tw.count(), 0);

        // Still pending (disabled)
        assert_eq!(poll_alarm(&mut alarm, &waker), Poll::Pending);
    }

    // -----------------------------------------------------------------------
    // Multiple alarms
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_alarms_different_thresholds() {
        let clock = pin!(AlarmClock::new(0u64));

        let a1 = ClockAlarm::new(clock.as_ref(), Some(5));
        let a2 = ClockAlarm::new(clock.as_ref(), Some(10));
        let a3 = ClockAlarm::new(clock.as_ref(), Some(15));
        let mut a1 = pin!(a1);
        let mut a2 = pin!(a2);
        let mut a3 = pin!(a3);

        let tw1 = TestWaker::new();
        let tw2 = TestWaker::new();
        let tw3 = TestWaker::new();
        let w1 = Waker::from(tw1.clone());
        let w2 = Waker::from(tw2.clone());
        let w3 = Waker::from(tw3.clone());

        // All pending
        assert_eq!(poll_alarm(&mut a1, &w1), Poll::Pending);
        assert_eq!(poll_alarm(&mut a2, &w2), Poll::Pending);
        assert_eq!(poll_alarm(&mut a3, &w3), Poll::Pending);

        // Advance to 5: only a1 fires
        clock_set(&clock, 5);
        assert_eq!(tw1.count(), 1);
        assert_eq!(tw2.count(), 0);
        assert_eq!(tw3.count(), 0);
        assert_eq!(poll_alarm(&mut a1, &w1), Poll::Ready(()));
        assert_eq!(poll_alarm(&mut a2, &w2), Poll::Pending);
        assert_eq!(poll_alarm(&mut a3, &w3), Poll::Pending);

        // Advance to 12: a2 fires, a3 still pending
        clock_set(&clock, 12);
        assert_eq!(tw2.count(), 1);
        assert_eq!(tw3.count(), 0);
        assert_eq!(poll_alarm(&mut a2, &w2), Poll::Ready(()));
        assert_eq!(poll_alarm(&mut a3, &w3), Poll::Pending);

        // Advance to 20: a3 fires
        clock_set(&clock, 20);
        assert_eq!(tw3.count(), 1);
        assert_eq!(poll_alarm(&mut a3, &w3), Poll::Ready(()));
    }

    #[test]
    fn multiple_alarms_same_threshold() {
        let clock = pin!(AlarmClock::new(0u64));
        let a1 = ClockAlarm::new(clock.as_ref(), Some(10));
        let a2 = ClockAlarm::new(clock.as_ref(), Some(10));
        let mut a1 = pin!(a1);
        let mut a2 = pin!(a2);

        let tw1 = TestWaker::new();
        let tw2 = TestWaker::new();
        let w1 = Waker::from(tw1.clone());
        let w2 = Waker::from(tw2.clone());

        assert_eq!(poll_alarm(&mut a1, &w1), Poll::Pending);
        assert_eq!(poll_alarm(&mut a2, &w2), Poll::Pending);

        clock_set(&clock, 10);
        assert_eq!(tw1.count(), 1);
        assert_eq!(tw2.count(), 1);
        assert_eq!(poll_alarm(&mut a1, &w1), Poll::Ready(()));
        assert_eq!(poll_alarm(&mut a2, &w2), Poll::Ready(()));
    }

    // -----------------------------------------------------------------------
    // Re-arm after firing
    // -----------------------------------------------------------------------

    #[test]
    fn alarm_can_be_rearmed_after_firing() {
        let clock = pin!(AlarmClock::new(0u64));
        let alarm = ClockAlarm::new(clock.as_ref(), Some(5));
        let mut alarm = pin!(alarm);
        let tw = TestWaker::new();
        let waker = Waker::from(tw.clone());

        assert_eq!(poll_alarm(&mut alarm, &waker), Poll::Pending);
        clock_set(&clock, 5);
        assert_eq!(poll_alarm(&mut alarm, &waker), Poll::Ready(()));

        // Re-arm with a new threshold
        alarm_set(&alarm, Some(20));
        assert_eq!(poll_alarm(&mut alarm, &waker), Poll::Pending);

        clock_set(&clock, 20);
        assert_eq!(tw.count(), 2); // woken twice total
        assert_eq!(poll_alarm(&mut alarm, &waker), Poll::Ready(()));
    }

    // -----------------------------------------------------------------------
    // Drop safety
    // -----------------------------------------------------------------------

    #[test]
    fn drop_alarm_while_linked() {
        let clock = pin!(AlarmClock::new(0u64));
        let tw = TestWaker::new();
        let waker = Waker::from(tw.clone());

        {
            let alarm = ClockAlarm::new(clock.as_ref(), Some(10));
            let mut alarm = pin!(alarm);
            assert_eq!(poll_alarm(&mut alarm, &waker), Poll::Pending);
            // alarm is linked and dropped here
        }

        // Clock advance should not panic (the dropped alarm was properly unlinked)
        clock_set(&clock, 10);
        assert_eq!(tw.count(), 0); // waker was taken during drop/unlink
    }

    #[test]
    fn drop_alarm_before_polling() {
        let clock = pin!(AlarmClock::new(0u64));
        {
            let _alarm = ClockAlarm::new(clock.as_ref(), Some(10));
            // Never polled, just dropped
        }
        // Should not panic
        clock_set(&clock, 100);
    }

    #[test]
    fn drop_multiple_alarms() {
        let clock = pin!(AlarmClock::new(0u64));
        let tw = TestWaker::new();
        let waker = Waker::from(tw.clone());

        {
            let a1 = ClockAlarm::new(clock.as_ref(), Some(10));
            let mut a1 = pin!(a1);
            {
                let a2 = ClockAlarm::new(clock.as_ref(), Some(20));
                let mut a2 = pin!(a2);

                assert_eq!(poll_alarm(&mut a1, &waker), Poll::Pending);
                assert_eq!(poll_alarm(&mut a2, &waker), Poll::Pending);
                // a2 drops here while both are linked
            }
            // a1 should still work
            clock_set(&clock, 10);
            assert_eq!(poll_alarm(&mut a1, &waker), Poll::Ready(()));
        }
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn poll_ready_immediately_no_waker_stored() {
        // If the clock already meets the threshold on first poll, the alarm
        // should return Ready without storing a waker.
        let clock = pin!(AlarmClock::new(100u64));
        let alarm = ClockAlarm::new(clock.as_ref(), Some(50));
        let mut alarm = pin!(alarm);
        let tw = TestWaker::new();
        let waker = Waker::from(tw.clone());

        assert_eq!(poll_alarm(&mut alarm, &waker), Poll::Ready(()));
        // No spurious wakes
        assert_eq!(tw.count(), 0);
    }

    #[test]
    fn repoll_pending_alarm_updates_waker() {
        // Polling twice with different wakers should update the stored waker.
        let clock = pin!(AlarmClock::new(0u64));
        let alarm = ClockAlarm::new(clock.as_ref(), Some(10));
        let mut alarm = pin!(alarm);

        let tw1 = TestWaker::new();
        let w1 = Waker::from(tw1.clone());
        assert_eq!(poll_alarm(&mut alarm, &w1), Poll::Pending);

        let tw2 = TestWaker::new();
        let w2 = Waker::from(tw2.clone());
        assert_eq!(poll_alarm(&mut alarm, &w2), Poll::Pending);

        // Advance: should wake tw2, not tw1
        clock_set(&clock, 10);
        assert_eq!(tw1.count(), 0);
        assert_eq!(tw2.count(), 1);
    }

    #[test]
    fn advance_does_not_go_backwards() {
        let clock = pin!(AlarmClock::new(10u64));
        let alarm = ClockAlarm::new(clock.as_ref(), Some(5));
        let mut alarm = pin!(alarm);
        let tw = TestWaker::new();
        let waker = Waker::from(tw.clone());

        // Already past threshold
        assert_eq!(poll_alarm(&mut alarm, &waker), Poll::Ready(()));

        // Re-arm alarm at 15
        alarm_set(&alarm, Some(15));
        assert_eq!(poll_alarm(&mut alarm, &waker), Poll::Pending);

        // Try to advance backwards — should fail
        assert!(!clock.advance(5));
        assert_eq!(*clock.get(), 10);
        assert_eq!(tw.count(), 0);

        // Advance forward
        assert!(clock.advance(15));
        assert_eq!(tw.count(), 1);
    }

    #[test]
    fn set_clock_backwards_wakes_appropriate_alarms() {
        let clock = pin!(AlarmClock::new(0u64));
        let alarm = ClockAlarm::new(clock.as_ref(), Some(10));
        let mut alarm = pin!(alarm);
        let tw = TestWaker::new();
        let waker = Waker::from(tw.clone());

        assert_eq!(poll_alarm(&mut alarm, &waker), Poll::Pending);

        // Set clock to 20, alarm at 10 should fire
        clock_set(&clock, 20);
        assert_eq!(tw.count(), 1);
        assert_eq!(poll_alarm(&mut alarm, &waker), Poll::Ready(()));

        // Re-arm at 30
        alarm_set(&alarm, Some(30));
        assert_eq!(poll_alarm(&mut alarm, &waker), Poll::Pending);

        // Set clock backwards to 5 — alarm at 30 should NOT fire
        clock_set(&clock, 5);
        assert_eq!(tw.count(), 1); // unchanged
        assert_eq!(poll_alarm(&mut alarm, &waker), Poll::Pending);
    }

    // -----------------------------------------------------------------------
    // Tokio integration test
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn tokio_alarm_resolves() {
        let clock = pin!(AlarmClock::new(0u64));
        let clock_ref = clock.as_ref();

        let mut alarm = pin!(ClockAlarm::new(clock_ref, Some(10)));

        // Convert to usize to make it Send; SAFETY: clock outlives the spawned task
        // and AlarmClock is Sync (via AlarmNode's unsafe impl).
        let addr = clock_ref.get_ref() as *const AlarmClock<u64> as usize;
        let handle = tokio::task::spawn_blocking(move || {
            std::thread::sleep(std::time::Duration::from_millis(50));
            unsafe { &*(addr as *const AlarmClock<u64>) }.set(10);
        });

        alarm.as_mut().await;
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn tokio_multiple_alarms_resolve_in_order() {
        let clock = pin!(AlarmClock::new(0u64));
        let clock_ref = clock.as_ref();

        let mut a1 = pin!(ClockAlarm::new(clock_ref, Some(5)));
        let mut a2 = pin!(ClockAlarm::new(clock_ref, Some(10)));

        let addr = clock_ref.get_ref() as *const AlarmClock<u64> as usize;
        tokio::task::spawn_blocking(move || {
            std::thread::sleep(std::time::Duration::from_millis(30));
            let clock = unsafe { &*(addr as *const AlarmClock<u64>) };
            clock.set(5);
            std::thread::sleep(std::time::Duration::from_millis(30));
            clock.set(10);
        });

        a1.as_mut().await;
        a2.as_mut().await;
    }

    // -----------------------------------------------------------------------
    // poll_ref tests
    // -----------------------------------------------------------------------

    #[test]
    fn poll_ref_returns_pending_then_ready() {
        let clock = pin!(AlarmClock::new(0u64));
        let alarm = ClockAlarm::new(clock.as_ref(), Some(10));
        let mut alarm = pin!(alarm);
        let tw = TestWaker::new();
        let waker = Waker::from(tw.clone());
        let mut cx = Context::from_waker(&waker);

        assert_eq!(alarm.as_mut().poll_ref(&mut cx), Poll::Pending);
        clock_set(&clock, 10);
        assert_eq!(alarm.as_mut().poll_ref(&mut cx), Poll::Ready(()));
    }
}
