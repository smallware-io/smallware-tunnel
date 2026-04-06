//! Alarm clock primitives for async timeout management, built on the generic
//! intrusive linked list in [`crate::intrusive_list`].
//!
//! This module provides [`AlarmClock`] and [`ClockAlarm`], a pair of types that
//! implement an efficient, mutex-synchronized alarm system.  An [`AlarmClock`]
//! holds a monotonically increasing clock value, and any number of
//! [`ClockAlarm`] futures can register thresholds to be woken when the clock
//! reaches or exceeds their target.
//!
//! # Architecture
//!
//! [`ClockNodeValue`] is the [`IntrusiveNodeValue`] implementation that drives
//! the list.  Every `AlarmClock` owns a *head* [`IntrusiveListNode`], and every
//! `ClockAlarm` owns a *leaf* node.  The head node's `ClockNodeValue` contains
//! a [`Mutex`] protecting the current clock value; leaf nodes store their alarm
//! threshold and a [`Waker`] in `UnsafeCell`s.
//!
//! When the clock advances, [`AlarmClock::set`] / [`AlarmClock::advance`] walk
//! the linked list via [`IntrusiveListGuard::filter`] and wake every alarm
//! whose threshold has been met.  When a `ClockAlarm` is polled, it checks the
//! threshold under the lock and links itself into the list if it needs to wait.
//!
//! # Safety
//!
//! `AlarmClock` must be pinned before creating any `ClockAlarm` against it,
//! and `ClockAlarm` must be pinned before polling, because the list stores
//! raw pointers to the nodes' addresses.

use crate::intrusive_list::{IntrusiveListNode, IntrusiveNodeValue};
use parking_lot::Mutex;
use std::{
    cell::UnsafeCell,
    fmt::Debug,
    future::Future,
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll, Waker},
};

// ---------------------------------------------------------------------------
// ClockNodeValue — IntrusiveNodeValue implementation for AlarmClock / ClockAlarm
// ---------------------------------------------------------------------------

/// The [`IntrusiveNodeValue`] implementation used by [`AlarmClock`] and
/// [`ClockAlarm`].
///
/// Head nodes hold a `Mutex<T>` protecting the current clock value.
/// Leaf nodes store an alarm threshold (`Option<T>`), a [`Waker`], and a raw
/// pointer back to the head node.  `None` disables the alarm; comparisons
/// use `PartialOrd`.
enum ClockNodeValue<T: PartialOrd + Clone> {
    /// The sentinel head node.  Owns the mutex that protects the clock value
    /// and synchronises all list mutations.
    Head { mutex: Mutex<T> },
    /// A leaf (alarm) node.  Stores the alarm threshold in `val`, a waker to
    /// notify when the alarm fires, and a raw pointer back to the head node
    /// so it can acquire the mutex.
    Node {
        // SAFETY: The `ClockAlarm` constructor ensures that the target (head)
        // is pinned and outlives this node via the `'a` lifetime parameter.
        target: *const IntrusiveListNode<ClockNodeValue<T>>,
        val: UnsafeCell<Option<T>>,
        waker: UnsafeCell<Option<Waker>>,
    },
}

impl<T: PartialOrd + Clone> ClockNodeValue<T> {
    /// Creates a head-node value with the given initial clock value.
    fn new_head(val: T) -> Self {
        ClockNodeValue::Head {
            mutex: Mutex::new(val),
        }
    }

    /// Creates a leaf-node value targeting the given pinned head node.
    ///
    /// # Safety
    ///
    /// `target` must point to a pinned head node that outlives this leaf.
    fn new_node(target: *const IntrusiveListNode<Self>, val: Option<T>) -> Self {
        ClockNodeValue::Node {
            target,
            val: UnsafeCell::new(val),
            waker: UnsafeCell::new(None),
        }
    }

    /// Returns a reference to the leaf's stored alarm value.
    ///
    /// # Safety
    ///
    /// Caller must hold the head mutex.  Only valid on leaf nodes.
    unsafe fn get_val(&self) -> &Option<T> {
        match self {
            ClockNodeValue::Node { val, .. } => &*val.get(),
            ClockNodeValue::Head { .. } => panic!("get_val called on head node"),
        }
    }

    /// Overwrites the leaf's stored alarm value.
    ///
    /// # Safety
    ///
    /// Caller must hold the head mutex.  Only valid on leaf nodes.
    unsafe fn set_val(&self, new_val: Option<T>) {
        match self {
            ClockNodeValue::Node { val, .. } => *val.get() = new_val,
            ClockNodeValue::Head { .. } => panic!("set_val called on head node"),
        }
    }

    /// Takes the stored waker (if any) and wakes it.
    ///
    /// No-op on head nodes.
    ///
    /// # Safety
    ///
    /// Caller must hold the head mutex.
    unsafe fn wake(&self) {
        if let ClockNodeValue::Node { waker, .. } = self {
            if let Some(w) = (*waker.get()).take() {
                w.wake();
            }
        }
    }

    /// Returns a mutable reference to the leaf's stored waker slot.
    ///
    /// # Safety
    ///
    /// Caller must hold the head mutex.  Only valid on leaf nodes.
    unsafe fn get_waker(&self) -> &mut Option<Waker> {
        match self {
            ClockNodeValue::Node { waker, .. } => &mut *waker.get(),
            ClockNodeValue::Head { .. } => panic!("get_waker called on head node"),
        }
    }
}

impl<T: PartialOrd + Clone> IntrusiveNodeValue for ClockNodeValue<T> {
    type HeadValue = T;

    fn lock_mutex(&self) -> parking_lot::MutexGuard<'_, T> {
        match self {
            ClockNodeValue::Head { mutex } => mutex.lock(),
            ClockNodeValue::Node { .. } => panic!("lock_mutex called on leaf node"),
        }
    }

    fn target_node(&self) -> Option<&IntrusiveListNode<Self>> {
        unsafe {
            match self {
                ClockNodeValue::Node { target, .. } => Some(&**target),
                ClockNodeValue::Head { .. } => None,
            }
        }
    }
}

// ===========================================================================
// AlarmClock and ClockAlarm
//
// Public API: alarms triggered when a monotonically increasing value meets or
// exceeds the alarm threshold.
// ===========================================================================

/// A shared, monotonically-increasing clock that can wake [`ClockAlarm`] futures.
///
/// The clock value is protected by a mutex and can be read or advanced from any
/// thread.  When the value advances past an alarm's threshold, the alarm's waker
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
pub struct AlarmClock<T: PartialOrd + Clone> {
    head: IntrusiveListNode<ClockNodeValue<T>>,
}

impl<T: PartialOrd + Clone> AlarmClock<T> {
    /// Creates a new alarm clock with the given initial value.
    pub fn new(val: T) -> Self {
        Self {
            head: IntrusiveListNode::new(ClockNodeValue::new_head(val)),
        }
    }

    /// Sets the clock to `val` unconditionally, waking any alarms whose
    /// thresholds are now met.
    ///
    /// Unlike [`advance`](Self::advance), this allows setting the clock to a
    /// value less than or equal to the current value.
    pub fn set(&self, val: T) {
        let mut guard = self.head.lock_head();
        *guard = val;
        unsafe {
            guard.filter(|node| match node.get_val() {
                Some(a) if *guard >= *a => {
                    node.wake();
                    false
                }
                None => {
                    node.wake();
                    false
                }
                _ => true,
            });
        }
    }

    /// Returns a reference to the current clock value.
    ///
    /// # Note
    ///
    /// The returned reference is synchronized via an internal lock acquire, but
    /// the lock is not held for the lifetime of the reference.  This is safe when
    /// the clock is only mutated from a single task (the typical usage pattern).
    // TODO more safety
    #[inline(always)]
    pub fn get(&self) -> T {
        let guard = self.head.lock_head();
        (*guard).clone()
    }

    /// Advances the clock to `val` only if `val` is strictly greater than the
    /// current value.
    ///
    /// Returns `true` if the clock was updated, `false` if `val` was not greater.
    /// Any alarms whose thresholds are now met are woken.
    pub fn advance(&self, val: T) -> bool {
        let mut guard = self.head.lock_head();
        if *guard >= val {
            return false;
        }
        *guard = val;
        unsafe {
            guard.filter(|node| match node.get_val() {
                Some(a) if *guard >= *a => {
                    node.wake();
                    false
                }
                None => {
                    node.wake();
                    false
                }
                _ => true,
            });
        }
        true
    }
}

impl<T: PartialOrd + Clone + Debug> Debug for AlarmClock<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let g = self.head.lock_head();
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
/// is `>=` the threshold.  It also provides [`poll_ref`](Self::poll_ref) for
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
pub struct ClockAlarm<'a, T: PartialOrd + Clone> {
    node: IntrusiveListNode<ClockNodeValue<T>>,
    _lifetime: PhantomData<&'a AlarmClock<T>>,
}

impl<'a, T: PartialOrd + Clone> ClockAlarm<'a, T> {
    /// Creates a new alarm against the given pinned clock.
    ///
    /// `wake_at` is the threshold value; the alarm fires when the clock reaches
    /// or exceeds it.  Pass `None` to create a disabled alarm that can be armed
    /// later via [`set`](Self::set).
    pub fn new(clock: Pin<&'a AlarmClock<T>>, wake_at: Option<T>) -> Self {
        let head_ref = unsafe { &*Pin::into_inner_unchecked(clock) };
        Self {
            node: IntrusiveListNode::new(ClockNodeValue::new_node(
                &head_ref.head as *const IntrusiveListNode<ClockNodeValue<T>>,
                wake_at,
            )),
            _lifetime: PhantomData,
        }
    }

    /// Changes the alarm threshold.
    ///
    /// If the new threshold is already met by the current clock value, the
    /// stored waker is invoked immediately.  If set to `None`, the alarm is
    /// disabled and unlinked from the notification list.
    pub fn set(&self, wake_at: Option<T>) {
        let guard = self.node.lock_head();
        unsafe {
            match &wake_at {
                None => {
                    guard.unlink(&self.node);
                }
                Some(alarm) => {
                    if *guard >= *alarm {
                        guard.unlink(&self.node);
                        self.node.typ.wake();
                    }
                }
            }
            self.node.typ.set_val(wake_at);
        }
    }

    /// Returns the current alarm threshold, or `None` if disabled.
    pub fn get(&self) -> Option<&T> {
        let _guard = self.node.lock_head();
        unsafe { self.node.typ.get_val().as_ref() }
    }

    /// Polls the alarm without consuming the pin.
    ///
    /// This is useful when you need to poll the alarm from a `select!` or
    /// similar combinator that provides `&Pin<&mut Self>` rather than
    /// consuming the `Pin<&mut Self>`.
    ///
    /// Returns [`Poll::Ready`] if the clock has reached the threshold,
    /// [`Poll::Pending`] otherwise.
    pub fn poll_ref(self: &Pin<&mut Self>, cx: &mut Context<'_>) -> std::task::Poll<()> {
        let guard = self.node.lock_head();
        unsafe {
            match self.node.typ.get_val() {
                None => {
                    // Alarm disabled — unlink and pend forever.
                    guard.unlink(&self.node);
                    return Poll::Pending;
                }
                Some(alarm) => {
                    if *guard >= *alarm {
                        // Threshold reached — unlink, wake, and report ready.
                        guard.unlink(&self.node);
                        self.node.typ.wake();
                        return Poll::Ready(());
                    }
                }
            }

            // Clock hasn't reached our threshold yet.
            // Store / update the waker so a future clock change can notify us.
            let waker = self.node.typ.get_waker();
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

            // Link into the list so a future head update can wake us.
            guard.link(&self.node);
        }
        Poll::Pending
    }
}

impl<'a, T: PartialOrd + Clone> Future for ClockAlarm<'a, T> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> std::task::Poll<Self::Output> {
        self.poll_ref(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::task::{Wake, Waker};

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
    fn poll_alarm<T: PartialOrd + Clone>(
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
    // AlarmClock basic tests
    // -----------------------------------------------------------------------

    #[test]
    fn alarm_clock_new_and_get() {
        let clock = AlarmClock::new(42u64);
        assert_eq!(clock.get(), 42);
    }

    #[test]
    fn alarm_clock_set() {
        let clock = AlarmClock::new(0u64);
        clock.set(100);
        assert_eq!(clock.get(), 100);
        // set allows going backwards
        clock.set(50);
        assert_eq!(clock.get(), 50);
    }

    #[test]
    fn alarm_clock_advance_only_forward() {
        let clock = AlarmClock::new(10u64);
        // Advance to a larger value succeeds
        assert!(clock.advance(20));
        assert_eq!(clock.get(), 20);
        // Advance to same value fails
        assert!(!clock.advance(20));
        assert_eq!(clock.get(), 20);
        // Advance to smaller value fails
        assert!(!clock.advance(5));
        assert_eq!(clock.get(), 20);
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

        // set with Now should have woken us
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
        assert_eq!(clock.get(), 10);
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
        // and AlarmClock is Sync (via IntrusiveListNode's unsafe impl).
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
