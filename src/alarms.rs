use parking_lot::Mutex;
use std::{
    cell::UnsafeCell,
    fmt::Debug,
    future::Future,
    marker::{PhantomData, PhantomPinned},
    pin::Pin,
    task::{Context, Poll, Waker},
};

/// The relative order between a "clock" value and an "alarm" value
#[derive(Clone, Copy, PartialEq)]
enum AlarmOrder {
    /// No alarm can every be triggered for the alarm value given
    Never,
    /// The clock value triggers alarms with the alarm value
    Now,
    /// The clock value does not trigger the alarm, but a future value might
    Later,
}

struct UnsafeLink<T> {
    inner: UnsafeCell<*const T>,
}
impl<T> UnsafeLink<T> {
    fn new() -> Self {
        Self {
            inner: UnsafeCell::new(std::ptr::null_mut()),
        }
    }
    #[inline(always)]
    fn get(&self) -> *const T {
        unsafe { *self.inner.get() }
    }
    // UNSAFE: the lifetime of the returned reference is not checked
    #[inline(always)]
    unsafe fn get_ref(&self) -> Option<&T> {
        let p = *self.inner.get();
        if p.is_null() {
            None
        } else {
            Some(&*p)
        }
    }
    #[inline(always)]
    fn set(&self, val: *const T) {
        unsafe { *self.inner.get() = val };
    }
    #[inline(always)]
    fn set_ref(&self, val: &T) {
        unsafe { *self.inner.get() = val as *const T };
    }
    #[inline(always)]
    fn is_null(&self) -> bool {
        unsafe { (*self.inner.get()).is_null() }
    }
    #[inline(always)]
    fn clear(&self) {
        unsafe {
            *self.inner.get() = std::ptr::null_mut();
        }
    }
}

enum NodeType<T> {
    Head {
        mutex: Mutex<T>,
    },
    Node {
        // SAFETY: Alarm constructor ensures that target is pinned and has appropriate lifetime
        target: *const AlarmNode<T>,
        val: UnsafeCell<T>,
        waker: UnsafeCell<Option<Waker>>,
    },
}

struct AlarmNode<T> {
    typ: NodeType<T>,
    prev: UnsafeLink<AlarmNode<T>>,
    next: UnsafeLink<AlarmNode<T>>,
    _marker: PhantomPinned,
}
unsafe impl<T: PartialOrd> Send for AlarmNode<T> {}
unsafe impl<T: PartialOrd> Sync for AlarmNode<T> {}

impl<T> NodeType<T> {
    fn is_head(&self) -> bool {
        matches!(self, NodeType::Head { .. })
    }
    fn lock_target(&self) -> parking_lot::MutexGuard<'_, T> {
        match self {
            NodeType::Node { target, .. } => unsafe {
                match &((**target).typ) {
                    NodeType::Node { .. } => {
                        panic!();
                    }
                    NodeType::Head { mutex } => mutex.lock(),
                }
            },
            NodeType::Head { mutex } => mutex.lock(),
        }
    }
    unsafe fn wake(&self) {
        if let NodeType::Node { waker, .. } = self {
            if let Some(w) = (*waker.get()).take() {
                w.wake();
            }
        }
    }
}

impl<T> AlarmNode<T> {
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

    // SAFETY: Caller must own the target mutex
    unsafe fn is_linked(&self) -> bool {
        !self.prev.is_null() && !self.next.is_null()
    }

    // SAFETY: Caller must own the target mutex
    #[inline(always)]
    unsafe fn unlink(&self) {
        if self.typ.is_head() {
            // If we unlink the head, we have to unlink the whole list
            while !self.next.is_null() && !(*self.next.get()).typ.is_head() {
                (*self.next.get()).unlink();
            }
        }
        if self.is_linked() {
            let pn = &*self.prev.get();
            let nn = &*self.next.get();
            pn.next.set_ref(nn);
            nn.prev.set_ref(pn);
        }
        self.prev.clear();
        self.next.clear();
    }

    fn set_alarm<F>(&self, cmp: F, val: T)
    where
        F: Fn(&T, &T) -> AlarmOrder,
    {
        let guard = self.typ.lock_target();
        let val_cell = match &self.typ {
            NodeType::Head { .. } => {
                panic!("Can not set_alarm on a head node");
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

    fn get_alarm(&self) -> &T {
        let _ = self.typ.lock_target();
        match &self.typ {
            NodeType::Head { .. } => panic!("Can't get_alarm on a head node"),
            NodeType::Node { val, .. } => unsafe { &*val.get() },
        }
    }

    fn check_alarm<F>(self: Pin<&Self>, cx: &Context<'_>, f: F) -> bool
    where
        F: Fn(&T, &T) -> AlarmOrder,
    {
        let guard = self.typ.lock_target();
        let (target, val_cell, waker) = match &self.typ {
            NodeType::Head { .. } => {
                panic!("Can not check_alarm on a head node");
            }
            NodeType::Node { target, waker, val } => unsafe { (&**target, val, &mut *waker.get()) },
        };
        unsafe {
            let val = &*val_cell.get();
            match f(&*guard, val) {
                AlarmOrder::Never => {
                    if self.is_linked() {
                        self.unlink();
                    }
                    return false;
                }
                AlarmOrder::Now => {
                    if self.is_linked() {
                        self.unlink();
                    }
                    self.typ.wake();
                    return true;
                }
                _ => (),
            };
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
            if self.is_linked() {
                return true;
            }
            if !target.is_linked() {
                target.next.set_ref(target);
                target.prev.set_ref(target);
            }
            if !self.is_linked() {
                let pn = target.prev.get_ref().unwrap();
                pn.next.set_ref(&*self);
                self.prev.set_ref(pn);
                self.next.set(target);
                target.prev.set_ref(&*self);
            }
        }
        return false;
    }

    fn get_clock<'a>(&'a self) -> &'a T {
        let guard = self.typ.lock_target();
        unsafe { &*(&*guard as *const T) }
    }

    fn set_clock<F>(&self, val: T, f: F, advance_only: bool) -> bool
    where
        F: Fn(&T, &T) -> AlarmOrder,
    {
        if !self.typ.is_head() {
            panic!("Can only set_clock on a head node");
        }
        let mut guard = self.typ.lock_target();
        let order = f(&*guard, &val);
        if advance_only && order != AlarmOrder::Later {
            return false;
        }
        *guard = val;
        unsafe {
            if !self.is_linked() {
                return true;
            }
            let mut pn = self.next.get();
            while !(*pn).typ.is_head() {
                let n = &*pn;
                pn = n.next.get();
                if let NodeType::Node { val, waker, .. } = &n.typ {
                    match f(&*guard, &*val.get()) {
                        AlarmOrder::Never => {
                            // should never happen, because it wouldn't be linked, but just in case
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
        unsafe {
            let _ = self.typ.lock_target();
            self.unlink();
        };
    }
}

//=======================================================================================
// AlarmClock and ClockAlarm
//
// Alarms triggered when a monotonically increasing value meets or exceeds the alarm threshold
//=======================================================================================

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

pub struct AlarmClock<T: PartialOrd> {
    head: AlarmNode<Option<T>>,
}

impl<T: PartialOrd> AlarmClock<T> {
    pub fn new(val: T) -> Self {
        Self {
            head: AlarmNode::new_head(Some(val)),
        }
    }

    #[inline(always)]
    pub fn set(&self, val: T) {
        self.head.set_clock(Some(val), alarm_clock_order, false);
    }
    #[inline(always)]
    pub fn get(&self) -> &T {
        self.head.get_clock().as_ref().unwrap()
    }
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

pub struct ClockAlarm<'a, T: PartialOrd> {
    node: AlarmNode<Option<T>>,
    _lifetime: PhantomData<&'a AlarmClock<T>>,
}

impl<'a, T: PartialOrd> ClockAlarm<'a, T> {
    pub fn new(clock: Pin<&'a AlarmClock<T>>, wake_at: Option<T>) -> Self {
        let head_pin = unsafe { Pin::new_unchecked(&clock.head) };
        Self {
            node: AlarmNode::new_node(head_pin, wake_at),
            _lifetime: PhantomData,
        }
    }

    pub fn set(&self, wake_at: Option<T>) {
        self.node.set_alarm(alarm_clock_order, wake_at);
    }

    pub fn get(&self) -> Option<&T> {
        self.node.get_alarm().as_ref()
    }
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
