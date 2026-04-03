use parking_lot::Mutex;
use std::{
    cell::UnsafeCell, fmt::Debug, future::Future, marker::{PhantomData, PhantomPinned}, pin::Pin, task::{Context, Poll, Waker}
};

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

enum NodeType<T: PartialOrd> {
    Head {
        mutex: Mutex<T>,
    },
    Node {
        target: *const AlarmNode<T>,
        val: UnsafeCell<Option<T>>,
        waker: UnsafeCell<Option<Waker>>,
    },
}
struct AlarmNode<T: PartialOrd> {
    typ: NodeType<T>,
    prev: UnsafeLink<AlarmNode<T>>,
    next: UnsafeLink<AlarmNode<T>>,
    _marker: PhantomPinned,
}
unsafe impl<T: PartialOrd> Send for AlarmNode<T> {}

impl<T: PartialOrd> NodeType<T> {
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

impl<T: PartialOrd> AlarmNode<T> {
    fn new_node<'a>(target: Pin<&'a AlarmNode<T>>, val: Option<T>) -> Self {
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

    fn set_alarm(&self, val: Option<T>) {
        let guard = self.typ.lock_target();
        let val_cell = match &self.typ {
            NodeType::Head { .. } => {
                panic!("Can not set_alarm on a head node");
            }
            NodeType::Node { val, .. } => val,
        };
        unsafe {
            if val.is_none() {
                self.unlink();
            } else if *guard >= *val.as_ref().unwrap() {
                // alarm time has already passed
                self.unlink();
                self.typ.wake();
            }
            (*val_cell.get()) = val;
        }
    }

    fn get_alarm(&self) -> Option<&T> {
        let _ = self.typ.lock_target();
        match &self.typ {
            NodeType::Head { .. } => None,
            NodeType::Node { val, .. } => unsafe { (*val.get()).as_ref() },
        }
    }

    fn check_alarm(self: Pin<&Self>, cx: &Context<'_>) -> bool {
        let guard = self.typ.lock_target();
        let (target, val_cell, waker) = match &self.typ {
            NodeType::Head { .. } => {
                panic!("Can not check_alarm on a head node");
            }
            NodeType::Node { target, waker, val } => unsafe { (&**target, val, &mut *waker.get()) },
        };
        unsafe {
            let val = &*val_cell.get();
            if val.is_none() {
                if self.is_linked() {
                    self.unlink();
                }
                *waker = None;
                return false;
            } else if *guard >= *val.as_ref().unwrap() {
                // alarm time has already passed
                if self.is_linked() {
                    self.unlink();
                }
                self.typ.wake();
                return true;
            }
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

    fn get_clock<'a>(&'a self) -> &'a T{
        let guard = self.typ.lock_target();
        unsafe {&*(&*guard as *const T)}
    }

    fn set_clock(&self, val: T, advance_only: bool) -> bool {
        if !self.typ.is_head() {
            panic!("Can only set_clock on a head node");
        }
        let mut guard = self.typ.lock_target();
        if *guard >= val {
            // old value is as big as new value.  No alarms will fire
            if !advance_only {
                *guard = val;
            }
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
                    let val = &*val.get();
                    if val.is_none() {
                        // should never happen, because it wouldn't be linked, but just in case
                        n.unlink();
                    } else if *guard >= *val.as_ref().unwrap() {
                        n.unlink();
                        if let Some(w) = (*waker.get()).take() {
                            w.wake();
                        }
                    }
                }
            };
        }
        true
    }
}

impl<T: PartialOrd> Drop for AlarmNode<T> {
    fn drop(&mut self) {
        unsafe {
            let _ = self.typ.lock_target();
            self.unlink();
        };
    }
}

pub struct AlarmClock<T: PartialOrd> {
    head: AlarmNode<T>,
}
unsafe impl<T: PartialOrd> Send for AlarmClock<T> {}
unsafe impl<T: PartialOrd> Sync for AlarmClock<T> {}

impl<T: PartialOrd> AlarmClock<T> {
    pub fn new(val: T) -> Self {
        Self {
            head: AlarmNode::new_head(val),
        }
    }

    #[inline(always)]
    pub fn set(&self, val: T) {
        self.head.set_clock(val, false);
    }
    #[inline(always)]
    pub fn get(&self) -> &T{
        self.head.get_clock()
    }
    #[inline(always)]
    pub fn advance(&self, val: T) -> bool {
        self.head.set_clock(val, true)
    }
}

impl<T: PartialOrd + Debug> Debug for AlarmClock<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let g = self.head.typ.lock_target();
        f.debug_struct("AlarmClock").field("val", &*g).finish()
    }
}

pub struct Alarm<'a, T: PartialOrd> {
    node: AlarmNode<T>,
    _lifetime: PhantomData<&'a AlarmClock<T>>,
}

impl<'a, T: PartialOrd> Alarm<'a, T> {
    pub fn new(clock: Pin<&'a AlarmClock<T>>, wake_at: Option<T>) -> Self {
        let head_pin = unsafe { Pin::new_unchecked(&clock.head) };
        Self {
            node: AlarmNode::new_node(head_pin, wake_at),
            _lifetime: PhantomData,
        }
    }

    pub fn set(&self, wake_at: Option<T>) {
        self.node.set_alarm(wake_at);
    }

    pub fn get(&self) -> Option<&T> {
        self.node.get_alarm()
    }
}

impl<'a, T: PartialOrd> Future for Alarm<'a, T> {
    type Output = ();

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let node_pin = unsafe { Pin::new_unchecked(&self.node) };
        match node_pin.check_alarm(cx) {
            true => Poll::Ready(()),
            false => Poll::Pending,
        }
    }
}
