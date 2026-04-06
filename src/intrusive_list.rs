//! A generic mutex-synchronized intrusive doubly-linked list.
//!
//! This module provides [`IntrusiveListNode`], [`IntrusiveListGuard`], and the
//! [`IntrusiveNodeValue`] trait — the building blocks for intrusive linked lists
//! where each node carries its own discriminant value and the head node owns a
//! mutex that synchronizes all list operations.
//!
//! # Architecture
//!
//! Every list has exactly one *head* node and zero or more *leaf* nodes, all
//! sharing the [`IntrusiveListNode`] structure.  The [`IntrusiveNodeValue`]
//! trait, implemented by the discriminant stored in each node, defines how to
//! acquire the head mutex and how to navigate from a leaf back to its head.
//!
//! List mutations (link, unlink, filter) are performed through an
//! [`IntrusiveListGuard`], which holds both a reference to the head node and
//! the mutex guard, ensuring all operations are properly synchronized.
//!
//! # Safety
//!
//! The linked-list pointers are raw (`*const IntrusiveListNode<V>`) wrapped in
//! `UnsafeCell`.  All mutations go through the head's mutex.  Nodes must be
//! pinned before linking, because the list stores pointers to their addresses.

use std::{cell::UnsafeCell, marker::PhantomPinned};

// ---------------------------------------------------------------------------
// IntrusiveNodeValue — trait for the node-type discriminant
// ---------------------------------------------------------------------------

/// Trait that captures all functionality required from the node-type
/// discriminant in the intrusive list.
///
/// Each implementation defines how to acquire the head mutex and how to
/// navigate from a leaf back to its head node.
pub trait IntrusiveNodeValue: Sized {
    /// The value type stored in the head node mutex.
    type HeadValue;

    /// Locks the mutex on this head node.
    ///
    /// # Panics
    ///
    /// Panics if called on a leaf node.
    fn lock_mutex(&self) -> parking_lot::MutexGuard<'_, Self::HeadValue>;

    /// Returns the head [`IntrusiveListNode`] that this leaf targets, or
    /// `None` if this is itself a head node.
    fn target_node(&self) -> Option<&IntrusiveListNode<Self>>;
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
// IntrusiveListGuard — holds the head node reference and the mutex guard
// ---------------------------------------------------------------------------

/// A guard returned by [`IntrusiveListNode::lock_head`] that holds both a
/// reference to the head [`IntrusiveListNode`] and the
/// [`MutexGuard`](parking_lot::MutexGuard) protecting the head's value.
pub struct IntrusiveListGuard<'a, V: IntrusiveNodeValue> {
    head: &'a IntrusiveListNode<V>,
    guard: parking_lot::MutexGuard<'a, V::HeadValue>,
}

impl<V: IntrusiveNodeValue> std::ops::Deref for IntrusiveListGuard<'_, V> {
    type Target = V::HeadValue;
    #[inline(always)]
    fn deref(&self) -> &V::HeadValue {
        &self.guard
    }
}

impl<V: IntrusiveNodeValue> std::ops::DerefMut for IntrusiveListGuard<'_, V> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut V::HeadValue {
        &mut self.guard
    }
}

impl<V: IntrusiveNodeValue> IntrusiveListGuard<'_, V> {
    /// Links a leaf node into this list, if it is not already linked.
    ///
    /// # Panics
    ///
    /// Panics if `node` does not target this guard's head node.
    pub fn link(&self, node: &IntrusiveListNode<V>) {
        unsafe {
            assert!(
                matches!(node.typ.target_node(), Some(h) if std::ptr::eq(h, self.head)),
                "node does not target this list's head"
            );
            if node.is_linked() {
                return;
            }
            let head = self.head;
            // Lazily initialise the head's self-link (circular sentinel) the
            // first time any node is linked.
            if !head.is_linked() {
                head.next.set_ref(head);
                head.prev.set_ref(head);
            }
            // Insert at the tail of the circular list (just before the head).
            let pn = head.prev.get_ref().unwrap();
            pn.next.set_ref(node);
            node.prev.set_ref(pn);
            node.next.set(head);
            head.prev.set_ref(node);
        }
    }

    /// Unlinks a node from this list.
    ///
    /// If `node` is the head node, the entire list is torn down (all leaves
    /// are unlinked first, then the head's self-link is cleared).  If `node`
    /// is a leaf that is not currently linked, this is a no-op.
    ///
    /// # Panics
    ///
    /// Panics if `node` is a leaf that does not target this guard's head node.
    pub fn unlink(&self, node: &IntrusiveListNode<V>) {
        unsafe {
            if std::ptr::eq(node, self.head) {
                // Tearing down the entire list: unlink every leaf until we loop
                // back to the head, then clear the head's self-link.
                while !node.next.is_null() && !std::ptr::eq(node.next.get(), self.head) {
                    self.unlink(&*node.next.get());
                }
            } else {
                assert!(
                    matches!(node.typ.target_node(), Some(h) if std::ptr::eq(h, self.head)),
                    "node does not target this list's head"
                );
                if !node.is_linked() {
                    return;
                }
                // Stitch prev and next together, bypassing this node.
                let pn = &*node.prev.get();
                let nn = &*node.next.get();
                pn.next.set_ref(nn);
                nn.prev.set_ref(pn);
            }
            node.prev.clear();
            node.next.clear();
        }
    }

    /// Walks every leaf node in the list, calling `f` on each one's
    /// [`IntrusiveNodeValue`].
    ///
    /// If `f` returns `true`, the node is kept in the list.  If `f` returns
    /// `false`, the node is unlinked.  The caller is responsible for any
    /// additional actions (e.g. waking) on unlinked nodes.
    pub fn filter<F>(&self, mut f: F)
    where
        F: FnMut(&V) -> bool,
    {
        unsafe {
            let head = self.head;
            if !head.is_linked() {
                return;
            }
            let mut pn = head.next.get();
            while !std::ptr::eq(pn, head) {
                let n = &*pn;
                pn = n.next.get();
                if !f(&n.typ) {
                    self.unlink(n);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// IntrusiveListNode — intrusive doubly-linked list node
// ---------------------------------------------------------------------------

/// An intrusive doubly-linked list node, generic over [`IntrusiveNodeValue`].
///
/// Both head and leaf nodes share this structure so they can participate
/// in the same circular linked list.  The [`IntrusiveNodeValue`] discriminant
/// (`typ`) determines the node's role and provides mutex access and
/// head-pointer navigation.
pub struct IntrusiveListNode<V: IntrusiveNodeValue> {
    pub typ: V,
    prev: UnsafeLink<IntrusiveListNode<V>>,
    next: UnsafeLink<IntrusiveListNode<V>>,
    // Nodes must not be moved once linked, because the list stores raw pointers.
    _marker: PhantomPinned,
}

// SAFETY: All mutable state is behind a Mutex or only accessed while the Mutex
// is held. The raw pointers point to pinned, lifetime-guaranteed nodes.
unsafe impl<V: IntrusiveNodeValue> Send for IntrusiveListNode<V> {}
unsafe impl<V: IntrusiveNodeValue> Sync for IntrusiveListNode<V> {}

impl<V: IntrusiveNodeValue> IntrusiveListNode<V> {
    /// Creates a new node with the given [`IntrusiveNodeValue`] discriminant.
    pub fn new(typ: V) -> Self {
        Self {
            typ,
            prev: UnsafeLink::new(),
            next: UnsafeLink::new(),
            _marker: PhantomPinned,
        }
    }

    /// Acquires the head mutex and returns an [`IntrusiveListGuard`] holding
    /// both a reference to the head node and the mutex guard.
    ///
    /// For a head node, the head is `self`.  For a leaf node, the head is
    /// found by following the target pointer.
    pub fn lock_head(&self) -> IntrusiveListGuard<'_, V> {
        let head = self.typ.target_node().unwrap_or(self);
        IntrusiveListGuard {
            guard: head.typ.lock_mutex(),
            head,
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
}

impl<V: IntrusiveNodeValue> Drop for IntrusiveListNode<V> {
    fn drop(&mut self) {
        // Acquire the head mutex and unlink ourselves so no dangling pointers
        // remain in the list. For a head node this tears down the entire list.
        let guard = self.lock_head();
        guard.unlink(self);
    }
}
