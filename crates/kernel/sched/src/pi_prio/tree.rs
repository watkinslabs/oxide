//! Allocation-free intrusive waiter tree shared by rtmutex wait and owner trees.

use alloc::sync::{Arc, Weak};
use core::marker::PhantomPinned;
use core::pin::Pin;

use crate::Task;
use super::{PiDonorKey, donor_key_outranks};

const BLACK: bool = false;
const RED: bool = true;

/// One stable node in either an rtmutex wait tree or a task's PI waiter tree.
///
/// The enclosing futex waiter owns and pins two of these, matching Linux's
/// separate `tree` and `pi_tree` nodes. Tree links never own the node.
pub struct PiTreeNode {
    parent: usize,
    left: usize,
    right: usize,
    red: bool,
    linked: bool,
    key: PiDonorKey,
    order: u64,
    lock_id: u64,
    waiter_id: u64,
    visit_epoch: u64,
    donor: Weak<Task>,
    _pin: PhantomPinned,
}

impl PiTreeNode {
    pub fn new(donor: &Arc<Task>, key: PiDonorKey, order: u64,
               lock_id: u64, waiter_id: u64) -> Self {
        Self { parent: 0, left: 0, right: 0, red: BLACK, linked: false,
            key, order, lock_id, waiter_id, visit_epoch: 0, donor: Arc::downgrade(donor),
            _pin: PhantomPinned }
    }

    pub fn key(&self) -> PiDonorKey { self.key }
    pub fn order(&self) -> u64 { self.order }
    pub fn lock_id(&self) -> u64 { self.lock_id }
    pub fn waiter_id(&self) -> u64 { self.waiter_id }
    pub fn donor(&self) -> Option<Arc<Task>> { self.donor.upgrade() }
    pub fn is_linked(&self) -> bool { self.linked }

    /// Change the sort key only while this node is outside a tree.
    pub fn set_key(self: Pin<&mut Self>, key: PiDonorKey, order: u64) {
        // SAFETY: pinning preserves the address; changing scalar keys cannot move the node.
        let node = unsafe { self.get_unchecked_mut() };
        assert!(!node.linked, "cannot rekey a linked PI waiter node");
        node.key = key;
        node.order = order;
    }

    /// Bind/rebind this unlinked node to a futex state and queue key.
    pub fn set_position(self: Pin<&mut Self>, key: PiDonorKey, order: u64, lock_id: u64) {
        // SAFETY: pinning preserves the address; changing scalar keys cannot move the node.
        let node = unsafe { self.get_unchecked_mut() };
        assert!(!node.linked, "cannot reposition a linked PI waiter node");
        node.key = key;
        node.order = order;
        node.lock_id = lock_id;
    }

    /// Mark a chain walk; true means this walk already visited the waiter.
    pub fn revisit(self: Pin<&mut Self>, epoch: u64) -> bool {
        // SAFETY: the scalar does not participate in tree topology or ordering.
        let node = unsafe { self.get_unchecked_mut() };
        if node.visit_epoch == epoch { true } else { node.visit_epoch = epoch; false }
    }
}

/// Linux-shaped cached intrusive rb-root. The leftmost node is the top waiter.
pub struct PiWaiterTree {
    root: usize,
    first: usize,
    len: usize,
}

impl PiWaiterTree {
    pub const fn new() -> Self { Self { root: 0, first: 0, len: 0 } }
    pub fn is_empty(&self) -> bool { self.root == 0 }
    pub fn len(&self) -> usize { self.len }

    pub fn first(&self) -> Option<&PiTreeNode> {
        if self.first == 0 { None }
        else {
            // SAFETY: a tree link is published only for a pinned live node and
            // mutable tree access is required before that node can be removed.
            Some(unsafe { node(self.first) })
        }
    }

    /// Insert an unlinked pinned node. No allocation is performed.
    pub fn insert(&mut self, mut item: Pin<&mut PiTreeNode>) {
        let ptr = item.as_ref().get_ref() as *const PiTreeNode as usize;
        // SAFETY: the node is pinned for the entire interval in which its owner
        // permits it to remain linked; this method initializes only link fields.
        let z = unsafe { item.as_mut().get_unchecked_mut() };
        assert!(!z.linked, "PI waiter node inserted twice");
        z.parent = 0;
        z.left = 0;
        z.right = 0;
        z.red = RED;
        z.linked = true;

        let mut parent = 0;
        let mut cursor = self.root;
        while cursor != 0 {
            parent = cursor;
            cursor = if unsafe { before(ptr, cursor) } {
                unsafe { node(cursor).left }
            } else {
                unsafe { node(cursor).right }
            };
        }
        z.parent = parent;
        if parent == 0 { self.root = ptr; }
        else if unsafe { before(ptr, parent) } { unsafe { node_mut(parent).left = ptr; } }
        else { unsafe { node_mut(parent).right = ptr; } }
        self.len += 1;
        self.insert_fixup(ptr);
        self.first = minimum(self.root);
    }

    /// Remove a linked pinned node. No allocation or destruction is performed.
    pub fn remove(&mut self, mut item: Pin<&mut PiTreeNode>) {
        let zptr = item.as_ref().get_ref() as *const PiTreeNode as usize;
        assert!(item.as_ref().get_ref().linked, "PI waiter node removed while unlinked");
        let mut y = zptr;
        let mut y_red = unsafe { node(y).red };
        let x;
        let x_parent;
        if unsafe { node(zptr).left } == 0 {
            x = unsafe { node(zptr).right };
            x_parent = unsafe { node(zptr).parent };
            self.transplant(zptr, x);
        } else if unsafe { node(zptr).right } == 0 {
            x = unsafe { node(zptr).left };
            x_parent = unsafe { node(zptr).parent };
            self.transplant(zptr, x);
        } else {
            y = minimum(unsafe { node(zptr).right });
            y_red = unsafe { node(y).red };
            x = unsafe { node(y).right };
            if unsafe { node(y).parent } == zptr {
                x_parent = y;
                if x != 0 { unsafe { node_mut(x).parent = y; } }
            } else {
                x_parent = unsafe { node(y).parent };
                self.transplant(y, x);
                unsafe {
                    node_mut(y).right = node(zptr).right;
                    node_mut(node(y).right).parent = y;
                }
            }
            self.transplant(zptr, y);
            unsafe {
                node_mut(y).left = node(zptr).left;
                node_mut(node(y).left).parent = y;
                node_mut(y).red = node(zptr).red;
            }
        }
        if y_red == BLACK { self.remove_fixup(x, x_parent); }
        self.len -= 1;
        self.first = minimum(self.root);
        // SAFETY: pinning keeps the address stable while links are cleared.
        let z = unsafe { item.as_mut().get_unchecked_mut() };
        z.parent = 0;
        z.left = 0;
        z.right = 0;
        z.red = BLACK;
        z.linked = false;
    }

    fn transplant(&mut self, old: usize, new: usize) {
        let parent = unsafe { node(old).parent };
        if parent == 0 { self.root = new; }
        else if old == unsafe { node(parent).left } { unsafe { node_mut(parent).left = new; } }
        else { unsafe { node_mut(parent).right = new; } }
        if new != 0 { unsafe { node_mut(new).parent = parent; } }
    }

    fn rotate_left(&mut self, x: usize) {
        let y = unsafe { node(x).right };
        let middle = unsafe { node(y).left };
        unsafe { node_mut(x).right = middle; }
        if middle != 0 { unsafe { node_mut(middle).parent = x; } }
        let parent = unsafe { node(x).parent };
        unsafe { node_mut(y).parent = parent; }
        if parent == 0 { self.root = y; }
        else if x == unsafe { node(parent).left } { unsafe { node_mut(parent).left = y; } }
        else { unsafe { node_mut(parent).right = y; } }
        unsafe { node_mut(y).left = x; node_mut(x).parent = y; }
    }

    fn rotate_right(&mut self, x: usize) {
        let y = unsafe { node(x).left };
        let middle = unsafe { node(y).right };
        unsafe { node_mut(x).left = middle; }
        if middle != 0 { unsafe { node_mut(middle).parent = x; } }
        let parent = unsafe { node(x).parent };
        unsafe { node_mut(y).parent = parent; }
        if parent == 0 { self.root = y; }
        else if x == unsafe { node(parent).right } { unsafe { node_mut(parent).right = y; } }
        else { unsafe { node_mut(parent).left = y; } }
        unsafe { node_mut(y).right = x; node_mut(x).parent = y; }
    }

    fn insert_fixup(&mut self, mut z: usize) {
        while color(unsafe { node(z).parent }) == RED {
            let parent = unsafe { node(z).parent };
            let grand = unsafe { node(parent).parent };
            if parent == unsafe { node(grand).left } {
                let uncle = unsafe { node(grand).right };
                if color(uncle) == RED {
                    set_color(parent, BLACK); set_color(uncle, BLACK); set_color(grand, RED); z = grand;
                } else {
                    if z == unsafe { node(parent).right } { z = parent; self.rotate_left(z); }
                    let parent = unsafe { node(z).parent };
                    let grand = unsafe { node(parent).parent };
                    set_color(parent, BLACK); set_color(grand, RED); self.rotate_right(grand);
                }
            } else {
                let uncle = unsafe { node(grand).left };
                if color(uncle) == RED {
                    set_color(parent, BLACK); set_color(uncle, BLACK); set_color(grand, RED); z = grand;
                } else {
                    if z == unsafe { node(parent).left } { z = parent; self.rotate_right(z); }
                    let parent = unsafe { node(z).parent };
                    let grand = unsafe { node(parent).parent };
                    set_color(parent, BLACK); set_color(grand, RED); self.rotate_left(grand);
                }
            }
        }
        set_color(self.root, BLACK);
    }

    fn remove_fixup(&mut self, mut x: usize, mut parent: usize) {
        while x != self.root && color(x) == BLACK {
            if x == unsafe { node(parent).left } {
                let mut sibling = unsafe { node(parent).right };
                if color(sibling) == RED {
                    set_color(sibling, BLACK); set_color(parent, RED); self.rotate_left(parent);
                    sibling = unsafe { node(parent).right };
                }
                let left = child(sibling, true);
                let right = child(sibling, false);
                if color(left) == BLACK && color(right) == BLACK {
                    set_color(sibling, RED); x = parent; parent = unsafe { node(x).parent };
                } else {
                    if color(right) == BLACK {
                        set_color(left, BLACK); set_color(sibling, RED); self.rotate_right(sibling);
                        sibling = unsafe { node(parent).right };
                    }
                    set_color(sibling, color(parent)); set_color(parent, BLACK);
                    set_color(child(sibling, false), BLACK); self.rotate_left(parent);
                    x = self.root; parent = 0;
                }
            } else {
                let mut sibling = unsafe { node(parent).left };
                if color(sibling) == RED {
                    set_color(sibling, BLACK); set_color(parent, RED); self.rotate_right(parent);
                    sibling = unsafe { node(parent).left };
                }
                let right = child(sibling, false);
                let left = child(sibling, true);
                if color(right) == BLACK && color(left) == BLACK {
                    set_color(sibling, RED); x = parent; parent = unsafe { node(x).parent };
                } else {
                    if color(left) == BLACK {
                        set_color(right, BLACK); set_color(sibling, RED); self.rotate_left(sibling);
                        sibling = unsafe { node(parent).left };
                    }
                    set_color(sibling, color(parent)); set_color(parent, BLACK);
                    set_color(child(sibling, true), BLACK); self.rotate_right(parent);
                    x = self.root; parent = 0;
                }
            }
        }
        set_color(x, BLACK);
    }
}

unsafe fn node<'a>(ptr: usize) -> &'a PiTreeNode {
    // SAFETY: callers pass a non-null link owned by a live intrusive tree.
    unsafe { &*(ptr as *const PiTreeNode) }
}
unsafe fn node_mut<'a>(ptr: usize) -> &'a mut PiTreeNode {
    // SAFETY: callers hold the tree's exclusive lock and pass a live link.
    unsafe { &mut *(ptr as *mut PiTreeNode) }
}
unsafe fn before(a: usize, b: usize) -> bool {
    // SAFETY: both pointers are live tree nodes under exclusive tree access.
    let (a, b) = unsafe { (node(a), node(b)) };
    if donor_key_outranks(a.key, b.key) { return true; }
    if donor_key_outranks(b.key, a.key) { return false; }
    (a.order.wrapping_sub(b.order) as i64) < 0
}
fn minimum(mut ptr: usize) -> usize {
    if ptr == 0 { return 0; }
    while unsafe { node(ptr).left } != 0 { ptr = unsafe { node(ptr).left }; }
    ptr
}
fn color(ptr: usize) -> bool { if ptr == 0 { BLACK } else { unsafe { node(ptr).red } } }
fn set_color(ptr: usize, red: bool) { if ptr != 0 { unsafe { node_mut(ptr).red = red; } } }
fn child(ptr: usize, left: bool) -> usize {
    if ptr == 0 { 0 } else if left { unsafe { node(ptr).left } } else { unsafe { node(ptr).right } }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use crate::{SchedClass, SchedPolicy};

    fn key(priority: u8) -> PiDonorKey {
        PiDonorKey { class: SchedClass::Rt { prio: priority, policy: SchedPolicy::Fifo },
            ..PiDonorKey::default() }
    }

    fn test_node(priority: u8, order: u64, lock_id: u64, waiter_id: u64) -> PiTreeNode {
        PiTreeNode { parent: 0, left: 0, right: 0, red: BLACK, linked: false,
            key: key(priority), order, lock_id, waiter_id, visit_epoch: 0,
            donor: Weak::new(), _pin: PhantomPinned }
    }

    fn validate(tree: &PiWaiterTree) {
        if tree.root == 0 { assert_eq!(tree.len, 0); assert_eq!(tree.first, 0); return; }
        assert_eq!(color(tree.root), BLACK);
        fn walk(ptr: usize, parent: usize) -> (usize, usize) {
            if ptr == 0 { return (1, 0); }
            let n = unsafe { node(ptr) };
            assert_eq!(n.parent, parent);
            if n.left != 0 { assert!(unsafe { before(n.left, ptr) }); }
            if n.right != 0 { assert!(!unsafe { before(n.right, ptr) }); }
            if n.red { assert_eq!(color(n.left), BLACK); assert_eq!(color(n.right), BLACK); }
            let (left_black, left_len) = walk(n.left, ptr);
            let (right_black, right_len) = walk(n.right, ptr);
            assert_eq!(left_black, right_black);
            (left_black + usize::from(!n.red), left_len + right_len + 1)
        }
        let (_, count) = walk(tree.root, 0);
        assert_eq!(count, tree.len);
        assert_eq!(tree.first, minimum(tree.root));
    }

    #[test]
    fn intrusive_rb_tree_preserves_cached_top_and_black_height_through_removal() {
        let priorities = [40, 90, 10, 70, 30, 80, 20, 60, 50];
        let mut nodes: alloc::vec::Vec<_> = priorities.iter().enumerate()
            .map(|(index, priority)| Box::pin(test_node(*priority, index as u64,
                index as u64 + 1, index as u64 + 1))).collect();
        let mut tree = PiWaiterTree::new();
        for node in &mut nodes { tree.insert(node.as_mut()); validate(&tree); }
        assert_eq!(tree.first().unwrap().key(), key(90));
        for index in [1usize, 3, 5, 7, 8, 0, 4, 6, 2] {
            tree.remove(nodes[index].as_mut());
            validate(&tree);
        }
        assert!(tree.is_empty());
    }

    #[test]
    fn equal_keys_retain_fifo_order_in_both_waiter_trees() {
        let mut late = Box::pin(test_node(50, 2, 1, 2));
        let mut early = Box::pin(test_node(50, 1, 1, 1));
        let mut tree = PiWaiterTree::new();
        tree.insert(late.as_mut());
        tree.insert(early.as_mut());
        validate(&tree);
        assert_eq!(tree.first().unwrap().waiter_id(), 1);
        tree.remove(early.as_mut());
        assert_eq!(tree.first().unwrap().waiter_id(), 2);
        tree.remove(late.as_mut());
    }
}
