extern crate alloc;

use alloc::sync::Arc;
use core::cmp::Ordering;
use core::marker::PhantomData;

use crate::task::TreeRunNode;
use crate::Task;

/// Selects one task-owned node and one stable ordering key for a class tree.
///
/// # Safety
/// The selected node must be unique to this adapter. Callers serialize every
/// access with the queue that atomically owns the task's class-node claim.
pub(crate) unsafe trait Adapter {
    fn cmp(a: &Task, b: &Task) -> Ordering;
    unsafe fn node(task: &Task) -> &TreeRunNode;
    unsafe fn node_mut(task: &Task) -> &mut TreeRunNode;
}

/// Cached, allocation-free AVL tree over nodes embedded in `Task`.
pub(crate) struct IntrusiveTaskTree<A: Adapter> {
    root: Option<Arc<Task>>,
    first: Option<Arc<Task>>,
    len: u32,
    adapter: PhantomData<A>,
}

impl<A: Adapter> IntrusiveTaskTree<A> {
    pub(crate) const fn new() -> Self {
        Self { root: None, first: None, len: 0, adapter: PhantomData }
    }

    pub(crate) fn len(&self) -> u32 { self.len }

    pub(crate) fn first(&self) -> Option<Arc<Task>> {
        self.first.as_ref().map(Arc::clone)
    }

    pub(crate) fn last(&self) -> Option<Arc<Task>> {
        right_edge::<A>(self.root.as_ref())
    }

    pub(crate) fn insert(&mut self, task: Arc<Task>) {
        let node = node_mut::<A>(&task);
        hal::kassert!(node.left.is_none() && node.right.is_none()
            && node.parent == 0, "class task retained stale tree links");
        node.height = 1;
        let replace_first = self.first.as_ref()
            .is_none_or(|first| A::cmp(&task, first) == Ordering::Less);
        self.root = Some(insert::<A>(self.root.take(), Arc::clone(&task), 0));
        if replace_first { self.first = Some(task); }
        self.len += 1;
    }

    /// Erase this exact embedded node, using its parent link rather than a
    /// TID/tree scan. The caller has already verified queue identity.
    pub(crate) fn remove(&mut self, task: &Task) -> Option<Arc<Task>> {
        let target = address(task);
        let parent = node_ref::<A>(task).parent;
        let has_left = node_ref::<A>(task).left.is_some();
        let has_right = node_ref::<A>(task).right.is_some();
        let removed = if has_left && has_right {
            self.remove_two_children(task, target, parent)?
        } else {
            let slot = self.slot_for(task)?;
            // SAFETY: `slot` is the owning tree slot under exclusive access.
            let owned = unsafe { &mut *slot }.take().expect("tree slot disappeared");
            let child = if has_left { take_left::<A>(&owned) }
                else { take_right::<A>(&owned) };
            put_slot::<A>(slot, child, parent);
            clear::<A>(&owned);
            self.rebalance_up(parent);
            owned
        };
        self.len -= 1;
        self.first = left_edge::<A>(self.root.as_ref());
        Some(removed)
    }

    fn remove_two_children(&mut self, task: &Task, target: usize,
                           parent: usize) -> Option<Arc<Task>> {
        let right = node_ref::<A>(task).right.as_ref()?;
        let successor = left_edge::<A>(Some(right))?;
        let successor_addr = address(&successor);
        let successor_parent = node_ref::<A>(&successor).parent;
        let successor_slot = self.slot_for(&successor)?;
        // SAFETY: the successor slot belongs to this exclusively-owned tree.
        let successor = unsafe { &mut *successor_slot }.take()
            .expect("successor slot disappeared");
        let successor_right = take_right::<A>(&successor);
        put_slot::<A>(successor_slot, successor_right, successor_parent);

        let target_slot = self.slot_for(task)?;
        // SAFETY: removing the successor did not alter the target's own slot.
        let owned = unsafe { &mut *target_slot }.take().expect("tree target disappeared");
        let left = take_left::<A>(&owned);
        let right = take_right::<A>(&owned);
        set_left::<A>(&successor, left);
        set_right::<A>(&successor, right);
        set_parent::<A>(&successor, parent);
        // SAFETY: `target_slot` is vacant and still owned by this tree.
        unsafe { *target_slot = Some(successor); }
        clear::<A>(&owned);

        let start = if successor_parent == target { successor_addr }
            else { successor_parent };
        self.rebalance_up(start);
        Some(owned)
    }

    fn rebalance_up(&mut self, mut current: usize) {
        while current != 0 {
            // SAFETY: every address on the parent chain is retained by the
            // tree until its subtree is reattached below.
            let task = unsafe { &*(current as *const Task) };
            let parent = node_ref::<A>(task).parent;
            let slot = self.slot_for(task).expect("tree parent chain detached");
            // SAFETY: `slot` owns this subtree under exclusive tree access.
            let root = unsafe { &mut *slot }.take().expect("tree subtree disappeared");
            let root = rebalance::<A>(root, parent);
            // SAFETY: rebalancing preserves ownership of the same vacant slot.
            unsafe { *slot = Some(root); }
            current = parent;
        }
    }

    fn slot_for(&mut self, task: &Task) -> Option<*mut Option<Arc<Task>>> {
        let parent = node_ref::<A>(task).parent;
        if parent == 0 {
            let owns_root = self.root.as_ref()
                .is_some_and(|root| core::ptr::eq(root.as_ref(), task));
            return owns_root.then(|| core::ptr::from_mut(&mut self.root));
        }
        // SAFETY: a linked node's parent is retained by this tree.
        let parent = unsafe { &*(parent as *const Task) };
        let links = node_mut::<A>(parent);
        if links.left.as_ref().is_some_and(|node| core::ptr::eq(node.as_ref(), task)) {
            return Some(core::ptr::from_mut(&mut links.left));
        }
        if links.right.as_ref().is_some_and(|node| core::ptr::eq(node.as_ref(), task)) {
            return Some(core::ptr::from_mut(&mut links.right));
        }
        None
    }

    pub(crate) fn sum<F>(&self, value: F) -> u64
    where F: Fn(&Task) -> u64 {
        sum::<A, F>(self.root.as_ref(), &value)
    }

    pub(crate) fn sum_i128<F>(&self, value: F) -> i128
    where F: Fn(&Task) -> i128 {
        sum_i128::<A, F>(self.root.as_ref(), &value)
    }

    pub(crate) fn find<F>(&self, predicate: F) -> Option<Arc<Task>>
    where F: Fn(&Task) -> bool {
        find::<A, F>(self.root.as_ref(), &predicate)
    }

    pub(crate) fn find_best<F>(&self, better: F) -> Option<Arc<Task>>
    where F: Fn(&Task, &Task) -> bool {
        find_best::<A, F>(self.root.as_ref(), &better)
    }

    #[cfg(test)]
    pub(crate) fn height(&self) -> i32 { height::<A>(self.root.as_ref()) }
}

fn sum_i128<A: Adapter, F>(root: Option<&Arc<Task>>, value: &F) -> i128
where F: Fn(&Task) -> i128 {
    let Some(task) = root else { return 0 };
    let node = node_ref::<A>(task);
    sum_i128::<A, F>(node.left.as_ref(), value)
        .saturating_add(value(task))
        .saturating_add(sum_i128::<A, F>(node.right.as_ref(), value))
}

fn address(task: &Task) -> usize { core::ptr::from_ref(task) as usize }

fn node_ref<A: Adapter>(task: &Task) -> &TreeRunNode {
    // SAFETY: all callers own the adapter's queue against mutation.
    unsafe { A::node(task) }
}

fn node_mut<A: Adapter>(task: &Task) -> &mut TreeRunNode {
    // SAFETY: all callers exclusively own the adapter's queue and its claim.
    unsafe { A::node_mut(task) }
}

fn set_parent<A: Adapter>(task: &Task, parent: usize) {
    node_mut::<A>(task).parent = parent;
}

fn take_left<A: Adapter>(task: &Task) -> Option<Arc<Task>> {
    let child = node_mut::<A>(task).left.take();
    if let Some(child) = child.as_ref() { set_parent::<A>(child, 0); }
    child
}

fn take_right<A: Adapter>(task: &Task) -> Option<Arc<Task>> {
    let child = node_mut::<A>(task).right.take();
    if let Some(child) = child.as_ref() { set_parent::<A>(child, 0); }
    child
}

fn set_left<A: Adapter>(task: &Task, child: Option<Arc<Task>>) {
    if let Some(child) = child.as_ref() { set_parent::<A>(child, address(task)); }
    node_mut::<A>(task).left = child;
}

fn set_right<A: Adapter>(task: &Task, child: Option<Arc<Task>>) {
    if let Some(child) = child.as_ref() { set_parent::<A>(child, address(task)); }
    node_mut::<A>(task).right = child;
}

fn clear<A: Adapter>(task: &Task) {
    let node = node_mut::<A>(task);
    hal::kassert!(node.left.is_none() && node.right.is_none(),
        "detached class-tree node retained children");
    node.parent = 0;
    node.height = 1;
}

fn put_slot<A: Adapter>(slot: *mut Option<Arc<Task>>, child: Option<Arc<Task>>,
                        parent: usize) {
    if let Some(child) = child.as_ref() { set_parent::<A>(child, parent); }
    // SAFETY: callers exclusively own the vacant tree slot.
    unsafe { *slot = child; }
}

fn height<A: Adapter>(task: Option<&Arc<Task>>) -> i32 {
    task.map_or(0, |task| node_ref::<A>(task).height as i32)
}

fn update<A: Adapter>(task: &Task) {
    let node = node_ref::<A>(task);
    let height = height::<A>(node.left.as_ref()).max(height::<A>(node.right.as_ref())) + 1;
    node_mut::<A>(task).height = height as u16;
}

fn skew<A: Adapter>(task: &Task) -> i32 {
    let node = node_ref::<A>(task);
    height::<A>(node.left.as_ref()) - height::<A>(node.right.as_ref())
}

fn rotate_right<A: Adapter>(root: Arc<Task>, parent: usize) -> Arc<Task> {
    let pivot = take_left::<A>(&root).expect("left-heavy tree node lacks child");
    let middle = take_right::<A>(&pivot);
    set_left::<A>(&root, middle);
    update::<A>(&root);
    set_right::<A>(&pivot, Some(root));
    update::<A>(&pivot);
    set_parent::<A>(&pivot, parent);
    pivot
}

fn rotate_left<A: Adapter>(root: Arc<Task>, parent: usize) -> Arc<Task> {
    let pivot = take_right::<A>(&root).expect("right-heavy tree node lacks child");
    let middle = take_left::<A>(&pivot);
    set_right::<A>(&root, middle);
    update::<A>(&root);
    set_left::<A>(&pivot, Some(root));
    update::<A>(&pivot);
    set_parent::<A>(&pivot, parent);
    pivot
}

fn rebalance<A: Adapter>(root: Arc<Task>, parent: usize) -> Arc<Task> {
    update::<A>(&root);
    let balance = skew::<A>(&root);
    if balance > 1 {
        let left = node_ref::<A>(&root).left.as_ref().expect("tree left child");
        if skew::<A>(left) < 0 {
            let left = take_left::<A>(&root).expect("tree left child");
            set_left::<A>(&root, Some(rotate_left::<A>(left, address(&root))));
        }
        return rotate_right::<A>(root, parent);
    }
    if balance < -1 {
        let right = node_ref::<A>(&root).right.as_ref().expect("tree right child");
        if skew::<A>(right) > 0 {
            let right = take_right::<A>(&root).expect("tree right child");
            set_right::<A>(&root, Some(rotate_right::<A>(right, address(&root))));
        }
        return rotate_left::<A>(root, parent);
    }
    set_parent::<A>(&root, parent);
    root
}

fn insert<A: Adapter>(root: Option<Arc<Task>>, task: Arc<Task>, parent: usize) -> Arc<Task> {
    let Some(root) = root else {
        set_parent::<A>(&task, parent);
        return task;
    };
    match A::cmp(&task, &root) {
        Ordering::Less => {
            let child = insert::<A>(take_left::<A>(&root), task, address(&root));
            set_left::<A>(&root, Some(child));
        }
        Ordering::Greater => {
            let child = insert::<A>(take_right::<A>(&root), task, address(&root));
            set_right::<A>(&root, Some(child));
        }
        Ordering::Equal => hal::kassert!(false, "duplicate class-tree key"),
    }
    rebalance::<A>(root, parent)
}

fn left_edge<A: Adapter>(mut task: Option<&Arc<Task>>) -> Option<Arc<Task>> {
    let mut out = None;
    while let Some(current) = task {
        out = Some(Arc::clone(current));
        task = node_ref::<A>(current).left.as_ref();
    }
    out
}

fn right_edge<A: Adapter>(mut task: Option<&Arc<Task>>) -> Option<Arc<Task>> {
    let mut out = None;
    while let Some(current) = task {
        out = Some(Arc::clone(current));
        task = node_ref::<A>(current).right.as_ref();
    }
    out
}

fn sum<A: Adapter, F: Fn(&Task) -> u64>(task: Option<&Arc<Task>>, value: &F) -> u64 {
    let Some(task) = task else { return 0 };
    let node = node_ref::<A>(task);
    value(task).saturating_add(sum::<A, F>(node.left.as_ref(), value))
        .saturating_add(sum::<A, F>(node.right.as_ref(), value))
}

fn find<A: Adapter, F: Fn(&Task) -> bool>(task: Option<&Arc<Task>>,
                                          predicate: &F) -> Option<Arc<Task>> {
    let task = task?;
    let node = node_ref::<A>(task);
    find::<A, F>(node.left.as_ref(), predicate)
        .or_else(|| predicate(task).then(|| Arc::clone(task)))
        .or_else(|| find::<A, F>(node.right.as_ref(), predicate))
}

fn find_best<A: Adapter, F: Fn(&Task, &Task) -> bool>(task: Option<&Arc<Task>>,
                                                     better: &F) -> Option<Arc<Task>> {
    let task = task?;
    let mut best = find_best::<A, F>(node_ref::<A>(task).left.as_ref(), better);
    if best.as_ref().is_none_or(|candidate| better(task, candidate)) {
        best = Some(Arc::clone(task));
    }
    if let Some(candidate) = find_best::<A, F>(node_ref::<A>(task).right.as_ref(), better) {
        if best.as_ref().is_none_or(|current| better(&candidate, current)) {
            best = Some(candidate);
        }
    }
    best
}
