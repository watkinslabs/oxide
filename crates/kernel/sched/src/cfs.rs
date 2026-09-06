// EEVDF fair hierarchy: each non-root task group owns one child queue and one
// parent-facing entity. Queue mutation runs under the owning CPU rq lock.

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::cmp::Ordering as CmpOrdering;
use core::sync::atomic::Ordering;

use crate::intrusive_tree::{Adapter, IntrusiveTaskTree};
use crate::task::{SchedClass, Task, TreeRunNode};
use crate::task_group::{ROOT_GROUP_ID, TaskGroup};

const FAIR_SLICE_NS: u64 = 4_000_000;

struct GroupEntity {
    id: u64,
    shares: u32,
    vruntime: u64,
    deadline: u64,
    rq: Box<CfsRunqueue>,
}

impl GroupEntity {
    fn new(group: &TaskGroup) -> Self {
        let shares = group.shares();
        Self { id: group.id(), shares, vruntime: 0,
            deadline: request_deadline(0, shares),
            rq: Box::new(CfsRunqueue::new_group(group.id(), group.depth())) }
    }

    fn charge(&mut self, delta_ns: u64) {
        self.vruntime = self.vruntime.wrapping_add(
            crate::eevdf::request_delta(delta_ns, self.shares.max(1) as u64));
        if !vruntime_before(self.vruntime, self.deadline) {
            self.deadline = request_deadline(self.vruntime, self.shares);
        }
    }
}

enum Choice { Task(Arc<Task>), Group(u64) }

#[derive(Clone, Copy)]
struct PickKey { eligible: bool, deadline: u64, id: u64, group: bool }

struct FairTree;

// SAFETY: this adapter exclusively selects `Task::sched.se.run_node`; the
// owning leaf CFS queue's identity claim serializes accesses until detach.
unsafe impl Adapter for FairTree {
    fn cmp(a: &Task, b: &Task) -> CmpOrdering { cmp(key(a), key(b)) }

    unsafe fn node(task: &Task) -> &TreeRunNode {
        // SAFETY: inherited from the adapter call contract.
        unsafe { task.sched.se.run_node() }
    }

    unsafe fn node_mut(task: &Task) -> &mut TreeRunNode {
        // SAFETY: inherited from the adapter call contract.
        unsafe { task.sched.se.run_node_mut() }
    }
}

/// Per-group fair runqueue. Root additionally indexes every installed path.
pub(crate) struct CfsRunqueue {
    tree: IntrusiveTaskTree<FairTree>,
    queue_id: u64,
    group_id: u64,
    depth: u16,
    nr_running: u32,
    children: BTreeMap<u64, GroupEntity>,
    paths: BTreeMap<u64, Arc<[u64]>>,
}

impl CfsRunqueue {
    /// # C: O(1)
    pub(crate) fn new() -> Self { Self::new_group(ROOT_GROUP_ID, 0) }

    fn new_group(group_id: u64, depth: u16) -> Self {
        Self { tree: IntrusiveTaskTree::new(), queue_id: crate::class_queue::fresh_id(),
            group_id, depth, nr_running: 0, children: BTreeMap::new(),
            paths: BTreeMap::new() }
    }

    /// Install one prebuilt scheduler group into this CPU hierarchy.
    pub(crate) fn online_group(&mut self, group: &TaskGroup) {
        if group.id() == ROOT_GROUP_ID { return; }
        let path = group.path();
        assert_eq!(path.first().copied(), Some(ROOT_GROUP_ID),
            "fair task group path lacks root");
        assert_eq!(path.last().copied(), Some(group.id()),
            "fair task group path ends at another group");
        self.online_path(&path[1..], group);
        self.paths.insert(group.id(), path);
    }

    fn online_path(&mut self, path: &[u64], group: &TaskGroup) {
        assert!(!path.is_empty(), "non-root fair group has empty path");
        if path.len() == 1 {
            let entry = self.children.entry(path[0])
                .or_insert_with(|| GroupEntity::new(group));
            assert_eq!(entry.id, group.id(), "fair group installed at wrong parent");
            assert_eq!(entry.rq.depth, self.depth.saturating_add(1),
                "fair group depth changed during online");
            return;
        }
        let child = self.children.get_mut(&path[0])
            .expect("fair task group parent was not online first");
        child.rq.online_path(&path[1..], group);
    }

    /// Remove one empty leaf group from this CPU hierarchy.
    pub(crate) fn offline_group(&mut self, id: u64) {
        let Some(path) = self.paths.remove(&id) else { return; };
        self.offline_path(&path[1..]);
    }

    fn offline_path(&mut self, path: &[u64]) {
        assert!(!path.is_empty(), "root fair group cannot go offline");
        if path.len() == 1 {
            let group = self.children.get(&path[0]).expect("offline fair group is absent");
            assert_eq!(group.rq.nr_running, 0, "live fair group went offline");
            assert!(group.rq.children.is_empty(), "fair group went offline before child");
            self.children.remove(&path[0]);
            return;
        }
        self.children.get_mut(&path[0]).expect("offline fair group lost parent")
            .rq.offline_path(&path[1..]);
    }

    /// Update one parent-facing entity without touching member task weights.
    pub(crate) fn reweight_group(&mut self, group: &TaskGroup) {
        if group.id() == ROOT_GROUP_ID { return; }
        let path = self.paths.get(&group.id()).cloned()
            .expect("reweighted fair group is not online");
        self.reweight_path(&path[1..], group.shares());
    }

    fn reweight_path(&mut self, path: &[u64], shares: u32) {
        let group = self.children.get_mut(&path[0]).expect("fair group path is stale");
        if path.len() == 1 {
            group.shares = shares.max(1);
            group.deadline = request_deadline(group.vruntime, group.shares);
        } else { group.rq.reweight_path(&path[1..], shares); }
    }

    /// # C: O(1)
    pub(crate) fn nr_running(&self) -> u32 { self.nr_running }

    /// # C: O(1)
    #[cfg(test)]
    pub(crate) fn has_runnable(&self) -> bool { self.nr_running != 0 }

    #[cfg(test)]
    pub(crate) fn root_height_for_test(&self) -> i32 { self.tree.height() }

    #[cfg(test)]
    pub(crate) fn group_shape_for_test(&self, id: u64) -> Option<(u16, u32)> {
        let path = self.paths.get(&id)?;
        let rq = self.queue_for_path(&path[1..])?;
        Some((rq.depth, rq.nr_running))
    }

    /// Sum current fair task signals across every child queue.
    pub(crate) fn util_avg(&self) -> u32 {
        let tasks = self.tree.sum(|task| task.sched.se.avg_util.load(Ordering::Acquire));
        self.children.values().fold(tasks, |sum, child|
            sum.saturating_add(child.rq.util_avg() as u64)).min(u32::MAX as u64) as u32
    }

    /// Lowest queued entity virtual runtime, or zero when empty. # C: O(1 + groups)
    pub(crate) fn min_vruntime(&self) -> u64 {
        let task = self.tree.first().map(|task| key(&task).0);
        self.children.values().filter(|group| group.rq.nr_running != 0)
            .map(|group| group.vruntime).chain(task).min().unwrap_or(0)
    }

    /// Leaf-queue minimum for this task's scheduler placement. # C: O(depth)
    pub(crate) fn min_vruntime_for(&self, task: &Task) -> u64 {
        self.task_queue(task).map_or(0, Self::min_vruntime)
    }

    /// Highest queued root entity virtual runtime, or zero when empty.
    pub(crate) fn max_vruntime(&self) -> u64 {
        let task = self.tree.last().map(|task| key(&task).0);
        self.children.values().filter(|group| group.rq.nr_running != 0)
            .map(|group| group.vruntime).chain(task).max().unwrap_or(0)
    }

    /// Leaf-queue maximum for this task's scheduler placement. # C: O(depth)
    pub(crate) fn max_vruntime_for(&self, task: &Task) -> u64 {
        self.task_queue(task).map_or(0, Self::max_vruntime)
    }

    fn task_queue(&self, task: &Task) -> Option<&Self> {
        if task.sched.group_id() == ROOT_GROUP_ID { return Some(self); }
        let path = self.paths.get(&task.sched.group_id())?;
        self.queue_for_path(&path[1..])
    }

    fn queue_for_path(&self, path: &[u64]) -> Option<&Self> {
        if path.is_empty() { return Some(self); }
        self.children.get(&path[0])?.rq.queue_for_path(&path[1..])
    }

    /// Insert through the task's cached group path. # C: O(depth * log entities)
    pub(crate) fn enqueue(&mut self, task: Arc<Task>) -> bool {
        let id = task.sched.group_id();
        if id == ROOT_GROUP_ID { return self.enqueue_path(task, &[]); }
        let path = self.paths.get(&id).cloned()
            .expect("task references an offline fair group");
        self.enqueue_path(task, &path[1..])
    }

    fn enqueue_path(&mut self, task: Arc<Task>, path: &[u64]) -> bool {
        if path.is_empty() { return self.enqueue_local(task); }
        let floor = self.min_vruntime();
        let group = self.children.get_mut(&path[0]).expect("task fair path is stale");
        let was_empty = group.rq.nr_running == 0;
        let inserted = group.rq.enqueue_path(task, &path[1..]);
        if inserted {
            self.nr_running = self.nr_running.saturating_add(1);
            if was_empty {
                if vruntime_before(group.vruntime, floor) { group.vruntime = floor; }
                group.deadline = request_deadline(group.vruntime, group.shares);
            }
        }
        inserted
    }

    fn enqueue_local(&mut self, task: Arc<Task>) -> bool {
        debug_assert!(matches!(task.sched_class(), SchedClass::Normal { .. }),
            "CfsRunqueue::enqueue: non-Normal task");
        assert_eq!(task.sched.group_id(), self.group_id,
            "fair task entered another group's child queue");
        if !crate::class_queue::claim(&task, self.queue_id) { return false; }
        let vruntime = task.sched.se.vruntime.load(Ordering::Acquire);
        let slice = task.sched.se.slice.load(Ordering::Acquire).max(FAIR_SLICE_NS);
        task.sched.se.slice.store(slice, Ordering::Release);
        let weight = task_weight(&task);
        let request = crate::eevdf::request_delta(slice, weight);
        task.sched.se.deadline.store(vruntime.wrapping_add(request), Ordering::Release);
        let (floor, total, sum) = self.stats();
        task.sched.se.vlag.store(crate::eevdf::bounded_lag(
            sum, total.max(1) as u128, floor, vruntime, request), Ordering::Release);
        task.sched.se.on_rq.store(true, Ordering::Release);
        self.tree.insert(task);
        self.nr_running = self.nr_running.saturating_add(1);
        true
    }

    /// Pick and detach one task by root-to-leaf EEVDF descent.
    #[inline(never)]
    pub(crate) fn pick_leftmost(&mut self) -> Option<Arc<Task>> { self.pick_one() }

    fn pick_one(&mut self) -> Option<Arc<Task>> {
        match self.pick_entity()? {
            Choice::Task(task) => self.remove_local(&task),
            Choice::Group(id) => {
                let group = self.children.get_mut(&id)
                    .expect("selected fair group disappeared");
                let task = group.rq.pick_one()?;
                self.nr_running = self.nr_running.saturating_sub(1);
                Some(task)
            }
        }
    }

    fn pick_entity(&self) -> Option<Choice> {
        let (floor, total, sum) = self.stats();
        if total == 0 { return None; }
        self.best_queued(floor, total, sum).map(|(_, choice)| choice)
    }

    fn best_queued(&self, floor: u64, total: u64, sum: i128) -> Option<(PickKey, Choice)> {
        let task_key = |task: &Task| entity_key(sum, total, floor,
            task.sched.se.vruntime.load(Ordering::Acquire),
            task.sched.se.deadline.load(Ordering::Acquire), task.tid as u64, false);
        let task = self.tree.find_best(|a, b| better(task_key(a), task_key(b)));
        let mut best = task.as_ref().map(|task| (task_key(task), Choice::Task(Arc::clone(task))));
        for group in self.children.values().filter(|group| group.rq.nr_running != 0) {
            let key = entity_key(sum, total, floor, group.vruntime, group.deadline, group.id, true);
            if best.as_ref().is_none_or(|(current, _)| better(key, *current)) {
                best = Some((key, Choice::Group(group.id)));
            }
        }
        best
    }

    /// Charge actual execution to each ancestor of the running task. # C: O(depth)
    pub(crate) fn account_runtime(&mut self, task: &Task, delta_ns: u64) {
        if delta_ns == 0 || task.sched.group_id() == ROOT_GROUP_ID { return; }
        let path = self.paths.get(&task.sched.group_id())
            .expect("running task references an offline fair group");
        let mut children = &mut self.children;
        for id in &path[1..] {
            let group = children.get_mut(id).expect("running fair path is stale");
            group.charge(delta_ns);
            children = &mut group.rq.children;
        }
    }

    fn stats(&self) -> (u64, u64, i128) {
        let floor = self.min_vruntime();
        let task_weight_sum = self.tree.sum(|task| task_weight(task));
        let group_weight_sum = self.children.values()
            .filter(|group| group.rq.nr_running != 0)
            .map(|group| group.shares.max(1) as u64).sum::<u64>();
        let total = task_weight_sum.saturating_add(group_weight_sum);
        let task_sum = self.tree.sum_i128(|task| {
            signed_delta(floor, task.sched.se.vruntime.load(Ordering::Acquire))
                * task_weight(task) as i128
        });
        let group_sum = self.children.values()
            .filter(|group| group.rq.nr_running != 0)
            .map(|group| signed_delta(floor, group.vruntime) * group.shares.max(1) as i128)
            .sum::<i128>();
        (floor, total, task_sum.saturating_add(group_sum))
    }

    /// Clone the task selected by hierarchy descent without mutation.
    pub(crate) fn peek_leftmost(&self) -> Option<Arc<Task>> {
        match self.pick_entity()? {
            Choice::Task(task) => Some(task),
            Choice::Group(id) => self.children.get(&id)?.rq.peek_leftmost(),
        }
    }

    /// First queued task accepted by `predicate`, bounded by queue size.
    pub(crate) fn find<F>(&self, predicate: F) -> Option<Arc<Task>>
    where F: Fn(&Task) -> bool + Copy {
        self.tree.find(predicate).or_else(|| self.children.values()
            .find_map(|group| group.rq.find(predicate)))
    }

    /// Remove this exact task through its cached hierarchy path.
    pub(crate) fn remove(&mut self, task: &Task) -> Option<Arc<Task>> {
        let id = task.sched.group_id();
        if id == ROOT_GROUP_ID { return self.remove_path(task, &[]); }
        let path = self.paths.get(&id).cloned()?;
        self.remove_path(task, &path[1..])
    }

    fn remove_path(&mut self, task: &Task, path: &[u64]) -> Option<Arc<Task>> {
        if path.is_empty() { return self.remove_local(task); }
        let removed = self.children.get_mut(&path[0])?.rq.remove_path(task, &path[1..])?;
        self.nr_running = self.nr_running.saturating_sub(1);
        Some(removed)
    }

    fn remove_local(&mut self, task: &Task) -> Option<Arc<Task>> {
        if !crate::class_queue::owns(task, self.queue_id) { return None; }
        let removed = self.tree.remove(task).expect("fair queue claim lacks tree node");
        removed.sched.se.on_rq.store(false, Ordering::Release);
        self.nr_running = self.nr_running.saturating_sub(1);
        crate::class_queue::release(&removed, self.queue_id);
        Some(removed)
    }

    #[cfg(test)]
    pub(crate) fn find_tid(&self, tid: u32) -> Option<Arc<Task>> {
        self.find(|task| task.tid == tid)
    }
}

impl Default for CfsRunqueue {
    fn default() -> Self { Self::new() }
}

impl Drop for CfsRunqueue {
    fn drop(&mut self) {
        while self.pick_one().is_some() {}
    }
}

fn entity_key(sum: i128, total: u64, floor: u64, vruntime: u64,
              deadline: u64, id: u64, group: bool) -> PickKey {
    PickKey { eligible: crate::eevdf::eligible(sum, total as u128, floor, vruntime),
        deadline, id, group }
}

fn better(a: PickKey, b: PickKey) -> bool {
    if a.eligible != b.eligible { return a.eligible; }
    if a.deadline != b.deadline { return a.deadline < b.deadline; }
    if a.id != b.id { return a.id < b.id; }
    !a.group && b.group
}

fn task_weight(task: &Task) -> u64 {
    (task.sched.se.load.snapshot().weight >> 10).max(1)
}

fn signed_delta(floor: u64, vruntime: u64) -> i128 {
    vruntime.wrapping_sub(floor) as i64 as i128
}

fn key(task: &Task) -> (u64, u32) {
    (task.sched.se.vruntime.load(Ordering::Acquire), task.tid)
}

fn group_request(shares: u32) -> u64 {
    crate::eevdf::request_delta(FAIR_SLICE_NS, shares.max(1) as u64)
}

fn request_deadline(vruntime: u64, shares: u32) -> u64 {
    vruntime.wrapping_add(group_request(shares))
}

fn cmp(a: (u64, u32), b: (u64, u32)) -> CmpOrdering {
    if a.0 == b.0 { return a.1.cmp(&b.1); }
    if vruntime_before(a.0, b.0) { CmpOrdering::Less }
    else { CmpOrdering::Greater }
}

/// Wrap-safe strict vruntime ordering within the signed clock horizon.
pub(crate) fn vruntime_before(a: u64, b: u64) -> bool {
    (a.wrapping_sub(b) as i64) < 0
}

#[cfg(test)]
#[path = "cfs/tests/runtime.rs"]
mod runtime_tests;

#[path = "cfs/preempt.rs"]
mod preempt;
