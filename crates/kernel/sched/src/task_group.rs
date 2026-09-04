//! Scheduler-owned fair-group hierarchy mirroring Linux task_group/cfs_rq.

extern crate alloc;
use alloc::vec::Vec;

const DEFAULT_SLICE: i64 = 4_000_000;

/// Linux `cpu.weight` range, distinct from the nice-table task weight.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GroupShares(u32);

impl GroupShares {
    pub const MIN: u32 = 1;
    pub const MAX: u32 = 10_000;
    pub const ROOT: Self = Self(1024);
    pub const fn new(value: u32) -> Option<Self> {
        if value < Self::MIN || value > Self::MAX { None } else { Some(Self(value)) }
    }
    pub const fn get(self) -> u32 { self.0 }
}

#[derive(Clone, Copy, Debug)]
struct Entity { id: u32, weight: u32, vruntime: i64 }

/// A Linux-shaped fair hierarchy node. Mutation is serialized by its owner.
#[derive(Debug)]
pub struct TaskGroup {
    id: u32,
    shares: GroupShares,
    entity: Entity,
    tasks: Vec<Entity>,
    children: Vec<TaskGroup>,
    next_id: u32,
}

impl TaskGroup {
    pub fn root(id: u32) -> Self {
        Self { id, shares: GroupShares::ROOT,
            entity: Entity { id, weight: GroupShares::ROOT.get(), vruntime: 0 },
            tasks: Vec::new(), children: Vec::new(), next_id: 1 }
    }
    pub fn id(&self) -> u32 { self.id }
    pub fn shares(&self) -> GroupShares { self.shares }
    pub fn set_shares(&mut self, shares: GroupShares) {
        self.shares = shares; self.entity.weight = shares.get();
    }
    pub fn add_child(&mut self, id: u32, shares: GroupShares) -> &mut Self {
        self.children.push(Self { id, shares,
            entity: Entity { id, weight: shares.get(), vruntime: 0 },
            tasks: Vec::new(), children: Vec::new(), next_id: 1 });
        self.children.last_mut().unwrap()
    }
    pub fn enqueue_task(&mut self, weight: u32) -> u32 {
        let id = self.next_id; self.next_id += 1;
        self.tasks.push(Entity { id, weight: weight.max(1), vruntime: 0 }); id
    }
    pub fn child(&self, id: u32) -> Option<&Self> {
        self.children.iter().find(|child| child.id == id)
    }

    /// Pick and charge one leaf using EEVDF eligibility and virtual deadline.
    pub fn pick(&mut self) -> Option<u32> {
        let total = self.tasks.iter().map(|task| task.weight as i64)
            .chain(self.children.iter().map(|child| child.entity.weight as i64)).sum::<i64>();
        if total == 0 { return None; }
        let service = self.tasks.iter().map(|task| task.vruntime * task.weight as i64)
            .chain(self.children.iter().map(|child| child.entity.vruntime * child.entity.weight as i64))
            .sum::<i64>() / total;
        let mut best: Option<(i64, bool, usize)> = None;
        for (index, task) in self.tasks.iter().enumerate() {
            let deadline = task.vruntime + request(task.weight);
            if task.vruntime <= service && best.is_none_or(|candidate| deadline < candidate.0) {
                best = Some((deadline, false, index));
            }
        }
        for (index, child) in self.children.iter().enumerate() {
            let deadline = child.entity.vruntime + request(child.entity.weight);
            if child.entity.vruntime <= service && best.is_none_or(|candidate| deadline < candidate.0) {
                best = Some((deadline, true, index));
            }
        }
        let (_, is_child, index) = best.or_else(|| self.fallback())?;
        if is_child {
            let child = &mut self.children[index];
            let leaf = child.pick()?;
            child.entity.vruntime += request(child.entity.weight); Some(leaf)
        } else {
            let task = &mut self.tasks[index]; let id = task.id;
            task.vruntime += request(task.weight); Some(id)
        }
    }

    fn fallback(&self) -> Option<(i64, bool, usize)> {
        let tasks = self.tasks.iter().enumerate().map(|(i, task)|
            (task.vruntime + request(task.weight), false, i));
        let children = self.children.iter().enumerate().map(|(i, child)|
            (child.entity.vruntime + request(child.entity.weight), true, i));
        tasks.chain(children).min_by_key(|candidate| candidate.0)
    }
}

fn request(weight: u32) -> i64 { (DEFAULT_SLICE / weight.max(1) as i64).max(1) }

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn shares_are_linux_bounded() {
        assert!(GroupShares::new(0).is_none());
        assert!(GroupShares::new(1).is_some());
        assert!(GroupShares::new(10_000).is_some());
        assert!(GroupShares::new(10_001).is_none());
    }
    #[test] fn nested_group_is_a_schedulable_entity() {
        let mut root = TaskGroup::root(0); root.enqueue_task(1024);
        root.add_child(7, GroupShares::new(512).unwrap()).enqueue_task(1024);
        assert!(root.pick().is_some()); assert_eq!(root.child(7).unwrap().id(), 7);
    }
    #[test] fn weighted_entities_receive_more_service() {
        let mut root = TaskGroup::root(0);
        let first = root.enqueue_task(1024); let second = root.enqueue_task(2048);
        let mut a = 0; let mut b = 0;
        for _ in 0..9 { match root.pick() { Some(id) if id == first => a += 1, Some(id) if id == second => b += 1, _ => {} } }
        assert!(b > a);
    }
}
