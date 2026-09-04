//! Scheduler-owned fair task-group descriptors and hierarchy registry.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};
use sync::{Spinlock, TaskList as TaskListClass};

pub(crate) const ROOT_GROUP_ID: u64 = 0;
pub(crate) const ROOT_GROUP_SHARES: u32 = 1024;
const MIN_GROUP_SHARES: u32 = 1;
const MAX_GROUP_SHARES: u32 = 102_400;

/// Scheduler execution identity for one cgroup CPU-controller node.
pub struct TaskGroup {
    id: u64,
    parent: Option<u64>,
    depth: u16,
    shares: AtomicU32,
    online: AtomicU8,
    path: Arc<[u64]>,
}

impl TaskGroup {
    /// Opaque scheduler group identity. # C: O(1)
    pub fn id(&self) -> u64 { self.id }

    /// Parent scheduler group identity; root has none. # C: O(1)
    pub fn parent_id(&self) -> Option<u64> { self.parent }

    /// Root-first hierarchy depth. # C: O(1)
    pub fn depth(&self) -> u16 { self.depth }

    /// Current parent-entity shares. # C: O(1)
    pub fn shares(&self) -> u32 { self.shares.load(Ordering::Acquire) }

    pub(crate) fn path(&self) -> Arc<[u64]> { Arc::clone(&self.path) }

    pub(crate) fn store_shares(&self, shares: u32) {
        self.shares.store(clamp_shares(shares), Ordering::Release);
    }

    pub(crate) fn claim_online(&self) -> bool {
        self.online.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire).is_ok()
    }

    pub(crate) fn finish_online(&self) { self.online.store(2, Ordering::Release); }

    pub(crate) fn wait_online(&self) {
        while self.online.load(Ordering::Acquire) != 2 { core::hint::spin_loop(); }
    }
}

static GROUPS: Spinlock<BTreeMap<u64, Arc<TaskGroup>>, TaskListClass> =
    Spinlock::new(BTreeMap::new());

/// Return the permanent root execution group. # C: O(log groups)
pub fn root() -> Arc<TaskGroup> {
    let mut groups = GROUPS.lock();
    if let Some(root) = groups.get(&ROOT_GROUP_ID) { return Arc::clone(root); }
    let root = Arc::new(TaskGroup {
        id: ROOT_GROUP_ID, parent: None, depth: 0,
        shares: AtomicU32::new(ROOT_GROUP_SHARES),
        online: AtomicU8::new(2),
        path: Arc::from([ROOT_GROUP_ID]),
    });
    groups.insert(ROOT_GROUP_ID, Arc::clone(&root));
    root
}

pub(crate) fn lookup(id: u64) -> Option<Arc<TaskGroup>> {
    GROUPS.lock().get(&id).cloned()
}

/// Publish a complete child descriptor before any task can attach to it.
/// Returns the canonical descriptor and whether this call created it.
pub(crate) fn register(id: u64, parent: &Arc<TaskGroup>, shares: u32)
    -> (Arc<TaskGroup>, bool) {
    assert!(id != ROOT_GROUP_ID, "root task group cannot be registered as a child");
    let mut groups = GROUPS.lock();
    if let Some(group) = groups.get(&id) {
        assert_eq!(group.parent_id(), Some(parent.id()),
            "task group identity changed parent");
        return (Arc::clone(group), false);
    }
    let mut path = Vec::from(parent.path.as_ref());
    path.push(id);
    let group = Arc::new(TaskGroup {
        id, parent: Some(parent.id()), depth: parent.depth.saturating_add(1),
        shares: AtomicU32::new(clamp_shares(shares)), path: Arc::from(path),
        online: AtomicU8::new(0),
    });
    groups.insert(id, Arc::clone(&group));
    (group, true)
}

pub(crate) fn snapshot() -> Vec<Arc<TaskGroup>> {
    let _ = root();
    GROUPS.lock().values().cloned().collect()
}

pub(crate) fn unregister(id: u64) -> Option<Arc<TaskGroup>> {
    if id == ROOT_GROUP_ID { return None; }
    let mut groups = GROUPS.lock();
    assert!(!groups.values().any(|group| group.parent_id() == Some(id)),
        "task group removed before its children");
    groups.remove(&id)
}

fn clamp_shares(shares: u32) -> u32 {
    shares.clamp(MIN_GROUP_SHARES, MAX_GROUP_SHARES)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_group_keeps_root_first_parent_path() {
        let root = root();
        let (parent, _) = register(91_000, &root, 1024);
        let (child, _) = register(91_001, &parent, 512);
        assert_eq!(child.path().as_ref(), &[ROOT_GROUP_ID, 91_000, 91_001]);
        assert_eq!(child.parent_id(), Some(parent.id()));
        assert_eq!(child.depth(), 2);
        unregister(child.id());
        unregister(parent.id());
    }

    #[test]
    fn registration_is_canonical_and_reweight_does_not_change_task_load() {
        let root = root();
        let (first, created) = register(91_002, &root, 1024);
        let (second, duplicate) = register(91_002, &root, 2048);
        assert!(created);
        assert!(!duplicate);
        assert!(Arc::ptr_eq(&first, &second));
        first.store_shares(2048);
        assert_eq!(second.shares(), 2048);
        unregister(first.id());
    }
}
