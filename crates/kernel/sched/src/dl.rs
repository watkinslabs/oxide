// Deadline-class ready set: earliest-deadline-first over the runnable
// `SCHED_DEADLINE` entities of one CPU.
//
// Keyed `(absolute deadline, tid)`. The tid is a tie-break for map uniqueness
// only — the deadline comparison the CLASS makes is strict everywhere
// (`cbs::dl_time_before`), so an equal deadline never preempts and never
// reorders. A throttled entity is not here at all: it lives on the
// replenishment queue until its next instance starts, which is exactly what
// makes an exhausted budget an enforcement rather than a hint.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::task::{SchedClass, Task};

/// EDF ready set.
pub struct DlRunqueue {
    tree: BTreeMap<(u64, u32), Arc<Task>>,
}

impl DlRunqueue {
    /// # C: O(1)
    pub fn new() -> Self { DlRunqueue { tree: BTreeMap::new() } }

    /// # C: O(1)
    pub fn nr_running(&self) -> u32 { self.tree.len() as u32 }

    /// # C: O(1)
    pub fn has_runnable(&self) -> bool { !self.tree.is_empty() }

    /// Earliest absolute deadline queued, or `None`.
    /// # C: O(log N)
    pub fn earliest_deadline(&self) -> Option<u64> { self.tree.keys().next().map(|(d, _)| *d) }

    /// Insert keyed on the entity's current absolute deadline.
    /// # C: O(log N)
    pub fn enqueue(&mut self, task: Arc<Task>) {
        debug_assert!(matches!(task.sched_class(), SchedClass::Deadline),
            "DlRunqueue::enqueue: non-deadline task");
        let key = (task.dl.abs_deadline(), task.tid);
        self.tree.insert(key, task);
    }

    /// Pick + remove the earliest-deadline entity.
    /// # C: O(log N)
    pub fn pick_earliest(&mut self) -> Option<Arc<Task>> {
        let (&k, _) = self.tree.iter().next()?;
        let t = self.tree.remove(&k).expect("leftmost key just observed");
        t.on_rq.store(false, Ordering::Release);
        Some(t)
    }

    /// # C: O(log N)
    pub fn peek_earliest(&self) -> Option<&Arc<Task>> { self.tree.values().next() }

    /// Remove by tid — class change, migration, throttle.
    /// # C: O(N)
    pub fn remove(&mut self, tid: u32) -> Option<Arc<Task>> {
        let key = self.tree.iter().find(|(_, t)| t.tid == tid).map(|(k, _)| *k)?;
        let t = self.tree.remove(&key)?;
        t.on_rq.store(false, Ordering::Release);
        Some(t)
    }
}

impl Default for DlRunqueue {
    fn default() -> Self { Self::new() }
}
