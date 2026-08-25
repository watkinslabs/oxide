// CFS runqueue per `13§3` / `13§7`: BTreeMap<(vruntime, tid), Arc<Task>>
// keyed by composite (vruntime, tid) to dedupe ties. `min_vruntime` is
// the leftmost key's vruntime; used to lift waking tasks per `13§5`
// invariant 5.
//
// Task vruntime updates are owned by the timer-tick / wakeup paths
// (out of scope here); the runqueue itself only re-keys on
// `enqueue` / `dequeue`.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;

use core::sync::atomic::Ordering;

use crate::task::{SchedClass, Task};

/// CFS runqueue.
pub struct CfsRunqueue {
    tree: BTreeMap<(u64, u32), Arc<Task>>,
    nr_running: u32,
}

impl CfsRunqueue {
    /// # C: O(1)
    pub fn new() -> Self {
        Self { tree: BTreeMap::new(), nr_running: 0 }
    }

    /// # C: O(1)
    pub fn nr_running(&self) -> u32 { self.nr_running }

    /// # C: O(1)
    pub fn has_runnable(&self) -> bool { !self.tree.is_empty() }

    /// Sum the current entity signals for the CPU utilization hook.
    pub fn util_avg(&self) -> u32 {
        self.tree.values().map(|task| task.util_avg.load(Ordering::Acquire))
            .fold(0, u32::saturating_add)
    }

    /// `min_vruntime` is the leftmost task's vruntime per `13§3`.
    /// Empty tree returns `0` (matches an empty Linux RQ at boot).
    /// # C: O(log N)
    pub fn min_vruntime(&self) -> u64 {
        self.tree.keys().next().map(|(v, _)| *v).unwrap_or(0)
    }

    /// Rightmost task vruntime; used by Linux-shaped `sched_yield` to forfeit
    /// current's place behind queued CFS peers. # C: O(log N)
    pub fn max_vruntime(&self) -> u64 {
        self.tree.keys().next_back().map(|(v, _)| *v).unwrap_or(0)
    }

    /// Insert with key derived from the task's current vruntime
    /// snapshot.
    /// # C: O(log N)
    pub fn enqueue(&mut self, task: Arc<Task>) {
        debug_assert!(matches!(task.sched_class(), SchedClass::Normal { .. }),
            "CfsRunqueue::enqueue: non-Normal task");
        let v = task.vruntime.load(Ordering::Acquire);
        let key = (v, task.tid);
        let prev = self.tree.insert(key, task);
        debug_assert!(prev.is_none(), "duplicate (vruntime,tid) in CFS tree");
        self.nr_running += 1;
    }

    /// Pick + remove the leftmost task per `13§7`.
    /// # C: O(log N)
    #[inline(never)]
    pub fn pick_leftmost(&mut self) -> Option<Arc<Task>> {
        // `pop_first` is the cached-leftmost equivalent of Linux's
        // `rb_first_cached` followed by `rb_erase_cached`: it does not perform
        // a second key search before rebalancing the tree.
        let (_, t) = self.tree.pop_first()?;
        self.nr_running -= 1;
        // Off the tree → clear on-rq so a later enqueue (re-queue / migrate)
        // passes the guard in RunqueueInner::enqueue (Linux `p->on_rq`).
        t.on_rq.store(false, Ordering::Release);
        Some(t)
    }

    /// Peek at the leftmost task without removing.
    /// # C: O(log N)
    pub fn peek_leftmost(&self) -> Option<&Arc<Task>> {
        self.tree.values().next()
    }

    /// Remove by tid. Used by SMP migration and class transitions.
    /// # C: O(N) — linear scan since key is `(vruntime, tid)`.
    pub fn remove(&mut self, tid: u32) -> Option<Arc<Task>> {
        let key = self.tree.iter()
            .find(|(_, t)| t.tid == tid)
            .map(|(k, _)| *k)?;
        let t = self.tree.remove(&key)?;
        self.nr_running -= 1;
        t.on_rq.store(false, Ordering::Release);
        Some(t)
    }
}

impl Default for CfsRunqueue {
    fn default() -> Self { Self::new() }
}
