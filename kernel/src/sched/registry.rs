// Global tid → Weak<Task> registry per `13§5` / `19§4`. Populated
// at `spawn_user_thread`; entries decay naturally via `Weak::upgrade`
// once the runqueue + zombies drop their last `Arc<Task>`.
//
// Used by procfs to enumerate `/proc/<pid>/` and synthesise
// per-pid `status`/`cmdline`/`stat`/`maps`. Lock order: leaf —
// callers hold no other sched locks.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use sched::Task;
use sync::{Spinlock, TaskList as TaskListClass};

static REG: Spinlock<Vec<(u32, Weak<Task>)>, TaskListClass>
    = Spinlock::new(Vec::new());

/// Insert a new entry. Idempotent on `tid` (overwrites stale slot).
/// # C: O(N_tasks)
pub fn insert(task: &Arc<Task>) {
    let tid = task.tid;
    let weak = Arc::downgrade(task);
    let mut g = REG.lock();
    if let Some(slot) = g.iter_mut().find(|(t, _)| *t == tid) {
        slot.1 = weak;
    } else {
        g.push((tid, weak));
    }
}

/// Resolve `tid` → live `Arc<Task>` if still reachable.
/// # C: O(N_tasks)
pub fn lookup(tid: u32) -> Option<Arc<Task>> {
    let g = REG.lock();
    g.iter().find(|(t, _)| *t == tid).and_then(|(_, w)| w.upgrade())
}

/// Snapshot live tids for procfs readdir. Skips entries whose
/// `Weak<Task>` has decayed; opportunistically prunes them.
/// # C: O(N_tasks)
pub fn live_tids() -> Vec<u32> {
    let mut g = REG.lock();
    g.retain(|(_, w)| w.strong_count() > 0);
    g.iter().map(|(t, _)| *t).collect()
}
