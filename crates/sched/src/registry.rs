// Global tid → Weak<Task> registry per `13§5` / `19§4`. Populated
// at task spawn; entries decay naturally via `Weak::upgrade` once
// the runqueue + zombies drop their last `Arc<Task>`.
//
// Used by procfs to enumerate `/proc/<pid>/` and synthesise
// per-pid `status`/`cmdline`/`stat`/`maps`. Lock order: leaf —
// callers hold no other sched locks.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use sync::{Spinlock, TaskList as TaskListClass};

use crate::{Task, TaskState};

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

/// Flip `task.state` Stopped → Runnable. Returns `true` if the
/// transition actually happened (caller is then responsible for
/// re-enqueueing into the runqueue); `false` if the task wasn't
/// Stopped to begin with. Used by SIGCONT delivery per signal(7):
/// the state-flip half is hosted-testable here, the re-enqueue
/// half lives in kernel-side `wake_if_stopped`.
/// # C: O(1)
pub fn try_wake_stopped(task: &Task) -> bool {
    if task.state() != TaskState::Stopped { return false; }
    task.set_state(TaskState::Runnable);
    // Per `13§9` wakeup→resched: a newly-runnable task may outrank
    // current; flag a reschedule so the next preempt-enable or
    // syscall-return point picks it up. Cheaper than calling
    // schedule() directly here (registry holds no runqueue lock).
    crate::preempt::set_need_resched();
    true
}

/// Snapshot every live task whose pgid matches. Used by tty
/// line discipline + `kill(-pgid)` to fan signals to a process
/// group per `28§4`.
/// # C: O(N_tasks)
pub fn tasks_in_pgrp(pgid: u32) -> Vec<Arc<Task>> {
    use core::sync::atomic::Ordering;
    let g = REG.lock();
    g.iter()
        .filter_map(|(_, w)| w.upgrade())
        .filter(|t| t.pgid.load(Ordering::Acquire) == pgid)
        .collect()
}

/// Test-only: drop every registered entry. Hosted tests share the
/// process-global slot, so this resets the table between cases.
/// # C: O(N_tasks)
#[cfg(test)]
pub fn clear_for_tests() {
    REG.lock().clear();
}
