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

/// Resolve `(ns, vpid)` → live `Arc<Task>`. F109: pid-NS-aware
/// lookup for kill/wait4/tgkill from a task in a non-init pid_ns —
/// caller's vpid arg is interpreted within their NS instead of as a
/// real tid. Init-NS callers (`ns == 0`) match by real tid (the
/// init-NS shortcut).
/// # C: O(N_tasks)
pub fn lookup_in_ns(ns: u64, vpid: u32) -> Option<Arc<Task>> {
    use core::sync::atomic::Ordering;
    if ns == 0 { return lookup(vpid); }
    let g = REG.lock();
    g.iter()
        .filter_map(|(_, w)| w.upgrade())
        .find(|t| t.pid_ns.load(Ordering::Acquire) == ns
              && (t.vtgid.load(Ordering::Acquire) == vpid
                  || t.vtid.load(Ordering::Acquire) == vpid))
}

/// Snapshot live tids for procfs readdir. Skips entries whose
/// `Weak<Task>` has decayed; opportunistically prunes them.
/// # C: O(N_tasks)
pub fn live_tids() -> Vec<u32> {
    let mut g = REG.lock();
    g.retain(|(_, w)| w.strong_count() > 0);
    g.iter().map(|(t, _)| *t).collect()
}

/// Snapshot live process vtgids (Linux "PIDs") for procfs readdir.
/// Tasks without a vtgid (kernel threads pre-fork, smokes) are
/// skipped — they don't have a `/proc/N` directory in Linux either.
/// Sorted ascending for stable ordering.
/// # C: O(N_tasks log N_tasks)
pub fn live_vpids() -> Vec<u32> {
    use core::sync::atomic::Ordering;
    let mut g = REG.lock();
    g.retain(|(_, w)| w.strong_count() > 0);
    let mut out: Vec<u32> = g.iter()
        .filter_map(|(_, w)| w.upgrade())
        .map(|t| t.vtgid.load(Ordering::Acquire))
        .filter(|&v| v != 0)
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// Resolve a userspace PID (vtgid) to a Task. Different from
/// `lookup` which keys on the kernel-internal TID. Used by procfs's
/// `/proc/<PID>` lookup so `cat /proc/1/status` sees init.
/// # C: O(N_tasks)
pub fn lookup_by_vpid(vpid: u32) -> Option<Arc<Task>> {
    use core::sync::atomic::Ordering;
    let g = REG.lock();
    g.iter()
        .filter_map(|(_, w)| w.upgrade())
        .find(|t| t.vtgid.load(Ordering::Acquire) == vpid)
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
    task.cont_pending.store(true, core::sync::atomic::Ordering::Release);
    task.set_state(TaskState::Runnable);
    // Per `13§9` wakeup→resched: a newly-runnable task may outrank
    // current; flag a reschedule so the next preempt-enable or
    // syscall-return point picks it up. Cheaper than calling
    // schedule() directly here (registry holds no runqueue lock).
    #[cfg(target_os = "oxide-kernel")]
    crate::live::preempt::set_need_resched();
    true
}

/// wait4(WUNTRACED/WCONTINUED) helper: take first pending stop/cont.
/// `pid` follows wait4 semantics (-1/0/+pid/-pgid). Returns (tid, kind, sig)
/// where kind: 1 = stopped, 2 = continued.
/// # C: O(N_tasks)
/// # Lk: REG.lock
pub fn take_child_stop_event(parent: u32, pid: i32, want_stop: bool, want_cont: bool) -> Option<(u32, u8, u32)> {
    use core::sync::atomic::Ordering;
    let g = REG.lock();
    for (_, w) in g.iter() {
        let Some(t) = w.upgrade() else { continue };
        if t.parent_tid.load(Ordering::Acquire) != parent { continue }
        let vpid = t.vtgid.load(Ordering::Acquire) as i32;
        let pgid = t.pgid.load(Ordering::Acquire) as i32;
        let matches = if pid == -1 || pid == 0 { true }
                      else if pid > 0 { vpid == pid }
                      else { pgid == -pid };
        if !matches { continue }
        if want_stop && t.stop_pending.swap(false, Ordering::AcqRel) {
            let sig = t.stop_signal.load(Ordering::Acquire);
            return Some((t.tid, 1, sig as u32));
        }
        if want_cont && t.cont_pending.swap(false, Ordering::AcqRel) {
            return Some((t.tid, 2, 0));
        }
    }
    None
}

/// Returns true if any live task has `parent_tid == parent`.
/// # C: O(N_tasks)
pub fn has_children(parent: u32) -> bool {
    use core::sync::atomic::Ordering;
    let g = REG.lock();
    g.iter()
        .filter_map(|(_, w)| w.upgrade())
        .any(|t| t.parent_tid.load(Ordering::Acquire) == parent)
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
