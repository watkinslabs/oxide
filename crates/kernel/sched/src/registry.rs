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

static REG: Spinlock<Vec<(u32, Weak<Task>)>, TaskListClass> = Spinlock::new(Vec::new());

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
    g.iter()
        .find(|(t, _)| *t == tid)
        .and_then(|(_, w)| w.upgrade())
}

/// Resolve `(ns, vpid)` → live `Arc<Task>`. F109: pid-NS-aware
/// lookup for kill/wait4/tgkill from a task in a non-init pid_ns —
/// caller's vpid arg is interpreted within their NS instead of as a
/// real tid. Init-NS callers (`ns == 0`) match by real tid (the
/// init-NS shortcut).
/// # C: O(N_tasks)
pub fn lookup_in_ns(ns: u64, vpid: u32) -> Option<Arc<Task>> {
    use core::sync::atomic::Ordering;
    if ns == 0 {
        return lookup(vpid);
    }
    let g = REG.lock();
    g.iter().filter_map(|(_, w)| w.upgrade()).find(|t| {
        t.pid_ns.load(Ordering::Acquire) == ns
            && (t.vtgid.load(Ordering::Acquire) == vpid || t.vtid.load(Ordering::Acquire) == vpid)
    })
}

/// Best-effort snapshot of all live tasks for diagnostics (sysrq /
/// liveness-watchdog dump). Uses `try_lock` so a hung holder of `REG`
/// cannot deadlock the dump path itself — returns `None` if the lock
/// is contended (the dumper then reports "registry busy" rather than
/// wedging the whole machine while trying to diagnose a wedge).
/// # C: O(N_tasks)
/// # Lk: REG.try_lock (non-blocking)
pub fn try_snapshot() -> Option<Vec<Arc<Task>>> {
    let g = REG.try_lock()?;
    Some(g.iter().filter_map(|(_, w)| w.upgrade()).collect())
}

/// Snapshot live tids for procfs readdir. Skips entries whose
/// `Weak<Task>` has decayed; opportunistically prunes them.
/// # C: O(N_tasks)
pub fn live_tids() -> Vec<u32> {
    let mut g = REG.lock();
    g.retain(|(_, w)| w.strong_count() > 0);
    g.iter().map(|(t, _)| *t).collect()
}

/// `(total_live, runnable)` — used by `/proc/stat`'s `processes` and
/// `procs_running` lines. Blocked = total - runnable - stopped, which
/// callers can compute if they care; v1 procfs reports only running.
/// # C: O(N_tasks)
pub fn live_counts() -> (u64, u64) {
    let mut g = REG.lock();
    g.retain(|(_, w)| w.strong_count() > 0);
    let mut total = 0u64;
    let mut runnable = 0u64;
    for (_, w) in g.iter() {
        if let Some(t) = w.upgrade() {
            total += 1;
            if matches!(t.state(), TaskState::Runnable) {
                runnable += 1;
            }
        }
    }
    (total, runnable)
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
    let mut out: Vec<u32> = g
        .iter()
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

/// Namespace PID to display for the task with internal `tid`: its vtgid,
/// falling back to the internal tid for kernel threads / smokes that never
/// got a vpid stamped. procfs stat/status must show this (Linux "PID"),
/// not the opaque internal tid — PID1 is vtgid=1 but tid=0xC0DE….
/// # C: O(1) hash-free vec scan via `lookup`.
pub fn display_vpid(tid: u32) -> u64 {
    use core::sync::atomic::Ordering;
    match lookup(tid) {
        Some(t) => {
            let v = t.vtgid.load(Ordering::Acquire);
            if v != 0 {
                v as u64
            } else {
                tid as u64
            }
        }
        None => tid as u64,
    }
}

/// Namespace thread id to display for the task with internal `tid`:
/// its `vtid`, falling back to the internal tid for init-NS tasks.
/// `/proc/<pid>/task/<tid>` must expose thread ids, not process ids.
/// # C: O(1) hash-free vec scan via `lookup`.
pub fn display_vtid(tid: u32) -> u64 {
    use core::sync::atomic::Ordering;
    match lookup(tid) {
        Some(t) => {
            let v = t.vtid.load(Ordering::Acquire);
            if v != 0 {
                v as u64
            } else {
                tid as u64
            }
        }
        None => tid as u64,
    }
}

/// Parent's namespace PID for the task with internal `tid`: resolve its
/// internal parent_tid to that parent's vtgid. PID1's parent is the kernel
/// → 0 (Linux shows PPid 0 for init).
/// # C: O(N_tasks) — two registry lookups.
pub fn parent_vpid(tid: u32) -> u64 {
    use core::sync::atomic::Ordering;
    let ptid = match lookup(tid) {
        Some(t) => t.parent_tid.load(Ordering::Acquire),
        None => return 0,
    };
    lookup(ptid)
        .map(|p| p.vtgid.load(Ordering::Acquire))
        .filter(|&v| v != 0)
        .unwrap_or(0) as u64
}

/// Flip `task.state` Stopped → Runnable. Returns `true` if the
/// transition actually happened (caller is then responsible for
/// re-enqueueing into the runqueue); `false` if the task wasn't
/// Stopped to begin with. Used by SIGCONT delivery per signal(7):
/// the state-flip half is hosted-testable here, the re-enqueue
/// half lives in kernel-side `wake_if_stopped`.
/// # C: O(1)
pub fn try_wake_stopped(task: &Task) -> bool {
    if task.state() != TaskState::Stopped {
        return false;
    }
    task.cont_pending
        .store(true, core::sync::atomic::Ordering::Release);
    task.set_state(TaskState::Runnable);
    // Per `13§9` wakeup→resched: a newly-runnable task may outrank
    // current; flag a reschedule so the next preempt-enable or
    // syscall-return point picks it up. Cheaper than calling
    // schedule() directly here (registry holds no runqueue lock).
    #[cfg(target_os = "oxide-kernel")]
    crate::live::preempt::set_need_resched();
    true
}

/// wait4(2) child-selection predicate per `docs/15§5` — the single source
/// of truth shared by the zombie-reap path (`live::zombies::reap_one`/
/// `peek_one`) and the stop/cont path (`take_child_stop_event`). The four
/// POSIX `pid` forms (Linux `kernel/exit.c eligible_child`):
///   `-1`   any child of `parent`
///   `0`    child of `parent` in the waiter's process group (`parent_pgid`)
///   `>0`   that specific child by **kernel tid** — `056_clone` returns the
///          kernel tid to the parent, so `waitpid(pid)` carries a kernel
///          tid, NOT a vpid; matching `c_tid` is the inverse of that return
///   `<-1`  any child in process group `-pid`
/// `c_*` = the candidate child's fields. Pure (no globals) → unit-tested.
/// # C: O(1)
pub(crate) fn wait_pid_matches(
    c_parent_tid: u32, c_tid: u32, c_pgid: u32,
    parent: u32, pid: i32, parent_pgid: u32,
) -> bool {
    if c_parent_tid != parent { return false; }
    match pid {
        -1          => true,
        0           => c_pgid == parent_pgid,
        p if p > 0  => c_tid == p as u32,
        p           => c_pgid == (-p) as u32, // p < -1: process group -pid
    }
}

/// wait4(WUNTRACED/WCONTINUED) helper: take first pending stop/cont.
/// `pid` follows wait4 semantics (-1/0/+pid/-pgid). Returns (tid, kind, sig)
/// where kind: 1 = stopped, 2 = continued. `parent_pgid` is the waiter's
/// process group (for the `pid==0` form).
/// # C: O(N_tasks)
/// # Lk: REG.lock
pub fn take_child_stop_event(
    parent: u32,
    pid: i32,
    parent_pgid: u32,
    want_stop: bool,
    want_cont: bool,
) -> Option<(u32, u8, u32)> {
    use core::sync::atomic::Ordering;
    let g = REG.lock();
    for (_, w) in g.iter() {
        let Some(t) = w.upgrade() else { continue };
        if !wait_pid_matches(
            t.parent_tid.load(Ordering::Acquire), t.tid,
            t.pgid.load(Ordering::Acquire), parent, pid, parent_pgid)
        {
            continue;
        }
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

/// Snapshot live threads in the real thread-group `tgid`. Returns
/// `(visible_tid, real_tid)` pairs sorted by visible tid so
/// `/proc/<pid>/task` enumeration is stable and Linux-like.
/// # C: O(N_tasks log N_tasks)
pub fn thread_entries(tgid: u32) -> Vec<(u32, u32)> {
    use core::sync::atomic::Ordering;
    let g = REG.lock();
    let mut out: Vec<(u32, u32)> = g
        .iter()
        .filter_map(|(_, w)| w.upgrade())
        .filter(|t| t.tgid.load(Ordering::Acquire) == tgid)
        .map(|t| {
            let vtid = t.vtid.load(Ordering::Acquire);
            (if vtid != 0 { vtid } else { t.tid }, t.tid)
        })
        .collect();
    out.sort_unstable_by_key(|(vtid, _)| *vtid);
    out.dedup_by_key(|(vtid, _)| *vtid);
    out
}

/// Test-only: drop every registered entry. Hosted tests share the
/// process-global slot, so this resets the table between cases.
/// # C: O(N_tasks)
#[cfg(test)]
pub fn clear_for_tests() {
    REG.lock().clear();
}

#[cfg(test)]
mod wait_match_tests {
    use super::wait_pid_matches;
    // Candidate child: parent_tid=100, kernel tid=4242, pgid=70.
    // Waiter: parent_tid=100, process group 70.
    const PARENT: u32 = 100;
    const TID:    u32 = 4242;
    const PGID:   u32 = 70;
    fn m(pid: i32) -> bool { wait_pid_matches(PARENT, TID, PGID, 100, pid, 70) }

    #[test]
    fn minus_one_matches_any_child() { assert!(m(-1)); }

    #[test]
    fn positive_pid_matches_kernel_tid_not_pgid() {
        assert!(m(4242));   // clone returned the kernel tid → waitpid(tid) matches
        assert!(!m(70));    // a pgid is not a tid
        assert!(!m(4243));  // wrong tid
    }

    #[test]
    fn zero_matches_waiters_pgrp_only() {
        assert!(wait_pid_matches(PARENT, TID, 70, 100, 0, 70));  // same pgrp
        assert!(!wait_pid_matches(PARENT, TID, 88, 100, 0, 70)); // other pgrp
    }

    #[test]
    fn neg_pgid_matches_that_process_group() {
        assert!(m(-70));    // -pid == child pgid 70
        assert!(!m(-88));   // different pgrp
        assert!(!m(-4242)); // a tid is not a pgid
    }

    #[test]
    fn other_parent_never_matches() {
        for pid in [-4242, -70, -1, 0, 70, 4242] {
            assert!(!wait_pid_matches(PARENT, TID, PGID, 999, pid, 70), "pid={pid}");
        }
    }
}
