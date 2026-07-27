// Full-registry walks: legitimately O(N_tasks) (procfs readdir, /proc/stat,
// diagnostics, the pid-namespace fallback scan) — `08§7`/ticket B1429 keeps
// these list-shaped rather than indexing them. `next_live_tid_after` is the
// one exception inside this file: it is called from hard-IRQ context
// (`live/tick_deadline.rs::tick_wake_expired`, every ~100ms) and MUST NOT
// allocate or mutate the map there (the prior Vec-based version re-scanned +
// retained the WHOLE registry every call — O(N_tasks) per call from inside a
// timer ISR, growing with uptime), so it walks a `BTreeMap::range` and prunes
// nothing; dead entries in its path are cleaned up by the bulk walkers below
// on their next pass.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::core::{prune_dead_locked, RegIrq, REG};
use crate::{Task, TaskState};

/// Best-effort snapshot of all live tasks for diagnostics (sysrq /
/// liveness-watchdog dump). Uses `try_lock` so a hung holder of `REG`
/// cannot deadlock the dump path itself — returns `None` if the lock
/// is contended (the dumper then reports "registry busy" rather than
/// wedging the whole machine while trying to diagnose a wedge).
/// # C: O(N_tasks)
/// # Lk: REG.try_lock (non-blocking)
pub fn try_snapshot() -> Option<Vec<Arc<Task>>> {
    let g = REG.try_lock()?;
    Some(g.by_tid.values().filter_map(|w| w.upgrade()).collect())
}

/// Snapshot live Task-owned kernel-stack charges.  This is the scheduler's
/// canonical global `KernelStack` input: each Task contributes only the exact
/// memcg charge retained with its owned stack, never a fixed stack-size guess.
/// # C: O(N_tasks)
pub fn kernel_stack_bytes_snapshot() -> u64 {
    REG.lock_irqsave::<RegIrq>().by_tid.values().filter_map(|w| w.upgrade())
        .map(|task| task.kernel_stack_bytes()).sum()
}

/// Snapshot live tids for procfs readdir. Skips entries whose
/// `Weak<Task>` has decayed; prunes them via the shared bulk sweep.
/// # C: O(N_tasks)
pub fn live_tids() -> Vec<u32> {
    let mut g = REG.lock_irqsave::<RegIrq>();
    prune_dead_locked(&mut g);
    // Skip reaped-but-pinned tasks (Linux release_task): gone from the process
    // table, and never a valid reparent target / procfs entry.
    g.by_tid
        .iter()
        .filter(|(_, w)| w.upgrade().map_or(false, |t| !t.reaped.load(Ordering::Acquire)))
        .map(|(t, _)| *t)
        .collect()
}

/// Return the next live, non-reaped internal tid strictly greater than
/// `after`.  This is the allocation-free iterator primitive for hard-IRQ
/// callers: each call holds the registry only while choosing one tid, so the
/// caller can resolve and wake that task after releasing `REG`. Walks a
/// `BTreeMap::range` starting just past `after` instead of rescanning from
/// the top, so a full enumeration loop (`tick_wake_expired`) costs
/// O(N log N) total instead of the old O(N²) (O(N) retain+scan per tid).
/// # C: O(log N_tasks + k) where k = consecutive dead/reaped entries skipped
/// # Lk: REG only; no mutation (hard-IRQ safe — see module doc)
pub fn next_live_tid_after(after: u32) -> Option<u32> {
    use core::ops::Bound::{Excluded, Unbounded};
    let g = REG.lock_irqsave::<RegIrq>();
    g.by_tid
        .range((Excluded(after), Unbounded))
        .find_map(|(&tid, w)| {
            w.upgrade()
                .filter(|t| !t.reaped.load(Ordering::Acquire))
                .map(|_| tid)
        })
}

/// `(total_live, runnable)` — used by `/proc/stat`'s `processes` and
/// `procs_running` lines. Blocked = total - runnable - stopped, which
/// callers can compute if they care; v1 procfs reports only running.
/// # C: O(N_tasks)
pub fn live_counts() -> (u64, u64) {
    let mut g = REG.lock_irqsave::<RegIrq>();
    prune_dead_locked(&mut g);
    let mut total = 0u64;
    let mut runnable = 0u64;
    for w in g.by_tid.values() {
        if let Some(t) = w.upgrade() {
            // Skip reaped-but-pidfd-pinned tasks (Linux release_task): they are
            // gone from the process table even though the Arc is still alive.
            if t.reaped.load(Ordering::Acquire) { continue; }
            total += 1;
            if matches!(t.state(), TaskState::Runnable) {
                runnable += 1;
            }
        }
    }
    (total, runnable)
}

/// Snapshot live threads in the real thread-group `tgid`. Returns
/// `(visible_tid, real_tid)` pairs sorted by visible tid so
/// `/proc/<pid>/task` enumeration is stable and Linux-like.
/// # C: O(N_tasks log N_tasks)
pub fn thread_entries(tgid: u32) -> Vec<(u32, u32)> {
    let g = REG.lock_irqsave::<RegIrq>();
    let mut out: Vec<(u32, u32)> = g
        .by_tid
        .values()
        .filter_map(|w| w.upgrade())
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

/// # C: O(N_tasks)
pub(super) fn snapshot_tasks_for_pid_lookup() -> Vec<Arc<Task>> {
    REG.lock_irqsave::<RegIrq>().by_tid.values().filter_map(|w| w.upgrade()).collect()
}
