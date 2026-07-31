// wait4/waitid support: parent/child candidate matching and the
// stop/continue event scan. `parent_tgid_locked` is a tid-keyed point lookup
// (now O(log N) via `by_tid`, was an O(N) linear scan) — it runs once per
// candidate inside the O(N)/O(N²) walkers below, so this alone turns
// `has_wait_children`/`child_stop_event` from
// O(N²) into O(N log N).

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use syscall::rusage::{bytes_to_blocks, Rusage};
use syscall::wait::WaitEventKind;

use super::core::{RegIrq, REG, Registry};
use crate::wait_select::{self, Candidate, Waiter};
use crate::Task;

#[derive(Copy, Clone)]
pub struct WaitChildSnapshot {
    pub vpid:     u32,
    pub uid:      u32,
    pub utime_ns: u64,
    pub stime_ns: u64,
    /// The `rusage` the wait-family out-param reports: the child's own
    /// counters folded with the counters it had already accumulated from its
    /// own reaped children (`RUSAGE_BOTH`), so `time`-style callers see a
    /// whole subtree, not just the immediate child.
    pub rusage:   Rusage,
}

impl WaitChildSnapshot {
    /// # C: O(1)
    pub fn from_task(t: &Task) -> Self {
        Self {
            vpid:     t.vtgid.load(Ordering::Acquire),
            uid:      t.creds.ruid.load(Ordering::Acquire),
            utime_ns: t.utime_ns.load(Ordering::Acquire),
            stime_ns: t.stime_ns.load(Ordering::Acquire),
            rusage:   task_rusage_both(t),
        }
    }
}

/// A task's own resource counters — Linux `RUSAGE_SELF` for a single-threaded
/// process. # C: O(1)
pub fn task_rusage_self(t: &Task) -> Rusage {
    Rusage {
        utime_ns:  t.utime_ns.load(Ordering::Acquire),
        stime_ns:  t.stime_ns.load(Ordering::Acquire),
        // No RSS high-water accounting exists to source `ru_maxrss` from.
        maxrss_kb: 0,
        minflt:    t.min_flt.load(Ordering::Relaxed),
        majflt:    t.maj_flt.load(Ordering::Relaxed),
        inblock:   bytes_to_blocks(t.io_read_bytes.load(Ordering::Relaxed)),
        oublock:   bytes_to_blocks(t.io_write_bytes.load(Ordering::Relaxed)),
        nvcsw:     t.nvcsw.load(Ordering::Relaxed),
        nivcsw:    t.nivcsw.load(Ordering::Relaxed),
    }
}

/// Linux `RUSAGE_BOTH` for `t`: its own counters folded with everything its
/// process already accumulated from ITS reaped children. This is what a
/// wait-family `rusage` out-param reports, and what a dying task contributes
/// to its parent — so a whole subtree's cost reaches the ancestor measuring
/// it, not just the immediate child. # C: O(1)
pub fn task_rusage_both(t: &Task) -> Rusage {
    Rusage::both(task_rusage_self(t), t.thread_group.child_acct().snapshot())
}

/// True when this wait reaches `t` through a tracer relationship — the waiter
/// is `t`'s tracer, or a thread of the tracer's group. A traced tracee's stop
/// is visible to that waiter regardless of `WUNTRACED`, and reports
/// `CLD_TRAPPED` rather than `CLD_STOPPED`.
/// # C: O(log N_tasks)
fn is_ptrace_wait(g: &Registry, t: &Task, w: Waiter) -> bool {
    let tracer = t.traced_by.load(Ordering::Acquire);
    tracer != 0 && (tracer == w.tid || parent_tgid_locked(g, tracer) == w.tgid)
}

/// # C: O(log N_tasks)
fn parent_tgid_locked(g: &Registry, parent_tid: u32) -> u32 {
    g.by_tid
        .get(&parent_tid)
        .and_then(|w| w.upgrade())
        .map(|t| t.tgid.load(Ordering::Acquire))
        .unwrap_or(0)
}

/// # C: O(log N_tasks)
fn candidate_locked(g: &Registry, t: &Task) -> Candidate {
    let parent_tid = t.parent_tid.load(Ordering::Acquire);
    Candidate {
        parent_tid,
        parent_tgid: parent_tgid_locked(g, parent_tid),
        vpid:        t.vtgid.load(Ordering::Acquire),
        pgid:        t.pgid(),
        exit_signal: t.exit_signal.load(Ordering::Acquire),
    }
}

/// # C: O(N_tasks log N_tasks)
pub(crate) fn wait_candidate_matches(c: Candidate, waiter: Waiter, pid: i32, options: u64) -> bool {
    wait_select::eligible(c, waiter, pid, options)
}

/// wait4(WUNTRACED/WCONTINUED) / waitid(WSTOPPED/WCONTINUED) helper: take the
/// first pending stop/cont event. `pid` follows wait4 semantics
/// (-1/0/+pid/-pgid); `parent_pgid` is the waiter's process group (the
/// `pid==0` form). `consume` false leaves the event pending — the `WNOWAIT`
/// contract. Returns the child snapshot, the event kind, and the stop code.
///
/// A tracer sees its tracee's stop even without `WUNTRACED`, and that event
/// reports as a trap, not a job-control stop; `want_stop` gates only the
/// non-traced job-control case.
/// # C: O(N_tasks log N_tasks)
/// # Lk: REG.lock
pub fn child_stop_event(
    parent: u32,
    parent_tgid: u32,
    pid: i32,
    parent_pgid: u32,
    options: u64,
    want_stop: bool,
    want_cont: bool,
    consume: bool,
) -> Option<(WaitChildSnapshot, WaitEventKind, u32)> {
    let g = REG.lock_irqsave::<RegIrq>();
    let waiter = Waiter { tid: parent, tgid: parent_tgid, pgid: parent_pgid };
    for (_, w) in g.by_tid.iter() {
        let Some(t) = w.upgrade() else { continue };
        if !wait_candidate_matches(candidate_locked(&g, &t), waiter, pid, options) {
            continue;
        }
        let trapped = is_ptrace_wait(&g, &t, waiter);
        if (want_stop || trapped) && take_flag(&t.stop_pending, consume) {
            let code = t.stop_code.load(Ordering::Acquire);
            let kind = if trapped { WaitEventKind::Trapped } else { WaitEventKind::Stopped };
            return Some((WaitChildSnapshot::from_task(&t), kind, code));
        }
        if want_cont && take_flag(&t.cont_pending, consume) {
            return Some((WaitChildSnapshot::from_task(&t), WaitEventKind::Continued, 0));
        }
    }
    None
}

/// # C: O(1)
fn take_flag(f: &core::sync::atomic::AtomicBool, consume: bool) -> bool {
    if consume { f.swap(false, Ordering::AcqRel) } else { f.load(Ordering::Acquire) }
}

/// Returns true if any live task has `parent_tid == parent`.
/// # C: O(N_tasks)
pub fn has_children(parent: u32) -> bool {
    let g = REG.lock_irqsave::<RegIrq>();
    g.by_tid.values()
        .filter_map(|w| w.upgrade())
        .any(|t| t.parent_tid.load(Ordering::Acquire) == parent)
}

/// # C: O(N_tasks log N_tasks)
pub fn has_wait_children(parent: u32, parent_tgid: u32, pid: i32, parent_pgid: u32, options: u64) -> bool {
    let g = REG.lock_irqsave::<RegIrq>();
    let waiter = Waiter { tid: parent, tgid: parent_tgid, pgid: parent_pgid };
    g.by_tid.values()
        .filter_map(|w| w.upgrade())
        .any(|t| {
            !t.reaped.load(Ordering::Acquire)
                && wait_candidate_matches(candidate_locked(&g, &t), waiter, pid, options)
        })
}

/// Snapshot every live task whose pgid matches. Used by tty
/// line discipline + `kill(-pgid)` to fan signals to a process
/// group per `28§4`.
/// # C: O(N_tasks)
pub fn tasks_in_pgrp(pgid: u32) -> Vec<Arc<Task>> {
    let g = REG.lock_irqsave::<RegIrq>();
    g.by_tid.values()
        .filter_map(|w| w.upgrade())
        .filter(|t| !t.reaped.load(Ordering::Acquire) && t.pgid() == pgid)
        .collect()
}
