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

/// Peak resident set of `t`'s process, in KiB. Folds the process's latched
/// peak (surviving execve and thread exit) with the live `mm`'s own peak —
/// Linux reads `signal_struct::maxrss` then applies `setmax_mm_hiwater_rss`
/// against the current `mm` for exactly this reason. # C: O(1); # Lk: mm_pin
fn maxrss_kb(t: &Task) -> u64 {
    let latched = t.thread_group.group_acct().hiwater_rss_pages();
    let live = t.clone_mm().map(|mm| mm.accounting_snapshot().hiwater_rss_pages).unwrap_or(0);
    vmm::RssPages::kib(vmm::rss::hiwater_rss(latched, live))
}

/// Linux `RUSAGE_THREAD`: the CALLING THREAD's counters alone, with the
/// process-wide resident-set peak (Linux takes `maxrss` from `signal_struct`
/// on this path too — RSS is a property of the mm, which threads share).
/// # C: O(1)
pub fn task_rusage_thread(t: &Task) -> Rusage {
    Rusage {
        utime_ns:  t.utime_ns.load(Ordering::Acquire),
        stime_ns:  t.stime_ns.load(Ordering::Acquire),
        maxrss_kb: maxrss_kb(t),
        minflt:    t.min_flt.load(Ordering::Relaxed),
        majflt:    t.maj_flt.load(Ordering::Relaxed),
        inblock:   bytes_to_blocks(t.io_read_bytes.load(Ordering::Relaxed)),
        oublock:   bytes_to_blocks(t.io_write_bytes.load(Ordering::Relaxed)),
        nvcsw:     t.nvcsw.load(Ordering::Relaxed),
        nivcsw:    t.nivcsw.load(Ordering::Relaxed),
    }
}

/// Linux `RUSAGE_SELF`: the WHOLE THREAD GROUP — every live thread plus the
/// residue of every thread that already exited. Reporting the calling thread
/// alone made a threaded process under-report its own cost by however much its
/// siblings had spent, and made a `time` builtin read zero after the worker
/// thread that did the work exited. # C: O(1)
pub fn task_rusage_self(t: &Task) -> Rusage {
    let (utime_ns, stime_ns) = t.thread_group.cpu_sample();
    Rusage { utime_ns, stime_ns, maxrss_kb: maxrss_kb(t), ..t.thread_group.group_acct().snapshot() }
}

/// Linux `RUSAGE_BOTH` for `t`: its process's counters folded with everything
/// that process already accumulated from ITS reaped children. This is what a
/// wait-family `rusage` out-param reports, and what a dying task contributes
/// to its parent — so a whole subtree's cost reaches the ancestor measuring
/// it, not just the immediate child. # C: O(1)
pub fn task_rusage_both(t: &Task) -> Rusage {
    Rusage::both(task_rusage_self(t), t.thread_group.child_acct().snapshot())
}

/// True when this wait reaches `t` through the tracer link rather than the
/// real-parent one — Linux's `ptrace_do_wait` list. Such a stop is visible to
/// the waiter regardless of `WUNTRACED` and reports `CLD_TRAPPED` rather than
/// `CLD_STOPPED`.
///
/// The predicate is `wait_select::ptrace_scope_matches`, the same one
/// `eligible` admitted the candidate with — asking a second, differently
/// worded question here is how a candidate could be admitted as a tracee and
/// then reported as a job-control stop.
/// # C: O(log N_tasks)
fn is_ptrace_wait(g: &Registry, t: &Task, w: Waiter, options: u64) -> bool {
    wait_select::ptrace_scope_matches(candidate_locked(g, t), w, options)
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
    let tracer_tid = t.traced_by.load(Ordering::Acquire);
    Candidate {
        parent_tid,
        parent_tgid: parent_tgid_locked(g, parent_tid),
        tracer_tid,
        tracer_tgid: parent_tgid_locked(g, tracer_tid),
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
        let trapped = is_ptrace_wait(&g, &t, waiter, options);
        // Linux `wait_task_stopped` reads `*p_code` and bails on zero
        // (`if (!exit_code) goto unlock_sig;`) BEFORE consuming the event. Zero
        // is not a stop code: a tracer that resumed its tracee without waiting
        // wrote its `data` there and the tracee then cleared it, so reporting
        // it would hand userspace a `WIFSTOPPED` status with signal 0.
        if (want_stop || trapped) && t.stop_pending.load(Ordering::Acquire) {
            let code = t.stop_code.load(Ordering::Acquire);
            if code != 0 && take_flag(&t.stop_pending, consume) {
                let kind = if trapped { WaitEventKind::Trapped } else { WaitEventKind::Stopped };
                return Some((WaitChildSnapshot::from_task(&t), kind, code));
            }
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
