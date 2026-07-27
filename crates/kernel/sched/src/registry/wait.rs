// wait4/waitid support: parent/child candidate matching and the
// stop/continue event scan. `parent_tgid_locked` is a tid-keyed point lookup
// (now O(log N) via `by_tid`, was an O(N) linear scan) — it runs once per
// candidate inside the O(N)/O(N²) walkers below, so this alone turns
// `has_wait_children`/`take_child_stop_event`/`peek_child_stop_event` from
// O(N²) into O(N log N).

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::core::{RegIrq, REG, Registry};
use crate::wait_select::{self, Candidate, Waiter};
use crate::Task;

#[derive(Copy, Clone)]
pub struct WaitChildSnapshot {
    pub vpid:     u32,
    pub uid:      u32,
    pub utime_ns: u64,
    pub stime_ns: u64,
}

impl WaitChildSnapshot {
    /// # C: O(1)
    pub fn from_task(t: &Task) -> Self {
        Self {
            vpid:     t.vtgid.load(Ordering::Acquire),
            uid:      t.creds.ruid.load(Ordering::Acquire),
            utime_ns: t.utime_ns.load(Ordering::Acquire),
            stime_ns: t.stime_ns.load(Ordering::Acquire),
        }
    }
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
        pgid:        t.pgid.load(Ordering::Acquire),
        exit_signal: t.exit_signal.load(Ordering::Acquire),
    }
}

/// # C: O(N_tasks log N_tasks)
pub(crate) fn wait_candidate_matches(c: Candidate, waiter: Waiter, pid: i32, options: u64) -> bool {
    wait_select::eligible(c, waiter, pid, options)
}

/// wait4(WUNTRACED/WCONTINUED) helper: take first pending stop/cont. `pid`
/// follows wait4 semantics (-1/0/+pid/-pgid). Returns (tid, kind, sig) where
/// kind: 1 = stopped, 2 = continued. `parent_pgid` is the waiter's process
/// group (for the `pid==0` form).
/// # C: O(N_tasks log N_tasks)
/// # Lk: REG.lock
pub fn take_child_stop_event(
    parent: u32,
    parent_tgid: u32,
    pid: i32,
    parent_pgid: u32,
    options: u64,
    want_stop: bool,
    want_cont: bool,
) -> Option<(WaitChildSnapshot, u8, u32)> {
    let g = REG.lock_irqsave::<RegIrq>();
    let waiter = Waiter { tid: parent, tgid: parent_tgid, pgid: parent_pgid };
    for (_, w) in g.by_tid.iter() {
        let Some(t) = w.upgrade() else { continue };
        if !wait_candidate_matches(candidate_locked(&g, &t), waiter, pid, options) {
            continue;
        }
        if want_stop && t.stop_pending.swap(false, Ordering::AcqRel) {
            let sig = t.stop_signal.load(Ordering::Acquire);
            return Some((WaitChildSnapshot::from_task(&t), 1, sig as u32));
        }
        if want_cont && t.cont_pending.swap(false, Ordering::AcqRel) {
            return Some((WaitChildSnapshot::from_task(&t), 2, 0));
        }
    }
    None
}

/// waitid(WNOWAIT|WSTOPPED/WCONTINUED) helper: observe the first pending
/// stop/cont event without consuming it. Same scan/filter/order as
/// `take_child_stop_event`.
/// # C: O(N_tasks log N_tasks)
/// # Lk: REG.lock
pub fn peek_child_stop_event(
    parent: u32,
    parent_tgid: u32,
    pid: i32,
    parent_pgid: u32,
    options: u64,
    want_stop: bool,
    want_cont: bool,
) -> Option<(WaitChildSnapshot, u8, u32)> {
    let g = REG.lock_irqsave::<RegIrq>();
    let waiter = Waiter { tid: parent, tgid: parent_tgid, pgid: parent_pgid };
    for (_, w) in g.by_tid.iter() {
        let Some(t) = w.upgrade() else { continue };
        if !wait_candidate_matches(candidate_locked(&g, &t), waiter, pid, options) {
            continue;
        }
        if want_stop && t.stop_pending.load(Ordering::Acquire) {
            let sig = t.stop_signal.load(Ordering::Acquire);
            return Some((WaitChildSnapshot::from_task(&t), 1, sig as u32));
        }
        if want_cont && t.cont_pending.load(Ordering::Acquire) {
            return Some((WaitChildSnapshot::from_task(&t), 2, 0));
        }
    }
    None
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
        .filter(|t| !t.reaped.load(Ordering::Acquire) && t.pgid.load(Ordering::Acquire) == pgid)
        .collect()
}
