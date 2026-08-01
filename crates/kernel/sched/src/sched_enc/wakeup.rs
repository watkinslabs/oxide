// Wakeup preemption: "does this newly-runnable task get to take the CPU away
// from the one running on it right now?" — `wakeup_preempt` plus the rt / fair
// / idle class hooks it dispatches to.
//
// Deliberately a pure function over two value snapshots, in an UNGATED module:
// the answer is policy, and policy that lives inside a `target_os` -gated file
// is untestable (its `#[cfg(test)]` block compiles out silently). The live wake
// paths snapshot both tasks with [`cand_of`] and apply the answer.
//
// Answering "always yes" — the pre-B1587 behaviour — is what made SCHED_FIFO,
// SCHED_BATCH and SCHED_IDLE indistinguishable from SCHED_NORMAL: a FIFO task
// lost the CPU to an equal-priority peer on any unrelated wakeup (the one
// guarantee FIFO exists to make), and a SCHED_IDLE wakee preempted a
// SCHED_NORMAL task.

use core::sync::atomic::Ordering;

use crate::sched_enc::{SCHED_IDLE, SCHED_NORMAL};
use crate::task::{SchedClass, Task};

/// Scheduling-class rank. Ordered as upstream orders its class chain — a task
/// of a HIGHER rank preempts a task of a lower one on sight, and a lower rank
/// never preempts a higher. Only the relative order is meaningful.
pub const RANK_IDLE: u8 = 0;
/// Fair class (`SCHED_NORMAL` / `SCHED_BATCH` / `SCHED_IDLE`).
pub const RANK_FAIR: u8 = 1;
/// Real-time class (`SCHED_FIFO` / `SCHED_RR`).
pub const RANK_RT: u8 = 2;
/// Deadline class (`SCHED_DEADLINE`). Above RT: an admitted deadline task
/// carries a timing guarantee the priority-ordered class cannot make, so it
/// wins on sight and never loses to a priority however high.
pub const RANK_DL: u8 = 3;

/// The scheduler-visible facts about one task that the wakeup-preemption
/// decision reads. Snapshotted so the decision is a pure function and cannot
/// observe a task changing class halfway through.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Cand {
    /// Class rank (`RANK_*`).
    pub rank: u8,
    /// `SCHED_*` policy code. Distinguishes NORMAL / BATCH / IDLE inside the
    /// fair class, which is the entire difference between those policies.
    pub policy: u32,
    /// RT priority, higher = more urgent. Meaningful only at [`RANK_RT`].
    pub rt_prio: u8,
    /// Fair-class virtual runtime; the pick order within [`RANK_FAIR`].
    pub vruntime: u64,
    /// Absolute deadline; the pick order within [`RANK_DL`].
    pub dl_deadline: u64,
    /// Governor entity — outranks every deadline, including its own class.
    pub dl_special: bool,
}

/// Snapshot a live task for [`wakeup_preempt`].
/// # C: O(1)
pub fn cand_of(t: &Task) -> Cand {
    let (rank, rt_prio) = match t.sched_class() {
        SchedClass::Deadline        => (RANK_DL, 0),
        SchedClass::Rt { prio, .. } => (RANK_RT, prio),
        SchedClass::Normal { .. }   => (RANK_FAIR, 0),
        SchedClass::Idle            => (RANK_IDLE, 0),
    };
    Cand {
        rank,
        policy: t.policy.load(Ordering::Acquire),
        rt_prio,
        vruntime: t.vruntime.load(Ordering::Acquire),
        dl_deadline: t.dl.abs_deadline(),
        dl_special: t.dl.params().is_special(),
    }
}

/// Should waking `wakee` make the CPU running `curr` reschedule?
///
/// Rules, in order:
///   1. `curr` is the per-CPU idle task — always yes, there is no point idling
///      with runnable work available.
///   2. Different class — the higher rank wins outright, in both directions.
///   3. Same class — the class's own rule ([`rt_wakeup_preempt`] /
///      [`fair_wakeup_preempt`]).
/// # C: O(1)
pub fn wakeup_preempt(wakee: Cand, curr: Cand) -> bool {
    if curr.rank == RANK_IDLE { return true; }
    if wakee.rank > curr.rank { return true; }
    if wakee.rank < curr.rank { return false; }
    match wakee.rank {
        RANK_DL   => dl_wakeup_preempt(wakee, curr),
        RANK_RT   => rt_wakeup_preempt(wakee, curr),
        RANK_FAIR => fair_wakeup_preempt(wakee, curr),
        _         => true,
    }
}

/// Deadline-class rule: a STRICTLY earlier absolute deadline preempts.
///
/// Equal deadlines do not, for the same reason equal RT priorities do not —
/// two tasks that must finish at the same instant have no ordering between
/// them, and rescheduling on every such wakeup would swap them back and forth
/// without either getting closer to its deadline.
/// # C: O(1)
pub fn dl_wakeup_preempt(wakee: Cand, curr: Cand) -> bool {
    crate::deadline::dl_entity_preempt(wakee.dl_deadline, wakee.dl_special, curr.dl_deadline)
}

/// RT-class rule: a STRICTLY higher priority preempts; equal priority does NOT.
///
/// Equal-priority non-preemption is the `SCHED_FIFO` contract — a running FIFO
/// task keeps the CPU until it blocks or yields, and a peer waking at the same
/// priority queues behind it. Upstream's only equal-priority reschedule is the
/// push-balancer's attempt to migrate `curr` elsewhere for a wakee that cannot
/// migrate, which is a placement decision, not a preemption of `curr`.
/// # C: O(1)
pub fn rt_wakeup_preempt(wakee: Cand, curr: Cand) -> bool { wakee.rt_prio > curr.rt_prio }

/// Fair-class rule. `SCHED_IDLE` is a floor: anything non-idle preempts it, and
/// it preempts nothing. `SCHED_BATCH` never preempts either — a batch wakee is
/// explicitly saying it does not need the CPU now. That leaves `SCHED_NORMAL`,
/// which preempts only when it is the more eligible entity, i.e. when it would
/// be the next pick ahead of `curr`.
/// # C: O(1)
pub fn fair_wakeup_preempt(wakee: Cand, curr: Cand) -> bool {
    let curr_idle  = curr.policy  == SCHED_IDLE;
    let wakee_idle = wakee.policy == SCHED_IDLE;
    // Non-idle over idle, never the inverse.
    if curr_idle != wakee_idle { return curr_idle; }
    // Only SCHED_NORMAL preempts a peer; BATCH (and IDLE over IDLE) do not.
    if wakee.policy != SCHED_NORMAL { return false; }
    wakee.vruntime < curr.vruntime
}

#[cfg(test)]
#[path = "wakeup/tests.rs"] mod tests;
