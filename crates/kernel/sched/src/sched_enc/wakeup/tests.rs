// Wakeup-preemption contract. These encode the behaviour the reference
// scheduler exhibits, so a later rewrite can re-check the rules without
// re-deriving them: they ARE the provenance for `wakeup.rs`.

use super::*;
use crate::sched_enc::{SCHED_BATCH, SCHED_FIFO, SCHED_RR};

fn rt(prio: u8, policy: u32) -> Cand { Cand { rank: RANK_RT, policy, rt_prio: prio, vruntime: 0, dl_deadline: 0, dl_special: false } }
fn fair(policy: u32, vruntime: u64) -> Cand { Cand { rank: RANK_FAIR, policy, rt_prio: 0, vruntime, dl_deadline: 0, dl_special: false } }
fn idle_task() -> Cand { Cand { rank: RANK_IDLE, policy: SCHED_NORMAL, rt_prio: 0, vruntime: 0, dl_deadline: 0, dl_special: false } }

#[test]
fn idle_task_always_yields_the_cpu() {
    assert!(wakeup_preempt(fair(SCHED_IDLE, u64::MAX), idle_task()));
    assert!(wakeup_preempt(fair(SCHED_BATCH, u64::MAX), idle_task()));
    assert!(wakeup_preempt(rt(1, SCHED_FIFO), idle_task()));
}

#[test]
fn higher_class_preempts_lower_and_never_the_inverse() {
    assert!(wakeup_preempt(rt(1, SCHED_FIFO), fair(SCHED_NORMAL, 0)));
    assert!(!wakeup_preempt(fair(SCHED_NORMAL, 0), rt(1, SCHED_FIFO)));
}

#[test]
fn fifo_keeps_the_cpu_against_an_equal_priority_peer() {
    // The defining SCHED_FIFO guarantee: a running FIFO task is not preempted
    // by a peer waking at its own priority.
    assert!(!wakeup_preempt(rt(50, SCHED_FIFO), rt(50, SCHED_FIFO)));
    assert!(!wakeup_preempt(rt(50, SCHED_RR), rt(50, SCHED_RR)));
}

#[test]
fn rt_preempts_only_on_strictly_higher_priority() {
    assert!(wakeup_preempt(rt(51, SCHED_FIFO), rt(50, SCHED_FIFO)));
    assert!(!wakeup_preempt(rt(49, SCHED_FIFO), rt(50, SCHED_FIFO)));
}

#[test]
fn batch_wakee_never_preempts() {
    // A SCHED_BATCH wakee stays queued even when it is the more eligible
    // entity — that is the whole observable difference from SCHED_NORMAL.
    assert!(!wakeup_preempt(fair(SCHED_BATCH, 0), fair(SCHED_NORMAL, u64::MAX)));
    assert!(!wakeup_preempt(fair(SCHED_BATCH, 0), fair(SCHED_BATCH, u64::MAX)));
}

#[test]
fn sched_idle_wakee_never_preempts_a_normal_task() {
    assert!(!wakeup_preempt(fair(SCHED_IDLE, 0), fair(SCHED_NORMAL, u64::MAX)));
    assert!(!wakeup_preempt(fair(SCHED_IDLE, 0), fair(SCHED_BATCH, u64::MAX)));
}

#[test]
fn non_idle_wakee_preempts_a_sched_idle_task() {
    // Runs even when the wakee is behind on vruntime: the idle policy is a
    // floor, not a position in the fair ordering.
    assert!(wakeup_preempt(fair(SCHED_NORMAL, u64::MAX), fair(SCHED_IDLE, 0)));
    assert!(wakeup_preempt(fair(SCHED_BATCH, u64::MAX), fair(SCHED_IDLE, 0)));
}

#[test]
fn sched_idle_does_not_preempt_sched_idle() {
    assert!(!wakeup_preempt(fair(SCHED_IDLE, 0), fair(SCHED_IDLE, u64::MAX)));
}

#[test]
fn normal_preempts_only_when_it_would_be_picked_first() {
    assert!(wakeup_preempt(fair(SCHED_NORMAL, 10), fair(SCHED_NORMAL, 20)));
    assert!(!wakeup_preempt(fair(SCHED_NORMAL, 20), fair(SCHED_NORMAL, 10)));
    assert!(!wakeup_preempt(fair(SCHED_NORMAL, 10), fair(SCHED_NORMAL, 10)));
}

#[test]
fn every_policy_pair_is_decided_without_defaulting_to_yes() {
    // Guards against a regression to the unconditional `resched_curr` this
    // module replaced: at least one same-class pair must answer "no".
    let policies = [SCHED_NORMAL, SCHED_BATCH, SCHED_IDLE];
    let mut refused = 0;
    for w in policies { for c in policies {
        if !wakeup_preempt(fair(w, 5), fair(c, 5)) { refused += 1; }
    } }
    assert!(refused > 0, "wakeup preemption degenerated to always-preempt");
}

#[test]
fn cand_of_reads_a_live_task() {
    use crate::task::{SchedClass, SchedPolicy, Task};
    use core::sync::atomic::Ordering;
    let t = Task::new(4242, "wakeup-cand", SchedClass::Normal { weight: 1024 });
    assert_eq!(cand_of(&t).rank, RANK_FAIR);
    t.set_sched_class(SchedClass::Rt { prio: 7, policy: SchedPolicy::Fifo });
    t.policy.store(SCHED_FIFO, Ordering::Release);
    let c = cand_of(&t);
    assert_eq!((c.rank, c.rt_prio, c.policy), (RANK_RT, 7, SCHED_FIFO));
}

/// A deadline candidate at absolute deadline `d`.
fn dl(d: u64) -> Cand {
    Cand { rank: RANK_DL, policy: crate::sched_enc::SCHED_DEADLINE, rt_prio: 0, vruntime: 0,
           dl_deadline: d, dl_special: false }
}

#[test]
fn a_deadline_wakee_preempts_the_highest_real_time_priority() {
    assert!(wakeup_preempt(dl(100), rt(99, crate::sched_enc::SCHED_FIFO)));
}

#[test]
fn a_real_time_wakee_never_preempts_a_deadline_task() {
    assert!(!wakeup_preempt(rt(99, crate::sched_enc::SCHED_FIFO), dl(100)));
}

#[test]
fn a_deadline_wakee_preempts_a_fair_task() {
    assert!(wakeup_preempt(dl(100), fair(SCHED_NORMAL, 0)));
    assert!(!wakeup_preempt(fair(SCHED_NORMAL, 0), dl(100)));
}

#[test]
fn an_earlier_deadline_preempts_a_later_one() {
    assert!(wakeup_preempt(dl(50), dl(100)));
    assert!(!wakeup_preempt(dl(100), dl(50)));
}

#[test]
fn an_equal_deadline_does_not_preempt() {
    // Two tasks due at the same instant have no ordering; rescheduling on every
    // such wakeup would swap them without either getting closer to its deadline.
    assert!(!wakeup_preempt(dl(100), dl(100)));
}

#[test]
fn a_governor_entity_preempts_any_deadline() {
    let mut sugov = dl(u64::MAX);
    sugov.dl_special = true;
    assert!(wakeup_preempt(sugov, dl(1)));
}
