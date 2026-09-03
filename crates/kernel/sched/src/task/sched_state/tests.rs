use alloc::sync::Arc;

use super::*;
use crate::task::{AtomicLoadWeight, Task};

#[test]
fn fair_constructor_has_one_coherent_priority_and_load() {
    let task = Task::new(1, "fair-state", SchedClass::Normal { weight: 1_024 });
    let state = task.priority_snapshot();
    let fair = SchedPriority::fair(0).unwrap();
    assert_eq!((state.static_prio, state.normal_prio, state.prio), (fair, fair, fair));
    assert_eq!(state.sched_class, SchedClassId::Fair);
    assert_eq!(state.load, LoadWeight::for_nice(0).unwrap());
    assert_eq!(task.sched_class(), SchedClass::Normal { weight: 1_024 });
}

#[test]
fn utilization_clamp_type_rejects_noncanonical_state() {
    assert!(SchedUclamp::new(0, crate::sched_enc::UCLAMP_CAPACITY_SCALE, 0).is_some());
    assert!(SchedUclamp::new(800, 700, 0).is_some(),
        "an automatic RT minimum may exceed a retained user maximum");
    assert!(SchedUclamp::new(crate::sched_enc::UCLAMP_CAPACITY_SCALE + 1, 1_024, 0).is_none());
    assert!(SchedUclamp::new(0, crate::sched_enc::UCLAMP_CAPACITY_SCALE + 1, 0).is_none());
    assert!(SchedUclamp::new(0, crate::sched_enc::UCLAMP_CAPACITY_SCALE, 4).is_none());
}

#[test]
fn fork_snapshot_never_pairs_policy_and_clamp_from_different_transactions() {
    let task = Arc::new(Task::new(30, "fork-generation",
        SchedClass::Normal { weight: 1_024 }));
    let fair_clamp = SchedUclamp::new(100, 900, 3).unwrap();
    let rt_clamp = SchedUclamp::new(700, 1_024, 1).unwrap();
    task.set_sched_policy_controls(SchedClass::Normal { weight: 1_024 },
        crate::sched_enc::SCHED_NORMAL, fair_clamp, true);
    let writer = Arc::clone(&task);
    let join = std::thread::spawn(move || {
        for i in 0..20_000 {
            if i & 1 == 0 {
                writer.set_sched_policy_controls(SchedClass::Rt {
                    prio: 73, policy: SchedPolicy::Rr,
                }, crate::sched_enc::SCHED_RR, rt_clamp, false);
            } else {
                writer.set_sched_policy_controls(SchedClass::Normal { weight: 1_024 },
                    crate::sched_enc::SCHED_NORMAL, fair_clamp, true);
            }
        }
    });
    for _ in 0..20_000 {
        let (priority, clamp, _) = task.sched_fork_snapshot();
        let fair = priority.policy == TaskPolicy::Normal && clamp == fair_clamp
            && priority.sched_class == SchedClassId::Fair && priority.reset_on_fork;
        let rt = priority.policy == TaskPolicy::Rr && clamp == rt_clamp
            && priority.sched_class == SchedClassId::PosixRt && !priority.reset_on_fork;
        assert!(fair || rt);
    }
    join.join().unwrap();
}

#[test]
fn nonzero_nice_constructor_keeps_static_normal_and_load_equal() {
    let task = Task::new(2, "nice-state", SchedClass::Normal { weight: 3_121 });
    let state = task.priority_snapshot();
    let fair = SchedPriority::fair(-5).unwrap();
    assert_eq!((state.static_prio, state.normal_prio, state.prio), (fair, fair, fair));
    assert_eq!(state.load, LoadWeight::for_nice(-5).unwrap());
}

#[test]
fn rt_constructor_keeps_latent_fair_static_priority() {
    let task = Task::new(3, "rt-state", SchedClass::Rt { prio: 73, policy: SchedPolicy::Rr });
    let state = task.priority_snapshot();
    assert_eq!(state.static_prio, SchedPriority::fair(0).unwrap());
    assert_eq!(state.normal_prio, SchedPriority::posix_rt(73).unwrap());
    assert_eq!(state.prio, state.normal_prio);
    assert_eq!((state.rt_priority, state.policy, state.sched_class),
        (73, TaskPolicy::Rr, SchedClassId::PosixRt));
}

#[test]
fn nice_change_is_latent_for_rt_and_does_not_reweight_it() {
    let task = Task::new(4, "rt-nice", SchedClass::Rt { prio: 40, policy: SchedPolicy::Fifo });
    task.set_nice_value(-11);
    let state = task.priority_snapshot();
    assert_eq!(state.static_prio, SchedPriority::fair(-11).unwrap());
    assert_eq!(state.normal_prio, SchedPriority::posix_rt(40).unwrap());
    assert_eq!(state.prio, state.normal_prio);
    assert_eq!(state.load, LoadWeight::for_nice(0).unwrap());
}

#[test]
fn effective_donation_never_overwrites_normal_state_or_fair_load() {
    let task = Task::new(5, "donated", SchedClass::Normal { weight: 1_024 });
    task.set_sched_class(SchedClass::Rt { prio: 80, policy: SchedPolicy::Fifo });
    let state = task.priority_snapshot();
    assert_eq!(state.normal_prio, SchedPriority::fair(0).unwrap());
    assert_eq!(state.prio, SchedPriority::posix_rt(80).unwrap());
    assert_eq!(state.rt_priority, 0, "requested RT priority cannot inherit a donor value");
    assert_eq!(state.load, LoadWeight::for_nice(0).unwrap());
    assert!(task.sched_is_boosted());
}

#[test]
#[should_panic(expected = "fair task construction requires a Linux nice-table weight")]
fn unknown_legacy_weight_is_rejected() {
    let _ = Task::new(6, "bad-weight", SchedClass::Normal { weight: 2_048 });
}

#[test]
fn priority_snapshot_serializes_against_nice_writers() {
    let task = Arc::new(Task::new(7, "snapshot", SchedClass::Normal { weight: 1_024 }));
    let writer = Arc::clone(&task);
    let join = std::thread::spawn(move || {
        for i in 0..20_000 { writer.set_nice_value(if i & 1 == 0 { -20 } else { 19 }); }
    });
    for _ in 0..20_000 {
        let state = task.sched.priority_snapshot();
        let nice = state.static_prio.nice().unwrap() as i8;
        assert!(nice == -20 || nice == 19 || nice == 0);
        assert_eq!(state.load, LoadWeight::for_nice(nice).unwrap());
        assert_eq!(state.normal_prio, state.static_prio);
        assert_eq!(state.prio, state.normal_prio);
    }
    join.join().unwrap();
}

#[test]
fn priority_snapshot_never_tears_policy_class_and_rt_priority() {
    let task = Arc::new(Task::new(8, "policy-snapshot", SchedClass::Normal { weight: 1_024 }));
    let writer = Arc::clone(&task);
    let join = std::thread::spawn(move || {
        for i in 0..20_000 {
            if i & 1 == 0 {
                writer.set_normal_sched_class_policy(
                    SchedClass::Rt { prio: 73, policy: SchedPolicy::Rr },
                    crate::sched_enc::SCHED_RR);
            } else {
                writer.set_normal_sched_class_policy(SchedClass::Normal { weight: 1_024 },
                    crate::sched_enc::SCHED_NORMAL);
            }
        }
    });
    for _ in 0..20_000 {
        let state = task.sched.priority_snapshot();
        let fair = state.policy == TaskPolicy::Normal && state.rt_priority == 0
            && state.sched_class == SchedClassId::Fair
            && state.prio == SchedPriority::fair(0).unwrap();
        let rt = state.policy == TaskPolicy::Rr && state.rt_priority == 73
            && state.sched_class == SchedClassId::PosixRt
            && state.prio == SchedPriority::posix_rt(73).unwrap();
        assert!(fair || rt, "snapshot combined fields from different publications");
    }
    join.join().unwrap();
}

#[test]
fn donor_is_retained_while_a_stronger_normal_priority_temporarily_wins() {
    let task = Task::new(9, "normal-wins", SchedClass::Rt {
        prio: 20, policy: SchedPolicy::Fifo,
    });
    task.set_sched_class(SchedClass::Rt { prio: 40, policy: SchedPolicy::Fifo });
    task.set_normal_sched_class_policy(SchedClass::Rt {
        prio: 80, policy: SchedPolicy::Fifo,
    }, crate::sched_enc::SCHED_FIFO);
    let state = task.priority_snapshot();
    assert_eq!(state.normal_prio, SchedPriority::posix_rt(80).unwrap());
    assert_eq!(state.prio, state.normal_prio);
    assert!(task.sched_is_boosted(), "the still-blocked donor relationship remains recorded");

    task.set_normal_sched_class_policy(SchedClass::Rt {
        prio: 20, policy: SchedPolicy::Fifo,
    }, crate::sched_enc::SCHED_FIFO);
    let lowered = task.priority_snapshot();
    assert_eq!(lowered.normal_prio, SchedPriority::posix_rt(20).unwrap());
    assert_eq!(lowered.prio, SchedPriority::posix_rt(40).unwrap());
}

#[test]
fn nice_change_recomputes_effective_priority_against_retained_fair_donor() {
    let task = Task::new(11, "nice-donor", SchedClass::Normal { weight: 1_024 });
    task.set_sched_class(SchedClass::Normal { weight: 3_121 });
    task.set_nice_value(-10);
    let raised = task.priority_snapshot();
    assert_eq!(raised.normal_prio, SchedPriority::fair(-10).unwrap());
    assert_eq!(raised.prio, raised.normal_prio);
    assert!(raised.has_donor);
    task.set_nice_value(10);
    assert_eq!(task.priority_snapshot().prio, SchedPriority::fair(-5).unwrap());
}

#[test]
fn sched_idle_keeps_idle_load_while_a_fair_donor_survives_nice_changes() {
    let task = Task::new(12, "idle-donor", SchedClass::Normal {
        weight: super::super::sched_entity::WEIGHT_IDLEPRIO,
    });
    task.set_sched_class(SchedClass::Normal { weight: 15 });
    task.set_nice_value(-20);
    assert_eq!(task.normal_sched_class(), SchedClass::Normal { weight: 3 });
    assert_eq!(task.sched_class(), SchedClass::Normal { weight: 15 });
    assert_eq!(task.priority_snapshot().load, LoadWeight::idle());
    task.restore_normal_sched_class();
    assert_eq!(task.sched_class(), SchedClass::Normal { weight: 3 });
    assert!(!task.sched_is_boosted());
    assert_eq!(task.priority_snapshot().prio, SchedPriority::fair(-20).unwrap());
}

#[test]
fn fair_donation_changes_effective_descriptor_without_configured_load() {
    let task = Task::new(10, "fair-donor", SchedClass::Normal { weight: 15 });
    task.set_sched_class(SchedClass::Normal { weight: 88_761 });
    assert_eq!(task.sched_class(), SchedClass::Normal { weight: 88_761 });
    assert_eq!(task.normal_sched_class(), SchedClass::Normal { weight: 15 });
    assert_eq!(task.priority_snapshot().load, LoadWeight::for_nice(19).unwrap());
}

#[test]
fn load_snapshot_never_pairs_weight_from_one_nice_with_another_inverse() {
    let low = LoadWeight::for_nice(-20).unwrap();
    let high = LoadWeight::for_nice(19).unwrap();
    let load = Arc::new(AtomicLoadWeight::new(low));
    let writer = Arc::clone(&load);
    let join = std::thread::spawn(move || {
        for i in 0..20_000 { writer.store(if i & 1 == 0 { low } else { high }); }
    });
    for _ in 0..20_000 {
        let observed = load.snapshot();
        assert!(observed == low || observed == high, "load pair crossed publications");
    }
    join.join().unwrap();
}
