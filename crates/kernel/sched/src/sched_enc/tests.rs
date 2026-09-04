use crate::deadline::DlParams;
use crate::task::{SchedClass, SchedPolicy};
use crate::{SchedUclamp, SchedUpdate, Task};

fn update(class: SchedClass, policy: u32, deadline: Option<DlParams>) -> SchedUpdate {
    SchedUpdate { class, policy,
        clamp: SchedUclamp::new(0, super::UCLAMP_CAPACITY_SCALE, 0).unwrap(),
        reset_on_fork: false, nice: None, fair_slice: None,
        reload_rt_timeslice: false, clear_rt_timeout: false, deadline }
}

#[test]
fn queue_move_truth_table_matches_scheduler_class_rekey_rules() {
    let fifo = Task::new(1, "fifo", SchedClass::Rt { prio: 40, policy: SchedPolicy::Fifo });
    assert!(!fifo.sched_update_moves_queue(update(
        SchedClass::Rt { prio: 40, policy: SchedPolicy::Rr }, super::SCHED_RR, None)),
        "equal numeric RT priority preserves exact list position");
    assert!(fifo.sched_update_moves_queue(update(
        SchedClass::Rt { prio: 41, policy: SchedPolicy::Fifo }, super::SCHED_FIFO, None)),
        "same-policy RT priority change rekeys");

    let fair = Task::new(2, "fair", SchedClass::Normal { weight: 1024 });
    let changed_weight = crate::cputime::nice_to_weight(1);
    assert!(fair.sched_update_moves_queue(update(
        SchedClass::Normal { weight: changed_weight }, super::SCHED_NORMAL, None)),
        "fair weight change rekeys");
    assert!(fair.sched_update_moves_queue(update(
        SchedClass::Rt { prio: 1, policy: SchedPolicy::Fifo }, super::SCHED_FIFO, None)),
        "cross-class change moves");

    let deadline = Task::new(3, "deadline", SchedClass::Deadline);
    let params = DlParams::from_request(1_000_000, 10_000_000, 10_000_000, 0);
    assert!(deadline.sched_update_moves_queue(update(
        SchedClass::Deadline, super::SCHED_DEADLINE, Some(params))),
        "deadline parameter change rekeys its EDF node");
}
