use alloc::sync::Arc;

use crate::deadline::{cbs, clock, live, replenish, DlParams, DlSched};
use crate::{SchedClass, Task, TaskState};

const MS: u64 = 1_000_000;

fn throttled_task() -> (Arc<Task>, DlParams) {
    let task = Arc::new(Task::new(730, "replenish-aba", SchedClass::Deadline));
    task.set_state(TaskState::Sleeping);
    let params = DlParams::from_request(2 * MS, 10 * MS, 10 * MS, 0);
    live::enter_class(&task, &params);
    task.sched.dl.store_sched(&DlSched { runtime: 0, deadline: 10 * MS,
        throttled: true, yielded: false, overrun: false });
    (task, params)
}

#[test]
fn popped_generation_cannot_consume_a_rearmed_replenishment() {
    let _global = crate::tests::common::hosted_global_test_lock();
    replenish::clear_for_tests();
    clock::set_now_ns(0);
    let (task, _) = throttled_task();
    replenish::arm(&task, 10 * MS);
    let stale = replenish::take_due(10 * MS).expect("first generation due");

    replenish::arm(&task, 20 * MS);
    assert!(!live::replenish_claimed(&stale, 10 * MS),
        "popped generation committed after a newer arm");
    assert_eq!(task.sched.dl.replenish_at(), 20 * MS);
    assert!(task.sched.dl.is_throttled());

    let current = replenish::take_due(20 * MS).expect("replacement generation due");
    assert!(live::replenish_claimed(&current, 20 * MS));
    assert!(!task.sched.dl.is_throttled());
    replenish::clear_for_tests();
}

#[test]
fn unstamped_callback_positive_control_replenishes_the_wrong_generation() {
    let (_, params) = throttled_task();
    let mut stale = DlSched { runtime: 0, deadline: 10 * MS,
        throttled: true, yielded: false, overrun: false };
    cbs::replenish(&params, &mut stale, 10 * MS);
    assert!(!stale.throttled,
        "control must show why callback state needs an exact arm generation");
}
