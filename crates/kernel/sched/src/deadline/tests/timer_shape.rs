use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::deadline::{clock, inactive, live, replenish, DlParams};
use crate::{SchedClass, Task};

const MS: u64 = 1_000_000;
static PROGRAM_CALLS: AtomicU64 = AtomicU64::new(0);

fn count_program(_: u64) -> bool {
    PROGRAM_CALLS.fetch_add(1, Ordering::Relaxed);
    true
}

fn accept_program(_: u64) -> bool { true }

#[test]
fn arming_each_deadline_timer_reprograms_the_local_oneshot() {
    let _guard = crate::tests::common::hosted_global_test_lock();
    inactive::clear_for_tests();
    crate::deadline::replenish::clear_for_tests();
    crate::deadline::bw::init_default();
    crate::deadline::bw::DL_BW.release(crate::deadline::bw::DL_BW.total_bw());
    clock::set_now_ns(0);
    crate::timers::install_deadline_programmer(count_program);
    PROGRAM_CALLS.store(0, Ordering::Relaxed);

    let inactive_task = Task::new(710, "inactive-arm", SchedClass::Deadline);
    let p = DlParams::from_request(2 * MS, 10 * MS, 10 * MS, 0);
    live::enter_class(&inactive_task, &p);
    crate::deadline::bw::DL_BW.admit(crate::deadline::bw::capacity_of(64),
        true, false, 0, p.bw, false).expect("fixture reservation fits");
    assert!(inactive::arm(&inactive_task, 5 * MS, p.bw, true));
    let after_inactive = PROGRAM_CALLS.load(Ordering::Relaxed);
    assert!(after_inactive > 0, "inactive arm did not reach the one-shot programmer");

    let replenish_task = Arc::new(Task::new(711, "replenish-arm", SchedClass::Deadline));
    live::enter_class(&replenish_task, &p);
    replenish::arm(&replenish_task, 8 * MS);
    assert!(PROGRAM_CALLS.load(Ordering::Relaxed) > after_inactive,
        "replenishment arm did not reach the one-shot programmer");

    replenish::disarm(&replenish_task);
    inactive::expire(5 * MS);
    assert_eq!(crate::deadline::bw::DL_BW.total_bw(), 0);
    crate::timers::install_deadline_programmer(accept_program);
}

#[test]
fn a_stamp_without_reprogramming_is_the_hardware_positive_control() {
    let task = Task::new(712, "stamp-only", SchedClass::Deadline);
    PROGRAM_CALLS.store(0, Ordering::Relaxed);
    task.sched.dl.set_replenish_at(9 * MS);
    assert_eq!(PROGRAM_CALLS.load(Ordering::Relaxed), 0,
        "control unexpectedly programmed hardware without the arm hook");
}

#[test]
fn deadline_timer_queues_are_allocation_free_intrusive_lists() {
    let _guard = crate::tests::common::hosted_global_test_lock();
    inactive::clear_for_tests();
    replenish::clear_for_tests();
    crate::deadline::bw::init_default();
    crate::deadline::bw::DL_BW.release(crate::deadline::bw::DL_BW.total_bw());
    let p = DlParams::from_request(2 * MS, 10 * MS, 10 * MS, 0);
    let inactive_task = Task::new(713, "inactive-allocation", SchedClass::Deadline);
    let replenish_task = Arc::new(Task::new(714, "replenish-allocation", SchedClass::Deadline));
    live::enter_class(&inactive_task, &p);
    live::enter_class(&replenish_task, &p);
    crate::deadline::bw::DL_BW.admit(crate::deadline::bw::capacity_of(64),
        true, false, 0, p.bw, false).expect("fixture reservation fits");

    let traffic = crate::tests::queue_alloc::allocations_during(|| {
        assert!(inactive::arm(&inactive_task, 5 * MS, p.bw, true));
        replenish::arm(&replenish_task, 8 * MS);
        replenish::disarm(&replenish_task);
        inactive::expire(5 * MS);
    });
    assert_eq!(traffic, 0, "deadline timer queue mutation touched the heap");
}
