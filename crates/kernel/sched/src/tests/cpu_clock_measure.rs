// The three CPU-clock measures against real `Task`s / `ThreadGroup`s.
//
// CPUCLOCK_VIRT is user time, CPUCLOCK_PROF is user + system, and CPUCLOCK_SCHED
// is the scheduler's own runtime total — three different quantities off three
// different accumulators. Both static CPU clock ids select SCHED, which is why
// they advertise nanosecond resolution rather than a tick; folding SCHED onto
// user + system made `clock_gettime(CLOCK_THREAD_CPUTIME_ID)` report a
// tick-quantised number and made every `Sched` timer expire at the wrong point.

extern crate alloc;

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::posix_clock::{classify_clock, CLOCK_PROCESS_CPUTIME_ID, CLOCK_THREAD_CPUTIME_ID};
use crate::task::{SchedClass, Task};
use crate::timers::cpu_clock_sample_ns;

fn leader(tid: u32) -> Arc<Task> {
    let task = Arc::new(Task::new(tid, "cpuclock", SchedClass::Normal { weight: 1024 }));
    task.tgid.store(tid, Ordering::Release);
    crate::registry::insert(&task);
    task
}

fn sample(task: &Task, id: i32) -> u64 {
    cpu_clock_sample_ns(task, classify_clock(id).unwrap()).expect("a live self-naming CPU clock")
}

#[test]
fn the_thread_cpu_clock_reads_scheduler_runtime_not_user_plus_system() {
    let _g = crate::tests::common::registry_test_lock();
    crate::registry::clear_for_tests();
    let task = leader(0x7300);

    task.utime_ns.store(5_000_000, Ordering::Release);
    task.stime_ns.store(3_000_000, Ordering::Release);
    assert_eq!(sample(&task, CLOCK_THREAD_CPUTIME_ID), 0,
        "tick-sampled user/system time is not the measure this clock selects");

    crate::cputime::charge_exec_runtime(&task, 1_234);
    assert_eq!(sample(&task, CLOCK_THREAD_CPUTIME_ID), 1_234,
        "sub-tick precision is the whole reason this clock reports 1ns resolution");
}

#[test]
fn the_process_cpu_clock_reads_the_groups_scheduler_runtime() {
    let _g = crate::tests::common::registry_test_lock();
    crate::registry::clear_for_tests();
    let task = leader(0x7310);

    task.thread_group.charge_cpu(true, 9_000_000);
    task.thread_group.charge_cpu(false, 9_000_000);
    assert_eq!(sample(&task, CLOCK_PROCESS_CPUTIME_ID), 0);

    crate::cputime::charge_exec_runtime(&task, 4_096);
    assert_eq!(sample(&task, CLOCK_PROCESS_CPUTIME_ID), 4_096,
        "one charge feeds both the task total and its group's");
    assert_eq!(sample(&task, CLOCK_THREAD_CPUTIME_ID), 4_096);
}

/// A sibling's runtime counts towards the PROCESS clock and not towards the
/// leader's own THREAD clock — the property that makes a process-CPU sleep
/// completable by another thread while the sleeper accrues nothing.
#[test]
fn a_siblings_runtime_advances_only_the_process_clock() {
    let _g = crate::tests::common::registry_test_lock();
    crate::registry::clear_for_tests();
    let task = leader(0x7320);
    let mut sib = Task::new(0x7321, "sibling", SchedClass::Normal { weight: 1024 });
    sib.tgid.store(0x7320, Ordering::Release);
    sib.join_thread_group(Arc::clone(&task.thread_group));
    let sib = Arc::new(sib);
    crate::registry::insert(&sib);

    crate::cputime::charge_exec_runtime(&sib, 7_777);
    assert_eq!(sample(&task, CLOCK_PROCESS_CPUTIME_ID), 7_777);
    assert_eq!(sample(&task, CLOCK_THREAD_CPUTIME_ID), 0);
    assert_eq!(sample(&sib, CLOCK_THREAD_CPUTIME_ID), 7_777);
}

/// The group total must survive the thread that earned it, the way the
/// user/system totals already do — a process clock cannot go backwards when a
/// thread exits.
#[test]
fn the_group_total_outlives_the_thread_that_earned_it() {
    let _g = crate::tests::common::registry_test_lock();
    crate::registry::clear_for_tests();
    let task = leader(0x7330);
    let mut sib = Task::new(0x7331, "sibling", SchedClass::Normal { weight: 1024 });
    sib.tgid.store(0x7330, Ordering::Release);
    sib.join_thread_group(Arc::clone(&task.thread_group));
    let sib = Arc::new(sib);
    crate::registry::insert(&sib);

    crate::cputime::charge_exec_runtime(&sib, 512);
    // The sibling leaves: gone from the registry, its Arc dropped. A walk-based
    // total would lose its 512ns; the group counter cannot, because the charge
    // landed there at the same instant.
    drop(sib);
    crate::registry::clear_for_tests();
    crate::registry::insert(&task);
    assert_eq!(sample(&task, CLOCK_PROCESS_CPUTIME_ID), 512);
    assert_eq!(sample(&task, CLOCK_THREAD_CPUTIME_ID), 0);
}
