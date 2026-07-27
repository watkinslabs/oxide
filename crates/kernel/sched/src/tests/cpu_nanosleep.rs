// CPU-time `clock_nanosleep(2)` arm + tick-service, against real `Task`s.
//
// B1450: `clock_nanosleep(CLOCK_PROCESS_CPUTIME_ID, 0, {300ms}, NULL)` returned
// 0 immediately in the guest where Linux blocks until a signal. The arm sampled
// the UNRESOLVED `ClockSpec::CpuEncoded` that `classify_clock` produces for the
// static id, and `timers::clock::now_ns` has no arm for the encoded form — it
// samples only the resolved `ClockSpec::Cpu`. So the arm read `None` and
// reported "already expired". Linux resolves once in `posix_cpu_timer_create`
// (`kernel/time/posix-cpu-timers.c:386-411`) via `pid_for_clock()` and stores
// the resulting `struct pid` on the timer, which `do_cpu_nanosleep` (`:1552`)
// runs for its stack timer too.
//
// These drive `arm` / `account_cpu_tick` directly: the park loop needs a
// runqueue, the decision does not.

extern crate alloc;

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::posix_clock::{ClockSpec, CpuClock, CpuMeasure};
use crate::task::{SchedClass, Task};
use crate::timers::cpu_nanosleep::{arm, disarm, names_self, sleep_clock, CpuArm, CpuArmError};

/// `CLOCK_PROCESS_CPUTIME_ID` as `classify_clock` decodes it.
const PROCESS_CPUTIME: ClockSpec =
    ClockSpec::CpuEncoded { pid: 0, per_thread: false, measure: CpuMeasure::Sched };
/// The request `userspace/wait_diff/cputime.c` issues.
const SLEEP_NS: u64 = 300_000_000;

fn leader(tid: u32) -> Arc<Task> {
    let task = Arc::new(Task::new(tid, "cpusleep", SchedClass::Normal { weight: 1024 }));
    task.tgid.store(tid, Ordering::Release);
    crate::registry::insert(&task);
    task
}

/// A second thread of `leader`'s process: `CLONE_THREAD` shares the
/// `ThreadGroup`, which is where the POSIX timer slots live.
fn sibling_of(leader: &Task, tid: u32, name: &'static str) -> Task {
    let mut task = Task::new(tid, name, SchedClass::Normal { weight: 1024 });
    task.tgid.store(leader.tgid.load(Ordering::Acquire), Ordering::Release);
    task.join_thread_group(Arc::clone(&leader.thread_group));
    task
}

fn armed_deadline(task: &Task, id: usize) -> u64 {
    // SAFETY: hosted single-threaded test; no timer IRQ contends the slot table.
    let slots = unsafe { &*task.thread_group.posix_timers.get() };
    slots[id].deadline_ns
}

#[test]
fn a_process_cpu_sleep_arms_on_the_resolved_clock_not_the_encoding() {
    let _g = crate::tests::common::registry_test_lock();
    crate::registry::clear_for_tests();
    let task = leader(0x7200);

    let resolved = sleep_clock(&task, PROCESS_CPUTIME)
        .expect("pid_for_clock resolves a process CPU clock naming pid 0 to the caller's group");
    assert_eq!(resolved, ClockSpec::Cpu(CpuClock {
        target: 0x7200, per_thread: false, measure: CpuMeasure::Sched }));

    match arm(&task, PROCESS_CPUTIME, false, SLEEP_NS) {
        Ok(CpuArm::Armed(sleep)) => {
            assert_eq!(sleep.clock, resolved, "the timer samples the RESOLVED clock");
            assert_eq!(sleep.deadline_ns, SLEEP_NS,
                "a fresh process consumed no CPU, so the expiry is the whole request");
            assert_eq!(armed_deadline(&task, sleep.id), SLEEP_NS);
            assert_eq!(disarm(&task, sleep), SLEEP_NS, "nothing was consumed, so all is owed");
        }
        other => panic!("a 300ms process-CPU sleep must block, got {other:?}"),
    }
}

#[test]
fn the_accounting_tick_retires_an_armed_process_cpu_sleep() {
    let _g = crate::tests::common::registry_test_lock();
    crate::registry::clear_for_tests();
    let task = leader(0x7210);
    // A sibling thread: the one that actually burns the CPU while the caller
    // sleeps, and therefore the one whose tick services the timer.
    let sibling = Arc::new(sibling_of(&task, 0x7211, "burner"));
    crate::registry::insert(&sibling);

    let Ok(CpuArm::Armed(sleep)) = arm(&task, PROCESS_CPUTIME, false, SLEEP_NS)
        else { panic!("arm must block") };

    // Not yet: nothing has consumed CPU, which is `single_thread_no_progress`.
    crate::timers::account_cpu_tick(&sibling);
    assert_eq!(armed_deadline(&task, sleep.id), SLEEP_NS,
        "an unadvanced CPU clock must not retire the sleep");

    // The burner consumes past the expiry — `sibling_burn_completes`.
    task.thread_group.charge_cpu(true, SLEEP_NS + 1);
    crate::timers::account_cpu_tick(&sibling);
    assert_eq!(armed_deadline(&task, sleep.id), 0,
        "cpu_timer_fire's nanosleep branch disarms the timer and wakes the sleeper");
    assert_eq!(disarm(&task, sleep), 0, "nothing owed once the clock passed the expiry");
}

#[test]
fn a_perthread_sleep_clock_resolves_only_within_the_callers_thread_group() {
    let _g = crate::tests::common::registry_test_lock();
    crate::registry::clear_for_tests();
    let task = leader(0x7220);
    let sibling = Arc::new(Task::new(0x7221, "sibling", SchedClass::Normal { weight: 1024 }));
    sibling.tgid.store(0x7220, Ordering::Release);
    crate::registry::insert(&sibling);
    let stranger = leader(0x7230);

    let named = |pid: u32| ClockSpec::CpuEncoded {
        pid, per_thread: true, measure: CpuMeasure::Sched };
    assert_eq!(sleep_clock(&task, named(0x7221)), Some(ClockSpec::Cpu(CpuClock {
        target: 0x7221, per_thread: true, measure: CpuMeasure::Sched })));
    assert_eq!(sleep_clock(&task, named(stranger.tid)), None,
        "pid_for_clock rejects a per-thread clock outside the caller's group");
    assert!(matches!(arm(&task, named(stranger.tid), false, SLEEP_NS), Err(CpuArmError::Invalid)));
}

#[test]
fn a_perthread_clock_naming_the_caller_is_diagnosed_against_the_resolved_task() {
    let _g = crate::tests::common::registry_test_lock();
    crate::registry::clear_for_tests();
    let task = leader(0x7260);
    let sibling = Arc::new(sibling_of(&task, 0x7261, "sibling"));
    crate::registry::insert(&sibling);

    let named = |pid: u32| ClockSpec::CpuEncoded {
        pid, per_thread: true, measure: CpuMeasure::Sched };
    assert!(names_self(&task, named(0)), "pid 0 is the caller without any lookup");
    assert!(names_self(&task, named(0x7260)), "naming the caller can never make progress");
    assert!(!names_self(&task, named(0x7261)), "a sibling's clock DOES advance");
    assert!(!names_self(&task, PROCESS_CPUTIME),
        "CPUCLOCK_PERTHREAD gates the whole check");
}

#[test]
fn an_absolute_expiry_already_reached_completes_without_arming() {
    let _g = crate::tests::common::registry_test_lock();
    crate::registry::clear_for_tests();
    let task = leader(0x7240);
    task.thread_group.charge_cpu(false, SLEEP_NS);
    // `do_cpu_nanosleep`'s first loop test: expires already behind the clock.
    assert_eq!(arm(&task, PROCESS_CPUTIME, true, SLEEP_NS / 2), Ok(CpuArm::Expired));
}

#[test]
fn a_wall_clock_never_reaches_the_cpu_sleep_path() {
    let _g = crate::tests::common::registry_test_lock();
    crate::registry::clear_for_tests();
    let task = leader(0x7250);
    assert_eq!(sleep_clock(&task, ClockSpec::Monotonic), None);
    assert_eq!(sleep_clock(&task, ClockSpec::Realtime), None);
}
