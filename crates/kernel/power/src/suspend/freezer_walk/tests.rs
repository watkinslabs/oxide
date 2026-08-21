use super::*;
use super::freezer::FreezePhase;

// `facts_of` is the join between this kernel's task flags and the reference's
// freeze decision. The decision itself is tested in the power crate; what can
// go wrong here is reading the wrong flag into the wrong field, which no test
// over the decision alone would catch.

fn task() -> Arc<Task> {
    let t = Arc::new(Task::new(1, "freezer-test",
        sched::task::SchedClass::Normal { weight: 1024 }));
    // A task built with no address space is a kernel thread by construction;
    // these tests want a userspace one, so the flag is set explicitly rather
    // than inherited from how the fixture happens to be built.
    t.kernel_thread.store(false, Ordering::Release);
    t.nofreeze.store(false, Ordering::Release);
    t
}

#[test]
fn a_plain_user_task_reads_as_freezable() {
    let t = task();
    let f = facts_of(&t);
    assert!(!f.reaped && !f.kernel_thread && !f.nofreeze && !f.suspend_task && !f.frozen && !f.oom_victim);
    assert!(freezer::counts_outstanding(FreezePhase::user(), f));
}

#[test]
fn a_reaped_but_arc_pinned_task_is_not_in_the_live_freeze_set() {
    let t = task();
    t.reaped.store(true, Ordering::Release);
    assert!(facts_of(&t).reaped);
    assert!(!freezer::counts_outstanding(FreezePhase::user(), facts_of(&t)));
    assert!(!freezer::counts_outstanding(FreezePhase::kernel(), facts_of(&t)));
}

#[test]
fn an_unreaped_zombie_does_not_hold_the_system_freezer_open() {
    let t = task();
    t.mark_done();
    assert_eq!(t.state(), sched::TaskState::Zombie);
    assert!(facts_of(&t).nofreeze, "terminal publication must mirror do_task_dead PF_NOFREEZE");
    assert!(!freezer::counts_outstanding(FreezePhase::user(), facts_of(&t)));
    assert!(!freezer::counts_outstanding(FreezePhase::kernel(), facts_of(&t)));
}

#[test]
fn the_kernel_thread_flag_reaches_the_decision() {
    let t = task();
    t.kernel_thread.store(true, Ordering::Release);
    assert!(facts_of(&t).kernel_thread);
    assert!(!freezer::counts_outstanding(FreezePhase::user(), facts_of(&t)));
    assert!(freezer::counts_outstanding(FreezePhase::kernel(), facts_of(&t)));
}

#[test]
fn the_nofreeze_flag_reaches_the_decision() {
    let t = task();
    set_nofreeze(&t, true);
    assert!(facts_of(&t).nofreeze);
    assert!(!freezer::counts_outstanding(FreezePhase::kernel(), facts_of(&t)));
    set_nofreeze(&t, false);
    assert!(freezer::counts_outstanding(FreezePhase::kernel(), facts_of(&t)));
}

#[test]
fn the_suspend_driving_task_is_never_named() {
    let t = task();
    t.suspend_task.store(true, Ordering::Release);
    assert!(facts_of(&t).suspend_task);
    for phase in [FreezePhase::user(), FreezePhase::kernel()] {
        assert!(!freezer::counts_outstanding(phase, facts_of(&t)),
            "the task driving the suspend would freeze itself");
    }
}

#[test]
fn the_oom_victim_flag_reaches_the_decision() {
    let t = task();
    t.oom_victim.store(true, Ordering::Release);
    assert!(facts_of(&t).oom_victim);
    assert!(!freezer::counts_outstanding(FreezePhase::kernel(), facts_of(&t)));
}

#[test]
fn frozen_reads_the_tasks_acknowledgement_not_a_request_bit() {
    let t = task();
    t.freeze_reasons.store(freeze_reason::SLEEP, Ordering::Release);
    assert!(!facts_of(&t).frozen, "publishing a request falsely acknowledged it");
    assert!(freezer::counts_outstanding(FreezePhase::user(), facts_of(&t)));
    t.frozen.store(true, Ordering::Release);
    assert!(facts_of(&t).frozen);
    assert!(!freezer::counts_outstanding(FreezePhase::user(), facts_of(&t)));
}

#[test]
fn kernel_pass_never_reissues_a_request_to_an_already_frozen_user() {
    let t = task();
    t.freeze_reasons.store(freeze_reason::SLEEP, Ordering::Release);
    t.frozen.store(true, Ordering::Release);
    assert!(freezer::freezing(FreezePhase::kernel(), facts_of(&t)),
        "kernel phase must keep userspace under freeze policy");
    assert!(!request_needed(FreezePhase::kernel(), facts_of(&t)),
        "a frozen task must not be woken and retraced by the second pass");
    t.frozen.store(false, Ordering::Release);
    assert!(request_needed(FreezePhase::kernel(), facts_of(&t)),
        "the positive control must request the same task once it is outstanding");
}

#[test]
fn the_backoff_sleeps_in_linuxs_half_to_full_window() {
    assert_eq!(backoff_window(10_000, 1_000), (510_000, 500_000));
    assert_eq!(backoff_window(10_000, 8_000), (4_010_000, 4_000_000));
}
