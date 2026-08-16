use super::*;

fn user() -> TaskFreezeFacts { TaskFreezeFacts::default() }
fn kthread() -> TaskFreezeFacts {
    TaskFreezeFacts { kernel_thread: true, ..TaskFreezeFacts::default() }
}

#[test]
fn nothing_freezes_while_idle() {
    let p = FreezePhase::idle();
    assert!(!freezing(p, user()));
    assert!(!freezing(p, kthread()));
}

#[test]
fn the_user_pass_leaves_kernel_threads_running() {
    let p = FreezePhase::user();
    assert!(freezing(p, user()));
    assert!(!freezing(p, kthread()),
        "a kernel thread froze during the userspace pass, so nothing can service the tasks parking");
}

#[test]
fn the_kernel_pass_freezes_both() {
    let p = FreezePhase::kernel();
    assert!(freezing(p, user()));
    assert!(freezing(p, kthread()));
}

#[test]
fn the_requesting_task_never_freezes() {
    let facts = TaskFreezeFacts { suspend_task: true, ..user() };
    for p in [FreezePhase::user(), FreezePhase::kernel()] {
        assert!(!freezing(p, facts), "the task driving the suspend froze itself");
    }
}

#[test]
fn a_nofreeze_task_never_freezes_in_either_pass() {
    for base in [user(), kthread()] {
        let facts = TaskFreezeFacts { nofreeze: true, ..base };
        for p in [FreezePhase::user(), FreezePhase::kernel()] {
            assert!(!freezing(p, facts), "no-freeze task frozen in {p:?}");
        }
    }
}

#[test]
fn an_oom_victim_is_exempt() {
    let facts = TaskFreezeFacts { oom_victim: true, ..user() };
    assert!(!freezing(FreezePhase::kernel(), facts));
}

#[test]
fn an_already_frozen_task_is_not_outstanding() {
    let p = FreezePhase::user();
    let facts = TaskFreezeFacts { frozen: true, ..user() };
    assert!(freezing(p, facts));
    assert!(!counts_outstanding(p, facts));
    assert!(counts_outstanding(p, user()));
}

#[test]
fn an_exempt_task_is_never_outstanding() {
    let p = FreezePhase::kernel();
    assert!(!counts_outstanding(p, TaskFreezeFacts { nofreeze: true, ..user() }));
    assert!(!counts_outstanding(p, TaskFreezeFacts { suspend_task: true, ..user() }));
}

#[test]
fn the_backoff_doubles_to_the_ceiling_and_stops() {
    let mut s = FREEZE_SLEEP_MIN_US;
    let mut seen = [0u64; 5];
    for slot in seen.iter_mut() { *slot = s; s = next_sleep_us(s); }
    assert_eq!(seen, [1_000, 2_000, 4_000, 8_000, 8_000]);
    assert_eq!(next_sleep_us(FREEZE_SLEEP_MAX_US), FREEZE_SLEEP_MAX_US);
}

#[test]
fn a_round_with_nothing_outstanding_is_done() {
    assert_eq!(round_decision(0, 0, false), Some(FreezeOutcome::Done));
    // Even past the budget, and even with a wakeup: the tasks are frozen, so
    // reporting failure would thaw them for nothing.
    assert_eq!(round_decision(0, FREEZE_TIMEOUT_MS + 1, true), Some(FreezeOutcome::Done));
}

#[test]
fn a_round_inside_the_budget_with_work_left_retries() {
    assert_eq!(round_decision(3, 0, false), None);
    assert_eq!(round_decision(1, FREEZE_TIMEOUT_MS, false), None);
}

#[test]
fn the_budget_expiring_with_work_left_times_out() {
    assert_eq!(round_decision(1, FREEZE_TIMEOUT_MS + 1, false), Some(FreezeOutcome::TimedOut));
}

#[test]
fn a_wakeup_inside_the_budget_aborts() {
    assert_eq!(round_decision(1, 0, true), Some(FreezeOutcome::Aborted));
}

#[test]
fn only_success_leaves_tasks_frozen() {
    assert!(!thaws_on(FreezeOutcome::Done));
    assert!(thaws_on(FreezeOutcome::Aborted));
    assert!(thaws_on(FreezeOutcome::TimedOut));
}

#[test]
fn the_phase_flags_round_trip_and_report_activity() {
    // These touch the module statics; the test restores the idle phase so no
    // ordering dependency reaches another test.
    set_phase(FreezePhase::user());
    assert_eq!(phase(), FreezePhase::user());
    assert!(freezer_active());
    set_phase(FreezePhase::kernel());
    assert_eq!(phase(), FreezePhase::kernel());
    set_phase(FreezePhase::idle());
    assert_eq!(phase(), FreezePhase::idle());
    assert!(!freezer_active());
}
