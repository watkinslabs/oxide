// Hosted proof of the job-control / ptrace-trap latch rules. Every case here
// is a behaviour a tracer or a shell can observe, not an internal invariant.

use super::*;
use crate::exit::notify::{Cldstop, CLD_CONTINUED, CLD_STOPPED};

// --- who is told, and with which si_code -----------------------------------

#[test]
fn a_ptrace_stop_is_reported_to_the_tracer_as_trapped() {
    assert_eq!(notify_target(StopKind::Ptrace), NotifyTarget::Tracer);
    assert_eq!(stop_si_code(StopKind::Ptrace), Cldstop::Trapped);
}

#[test]
fn a_job_control_stop_is_reported_to_the_real_parent_as_stopped() {
    assert_eq!(notify_target(StopKind::JobControl), NotifyTarget::RealParent);
    assert_eq!(stop_si_code(StopKind::JobControl), Cldstop::Stopped);
}

#[test]
fn the_three_si_codes_are_the_uapi_numbers() {
    assert_eq!(CLD_STOPPED, 5);
    assert_eq!(CLD_CONTINUED, 6);
    assert_eq!(CLD_TRAPPED, 4);
}

// --- CLD_CONTINUED is a SIGCONT event only ---------------------------------

#[test]
fn only_a_real_sigcont_out_of_a_job_control_stop_is_a_continue_event() {
    assert_eq!(resume_notify(StopKind::JobControl, WakeKind::Cont), Some(Cldstop::Continued));
    assert!(records_continued(WakeKind::Cont));
}

#[test]
fn a_ptrace_resume_posts_no_continue_event() {
    // The regression this file exists for: PTRACE_CONT / PTRACE_SYSCALL /
    // PTRACE_SINGLESTEP / PTRACE_DETACH used to post SIGCHLD/CLD_CONTINUED to
    // the tracee's REAL parent on every single step, and to raise a
    // wait4(WCONTINUED) event that never happened.
    for kind in [StopKind::Ptrace, StopKind::JobControl] {
        assert_eq!(resume_notify(kind, WakeKind::PtraceResume), None, "{kind:?}");
    }
    assert!(!records_continued(WakeKind::PtraceResume));
}

#[test]
fn a_kill_wake_posts_no_continue_event() {
    for kind in [StopKind::Ptrace, StopKind::JobControl] {
        assert_eq!(resume_notify(kind, WakeKind::Kill), None, "{kind:?}");
    }
    assert!(!records_continued(WakeKind::Kill));
}

#[test]
fn a_sigcont_out_of_a_ptrace_stop_is_not_a_continue_event_either() {
    // The tracee is TRACED, so its stop was never reported as CLD_STOPPED and
    // there is no stop for a CLD_CONTINUED to be the counterpart of.
    assert_eq!(resume_notify(StopKind::Ptrace, WakeKind::Cont), None);
}

// --- latch mutators --------------------------------------------------------

#[test]
fn set_pending_refuses_to_arm_a_dying_task() {
    assert_eq!(set_pending(0, STOP_PENDING, true), None);
    assert_eq!(set_pending(0, TRAP_STOP, true), None);
    assert_eq!(set_pending(0, TRAP_NOTIFY, true), None);
    // LISTENING alone is not a trap arm, so it is still allowed.
    assert_eq!(set_pending(0, LISTENING, true), Some(LISTENING));
}

#[test]
fn set_pending_records_only_the_newest_group_stop_signal() {
    let armed = set_pending(0, STOP_PENDING | 19, false).unwrap();
    assert_eq!(armed & STOP_SIGMASK, 19);
    let rearmed = set_pending(armed, STOP_PENDING | 20, false).unwrap();
    // Not 19 | 20 == 31, which is not a signal number at all.
    assert_eq!(rearmed & STOP_SIGMASK, 20);
}

#[test]
fn clearing_stop_pending_also_clears_the_signal_and_the_counter_debt() {
    let armed = STOP_PENDING | STOP_CONSUME | 19 | TRAP_STOP;
    let cleared = clear_pending(armed, STOP_PENDING);
    assert_eq!(cleared & STOP_SIGMASK, 0);
    assert_eq!(cleared & STOP_CONSUME, 0);
    // An unrelated trap survives.
    assert_eq!(cleared & TRAP_STOP, TRAP_STOP);
}

// --- group-stop completion -------------------------------------------------

#[test]
fn the_last_thread_to_stop_completes_the_group_stop() {
    let t1 = participate_group_stop(STOP_PENDING | STOP_CONSUME, 2);
    assert_eq!(t1.count, 1);
    assert!(!t1.completed, "one thread of two still running");
    let t2 = participate_group_stop(STOP_PENDING | STOP_CONSUME, t1.count);
    assert_eq!(t2.count, 0);
    assert!(t2.completed, "the last thread completes the group stop");
}

#[test]
fn a_thread_that_already_paid_cannot_complete_the_stop_twice() {
    // A tracee re-stopped by its tracer re-enters the stop with the debt
    // already consumed; decrementing again would report a second CLD_STOPPED
    // for one group stop.
    let paid = participate_group_stop(STOP_PENDING | STOP_CONSUME, 1);
    assert!(paid.completed);
    assert_eq!(paid.jobctl & STOP_CONSUME, 0, "the debt is settled");
    let again = participate_group_stop(paid.jobctl, paid.count);
    assert!(!again.completed);
    assert_eq!(again.count, 0);
}

#[test]
fn participating_always_clears_stop_pending() {
    for jc in [STOP_PENDING | STOP_CONSUME | 19, STOP_PENDING | 19] {
        assert_eq!(participate_group_stop(jc, 3).jobctl & STOP_PENDING, 0);
    }
}

// --- PTRACE_LISTEN ---------------------------------------------------------

#[test]
fn listen_arms_the_trap_so_an_async_event_re_traps() {
    let jc = listen(0);
    assert_eq!(jc & LISTENING, LISTENING);
    assert_eq!(jc & TRAP_STOP, TRAP_STOP);
    assert!(wake_retraps(jc, WakeKind::Cont), "a SIGCONT re-traps a listening tracee");
}

#[test]
fn listen_re_traps_immediately_when_the_event_already_landed() {
    // The race PTRACE_LISTEN must close: the event arrived between the tracee
    // entering the trap and the tracer issuing LISTEN, so nothing further is
    // coming to wake it.
    assert!(retrap_pending(TRAP_NOTIFY));
    assert!(!retrap_pending(TRAP_STOP | LISTENING));
}

#[test]
fn trap_notify_only_wakes_a_listening_tracee() {
    let (jc, wake) = trap_notify(TRAP_STOP);
    assert_eq!(jc & TRAP_NOTIFY, TRAP_NOTIFY);
    assert!(!wake, "an ordinarily-stopped tracee keeps sleeping until its tracer resumes it");
    let (jc, wake) = trap_notify(TRAP_STOP | LISTENING);
    assert_eq!(jc & TRAP_NOTIFY, TRAP_NOTIFY);
    assert!(wake, "a LISTENING tracee is woken so it can re-report the stop");
}

#[test]
fn a_tracers_own_resume_lets_a_listening_tracee_out() {
    let jc = listen(0);
    assert!(!wake_retraps(jc, WakeKind::PtraceResume));
    assert_eq!(resume_clears(jc) & (LISTENING | TRAP_MASK | STOP_PENDING), 0);
}

#[test]
fn a_fatal_signal_is_never_swallowed_by_listen() {
    // A LISTENING tracee must still be killable — re-trapping a SIGKILL wake
    // would make PTRACE_LISTEN a way to make a process immortal.
    let jc = listen(0) | TRAP_NOTIFY;
    assert!(!wake_retraps(jc, WakeKind::Kill));
}

#[test]
fn a_non_listening_tracee_is_not_re_trapped() {
    assert!(!wake_retraps(TRAP_STOP, WakeKind::Cont));
    assert!(!wake_retraps(LISTENING, WakeKind::Cont), "nothing latched to re-report");
}

// --- the counter as the thread group actually drives it --------------------

#[test]
fn a_threaded_group_reports_one_cld_stopped_not_one_per_thread() {
    // Drives the REAL storage (`ThreadGroup::join_group_stop`) with the same
    // debt-arming the stop path does, so this proves the counter is consumed,
    // not merely computed.
    use crate::task::{SchedClass, Task};
    let leader = Task::new(7701, "grp", SchedClass::Normal { weight: 1024 });
    let tg = &leader.thread_group;
    tg.commit_member();
    tg.commit_member();
    let live = tg.live_count();
    assert!(live >= 3, "three threads in the group, got {live}");
    let mut reports = 0;
    for _ in 0..live {
        // Each thread arrives with a fresh debt, exactly as a park does.
        let step = tg.join_group_stop(STOP_PENDING | STOP_CONSUME);
        if step.completed { reports += 1; }
    }
    assert_eq!(reports, 1, "one ^Z owes the shell exactly one SIGCHLD");
    assert_eq!(tg.group_stop_count(), 0);
}

#[test]
fn a_sigcont_resets_the_tally_so_the_next_stop_counts_from_full() {
    use crate::task::{SchedClass, Task};
    let leader = Task::new(7702, "grp", SchedClass::Normal { weight: 1024 });
    let tg = &leader.thread_group;
    tg.commit_member();
    let live = tg.live_count();
    // A partial stop: one thread parked, the rest had not yet.
    assert!(!tg.join_group_stop(STOP_PENDING | STOP_CONSUME).completed);
    assert_eq!(tg.group_stop_count(), live - 1);
    tg.end_group_stop();
    // The next stop must re-seed, not resume the half-finished tally — which
    // would report CLD_STOPPED a thread early.
    assert!(!tg.join_group_stop(STOP_PENDING | STOP_CONSUME).completed || live == 1);
    assert_eq!(tg.group_stop_count(), live - 1);
}
