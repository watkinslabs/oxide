use super::*;
use sched::signum::Signum;

const SIGHUP:  u32 = Signum::Sighup as u32;
const SIGINT:  u32 = Signum::Sigint as u32;
const SIGKILL: u32 = Signum::Sigkill as u32;
const SIGSTOP: u32 = Signum::Sigstop as u32;
const SIGUSR1: u32 = Signum::Sigusr1 as u32;
const SIGSEGV: u32 = Signum::Sigsegv as u32;
const SIGSYS:  u32 = Signum::Sigsys as u32;
const SIGILL:  u32 = Signum::Sigill as u32;

fn mask(sigs: &[u32]) -> u64 {
    sigs.iter().filter_map(|s| sched::signum::bit_for(*s)).fold(0, |a, b| a | b)
}

#[test]
fn an_untraced_task_never_takes_a_signal_delivery_stop() {
    for s in [SIGHUP, SIGINT, SIGUSR1, SIGSTOP] { assert!(!stops_for_tracer(false, s, false)); }
}

#[test]
fn sigkill_is_never_stoppable_by_a_tracer() {
    // The one exclusion in Linux's gate: a tracer that could stop on SIGKILL
    // could make its tracee unkillable.
    assert!(!stops_for_tracer(true, SIGKILL, false));
    assert!(stops_for_tracer(true, SIGSTOP, false));
    for s in [SIGHUP, SIGINT, SIGUSR1] { assert!(stops_for_tracer(true, s, false)); }
}

#[test]
fn a_zero_resume_signal_cancels_the_signal_outright() {
    assert_eq!(after_stop(SIGINT, 0, 0, false), Outcome::Suppress);
    // Cancellation wins over both the blocked test and the dying test — a
    // tracer must always be able to drop a signal, whatever else is true.
    assert_eq!(after_stop(SIGINT, 0, mask(&[SIGINT]), true), Outcome::Suppress);
}

#[test]
fn resuming_with_the_same_signal_delivers_it_unsubstituted() {
    assert_eq!(after_stop(SIGINT, SIGINT, 0, false),
               Outcome::Deliver { sig: SIGINT, substituted: false });
}

#[test]
fn resuming_with_a_different_signal_substitutes_and_flags_the_siginfo_rebuild() {
    // The original record described SIGINT; delivering SIGUSR1 with it would
    // hand the handler a siginfo for a signal it is not receiving.
    assert_eq!(after_stop(SIGINT, SIGUSR1, 0, false),
               Outcome::Deliver { sig: SIGUSR1, substituted: true });
}

#[test]
fn a_signal_blocked_while_we_were_stopped_is_requeued_not_delivered() {
    // The tracer may have changed the mask with PTRACE_SETSIGMASK during the
    // stop, so the test uses the mask as it stands now, not at dequeue.
    assert_eq!(after_stop(SIGINT, SIGINT, mask(&[SIGINT]), false),
               Outcome::Requeue { sig: SIGINT });
    assert_eq!(after_stop(SIGINT, SIGUSR1, mask(&[SIGUSR1]), false),
               Outcome::Requeue { sig: SIGUSR1 });
    // A mask that blocks something else does not interfere.
    assert_eq!(after_stop(SIGINT, SIGINT, mask(&[SIGHUP]), false),
               Outcome::Deliver { sig: SIGINT, substituted: false });
}

#[test]
fn a_dying_task_requeues_rather_than_delivering() {
    assert_eq!(after_stop(SIGINT, SIGINT, 0, true), Outcome::Requeue { sig: SIGINT });
}

#[test]
fn the_unblockable_signals_can_never_take_the_requeue_arm() {
    // A tracer that substitutes SIGSTOP must stop the tracee even if the
    // tracee's mask nominally contains it — SIGKILL/SIGSTOP are not blockable.
    assert!(!is_blocked(SIGKILL, u64::MAX));
    assert!(!is_blocked(SIGSTOP, u64::MAX));
    assert_eq!(after_stop(SIGINT, SIGSTOP, u64::MAX, false),
               Outcome::Deliver { sig: SIGSTOP, substituted: true });
}

#[test]
fn an_out_of_range_resume_signal_is_treated_as_unblocked() {
    // `valid_signal` already bounded `data` to <= _NSIG at the PTRACE_CONT
    // gate, so this only guards the arithmetic; it must not panic or wrap.
    assert!(!is_blocked(0, u64::MAX));
    assert!(!is_blocked(200, u64::MAX));
}

#[test]
fn a_tracee_woken_without_a_tracer_write_delivers_the_reported_signal() {
    // `stop_code` was seeded with the reported signal before parking, so a
    // tracee woken by a fatal signal or by its tracer dying still delivers
    // what it reported rather than silently dropping it.
    assert_eq!(after_stop(SIGHUP, SIGHUP, 0, false),
               Outcome::Deliver { sig: SIGHUP, substituted: false });
}

#[test]
fn si_user_is_the_code_a_substituted_record_carries() {
    assert_eq!(SI_USER, 0);
}

#[test]
fn an_sa_immutable_signal_never_reaches_the_tracer() {
    // A forced-fatal signal (`force_fatal_sig`, seccomp `RET_KILL_*`) marks its
    // action `SA_IMMUTABLE`. The tracer's signal-delivery stop is skipped for
    // it, so the tracer cannot resume with signal 0 and cancel the death.
    for s in [SIGSEGV, SIGSYS, SIGILL, SIGUSR1] {
        assert!(stops_for_tracer(true, s, false), "an ordinary signal still stops");
        assert!(!stops_for_tracer(true, s, true), "an immutable action is not negotiable");
    }
}
