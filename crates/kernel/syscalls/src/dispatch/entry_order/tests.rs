// The entry sequence's observable properties. Each case is something a tracer
// or a sandbox can detect from userspace.

use super::*;
use core::cell::Cell;

const ENOSYS: u64 = (-38i64) as u64;
const READ: u64 = 0;
const EXECVE: u64 = 59;

#[test]
fn seccomp_is_shown_the_number_the_tracer_rewrote_it_to() {
    // The ordering bug this module exists for. A tracer stopped at the
    // PTRACE_SYSCALL entry stop rewrote `read` into `execve`; the filter must
    // judge `execve`. Running seccomp BEFORE the stop showed it `read` and let
    // the tracer substitute a call the filter would have refused.
    let seen = Cell::new(u64::MAX);
    let out = entry_work(false, EXECVE, ENOSYS, |nr| { seen.set(nr); None });
    assert_eq!(seen.get(), EXECVE, "the filter judges the REWRITTEN call");
    assert_eq!(out, EntryOutcome::Run(EXECVE));
}

#[test]
fn a_filter_refusing_the_rewritten_call_skips_it() {
    let out = entry_work(false, EXECVE, ENOSYS, |nr| {
        if nr == EXECVE { Some(ENOSYS) } else { None }
    });
    assert_eq!(out, EntryOutcome::Skip(ENOSYS), "the substituted call is refused");
}

#[test]
fn a_tracer_can_cancel_the_call_with_a_negative_number() {
    let called = Cell::new(false);
    let out = entry_work(false, u64::MAX, ENOSYS, |_| { called.set(true); None });
    assert_eq!(out, EntryOutcome::Skip(ENOSYS));
    assert!(!called.get(), "a cancelled call is never filtered — there is no call");
    assert!(tracer_cancelled((-1i64) as u64));
    assert!(!tracer_cancelled(READ), "syscall 0 is `read`, not a cancellation");
}

#[test]
fn a_dying_tracee_runs_neither_the_filter_nor_the_call() {
    // `fatal_signal_pending` after the stop: a SIGKILLed tracee must not
    // proceed into the syscall it was stopped on the way into.
    let called = Cell::new(false);
    let out = entry_work(true, READ, ENOSYS, |_| { called.set(true); None });
    assert_eq!(out, EntryOutcome::Skip(ENOSYS));
    assert!(!called.get());
}

#[test]
fn a_fatal_signal_wins_over_whatever_number_is_in_the_frame() {
    assert_eq!(entry_work(true, EXECVE, ENOSYS, |_| Some(0)), EntryOutcome::Skip(ENOSYS));
}

#[test]
fn an_untouched_call_runs_with_its_original_number() {
    let out = entry_work(false, READ, ENOSYS, |_| None);
    assert_eq!(out, EntryOutcome::Run(READ));
}

#[test]
fn a_skipped_call_still_carries_a_value_to_userspace() {
    // Skip is not "return early from the dispatcher": the value travels the
    // normal exit path, so the syscall-exit stop and signal delivery still run.
    let errno = (-1i64) as u64;
    assert_eq!(entry_work(false, READ, ENOSYS, |_| Some(errno)), EntryOutcome::Skip(errno));
}
