// Reap argument rules, timeout decoding and the two different interrupted
// returns io_getevents and io_pgetevents use.

use crate::aio_abi::events::*;
use syscall::errno::Errno;

#[test]
fn min_nr_must_be_non_negative_and_within_nr() {
    assert_eq!(validate_reap_counts(0, 0), Ok(()));
    assert_eq!(validate_reap_counts(0, 16), Ok(()));
    assert_eq!(validate_reap_counts(16, 16), Ok(()));
    assert_eq!(validate_reap_counts(17, 16), Err(Errno::Einval));
    assert_eq!(validate_reap_counts(-1, 16), Err(Errno::Einval));
    // A negative nr cannot pass: no non-negative min_nr is <= it.
    assert_eq!(validate_reap_counts(0, -1), Err(Errno::Einval));
    assert_eq!(validate_reap_counts(-1, -1), Err(Errno::Einval));
}

#[test]
fn zero_timeout_is_the_non_blocking_form() {
    assert_eq!(until_from_timespec(0, 0), Until::Immediate);
}

#[test]
fn a_positive_timeout_becomes_relative_nanoseconds() {
    assert_eq!(until_from_timespec(0, 1), Until::Relative(1));
    assert_eq!(until_from_timespec(1, 0), Until::Relative(1_000_000_000));
    assert_eq!(until_from_timespec(2, 500), Until::Relative(2_000_000_500));
}

#[test]
fn out_of_range_timespec_fields_are_accepted_not_rejected() {
    // Unlike ppoll/pselect6, this timeout is never validated: an oversized
    // nanosecond field is simply folded into the interval.
    assert_eq!(until_from_timespec(0, 1_500_000_000), Until::Relative(1_500_000_000));
    // A negative interval degrades to the immediate form rather than EINVAL.
    assert_eq!(until_from_timespec(-1, 0), Until::Immediate);
    assert_eq!(until_from_timespec(0, -5), Until::Immediate);
    assert_eq!(until_from_timespec(-5, 1_000_000_000), Until::Immediate);
}

#[test]
fn huge_second_counts_saturate_instead_of_wrapping() {
    assert_eq!(until_from_timespec(KTIME_SEC_MAX, 0), Until::Relative(u64::MAX));
    assert_eq!(until_from_timespec(i64::MAX, 0), Until::Relative(u64::MAX));
    // Just below the saturation point still produces a finite interval.
    match until_from_timespec(KTIME_SEC_MAX - 1, 0) {
        Until::Relative(ns) => assert!(ns < u64::MAX),
        other => panic!("expected a finite interval, got {:?}", other),
    }
}

#[test]
fn getevents_reports_eintr_only_for_an_empty_interrupted_reap() {
    let eintr = -(Errno::Eintr.as_i32() as i64);
    assert_eq!(getevents_return(0, true), eintr);
    assert_eq!(getevents_return(0, false), 0);
    // Events already delivered outrank the signal.
    assert_eq!(getevents_return(3, true), 3);
    // An error return is left alone.
    let einval = -(Errno::Einval.as_i32() as i64);
    assert_eq!(getevents_return(einval, true), einval);
}

#[test]
fn pgetevents_reports_the_restart_code_instead_of_eintr() {
    let restart = syscall::restart::restart_nohand();
    assert_eq!(pgetevents_return(0, true), restart);
    assert_ne!(pgetevents_return(0, true), -(Errno::Eintr.as_i32() as i64));
    assert_eq!(pgetevents_return(0, false), 0);
    assert_eq!(pgetevents_return(2, true), 2);
}

#[test]
fn only_the_restart_return_keeps_the_temporary_sigmask() {
    let restart = syscall::restart::restart_nohand();
    assert!(!restores_sigmask(restart));
    assert!(restores_sigmask(0));
    assert!(restores_sigmask(5));
    assert!(restores_sigmask(-(Errno::Einval.as_i32() as i64)));
    assert!(restores_sigmask(-(Errno::Eintr.as_i32() as i64)));
}
