use syscall::errno::Errno;
use syscalls::pselect_ppoll::*;

#[test]
fn argpack_layout_is_two_words_not_a_bare_sigset_pointer() {
    assert_eq!(SIGSET_ARGPACK_BYTES, 16);
    assert_eq!(SIGSET_ARGPACK_LEN_OFF, 8);
    assert_eq!(SIGSET_ARGPACK_BYTES, 2 * syscall::sigset::SIGSET_BYTES);
}

#[test]
fn timespec_layout_matches_kernel_timespec() {
    assert_eq!(TIMESPEC_BYTES, 16);
    assert_eq!(TIMESPEC_NSEC_OFF, 8);
}

#[test]
fn null_sigset_pointer_leaves_the_mask_alone_whatever_the_length_says() {
    assert_eq!(user_sigmask_wanted(0, 0), Ok(false));
    assert_eq!(user_sigmask_wanted(0, 4), Ok(false));
    assert_eq!(user_sigmask_wanted(0, u64::MAX), Ok(false));
}

#[test]
fn non_null_sigset_demands_exactly_sizeof_sigset_t() {
    assert_eq!(user_sigmask_wanted(0x1000, 8), Ok(true));
    for bad in [0u64, 1, 4, 7, 9, 16, 128, u64::MAX] {
        assert_eq!(user_sigmask_wanted(0x1000, bad), Err(Errno::Einval), "ss_len={bad}");
    }
}

#[test]
fn only_an_interrupted_wait_keeps_the_temporary_mask_installed() {
    assert!(!restores_saved_sigmask(syscall::restart::restart_nohand()));
    for rv in [0i64, 1, 7, -(Errno::Eintr.as_i32() as i64),
               -(Errno::Efault.as_i32() as i64), -(Errno::Ebadf.as_i32() as i64),
               -(Errno::Einval.as_i32() as i64), -(Errno::Enomem.as_i32() as i64)] {
        assert!(restores_saved_sigmask(rv), "rv={rv}");
    }
}

#[test]
fn readiness_outranks_a_pending_signal_which_outranks_a_timeout() {
    let nohand = syscall::restart::restart_nohand();
    assert_eq!(wait_verdict(3, true, true), Some(3));
    assert_eq!(wait_verdict(1, false, true), Some(1));
    assert_eq!(wait_verdict(0, true, true), Some(nohand));
    assert_eq!(wait_verdict(0, false, true), Some(nohand));
    assert_eq!(wait_verdict(0, true, false), Some(0));
    assert_eq!(wait_verdict(0, false, false), None);
}

#[test]
fn the_interrupted_verdict_is_restartnohand_not_eintr() {
    assert_eq!(wait_verdict(0, false, true), Some(-514));
    assert_ne!(wait_verdict(0, false, true), Some(-(Errno::Eintr.as_i32() as i64)));
}

#[test]
fn interrupted_calls_leave_the_callers_sets_untouched() {
    assert!(!copies_out_fd_sets(syscall::restart::restart_nohand()));
    assert!(!copies_out_fd_sets(-(Errno::Eintr.as_i32() as i64)));
    assert!(copies_out_fd_sets(0));
    assert!(copies_out_fd_sets(5));
}

#[test]
fn zero_timeout_never_updates_the_callers_timespec() {
    assert_eq!(timeout_writeback_plan(0, 0, 0), TimeoutWriteback::Skipped);
    assert_eq!(timeout_writeback_plan(0, 0, 1), TimeoutWriteback::Wrote);
    assert_eq!(timeout_writeback_plan(0, 1, 0), TimeoutWriteback::Wrote);
    assert_eq!(timeout_writeback_plan(0, 5, 500_000_000), TimeoutWriteback::Wrote);
}

#[test]
fn sticky_timeouts_personality_suppresses_every_writeback() {
    let sticky = sched::personality::STICKY_TIMEOUTS;
    assert_eq!(timeout_writeback_plan(sticky, 5, 0), TimeoutWriteback::Sticky);
    assert_eq!(
        timeout_writeback_plan(sticky | sched::personality::PER_LINUX32, 0, 1),
        TimeoutWriteback::Sticky,
    );
    assert_eq!(timeout_writeback_plan(sticky, 0, 0), TimeoutWriteback::Sticky);
    assert_eq!(
        timeout_writeback_plan(sched::personality::WHOLE_SECONDS, 5, 0),
        TimeoutWriteback::Wrote,
    );
}

#[test]
fn restartnohand_survives_a_successful_or_skipped_writeback() {
    let nohand = syscall::restart::restart_nohand();
    assert_eq!(finish_return(nohand, TimeoutWriteback::Wrote), nohand);
    assert_eq!(finish_return(nohand, TimeoutWriteback::Skipped), nohand);
}

#[test]
fn restartnohand_folds_to_eintr_only_when_the_timeout_cannot_be_updated() {
    let nohand = syscall::restart::restart_nohand();
    let eintr = -(Errno::Eintr.as_i32() as i64);
    assert_eq!(finish_return(nohand, TimeoutWriteback::Faulted), eintr);
    assert_eq!(finish_return(nohand, TimeoutWriteback::Sticky), eintr);
    for wb in [
        TimeoutWriteback::Skipped,
        TimeoutWriteback::Sticky,
        TimeoutWriteback::Wrote,
        TimeoutWriteback::Faulted,
    ] {
        for rv in [0i64, 3, eintr, -(Errno::Ebadf.as_i32() as i64)] {
            assert_eq!(finish_return(rv, wb), rv, "rv={rv} wb={wb:?}");
        }
    }
}

#[test]
fn remaining_time_splits_ns_and_clamps_an_expired_deadline_to_zero() {
    assert_eq!(remaining_timespec(5_500_000_000, 0), (5, 500_000_000));
    assert_eq!(remaining_timespec(5_500_000_000, 5_000_000_000), (0, 500_000_000));
    assert_eq!(remaining_timespec(1_000, 9_999), (0, 0));
    assert_eq!(remaining_timespec(0, 0), (0, 0));
}

#[test]
fn remaining_nanoseconds_stay_inside_one_second() {
    for now in [0u64, 1, 999_999_999, 1_000_000_000, 123_456_789_012] {
        let (_, ns) = remaining_timespec(999_999_999_999, now);
        assert!((0..1_000_000_000).contains(&ns), "now={now} ns={ns}");
    }
}
