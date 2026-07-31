// Verified wait(2)-family contract. These encode behavior checked against the
// complete reference implementation, not summaries: option-mask acceptance,
// per-class event gating, idtype mapping, and the siginfo decode for every
// CLD_* case including the core-dump and ptrace-trap arms.

use super::*;

#[test]
fn wait4_rejects_waitid_only_and_unknown_bits() {
    assert!(wait4_options_valid(WNOHANG | WUNTRACED | WCONTINUED | __WALL));
    assert!(!wait4_options_valid(WEXITED));
    assert!(!wait4_options_valid(WNOWAIT));
    assert!(!wait4_options_valid(1u64 << 40));
}

#[test]
fn a_sign_extended_int_option_set_survives_register_truncation() {
    // glibc's `waitpid(pid, &st, __WCLONE)` reaches the kernel as a
    // sign-extended negative int; the high half is not part of the value.
    let reg = 0xffff_ffff_8000_0000u64;
    assert_eq!(int_arg_from_reg(reg), __WCLONE);
    assert!(wait4_options_valid(int_arg_from_reg(reg)));
    assert!(!wait4_options_valid(reg));
    assert!(waitid_options_valid(int_arg_from_reg(reg | WEXITED)));
    assert_eq!(int_arg_from_reg(0xdead_beef_0000_0001), P_PID);
}

#[test]
fn waitid_requires_a_requested_event_class() {
    assert!(waitid_options_valid(WEXITED));
    assert!(waitid_options_valid(WSTOPPED | WNOWAIT | __WNOTHREAD));
    assert!(!waitid_options_valid(0));
    assert!(!waitid_options_valid(WNOHANG));
    assert!(!waitid_options_valid(WEXITED | (1u64 << 40)));
}

#[test]
fn wait4_always_reports_exits_regardless_of_its_option_bits() {
    // `wait4` has no WEXITED bit: the kernel ORs it in unconditionally.
    assert_eq!(WaitEvents::for_wait4(0),
               WaitEvents { exited: true, stopped: false, continued: false });
    assert_eq!(WaitEvents::for_wait4(WUNTRACED | WCONTINUED),
               WaitEvents { exited: true, stopped: true, continued: true });
    assert_eq!(WaitEvents::for_wait4(WNOHANG).exited, true);
}

#[test]
fn waitid_gates_each_event_class_independently() {
    // The divergence this lane fixed: WSTOPPED-only waitid must NOT consume
    // an exited child, and WEXITED-only must not consume a stop.
    assert_eq!(WaitEvents::for_waitid(WSTOPPED),
               WaitEvents { exited: false, stopped: true, continued: false });
    assert_eq!(WaitEvents::for_waitid(WEXITED),
               WaitEvents { exited: true, stopped: false, continued: false });
    assert_eq!(WaitEvents::for_waitid(WCONTINUED),
               WaitEvents { exited: false, stopped: false, continued: true });
    assert_eq!(WaitEvents::for_waitid(WEXITED | WSTOPPED | WCONTINUED),
               WaitEvents { exited: true, stopped: true, continued: true });
    // WNOWAIT/WNOHANG/__W* bits never enable an event class on their own.
    assert_eq!(WaitEvents::for_waitid(WNOWAIT | WNOHANG | __WALL),
               WaitEvents { exited: false, stopped: false, continued: false });
}

#[test]
fn wstopped_and_wuntraced_are_the_same_bit() {
    assert_eq!(WSTOPPED, WUNTRACED);
    assert!(WaitEvents::for_wait4(WSTOPPED).stopped);
    assert!(WaitEvents::for_waitid(WUNTRACED | WEXITED).stopped);
}

#[test]
fn waitid_idtype_maps_onto_the_wait4_pid_forms() {
    assert_eq!(waitid_target(P_ALL, 0), WaitTarget::Wait4Pid(-1));
    assert_eq!(waitid_target(P_ALL, 12345), WaitTarget::Wait4Pid(-1));
    assert_eq!(waitid_target(P_PID, 42), WaitTarget::Wait4Pid(42));
    // P_PGID id 0 means "the caller's own process group" — wait4's pid == 0.
    assert_eq!(waitid_target(P_PGID, 0), WaitTarget::Wait4Pid(0));
    assert_eq!(waitid_target(P_PGID, 70), WaitTarget::Wait4Pid(-70));
    assert_eq!(waitid_target(P_PIDFD, 7), WaitTarget::Pidfd(7));
}

#[test]
fn waitid_rejects_out_of_range_ids_and_unknown_idtypes() {
    assert_eq!(waitid_target(P_PID, 0), WaitTarget::Invalid);
    assert_eq!(waitid_target(P_PID, -1), WaitTarget::Invalid);
    assert_eq!(waitid_target(P_PGID, -1), WaitTarget::Invalid);
    assert_eq!(waitid_target(P_PIDFD, -1), WaitTarget::Invalid);
    assert_eq!(waitid_target(4, 1), WaitTarget::Invalid);
    assert_eq!(waitid_target(u64::MAX, 1), WaitTarget::Invalid);
}

#[test]
fn wait4_reports_esrch_only_for_the_unnegatable_int_min() {
    assert!(wait4_upid_is_esrch(i32::MIN));
    assert!(!wait4_upid_is_esrch(i32::MIN + 1));
    assert!(!wait4_upid_is_esrch(-1));
    assert!(!wait4_upid_is_esrch(0));
}

#[test]
fn exited_siginfo_separates_dumped_from_killed_and_carries_raw_values() {
    // si_status is the RAW exit code, not the wait-encoded status.
    assert_eq!(siginfo_from_event(WaitEventKind::Exited, 7 << 8), (CLD_EXITED, 7));
    assert_eq!(siginfo_from_event(WaitEventKind::Exited, 0), (CLD_EXITED, 0));
    assert_eq!(siginfo_from_event(WaitEventKind::Exited, 255 << 8), (CLD_EXITED, 255));
    // si_status is the signal number for a signal death.
    assert_eq!(siginfo_from_event(WaitEventKind::Exited, 9), (CLD_KILLED, 9));
    // Core bit 0x80 promotes CLD_KILLED to CLD_DUMPED and is stripped from
    // si_status — the same bit WCOREDUMP reads out of the wait status.
    assert_eq!(siginfo_from_event(WaitEventKind::Exited, 11 | WSTAT_CORE), (CLD_DUMPED, 11));
    assert_eq!(siginfo_from_event(WaitEventKind::Exited, 6 | WSTAT_CORE), (CLD_DUMPED, 6));
}

#[test]
fn stop_trap_and_continue_siginfo_use_their_own_codes() {
    assert_eq!(siginfo_from_event(WaitEventKind::Stopped, stopped_wstatus(19)), (CLD_STOPPED, 19));
    assert_eq!(siginfo_from_event(WaitEventKind::Trapped, stopped_wstatus(5)), (CLD_TRAPPED, 5));
    // A ptrace syscall-stop reports SIGTRAP|0x80 as its stop code.
    assert_eq!(siginfo_from_event(WaitEventKind::Trapped, stopped_wstatus(5 | 0x80)), (CLD_TRAPPED, 0x85));
    assert_eq!(siginfo_from_event(WaitEventKind::Continued, WSTAT_CONTINUED), (CLD_CONTINUED, SIGCONT));
}

#[test]
fn a_stopped_wait_status_is_never_decoded_as_a_signal_death() {
    let st = stopped_wstatus(19);
    assert_eq!(st, (19 << 8) | 0x7f);
    // The Exited decoder would call this CLD_KILLED(0x7f); the event kind is
    // what keeps the two apart, which is why the engine carries it.
    assert_eq!(siginfo_from_event(WaitEventKind::Stopped, st), (CLD_STOPPED, 19));
}
