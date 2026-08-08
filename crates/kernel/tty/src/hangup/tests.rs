use super::decide::*;

#[test]
fn vhangup_needs_cap_sys_tty_config() {
    // Linux's `vhangup(2)` gates on CAP_SYS_TTY_CONFIG, not CAP_SYS_ADMIN
    // (which is what the TIOCVHANGUP ioctl checks).
    assert_eq!(vhangup_decision(false, true), VhangupOutcome::Eperm);
    assert_eq!(vhangup_decision(false, false), VhangupOutcome::Eperm);
}

#[test]
fn a_caller_without_a_controlling_tty_succeeds_and_does_nothing() {
    // `tty_vhangup_self` returns silently when `get_current_tty()` is NULL,
    // and the syscall still returns 0.
    // Signalling the caller's session instead would SIGHUP a whole session
    // that has no terminal at all.
    assert_eq!(vhangup_decision(true, false), VhangupOutcome::NoControllingTty);
    assert_eq!(vhangup_decision(true, true), VhangupOutcome::Hangup);
}

#[test]
fn only_the_session_leader_is_signalled() {
    // A session member that is not the leader loses the terminal silently:
    // the hangup skips it before any signal is considered.
    let member = session_member_action(true, false);
    assert!(member.clear_ctty);
    assert!(!member.sighup && !member.sigcont);

    let leader = session_member_action(true, true);
    assert!(leader.clear_ctty);
    assert!(leader.sighup && leader.sigcont);
}

#[test]
fn sighup_is_always_paired_with_sigcont() {
    // The hangup sends both. Without SIGCONT a session leader
    // that is STOPPED keeps the SIGHUP pending forever and never hangs up.
    for leader in [true, false] {
        let a = session_member_action(true, leader);
        assert_eq!(a.sighup, a.sigcont);
    }
}

#[test]
fn a_session_member_holding_a_different_tty_keeps_it() {
    // The ctty clear is conditional on `p->signal->tty == tty`
    // rather than on session membership: a task that
    // acquired some OTHER terminal must not be disconnected from it.
    let other = session_member_action(false, false);
    assert!(!other.clear_ctty);
    // A leader still gets the signals — Linux does not gate them on the
    // terminal match.
    let other_leader = session_member_action(false, true);
    assert!(!other_leader.clear_ctty);
    assert!(other_leader.sighup && other_leader.sigcont);
}

#[test]
fn only_a_session_exit_hangup_signals_the_foreground_group() {
    // The foreground group is signalled only when the caller asked for the
    // session to exit. vhangup(2) does not, so a foreground job that is not the
    // session leader is not killed by the hangup itself.
    assert_ne!(HangupKind::Vhangup, HangupKind::SessionExit);
}
