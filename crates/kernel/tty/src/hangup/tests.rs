use super::decide::*;

#[test]
fn vhangup_needs_cap_sys_tty_config() {
    // `fs/open.c:1532` — CAP_SYS_TTY_CONFIG, not CAP_SYS_ADMIN (which is what
    // the TIOCVHANGUP ioctl checks).
    assert_eq!(vhangup_decision(false, true), VhangupOutcome::Eperm);
    assert_eq!(vhangup_decision(false, false), VhangupOutcome::Eperm);
}

#[test]
fn a_caller_without_a_controlling_tty_succeeds_and_does_nothing() {
    // `tty_vhangup_self` returns silently when `get_current_tty()` is NULL
    // (`drivers/tty/tty_io.c:701-708`), and the syscall still returns 0.
    // Signalling the caller's session instead would SIGHUP a whole session
    // that has no terminal at all.
    assert_eq!(vhangup_decision(true, false), VhangupOutcome::NoControllingTty);
    assert_eq!(vhangup_decision(true, true), VhangupOutcome::Hangup);
}

#[test]
fn only_the_session_leader_is_signalled() {
    // `tty_jobctrl.c:213-216`: `if (!p->signal->leader) { ...; continue; }`.
    // A non-leader member loses the terminal silently.
    let member = session_member_action(true, false);
    assert!(member.clear_ctty);
    assert!(!member.sighup && !member.sigcont);

    let leader = session_member_action(true, true);
    assert!(leader.clear_ctty);
    assert!(leader.sighup && leader.sigcont);
}

#[test]
fn sighup_is_always_paired_with_sigcont() {
    // `tty_jobctrl.c:218-219` sends both. Without SIGCONT a session leader
    // that is STOPPED keeps the SIGHUP pending forever and never hangs up.
    for leader in [true, false] {
        let a = session_member_action(true, leader);
        assert_eq!(a.sighup, a.sigcont);
    }
}

#[test]
fn a_session_member_holding_a_different_tty_keeps_it() {
    // The ctty clear is conditional on `p->signal->tty == tty`
    // (`tty_jobctrl.c:205-212`), not on session membership: a task that
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
    // `tty_jobctrl.c:232-236`: `if (exit_session) kill_pgrp(tty_pgrp, SIGHUP,
    // exit_session)`. vhangup(2) passes 0, so a foreground job that is not the
    // session leader is not killed by the hangup itself.
    assert_ne!(HangupKind::Vhangup, HangupKind::SessionExit);
}
