use crate::exit::notify::*;
use crate::signum::Signum;

const SIGCHLD: u32 = Signum::Sigchld as u32;
const DEFAULT: ParentSigchld = ParentSigchld { handler: SIG_DFL, flags: 0 };
const IGNORING: ParentSigchld = ParentSigchld { handler: SIG_IGN, flags: 0 };
const HANDLER: u64 = 0x4000_1234;
const NOCLDWAIT: ParentSigchld = ParentSigchld { handler: HANDLER, flags: SA_NOCLDWAIT };

#[test]
fn a_lone_leader_leaves_a_zombie_and_signals_sigchld() {
    let n = exit_notify(true, true, Some(SIGCHLD), DEFAULT);
    assert_eq!(n.signal, Some(SIGCHLD));
    assert!(!n.autoreap);
    assert!(n.wake_parent);
}

#[test]
fn sigchld_set_to_sig_ign_autoreaps_and_suppresses_the_signal() {
    let n = exit_notify(true, true, Some(SIGCHLD), IGNORING);
    assert!(n.autoreap, "POSIX: SIGCHLD=SIG_IGN must leave no zombie");
    assert_eq!(n.signal, None);
    assert!(n.wake_parent, "a blocked wait4 must still wake to return ECHILD");
}

#[test]
fn sa_nocldwait_autoreaps_but_still_delivers_sigchld() {
    let n = exit_notify(true, true, Some(SIGCHLD), NOCLDWAIT);
    assert!(n.autoreap);
    assert_eq!(n.signal, Some(SIGCHLD), "implementation-defined: Linux does send it");
    assert!(n.wake_parent);
}

#[test]
fn a_non_sigchld_clone_exit_signal_never_autoreaps() {
    // A clone(2) exit_signal other than SIGCHLD is outside the POSIX rule, so
    // an ignoring parent still gets a zombie to wait4(__WCLONE) for.
    let n = exit_notify(true, true, Some(Signum::Sigusr1 as u32), IGNORING);
    assert!(!n.autoreap);
    assert_eq!(n.signal, Some(Signum::Sigusr1 as u32));
}

#[test]
fn a_non_leader_thread_is_released_without_notifying() {
    let n = exit_notify(false, false, Some(SIGCHLD), DEFAULT);
    assert!(n.autoreap, "an untraced sub-thread never becomes a waitable zombie");
    assert_eq!(n.signal, None);
    // and the same holds once it is the last thread standing
    let n = exit_notify(false, true, Some(SIGCHLD), DEFAULT);
    assert!(n.autoreap);
    assert_eq!(n.signal, None);
}

#[test]
fn a_leader_with_live_threads_notifies_nothing_yet() {
    let n = exit_notify(true, false, Some(SIGCHLD), DEFAULT);
    assert!(!n.autoreap, "the leader stays a zombie until the group empties");
    assert_eq!(n.signal, None);
}

#[test]
fn a_leader_with_no_exit_signal_leaves_a_wall_reapable_zombie() {
    let n = exit_notify(true, true, None, DEFAULT);
    assert!(!n.autoreap);
    assert_eq!(n.signal, None);
}

#[test]
fn discards_children_matches_the_posix_pair() {
    assert!(!DEFAULT.discards_children());
    assert!(IGNORING.discards_children());
    assert!(NOCLDWAIT.discards_children());
    assert!(!ParentSigchld { handler: HANDLER, flags: 0 }.discards_children());
}

// ---------------------------------------------------------------------------
// do_notify_parent_cldstop (B1451) — the wake is unconditional.
// ---------------------------------------------------------------------------

const NOCLDSTOP: ParentSigchld = ParentSigchld { handler: HANDLER, flags: SA_NOCLDSTOP };

#[test]
fn a_job_control_stop_signals_the_parent_and_wakes_its_wait4() {
    let n = cldstop_notify(Cldstop::Stopped, DEFAULT);
    assert!(n.signal);
    assert!(n.wake_parent);
    assert_eq!(n.si_code, CLD_STOPPED);
}

#[test]
fn sigchld_ignored_or_nocldstop_suppresses_the_signal_but_never_the_wake() {
    // `kernel/signal.c:2342-2344`: "Even if SIGCHLD is not generated, we must
    // wake up wait4 calls." A waitpid(WUNTRACED) that slept through the stop
    // it was waiting for is exactly the B1451 `outcome=timeout`.
    for parent in [IGNORING, NOCLDSTOP] {
        let n = cldstop_notify(Cldstop::Stopped, parent);
        assert!(!n.signal, "{parent:?}");
        assert!(n.wake_parent, "{parent:?}");
    }
}

#[test]
fn a_continue_notifies_with_cld_continued_under_the_same_rule() {
    assert_eq!(cldstop_notify(Cldstop::Continued, DEFAULT).si_code, CLD_CONTINUED);
    assert!(cldstop_notify(Cldstop::Continued, DEFAULT).signal);
    assert!(!cldstop_notify(Cldstop::Continued, NOCLDSTOP).signal);
    assert!(cldstop_notify(Cldstop::Continued, NOCLDSTOP).wake_parent);
}

#[test]
fn sa_nocldwait_does_not_suppress_a_stop_notification() {
    // NOCLDWAIT is about zombies, not stops; only NOCLDSTOP gates this one.
    assert!(cldstop_notify(Cldstop::Stopped, NOCLDWAIT).signal);
}
