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
