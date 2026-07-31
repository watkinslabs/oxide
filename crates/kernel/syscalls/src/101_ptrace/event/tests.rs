use super::*;
use crate::s101_ptrace_uapi as uapi;

const ALL_EVENTS: [u32; 7] = [
    uapi::EVENT_FORK, uapi::EVENT_VFORK, uapi::EVENT_CLONE, uapi::EVENT_EXEC,
    uapi::EVENT_VFORK_DONE, uapi::EVENT_EXIT, uapi::EVENT_SECCOMP,
];

#[test]
fn a_plain_fork_reports_event_fork() {
    assert_eq!(clone_event(0, SIGCHLD), uapi::EVENT_FORK);
}

#[test]
fn vfork_wins_over_the_exit_signal_test() {
    // vfork(2) is CLONE_VFORK|CLONE_VM with SIGCHLD: the SIGCHLD would say
    // "fork" if the CLONE_VFORK arm did not come first.
    assert_eq!(clone_event(CLONE_VFORK, SIGCHLD), uapi::EVENT_VFORK);
    assert_eq!(clone_event(CLONE_VFORK, 0), uapi::EVENT_VFORK);
}

#[test]
fn a_thread_spawn_reports_event_clone_through_its_exit_signal() {
    // glibc's pthread_create passes exit_signal 0; it is that, not
    // CLONE_THREAD, that selects PTRACE_EVENT_CLONE.
    assert_eq!(clone_event(0, 0), uapi::EVENT_CLONE);
    assert_eq!(clone_event(0, SIGCHLD + 1), uapi::EVENT_CLONE);
}

#[test]
fn every_option_bit_is_one_shifted_by_its_event_code() {
    assert_eq!(1u32 << uapi::EVENT_FORK,       uapi::O_TRACEFORK);
    assert_eq!(1u32 << uapi::EVENT_VFORK,      uapi::O_TRACEVFORK);
    assert_eq!(1u32 << uapi::EVENT_CLONE,      uapi::O_TRACECLONE);
    assert_eq!(1u32 << uapi::EVENT_EXEC,       uapi::O_TRACEEXEC);
    assert_eq!(1u32 << uapi::EVENT_VFORK_DONE, uapi::O_TRACEVFORKDONE);
    assert_eq!(1u32 << uapi::EVENT_EXIT,       uapi::O_TRACEEXIT);
    assert_eq!(1u32 << uapi::EVENT_SECCOMP,    uapi::O_TRACESECCOMP);
}

#[test]
fn event_enabled_matches_the_option_bit_and_nothing_else() {
    for e in ALL_EVENTS {
        assert!(event_enabled(1u32 << e, e));
        assert!(!event_enabled(!(1u32 << e), e));
    }
    // EVENT_STOP is not an option-selected event: it is produced by
    // PTRACE_INTERRUPT / a SEIZE-mode group stop, never by an option bit.
    assert!(!event_enabled(u32::MAX, uapi::EVENT_STOP));
    assert!(!event_enabled(u32::MAX, 0));
}

#[test]
fn clone_untraced_suppresses_the_report_even_with_the_option_set() {
    let opts = uapi::O_TRACEFORK | uapi::O_TRACECLONE | uapi::O_TRACEVFORK;
    assert_eq!(clone_event_reported(CLONE_UNTRACED, SIGCHLD, true, opts), None);
    assert_eq!(clone_event_reported(0, SIGCHLD, true, opts), Some(uapi::EVENT_FORK));
}

#[test]
fn an_untraced_parent_reports_nothing() {
    assert_eq!(clone_event_reported(0, SIGCHLD, false, uapi::O_TRACEFORK), None);
}

#[test]
fn the_option_gate_is_per_event_not_a_blanket() {
    // TRACEFORK alone must not report a thread spawn, and TRACECLONE alone
    // must not report a fork — the exact confusion that makes a tracer lose
    // half a process tree.
    assert_eq!(clone_event_reported(0, 0, true, uapi::O_TRACEFORK), None);
    assert_eq!(clone_event_reported(0, SIGCHLD, true, uapi::O_TRACECLONE), None);
    assert_eq!(clone_event_reported(0, 0, true, uapi::O_TRACECLONE), Some(uapi::EVENT_CLONE));
    assert_eq!(clone_event_reported(CLONE_VFORK, SIGCHLD, true, uapi::O_TRACEVFORK),
               Some(uapi::EVENT_VFORK));
}

#[test]
fn a_reported_clone_auto_attaches_the_child_to_the_same_tracer() {
    let opts = uapi::O_TRACEFORK | uapi::O_TRACESYSGOOD | uapi::O_EXITKILL;
    let got = inherited_trace(Some(uapi::EVENT_FORK), 42, opts, false);
    assert_eq!(got, Some(InheritedTrace { tracer: 42, opts, seized: false }));
}

#[test]
fn an_unreported_clone_leaves_the_child_untraced() {
    assert_eq!(inherited_trace(None, 42, uapi::O_TRACEFORK, false), None);
    assert_eq!(inherited_trace(Some(uapi::EVENT_FORK), 0, uapi::O_TRACEFORK, false), None);
}

#[test]
fn an_auto_attached_child_rests_at_sigstop_or_event_stop_by_seize_mode() {
    let classic = InheritedTrace { tracer: 1, opts: 0, seized: false };
    let seized  = InheritedTrace { tracer: 1, opts: 0, seized: true };
    assert_eq!(classic.child_stop_code(), SIGSTOP);
    assert_eq!(seized.child_stop_code(), uapi::event_stop_code(uapi::EVENT_STOP));
    assert_eq!(uapi::event_of_stop_code(seized.child_stop_code()), uapi::EVENT_STOP);
}

#[test]
fn exec_falls_back_to_a_bare_sigtrap_only_for_a_classic_attach() {
    assert!(legacy_exec_sigtrap(true, false, 0));
    // PTRACE_O_TRACEEXEC replaces the legacy trap with the event stop.
    assert!(!legacy_exec_sigtrap(true, false, uapi::O_TRACEEXEC));
    // A SEIZED tracee never gets the legacy trap.
    assert!(!legacy_exec_sigtrap(true, true, 0));
    assert!(!legacy_exec_sigtrap(false, false, 0));
}

#[test]
fn exitkill_reads_only_its_own_bit() {
    assert!(exitkill(uapi::O_EXITKILL));
    assert!(!exitkill(uapi::O_MASK & !uapi::O_EXITKILL));
}

#[test]
fn the_two_syscall_stop_messages_are_distinct_and_nonzero() {
    assert_eq!(EVENTMSG_SYSCALL_ENTRY, 1);
    assert_eq!(EVENTMSG_SYSCALL_EXIT, 2);
}
