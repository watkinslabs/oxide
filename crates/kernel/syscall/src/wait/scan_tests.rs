// Verified child-scan contract, driven through the real `scan_pass` with the
// registry lookups injected. What is pinned: a class the caller did not
// request is never LOOKED UP (not merely discarded afterwards), an exit
// outranks a stop from the same pass, and the consume flag reaches both
// lookups so `WNOWAIT` peeks rather than reaps.

use super::*;
use crate::wait::{waitid_plan, wait4_prepare, WEXITED, WCONTINUED, WNOWAIT, WSTOPPED};
use core::cell::Cell;

/// A stand-in for the registry's child snapshot: the scan is generic over it.
type Child = u32;

const ZOMBIE: Child = 11;
const STOPPER: Child = 22;
const EXIT_WSTAT: i32 = 3 << 8;
const STOP_CODE: i32 = 19;

/// Records whether each lookup ran and with which consume flag.
#[derive(Default)]
struct Probes {
    zombie_consume: Cell<Option<bool>>,
    stop_args:      Cell<Option<(bool, bool, bool)>>,
}

fn run(plan: &WaitPlan, zombie: Option<(Child, i32)>, stop: Option<(Child, WaitEventKind, i32)>)
    -> (Option<(Child, WaitEventKind, i32)>, Probes)
{
    let p = Probes::default();
    let got = {
        let p = &p;
        scan_pass(plan,
            |consume| { p.zombie_consume.set(Some(consume)); zombie },
            |ws, wc, consume| { p.stop_args.set(Some((ws, wc, consume))); stop })
    };
    (got, p)
}

#[test]
fn a_stopped_only_waitid_never_looks_a_zombie_up() {
    // The B1581 defect: `waitid(P_ALL, WSTOPPED)` reaped and reported an
    // exited child. Asserting on the RESULT alone is not enough — the reap is
    // destructive, so the lookup must not run at all.
    let plan = waitid_plan(-1, WSTOPPED);
    let (got, probes) = run(&plan, Some((ZOMBIE, EXIT_WSTAT)), None);
    assert_eq!(probes.zombie_consume.get(), None, "WSTOPPED must not probe zombies");
    assert_eq!(got, None);

    let plan = waitid_plan(-1, WCONTINUED);
    let (_, probes) = run(&plan, Some((ZOMBIE, EXIT_WSTAT)), None);
    assert_eq!(probes.zombie_consume.get(), None, "WCONTINUED must not probe zombies");
}

#[test]
fn an_exited_class_wait_probes_zombies_and_reports_the_exit() {
    let plan = waitid_plan(-1, WEXITED);
    let (got, probes) = run(&plan, Some((ZOMBIE, EXIT_WSTAT)), None);
    assert_eq!(probes.zombie_consume.get(), Some(true));
    assert_eq!(got, Some((ZOMBIE, WaitEventKind::Exited, EXIT_WSTAT)));
}

#[test]
fn an_exit_outranks_a_stop_in_the_same_pass() {
    let plan = wait4_prepare(-1, WSTOPPED /* == WUNTRACED */).expect("legal wait4");
    let (got, probes) = run(&plan,
        Some((ZOMBIE, EXIT_WSTAT)),
        Some((STOPPER, WaitEventKind::Stopped, STOP_CODE)));
    assert_eq!(got, Some((ZOMBIE, WaitEventKind::Exited, EXIT_WSTAT)));
    assert_eq!(probes.stop_args.get(), None, "the stop lookup is not reached after a hit");
}

#[test]
fn the_stop_lookup_runs_even_when_no_stop_class_was_requested() {
    // A tracer sees its tracee's trap stop with no WUNTRACED bit set, so the
    // lookup is unconditional; the class flags are passed through for it to
    // apply. It is reached only after the zombie lookup missed.
    let plan = wait4_prepare(-1, 0).expect("legal wait4");
    let (got, probes) = run(&plan, None, Some((STOPPER, WaitEventKind::Trapped, STOP_CODE)));
    assert_eq!(probes.zombie_consume.get(), Some(true));
    assert_eq!(probes.stop_args.get(), Some((false, false, true)));
    assert_eq!(got, Some((STOPPER, WaitEventKind::Trapped, (STOP_CODE << 8) | 0x7f)));
}

#[test]
fn wnowait_reaches_both_lookups_as_a_peek() {
    let plan = waitid_plan(-1, WEXITED | WSTOPPED | WNOWAIT);
    let (_, probes) = run(&plan, None, None);
    assert_eq!(probes.zombie_consume.get(), Some(false));
    assert_eq!(probes.stop_args.get(), Some((true, false, false)));
}

#[test]
fn nothing_available_reports_nothing() {
    let plan = wait4_prepare(-1, 0).expect("legal wait4");
    let (got, _) = run(&plan, None, None);
    assert_eq!(got, None);
}

#[test]
fn stop_continue_and_trap_carry_their_own_wait_status_encodings() {
    // A continue is the fixed 0xffff; a stop is the 16-bit code shifted into
    // place with 0x7f in the low byte. Masking the code to a byte would erase
    // a ptrace event number from the high half.
    assert_eq!(stop_event_wstatus(WaitEventKind::Continued, 0), 0xffff);
    assert_eq!(stop_event_wstatus(WaitEventKind::Continued, 0x1234), 0xffff);
    assert_eq!(stop_event_wstatus(WaitEventKind::Stopped, 19), (19 << 8) | 0x7f);
    // SIGTRAP | (PTRACE_EVENT_EXEC << 8) — the event survives the encoding.
    let event_stop = 5 | (4 << 8);
    assert_eq!(stop_event_wstatus(WaitEventKind::Trapped, event_stop),
               (event_stop << 8) | 0x7f);
}

#[test]
fn only_a_consuming_exit_drains_the_parents_pending_sigchld() {
    assert!(drains_sigchld(WaitEventKind::Exited, true));
    // WNOWAIT left the child waitable: a later wait must still see SIGCHLD.
    assert!(!drains_sigchld(WaitEventKind::Exited, false));
    // A stop/continue report reaped nothing, so nothing drained.
    assert!(!drains_sigchld(WaitEventKind::Stopped, true));
    assert!(!drains_sigchld(WaitEventKind::Trapped, true));
    assert!(!drains_sigchld(WaitEventKind::Continued, true));
}
