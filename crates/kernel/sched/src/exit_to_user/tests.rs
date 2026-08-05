// Host tests for the return-to-user work-loop rules. This module is NOT
// target-gated (CLAUDE.md phantom-test rule), so `cargo test -p sched
// exit_to_user` really runs it — verified by breaking an assertion and
// watching the pass count drop.

use super::*;
use crate::live::sigpend::Signum;

fn bit(s: Signum) -> u64 { 1u64 << (s as u64 - 1) }

#[test]
fn a_standing_rseq_registration_never_keeps_the_loop_spinning() {
    // Caught by the FIRST boot of B1471: `RSEQ` reports "this thread
    // registered an rseq area", not an event a pass consumes, so with it in
    // the `while` condition every single return to user burned the whole pass
    // bound (`[BUG] exit_to_user_mode_loop: work never cleared`, thousands of
    // times a second). Linux carves the same bit out —
    // `EXIT_TO_USER_MODE_WORK_LOOP = EXIT_TO_USER_MODE_WORK & ~_TIF_RSEQ`.
    let w = work_flags(false, 0, 0, false, false, true);
    assert_eq!(w, work::RSEQ);
    assert!(!has_work(w), "a standing condition must not earn another pass");
    assert!(!should_continue(w, 0));
    // It still counts as work for the ENTRY test, so a pass another item earns
    // services it.
    assert!(enters_loop(w));
    assert!(runs_on_return(true, w));
}

#[test]
fn notify_resume_is_likewise_never_a_reason_to_loop_forever() {
    // Same shape, other bit: whatever sets it must also clear it. Nothing on
    // this port raises `NOTIFY_RESUME`, so if it ever appears it is a bug —
    // but it is in the loop mask because Linux's `resume_user_mode_work()`
    // does clear `_TIF_NOTIFY_RESUME` itself.
    let w = work_flags(false, 0, 0, false, true, false);
    assert_eq!(w, work::NOTIFY_RESUME);
    assert!(has_work(w));
    // The bound is the backstop that turns a mis-wired producer into a
    // complaint rather than a hard hang with interrupts enabled.
    assert!(!should_continue(w, MAX_PASSES));
}

#[test]
fn kernel_mode_return_never_runs_the_loop() {
    // Linux `irqentry_exit`: the user_mode(regs) arm is the ONLY one that
    // reaches `exit_to_user_mode_loop`. An IRQ that interrupted kernel code
    // must not deliver a signal or the handler frame lands over kernel state.
    let w = work_flags(true, bit(Signum::Sigterm), 0, false, true, true);
    assert!(has_work(w), "work is genuinely pending");
    assert!(!runs_on_return(false, w), "kernel-mode return must skip the loop");
    assert!(runs_on_return(true, w), "user-mode return with work must run it");
}

#[test]
fn no_work_means_no_loop_even_from_user() {
    let w = work_flags(false, 0, 0, false, false, false);
    assert_eq!(w, 0);
    assert!(!has_work(w));
    assert!(!runs_on_return(true, w));
}

#[test]
fn each_work_item_sets_exactly_its_own_bit() {
    assert_eq!(work_flags(true, 0, 0, false, false, false), work::NEED_RESCHED);
    assert_eq!(work_flags(false, bit(Signum::Sigusr1), 0, false, false, false), work::SIGPENDING);
    assert_eq!(work_flags(false, 0, 0, true, false, false), work::NOTIFY_SIGNAL);
    assert_eq!(work_flags(false, 0, 0, false, true, false), work::NOTIFY_RESUME);
    assert_eq!(work_flags(false, 0, 0, false, false, true), work::RSEQ);
    assert_eq!(work_flags(true, bit(Signum::Sigusr1), 0, true, true, true), work::MASK);
}

#[test]
fn blocked_signal_is_not_work() {
    // `signal_pending()` is `pending & ~blocked`: a masked signal must not
    // spin the loop, or every `sigprocmask`-holding task burns the CPU on
    // every tick.
    let s = bit(Signum::Sigusr1);
    assert!(!signal_pending(s, s));
    assert_eq!(work_flags(false, s, s, false, false, false), 0);
    assert!(signal_pending(s, 0));
}

#[test]
fn sigkill_is_work_even_when_blocked() {
    // signal(7): SIGKILL/SIGSTOP bypass the mask. This is the W9 case — a
    // spinning task that blocked everything must still die.
    let k = bit(Signum::Sigkill);
    assert!(signal_pending(k, !0), "SIGKILL must be deliverable through a full mask");
    assert!(signal_pending(bit(Signum::Sigstop), !0));
    assert_eq!(work_flags(false, k, !0, false, false, false), work::SIGPENDING);
}

#[test]
fn alarm_posted_by_the_tick_is_work_on_the_next_return() {
    // The `alarm(2)` half of W9: the tick posts SIGALRM into `sigpending`
    // while the task is spinning in user mode, and the IRQ return must see it.
    let w = work_flags(false, bit(Signum::Sigalrm), 0, false, false, false);
    assert!(runs_on_return(true, w));
}

#[test]
fn loop_continues_while_work_remains_and_stops_when_it_clears() {
    // Linux re-reads the flags at the bottom of each pass with interrupts
    // disabled; a single check would return to user with the second item
    // still owed.
    let mut w = work::NEED_RESCHED | work::SIGPENDING;
    assert_eq!(work::MASK_LOOP, work::MASK & !work::RSEQ);
    let mut passes = 0;
    assert!(should_continue(w, passes));
    w &= !work::NEED_RESCHED; passes += 1;
    assert!(should_continue(w, passes), "signal still owed after the reschedule");
    w &= !work::SIGPENDING; passes += 1;
    assert!(!should_continue(w, passes));
}

#[test]
fn pass_bound_stops_a_self_feeding_work_bit() {
    // A producer nothing consumes would otherwise hard-hang with interrupts
    // enabled; the bound turns it into a bounded complaint.
    assert!(should_continue(work::MASK, MAX_PASSES - 1));
    assert!(!should_continue(work::MASK, MAX_PASSES));
}

#[test]
fn pass_order_matches_linux() {
    // `__exit_to_user_mode_loop`: schedule, then signals, then resume work,
    // then the rseq restart check.
    assert_eq!(pass_order(),
               [work::NEED_RESCHED, work::NOTIFY_SIGNAL, work::SIGPENDING,
                work::NOTIFY_RESUME, work::RSEQ]);
    // Every ordered item is in the mask and the mask holds nothing else.
    let ored = pass_order().iter().fold(0, |a, b| a | b);
    assert_eq!(ored, work::MASK);
}
