use super::*;
use core::sync::atomic::{AtomicBool, Ordering};

static PLATFORM_WOKE: AtomicBool = AtomicBool::new(false);
fn platform_wake() -> bool { PLATFORM_WOKE.load(Ordering::SeqCst) }

#[test]
fn a_pending_wakeup_declines_to_commit() {
    assert_eq!(enter_decision(true), S2idleState::None);
}

#[test]
fn no_pending_wakeup_commits() {
    assert_eq!(enter_decision(false), S2idleState::Enter);
}

#[test]
fn a_wake_outside_a_cycle_is_dropped() {
    assert!(!wake_takes_effect(S2idleState::None));
}

#[test]
fn a_wake_inside_a_cycle_lands() {
    assert!(wake_takes_effect(S2idleState::Enter));
    // A second wake after the first must still land: the waiter may not have
    // run yet, and clearing the record would strand it.
    assert!(wake_takes_effect(S2idleState::Wake));
}

#[test]
fn the_platform_hook_replaces_the_generic_check() {
    let mut o = PlatformS2idleOps::none();
    o.wake = Some(platform_wake);

    PLATFORM_WOKE.store(false, Ordering::SeqCst);
    // Generic check says wake, platform says no: the platform wins.
    assert!(!loop_breaks(Some(&o), true));

    PLATFORM_WOKE.store(true, Ordering::SeqCst);
    // Generic check says no, platform says wake: the platform wins again.
    assert!(loop_breaks(Some(&o), false));
}

#[test]
fn without_a_platform_hook_the_generic_check_decides() {
    assert!(loop_breaks(None, true));
    assert!(!loop_breaks(None, false));
    let o = PlatformS2idleOps::none();
    assert!(loop_breaks(Some(&o), true));
    assert!(!loop_breaks(Some(&o), false));
}
