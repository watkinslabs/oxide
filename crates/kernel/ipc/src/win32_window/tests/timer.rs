//! Timer identity, id allocation, timeout clamp and expiry contracts.
use super::super::*;

fn manager() -> WindowManager { WindowManager::new() }

#[test]
fn timeout_clamps_to_the_documented_bounds() {
    assert_eq!(clamp_timeout(0), USER_TIMER_MINIMUM);
    assert_eq!(clamp_timeout(9), USER_TIMER_MINIMUM);
    assert_eq!(clamp_timeout(10), 10);
    assert_eq!(clamp_timeout(1_000), 1_000);
    assert_eq!(clamp_timeout(u32::MAX), USER_TIMER_MAXIMUM);
}

#[test]
fn a_windowed_timer_keeps_the_requested_id() {
    let mut state = manager();
    let window = state.create(7, None, 0).unwrap();
    assert_eq!(state.set_timer(7, Some(window), WM_TIMER, 42, 100, 0, 0).unwrap(), 42);
}

#[test]
fn re_arming_the_same_identity_replaces_rather_than_duplicates() {
    let mut state = manager();
    let window = state.create(7, None, 0).unwrap();
    state.set_timer(7, Some(window), WM_TIMER, 42, 1_000, 0, 0).unwrap();
    state.set_timer(7, Some(window), WM_TIMER, 42, 10, 0, 0).unwrap();
    assert_eq!(state.expire_timers(10_000_000), 1);
}

#[test]
fn timer_and_systimer_are_separate_id_spaces_on_one_window() {
    let mut state = manager();
    let window = state.create(7, None, 0).unwrap();
    state.set_timer(7, Some(window), WM_TIMER, 5, 10, 0, 0).unwrap();
    state.set_timer(7, Some(window), WM_SYSTIMER, 5, 10, 0, 0).unwrap();
    assert_eq!(state.expire_timers(10_000_000), 2);
    assert!(state.kill_timer(Some(window), WM_TIMER, 5));
    assert!(state.kill_timer(Some(window), WM_SYSTIMER, 5));
    assert!(!state.kill_timer(Some(window), WM_TIMER, 5));
}

#[test]
fn a_windowless_timer_is_assigned_an_id_from_the_descending_allocator() {
    let mut state = manager();
    state.create(7, None, 0).unwrap();
    assert_eq!(state.set_timer(7, None, WM_TIMER, 0, 10, 0, 0).unwrap(), TIMER_ID_FIRST);
    assert_eq!(state.set_timer(7, None, WM_TIMER, 0, 10, 0, 0).unwrap(), TIMER_ID_FIRST - 1);
    // A requested id that names no live timer is still replaced by an allocated one.
    assert_eq!(state.set_timer(7, None, WM_TIMER, 9, 10, 0, 0).unwrap(), TIMER_ID_FIRST - 2);
    // Naming a live windowless id re-arms that timer and keeps it.
    assert_eq!(state.set_timer(7, None, WM_TIMER, TIMER_ID_FIRST, 10, 0, 0).unwrap(), TIMER_ID_FIRST);
}

#[test]
fn an_absent_window_refuses_the_arm() {
    let mut state = manager();
    let window = state.create(7, None, 0).unwrap();
    state.destroy(window).unwrap();
    assert_eq!(state.set_timer(7, Some(window), WM_TIMER, 1, 10, 0, 0), Err(WindowError::NoSuchWindow));
}

#[test]
fn expiry_posts_the_timers_own_message_with_id_and_procedure() {
    let mut state = manager();
    let window = state.create(7, None, 0).unwrap();
    state.set_timer(7, Some(window), WM_SYSTIMER, 3, 10, 0xdead_beef, 0).unwrap();
    assert_eq!(state.expire_timers(10_000_000), 1);
    let found = state.peek_for_thread(7, MessageFilter { hwnd: None, first: 0, last: 0 }, true).unwrap();
    assert_eq!(found.message, WM_SYSTIMER);
    assert_eq!(found.wparam, 3);
    assert_eq!(found.lparam, 0xdead_beef);
    assert_eq!(found.hwnd, Some(window));
}

#[test]
fn a_timer_does_not_fire_before_its_clamped_period() {
    let mut state = manager();
    let window = state.create(7, None, 0).unwrap();
    state.set_timer(7, Some(window), WM_TIMER, 1, 0, 0, 0).unwrap();
    assert_eq!(state.expire_timers(9_000_000), 0);
    assert_eq!(state.expire_timers(10_000_000), 1);
}

#[test]
fn a_windowed_timer_follows_the_windows_owning_thread() {
    let mut state = manager();
    let window = state.create(9, None, 0).unwrap();
    state.set_timer(7, Some(window), WM_TIMER, 1, 10, 0, 0).unwrap();
    assert_eq!(state.expire_timers(10_000_000), 1);
    assert!(state.peek_for_thread(9, MessageFilter { hwnd: None, first: 0, last: 0 }, true).is_some());
}
