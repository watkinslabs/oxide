use super::*;
use super::super::WindowId;

fn hwnd() -> WindowId { WindowId::from_raw(7).unwrap() }

#[test]
fn default_interval_matches_wine_fallback_and_deadline_is_exact() {
    let mut blink = CaretBlink::new();
    blink.arm(11, hwnd(), 3, 1_000, DEFAULT_CARET_BLINK_MS);
    assert_eq!(blink.deadline(), Some(500_001_000));
    assert_eq!(blink.expire(500_000_999), None);
    assert_eq!(blink.expire(500_001_000), Some(ExpiredCaretCommit { owner_tid: 11, hwnd: hwnd(), generation: 3 }));
    assert_eq!(blink.deadline(), Some(1_000_001_000));
}

#[test]
fn expiry_commit_is_typed_and_rearms_without_mutating_caret_state() {
    let mut blink = CaretBlink::new();
    blink.arm(4, hwnd(), 9, 10, 20);
    let commit = blink.expire(20_000_010).unwrap();
    assert_eq!((commit.owner_tid, commit.hwnd, commit.generation), (4, hwnd(), 9));
    assert_eq!(blink.deadline(), Some(40_000_010));
}

#[test]
fn clear_rejects_stale_identity_and_accepts_current_queue_caret() {
    let mut blink = CaretBlink::new();
    blink.arm(4, hwnd(), 9, 10, 20);
    assert!(!blink.clear(5, Some(hwnd())));
    assert!(blink.deadline().is_some());
    assert!(blink.clear(4, Some(hwnd())));
    assert_eq!(blink.deadline(), None);
}

#[test]
fn saturated_time_conversion_never_wraps_deadline() {
    let mut blink = CaretBlink::new();
    blink.arm(4, hwnd(), 9, u64::MAX - 1, u32::MAX);
    assert_eq!(blink.deadline(), Some(u64::MAX));
}

#[test]
fn expiry_toggles_canonical_phase_advances_generation_and_rearms() {
    let mut manager = WindowManager::new();
    let window = manager.create(11, None, 0).unwrap();
    manager.create_caret(11, window, 2, 16).unwrap();
    manager.set_caret_pos(11, 4, 5).unwrap();
    manager.show_caret(11, Some(window)).unwrap();
    manager.arm_current_caret_blink(11, window, 3, 100, 20).unwrap();
    let commit = manager.expire_current_caret_blink(11, 20_000_100).unwrap().unwrap();
    assert!(commit.transition.old_visible);
    assert!(!commit.transition.new_visible);
    assert_eq!(commit.generation, 4);
    assert_eq!(manager.current_caret_blink_deadline(11), Ok(Some(40_000_100)));
}

#[test]
fn stale_expiry_clears_without_toggling_canonical_caret() {
    let mut manager = WindowManager::new();
    let window = manager.create(11, None, 0).unwrap();
    manager.create_caret(11, window, 2, 16).unwrap();
    manager.set_caret_pos(11, 4, 5).unwrap();
    manager.show_caret(11, Some(window)).unwrap();
    manager.arm_current_caret_blink(11, window, 2, 100, 20).unwrap();
    assert_eq!(manager.expire_current_caret_blink(11, 20_000_100).unwrap(), None);
    assert_eq!(manager.current_caret_blink_deadline(11), Ok(None));
    assert!(manager.show_caret(11, Some(window)).unwrap().transition.new_visible);
}

#[test]
fn preserve_retags_generation_without_restarting_deadline() {
    let mut manager = WindowManager::new();
    let window = manager.create(11, None, 0).unwrap();
    manager.create_caret(11, window, 2, 16).unwrap();
    manager.set_caret_pos(11, 4, 5).unwrap();
    manager.show_caret(11, Some(window)).unwrap();
    manager.arm_current_caret_blink(11, window, 3, 100, 20).unwrap();
    let same_position = manager.set_caret_pos(11, 4, 5).unwrap();
    assert!(manager.refresh_current_caret_blink_generation(11, window, same_position.generation).unwrap());
    assert_eq!(manager.current_caret_blink_deadline(11), Ok(Some(20_000_100)));
    let commit = manager.expire_current_caret_blink(11, 20_000_100).unwrap().unwrap();
    assert_eq!(commit.generation, 5);
    assert!(!commit.transition.new_visible);
}

#[test]
fn repeated_show_and_same_position_preserve_live_deadline_then_show_rearms_after_blink_off() {
    let mut manager = WindowManager::new();
    let window = manager.create(11, None, 0).unwrap();
    manager.create_caret(11, window, 2, 16).unwrap();
    manager.set_caret_pos(11, 4, 5).unwrap();
    manager.show_caret(11, Some(window)).unwrap();
    manager.arm_current_caret_blink(11, window, 3, 100, 20).unwrap();
    let deadline = manager.current_caret_blink_deadline(11).unwrap();
    let repeated = manager.show_caret(11, Some(window)).unwrap();
    assert!(repeated.transition.new_visible);
    assert!(manager.refresh_current_caret_blink_generation(11, window, repeated.generation).unwrap());
    assert_eq!(manager.current_caret_blink_deadline(11).unwrap(), deadline);
    let same_position = manager.set_caret_pos(11, 4, 5).unwrap();
    assert!(same_position.transition.new_visible);
    assert!(manager.refresh_current_caret_blink_generation(11, window, same_position.generation).unwrap());
    assert_eq!(manager.current_caret_blink_deadline(11).unwrap(), deadline);
    let off = manager.expire_current_caret_blink(11, 20_000_100).unwrap().unwrap();
    assert!(!off.transition.new_visible);
    let on = manager.show_caret(11, Some(window)).unwrap();
    assert!(on.transition.new_visible);
    // The canonical phase transition itself does not arm timers; the live
    // syscall wrapper supplies the new monotonic deadline on this ShowCaret.
    assert_eq!(manager.current_caret_blink_deadline(11), Ok(Some(40_000_100)));
}

#[test]
fn next_timer_deadline_is_minimum_of_existing_owner_timers_only() {
    let mut manager = WindowManager::new();
    let first = manager.create(11, None, 0).unwrap();
    let second = manager.create(12, None, 0).unwrap();
    manager.set_timer(11, Some(first), 1, 30, 0, 1_000).unwrap();
    manager.set_timer(11, None, 2, 10, 0, 2_000).unwrap();
    manager.set_timer(12, Some(second), 3, 1, 0, 3_000).unwrap();
    assert_eq!(manager.next_timer_deadline(11), Some(10_002_000));
    assert_eq!(manager.next_timer_deadline(12), Some(1_003_000));
    assert_eq!(manager.next_timer_deadline(13), None);
}

#[test]
fn retrieval_deadline_joins_caret_and_timer_and_missing_both_is_unbounded() {
    let mut manager = WindowManager::new();
    assert_eq!(manager.next_retrieval_deadline(11), None);
    let window = manager.create(11, None, 0).unwrap();
    manager.create_caret(11, window, 2, 16).unwrap();
    manager.set_caret_pos(11, 4, 5).unwrap();
    manager.show_caret(11, Some(window)).unwrap();
    manager.arm_current_caret_blink(11, window, 3, 100, 20).unwrap();
    manager.set_timer(11, Some(window), 1, 30, 0, 1_000).unwrap();
    assert_eq!(manager.next_retrieval_deadline(11), Some(20_000_100));
    manager.set_timer(11, Some(window), 1, 5, 0, 2_000).unwrap();
    assert_eq!(manager.next_retrieval_deadline(11), Some(5_002_000));
}
