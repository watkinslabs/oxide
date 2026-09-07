use super::*;
use crate::win32_window::{MessageFilter, QueueResult, WinMessage, WindowManager, WM_QUIT};

const TID: u64 = 4;
const WM_USER: u32 = 0x0400;
const ANY: MessageFilter = MessageFilter { hwnd: None, first: 0, last: 0 };

#[test]
fn the_tick_count_is_whole_milliseconds_of_the_monotonic_reading() {
    assert_eq!(tick_ms_from_ns(0), 0);
    assert_eq!(tick_ms_from_ns(999_999), 0);
    assert_eq!(tick_ms_from_ns(1_000_000), 1);
    assert_eq!(tick_ms_from_ns(1_999_999), 1);
    assert_eq!(tick_ms_from_ns(2_500_000_000), 2_500);
}

#[test]
fn the_tick_count_wraps_at_thirty_two_bits() {
    let wrap = (1u64 << 32) * 1_000_000;
    assert_eq!(tick_ms_from_ns(wrap), 0);
    assert_eq!(tick_ms_from_ns(wrap + 7_000_000), 7);
    assert_eq!(tick_ms_from_ns(wrap - 1_000_000), u32::MAX);
}

#[test]
fn a_thread_that_read_nothing_reports_zero() {
    let mut manager = WindowManager::new();
    let _ = manager.create(TID, None, 0).unwrap();
    assert_eq!(manager.message_time(TID), 0);
    assert_eq!(manager.message_time(TID + 1), 0);
}

#[test]
fn a_retrieval_reports_the_time_the_message_was_queued_not_the_time_it_was_read() {
    let mut manager = WindowManager::new();
    let window = manager.create(TID, None, 0).unwrap();
    manager.post_to_window_at(window, WinMessage { hwnd: Some(window), message: WM_USER, wparam: 0, lparam: 0 }, 1_234).unwrap();
    assert_eq!(manager.message_time(TID), 0);
    assert!(matches!(manager.take_for_thread(TID, ANY), QueueResult::Message(_)));
    assert_eq!(manager.message_time(TID), 1_234);
}

#[test]
fn each_retrieval_replaces_the_reported_time_with_its_own_messages_time() {
    let mut manager = WindowManager::new();
    let window = manager.create(TID, None, 0).unwrap();
    for time in [10, 20] {
        manager.post_to_window_at(window, WinMessage { hwnd: Some(window), message: WM_USER, wparam: 0, lparam: 0 }, time).unwrap();
    }
    assert!(matches!(manager.take_for_thread(TID, ANY), QueueResult::Message(_)));
    assert_eq!(manager.message_time(TID), 10);
    assert!(matches!(manager.take_for_thread(TID, ANY), QueueResult::Message(_)));
    assert_eq!(manager.message_time(TID), 20);
}

#[test]
fn a_peek_that_leaves_the_message_in_place_still_records_its_time() {
    let mut manager = WindowManager::new();
    let window = manager.create(TID, None, 0).unwrap();
    manager.post_to_window_at(window, WinMessage { hwnd: Some(window), message: WM_USER, wparam: 0, lparam: 0 }, 77).unwrap();
    assert!(manager.peek_for_thread(TID, ANY, false).is_some());
    assert_eq!(manager.message_time(TID), 77);
}

/// An empty retrieval reports no message, so it leaves the reported time alone.
#[test]
fn an_empty_retrieval_leaves_the_previous_time_standing() {
    let mut manager = WindowManager::new();
    let window = manager.create(TID, None, 0).unwrap();
    manager.post_to_window_at(window, WinMessage { hwnd: Some(window), message: WM_USER, wparam: 0, lparam: 0 }, 55).unwrap();
    assert!(matches!(manager.take_for_thread(TID, ANY), QueueResult::Message(_)));
    assert!(manager.peek_for_thread(TID, ANY, true).is_none());
    assert_eq!(manager.message_time(TID), 55);
}

/// The quit message is never a queue entry, so it carries the time of the
/// retrieval that reported it rather than a queued stamp.
#[test]
fn the_quit_message_carries_the_time_of_its_retrieval() {
    let mut manager = WindowManager::new();
    let _ = manager.create(TID, None, 0).unwrap();
    manager.post_quit(TID, 3);
    let before = tick_ms();
    let found = manager.peek_for_thread(TID, ANY, true);
    assert_eq!(found.map(|message| message.message), Some(WM_QUIT));
    assert!(manager.message_time(TID) >= before);
}
