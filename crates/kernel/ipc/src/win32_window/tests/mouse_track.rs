use super::*;
use crate::win32_window::{WindowId, WindowManager, WindowRect};

fn window() -> WindowId { WindowId::from_raw(4).unwrap() }

#[test]
fn a_query_answers_the_stored_record_untouched() {
    let stored = MouseTracking { hwnd: Some(window()), flags: TME_LEAVE, hover_time: 400 };
    assert_eq!(track_action(stored, window(), TME_QUERY, 0, true, 400), TrackAction::Query(stored));
}

#[test]
fn a_leave_request_over_a_window_the_pointer_left_posts_the_leave_at_once() {
    let stored = MouseTracking::default();
    assert_eq!(track_action(stored, window(), TME_LEAVE, 0, false, 400),
        TrackAction::PostLeave { hwnd: window(), nonclient: false });
    assert_eq!(track_action(stored, window(), TME_LEAVE | TME_NONCLIENT, 0, false, 400),
        TrackAction::PostLeave { hwnd: window(), nonclient: true });
}

#[test]
fn a_hover_request_takes_the_system_dwell_for_a_default_or_zero_request() {
    let stored = MouseTracking::default();
    let TrackAction::Track(record) = track_action(stored, window(), TME_HOVER, HOVER_DEFAULT, true, 400) else { panic!("must track") };
    assert_eq!(record.hover_time, 400);
    let TrackAction::Track(record) = track_action(stored, window(), TME_HOVER, 0, true, 400) else { panic!("must track") };
    assert_eq!(record.hover_time, 400);
    let TrackAction::Track(record) = track_action(stored, window(), TME_HOVER, 90, true, 400) else { panic!("must track") };
    assert_eq!(record.hover_time, 90);
}

#[test]
fn cancelling_the_last_tracked_event_stops_tracking() {
    let stored = MouseTracking { hwnd: Some(window()), flags: TME_LEAVE | TME_HOVER, hover_time: 400 };
    let TrackAction::Track(record) = track_action(stored, window(), TME_CANCEL | TME_HOVER, 0, true, 400) else { panic!("must keep tracking") };
    assert_eq!(record.flags, TME_LEAVE);
    assert_eq!(track_action(stored, window(), TME_CANCEL | TME_HOVER | TME_LEAVE, 0, true, 400),
        TrackAction::Stop { hwnd: Some(window()) });
}

#[test]
fn cancelling_a_window_that_is_not_tracked_leaves_the_record_alone() {
    let stored = MouseTracking { hwnd: Some(WindowId::from_raw(9).unwrap()), flags: TME_LEAVE, hover_time: 1 };
    assert_eq!(track_action(stored, window(), TME_CANCEL | TME_LEAVE, 0, true, 400), TrackAction::Query(stored));
}

#[test]
fn the_record_is_stored_per_thread_and_the_pointer_test_uses_the_window_rect() {
    let mut manager = WindowManager::new();
    let id = manager.create(1, None, 0).unwrap();
    manager.set_rect(id, WindowRect { left: 0, top: 0, right: 10, bottom: 10 }).unwrap();
    manager.set_cursor_pos(5, 5, WindowRect { left: 0, top: 0, right: 100, bottom: 100 }, 1);
    assert!(manager.pointer_inside(id));
    manager.set_cursor_pos(50, 50, WindowRect { left: 0, top: 0, right: 100, bottom: 100 }, 2);
    assert!(!manager.pointer_inside(id));
    let record = MouseTracking { hwnd: Some(id), flags: TME_LEAVE, hover_time: 5 };
    manager.set_mouse_tracking(1, record);
    assert_eq!(manager.mouse_tracking(1), record);
    assert_eq!(manager.mouse_tracking(2), MouseTracking::default());
}
