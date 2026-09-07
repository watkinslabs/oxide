use super::*;
use crate::win32_window::{WindowManager, WindowRect};

const SCREEN: WindowRect = WindowRect { left: 0, top: 0, right: 800, bottom: 600 };

#[test]
fn an_unclipped_cursor_is_bounded_only_by_the_screen() {
    let mut manager = WindowManager::new();
    assert_eq!(manager.clip_cursor_rect(SCREEN), SCREEN);
    assert!(manager.set_cursor_pos(1000, 1000, SCREEN, 5));
    assert_eq!(manager.cursor_pos(), (799, 599));
    assert_eq!(manager.cursor_last_change(), 5);
}

#[test]
fn a_clip_rectangle_is_intersected_with_the_screen_and_warps_the_cursor() {
    let mut manager = WindowManager::new();
    manager.set_cursor_pos(700, 500, SCREEN, 1);
    let rect = WindowRect { left: -50, top: 10, right: 100, bottom: 200 };
    assert!(manager.clip_cursor(Some(rect), SCREEN, 2));
    assert_eq!(manager.clip_cursor_rect(SCREEN), WindowRect { left: 0, top: 10, right: 100, bottom: 200 });
    assert_eq!(manager.cursor_pos(), (99, 199));
}

#[test]
fn an_inverted_clip_request_is_refused_before_anything_changes() {
    let mut manager = WindowManager::new();
    manager.set_cursor_pos(10, 10, SCREEN, 1);
    let rect = WindowRect { left: 100, top: 0, right: 10, bottom: 10 };
    assert!(!manager.clip_cursor(Some(rect), SCREEN, 2));
    assert_eq!(manager.clip_cursor_rect(SCREEN), SCREEN);
    assert_eq!(manager.cursor_pos(), (10, 10));
}

#[test]
fn clearing_the_clip_restores_the_whole_screen() {
    let mut manager = WindowManager::new();
    manager.clip_cursor(Some(WindowRect { left: 0, top: 0, right: 10, bottom: 10 }), SCREEN, 1);
    assert!(manager.clip_cursor(None, SCREEN, 2));
    assert_eq!(manager.clip_cursor_rect(SCREEN), SCREEN);
}

#[test]
fn an_empty_clip_intersection_falls_back_to_the_screen() {
    let outside = WindowRect { left: 900, top: 900, right: 950, bottom: 950 };
    assert_eq!(clip_within(Some(outside), SCREEN), SCREEN);
}

#[test]
fn the_history_reads_back_newest_first_and_a_probe_walks_forward_from_its_match() {
    let mut manager = WindowManager::new();
    for step in 0..5 { manager.set_cursor_pos(step, step, SCREEN, step as u32 + 1); }
    let history = manager.cursor_history();
    assert_eq!((history[0].x, history[0].time), (4, 5));
    assert_eq!((history[1].x, history[1].time), (3, 4));
    let probe = CursorPos { x: 3, y: 3, time: 0, info: 0 };
    let walked = move_points_from(&history, probe, 3).unwrap();
    assert_eq!(walked.iter().map(|pos| pos.x).collect::<Vec<_>>(), alloc::vec![3, 2, 1]);
    let missing = CursorPos { x: 3, y: 3, time: 99, info: 0 };
    assert_eq!(move_points_from(&history, missing, 1), None);
}
