use crate::emulator::Emulator;
use crate::vc::Vc;

use super::{run, trimmed};

#[test]
fn resize_noop_on_same_dims() {
    let mut vc = run(10, 3, b"abc\r\nde");
    vc.move_to(1, 2);
    let (x, y) = (vc.x, vc.y);
    vc.resize(10, 3);
    assert_eq!((vc.cols, vc.rows), (10, 3));
    assert_eq!((vc.x, vc.y), (x, y));
    assert_eq!(trimmed(&vc, 0), "abc");
}

#[test]
fn resize_grow_preserves_top_left_content() {
    let mut vc = run(5, 2, b"AB\r\nCD");
    vc.resize(8, 4);
    assert_eq!((vc.cols, vc.rows), (8, 4));
    assert_eq!(trimmed(&vc, 0), "AB");
    assert_eq!(trimmed(&vc, 1), "CD");
    assert_eq!(trimmed(&vc, 2), "");
    assert_eq!(trimmed(&vc, 3), "");
    assert_eq!(vc.glyph_at(5, 0), ' ' as u32);
}

#[test]
fn resize_shrink_rows_keeps_cursor_neighbourhood() {
    let mut vc = run(6, 4, b"r0\r\nr1\r\nr2\r\nr3");
    assert_eq!(vc.y, 3);
    vc.resize(6, 2);
    assert_eq!((vc.cols, vc.rows), (6, 2));
    assert_eq!(trimmed(&vc, 0), "r2");
    assert_eq!(trimmed(&vc, 1), "r3");
    assert_eq!(vc.y, 1);
}

#[test]
fn resize_shrink_cols_clamps_cursor_x() {
    let mut vc = run(20, 2, b"");
    vc.move_to(0, 18);
    assert_eq!(vc.x, 18);
    vc.resize(10, 2);
    assert_eq!(vc.cols, 10);
    assert_eq!(vc.x, 9);
}

#[test]
fn resize_full_scroll_region_re_expands() {
    let mut vc = Vc::new(10, 5);
    assert_eq!((vc.scroll_top, vc.scroll_bot), (0, 4));
    vc.resize(10, 8);
    assert_eq!((vc.scroll_top, vc.scroll_bot), (0, 7));
    vc.resize(10, 3);
    assert_eq!((vc.scroll_top, vc.scroll_bot), (0, 2));
}

#[test]
fn resize_partial_scroll_region_clamps_or_resets() {
    let mut vc = Vc::new(10, 10);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, b"\x1b[3;7r");
    assert_eq!((vc.scroll_top, vc.scroll_bot), (2, 6));
    vc.resize(10, 8);
    assert_eq!((vc.scroll_top, vc.scroll_bot), (2, 6));
    vc.resize(10, 4);
    assert_eq!((vc.scroll_top, vc.scroll_bot), (2, 3));
    vc.resize(10, 3);
    assert_eq!((vc.scroll_top, vc.scroll_bot), (0, 2));
}

#[test]
fn resize_rebuilds_tab_stops_at_new_width() {
    let mut vc = Vc::new(10, 2);
    assert!(vc.tab_set(8));
    vc.resize(30, 2);
    assert!(vc.tab_set(8) && vc.tab_set(16) && vc.tab_set(24));
    vc.resize(6, 2);
    assert!(!vc.tab_set(8));
}

#[test]
fn resize_clamps_view_offset_and_snaps_to_bottom() {
    let mut vc = run(8, 3, b"r0\r\nr1\r\nr2\r\nr3\r\nr4\r\nr5");
    vc.scroll_view_up(2);
    assert_eq!(vc.view_offset(), 2);
    vc.resize(8, 4);
    assert_eq!(vc.view_offset(), 0);
    assert!(vc.view_offset() <= vc.history_len());
}
