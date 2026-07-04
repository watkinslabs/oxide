use crate::emulator::Emulator;
use crate::vc::{Vc, SCROLLBACK_LINES};

use super::{run, trimmed};

#[test]
fn scrolled_off_rows_enter_history_in_order() {
    let vc = run(10, 3, b"r0\r\nr1\r\nr2\r\nr3\r\nr4\r\nr5");
    assert_eq!(trimmed(&vc, 0), "r3");
    assert_eq!(trimmed(&vc, 2), "r5");
    assert_eq!(vc.history_len(), 3);
}

#[test]
fn scroll_view_up_shows_history_rows() {
    let mut vc = run(10, 3, b"r0\r\nr1\r\nr2\r\nr3\r\nr4\r\nr5");
    vc.scroll_view_up(2);
    assert_eq!(vc.view_offset(), 2);
    let vrow = |r: u16| -> alloc::string::String {
        (0..vc.cols)
            .map(|c| char::from_u32(vc.visible_glyph_at(c, r)).unwrap_or('?'))
            .collect::<alloc::string::String>()
            .trim_end()
            .into()
    };
    assert_eq!(vrow(0), "r1");
    assert_eq!(vrow(1), "r2");
    assert_eq!(vrow(2), "r3");
}

#[test]
fn scroll_view_clamps_to_history_len() {
    let mut vc = run(10, 3, b"r0\r\nr1\r\nr2\r\nr3");
    vc.scroll_view_up(50);
    assert_eq!(vc.view_offset(), 1);
    assert_eq!(vc.view_offset(), vc.history_len());
    vc.scroll_view_down(50);
    assert_eq!(vc.view_offset(), 0);
}

#[test]
fn new_output_snaps_view_to_bottom() {
    let mut vc = run(10, 3, b"r0\r\nr1\r\nr2\r\nr3");
    vc.scroll_view_up(1);
    assert_eq!(vc.view_offset(), 1);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, b"x");
    assert_eq!(vc.view_offset(), 0);
}

#[test]
fn history_ring_bounded_evicts_oldest() {
    let mut vc = Vc::new(4, 2);
    let mut em = Emulator::new();
    for _ in 0..(SCROLLBACK_LINES + 50) {
        em.feed_bytes(&mut vc, b"\n");
    }
    assert_eq!(vc.history_len(), SCROLLBACK_LINES);
}

#[test]
fn view_offset_change_marks_all_rows_dirty() {
    let mut vc = run(10, 3, b"r0\r\nr1\r\nr2\r\nr3");
    vc.clear_dirty();
    vc.scroll_view_up(1);
    for r in 0..vc.rows {
        assert!(vc.is_row_dirty(r), "row {r} must be dirty after view change");
    }
}
