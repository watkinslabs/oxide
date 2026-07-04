use crate::emulator::{CsiState, Emulator};
use crate::vc::{Vc, DEFAULT_FG_RGB};

use super::{run, trimmed};

#[test]
fn dectcem_toggles_cursor_visible() {
    let vc = run(20, 2, b"\x1b[?25l");
    assert!(!vc.cursor_visible);
    let vc2 = run(20, 2, b"\x1b[?25l\x1b[?25h");
    assert!(vc2.cursor_visible);
}

#[test]
fn decaln_fills_screen_with_e() {
    let vc = run(4, 3, b"\x1b#8");
    for r in 0..3 {
        assert_eq!(trimmed(&vc, r), "EEEE");
    }
    assert_eq!((vc.x, vc.y), (0, 0));
}

#[test]
fn bs_stops_at_column_zero() {
    let vc = run(10, 2, b"\x08\x08X");
    assert_eq!((vc.x, vc.y), (1, 0));
    assert_eq!(vc.glyph_at(0, 0), 'X' as u32);
}

#[test]
fn control_char_mid_csi_executes_then_resumes() {
    let vc = run(10, 2, b"ab\x1b[1\r0mX");
    assert_eq!(vc.glyph_at(0, 0), 'X' as u32);
}

#[test]
fn can_aborts_sequence() {
    let vc = run(10, 2, b"\x1b[12\x18AB");
    assert_eq!(vc.glyph_at(0, 0), 'A' as u32);
    assert_eq!(vc.glyph_at(1, 0), 'B' as u32);
}

#[test]
fn sub_aborts_sequence() {
    let vc = run(10, 2, b"\x1b[3;3\x1aCD");
    assert_eq!(vc.glyph_at(0, 0), 'C' as u32);
    assert_eq!(vc.glyph_at(1, 0), 'D' as u32);
}

#[test]
fn primary_da_and_decid_reply_vt102_id() {
    let mut vc = Vc::new(10, 2);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, b"\x1b[c");
    assert_eq!(em.take_reply().as_slice(), b"\x1b[?6c");
    em.feed_bytes(&mut vc, b"\x1b[0c");
    assert_eq!(em.take_reply().as_slice(), b"\x1b[?6c");
    em.feed_bytes(&mut vc, b"\x1bZ");
    assert_eq!(em.take_reply().as_slice(), b"\x1b[?6c");
}

#[test]
fn secondary_da_not_answered() {
    let mut vc = Vc::new(10, 2);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, b"\x1b[>c");
    assert!(em.take_reply().is_empty());
}

#[test]
fn irm_insert_mode_shifts_line_right() {
    let mut vc = Vc::new(10, 2);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, b"ACE");
    em.feed_bytes(&mut vc, b"\x1b[1G");
    em.feed_bytes(&mut vc, b"\x1b[4h");
    em.feed_bytes(&mut vc, b"B");
    assert_eq!(vc.glyph_at(0, 0), 'B' as u32);
    assert_eq!(vc.glyph_at(1, 0), 'A' as u32);
    assert_eq!(vc.glyph_at(2, 0), 'C' as u32);
    em.feed_bytes(&mut vc, b"\x1b[4l");
    em.feed_bytes(&mut vc, b"X");
    assert_eq!(vc.glyph_at(1, 0), 'X' as u32);
}

#[test]
fn c1_csi_8bit_moves_cursor_like_esc_bracket() {
    let mut vc = Vc::new(10, 4);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, &[0x9b, b'2', b'B']);
    assert_eq!(vc.y, 2);
    em.feed_bytes(&mut vc, &[0x84]);
    assert_eq!(vc.y, 3);
}

#[test]
fn osc_title_with_backslash_not_terminated_early() {
    let mut vc = Vc::new(10, 2);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, b"\x1b]0;a\\b\x07Z");
    assert_eq!(vc.glyph_at(0, 0), 'Z' as u32);
    assert_eq!(em.state(), CsiState::Ground);
}

#[test]
fn dcs_payload_not_executed_as_commands() {
    let mut vc = Vc::new(10, 2);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, b"\x1bP1$r\x1b[31m\x1b\\Q");
    assert_eq!(vc.glyph_at(0, 0), 'Q' as u32);
    assert_eq!(vc.attr_at(0, 0).unwrap().fg, DEFAULT_FG_RGB);
}
