use crate::emulator::Emulator;
use crate::vc::{Charset, Vc, DEFAULT_FG_RGB};

use super::{run, trimmed};

#[test]
fn decsc_decrc_saves_position_attr_charset_origin() {
    let mut vc = Vc::new(20, 10);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, b"\x1b[?6h\x1b[31m\x1b(0\x1b[3;5H\x1b7");
    em.feed_bytes(&mut vc, b"\x1b[?6l\x1b[0m\x1b(B\x1b[1;1H");
    assert!(!vc.origin_mode);
    assert_eq!(vc.g0, Charset::Ascii);
    em.feed_bytes(&mut vc, b"\x1b8");
    assert!(vc.origin_mode);
    assert_eq!(vc.g0, Charset::DecSpecial);
    assert_eq!(vc.attr.fg, crate::palette::xterm_256_rgb(1));
    assert_eq!((vc.x, vc.y), (4, 2));
}

#[test]
fn decsc_saves_gl_selector() {
    let mut vc = Vc::new(20, 5);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, b"\x0e\x1b7\x0f\x1b8");
    assert_eq!(vc.gl, 1);
}

#[test]
fn decrc_without_decsc_restores_defaults() {
    let vc = run(20, 5, b"\x1b[5;5H\x1b[31m\x1b8X");
    assert_eq!((vc.x, vc.y), (1, 0));
    assert_eq!(vc.attr.fg, DEFAULT_FG_RGB);
}

#[test]
fn decom_cup_relative_to_region() {
    let vc = run(20, 10, b"\x1b[3;6r\x1b[?6h\x1b[1;1HX");
    assert_eq!(vc.glyph_at(0, 2), 'X' as u32);
}

#[test]
fn decom_cup_clamped_to_region_bottom() {
    let vc = run(20, 10, b"\x1b[3;6r\x1b[?6h\x1b[99;1HY");
    assert_eq!(vc.glyph_at(0, 5), 'Y' as u32);
}

#[test]
fn decom_off_is_absolute() {
    let vc = run(20, 10, b"\x1b[3;6r\x1b[?6l\x1b[1;1HZ");
    assert_eq!(vc.glyph_at(0, 0), 'Z' as u32);
}

#[test]
fn decom_toggle_homes_cursor() {
    let vc = run(20, 10, b"\x1b[4;8r\x1b[?6h");
    assert_eq!((vc.x, vc.y), (0, 3));
}

#[test]
fn pending_wrap_exactly_cols_chars() {
    let vc = run(5, 3, b"abcde");
    assert_eq!((vc.x, vc.y), (4, 0));
    assert!(vc.wrap_pending);
    assert_eq!(trimmed(&vc, 0), "abcde");
}

#[test]
fn pending_wrap_next_char_wraps() {
    let vc = run(5, 3, b"abcdef");
    assert_eq!(trimmed(&vc, 0), "abcde");
    assert_eq!(vc.glyph_at(0, 1), 'f' as u32);
    assert_eq!((vc.x, vc.y), (1, 1));
    assert!(!vc.wrap_pending);
}

#[test]
fn cr_clears_pending_wrap_without_wrapping() {
    let vc = run(5, 2, b"abcde\rX");
    assert_eq!(vc.glyph_at(0, 0), 'X' as u32);
    assert_eq!(trimmed(&vc, 1), "");
    assert_eq!((vc.x, vc.y), (1, 0));
}

#[test]
fn cursor_move_clears_pending_wrap() {
    let vc = run(5, 2, b"abcde\x1b[1DX");
    assert!(!vc.wrap_pending);
    assert_eq!(vc.glyph_at(3, 0), 'X' as u32);
    assert_eq!(trimmed(&vc, 1), "");
}

#[test]
fn no_autowrap_no_latch() {
    let vc = run(5, 3, b"\x1b[?7labcdef");
    assert_eq!((vc.x, vc.y), (4, 0));
    assert!(!vc.wrap_pending);
    assert_eq!(vc.glyph_at(4, 0), 'f' as u32);
}

#[test]
fn vttest_cursor_movement_pattern() {
    let vc = run(10, 10, b"\x1b[3;3H*\x1b[3;3H\x1b[1A^\x1b[3;3H\x1b[1Bv\x1b[3;3H\x1b[1D<\x1b[3;3H\x1b[1C>");
    assert_eq!(vc.glyph_at(2, 2), '*' as u32);
    assert_eq!(vc.glyph_at(2, 1), '^' as u32);
    assert_eq!(vc.glyph_at(2, 3), 'v' as u32);
    assert_eq!(vc.glyph_at(1, 2), '<' as u32);
    assert_eq!(vc.glyph_at(3, 2), '>' as u32);
}
