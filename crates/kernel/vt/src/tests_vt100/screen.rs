use crate::emulator::Emulator;
use crate::vc::Vc;

use super::{run, trimmed};

#[test]
fn ind_scrolls_only_region_at_bottom() {
    let vc = run(10, 4, b"top\x1b[2;3r\x1b[2;1HA\x1b[3;1HB\x1bDC");
    assert_eq!(trimmed(&vc, 0), "top");
    assert_eq!(trimmed(&vc, 1), "B");
    assert_eq!(vc.glyph_at(1, 2), 'C' as u32);
}

#[test]
fn ri_scrolls_only_region_at_top() {
    let vc = run(10, 4, b"top\x1b[2;3r\x1b[2;1HA\x1b[3;1HB\x1b[2;1H\x1bM");
    assert_eq!(trimmed(&vc, 0), "top");
    assert_eq!(trimmed(&vc, 1), "");
    assert_eq!(trimmed(&vc, 2), "A");
}

#[test]
fn nel_at_region_bottom_scrolls_region() {
    let vc = run(10, 4, b"top\x1b[2;3r\x1b[3;5HX\x1bE");
    assert_eq!(trimmed(&vc, 0), "top");
    assert_eq!((vc.x, vc.y), (0, 2));
}

#[test]
fn cup_without_origin_can_address_outside_region() {
    let vc = run(10, 6, b"\x1b[2;3r\x1b[5;1HX");
    assert_eq!(vc.glyph_at(0, 4), 'X' as u32);
}

#[test]
fn ed_modes_0_1_2() {
    let vc = run(4, 3, b"abcdABCDwxyz\x1b[2;3H\x1b[0J");
    assert_eq!(trimmed(&vc, 0), "abcd");
    assert_eq!(trimmed(&vc, 1), "AB");
    assert_eq!(trimmed(&vc, 2), "");
    let vc1 = run(4, 3, b"abcdABCDwxyz\x1b[2;3H\x1b[1J");
    assert_eq!(trimmed(&vc1, 0), "");
    assert_eq!(vc1.glyph_at(3, 1), 'D' as u32);
    let vc2 = run(4, 3, b"abcdABCDwxyz\x1b[2J");
    for r in 0..3 {
        assert_eq!(trimmed(&vc2, r), "");
    }
}

#[test]
fn ed_3_clears_scrollback() {
    let mut vc = run(4, 2, b"r0\r\nr1\r\nr2\r\nr3");
    assert!(vc.history_len() > 0);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, b"\x1b[3J");
    assert_eq!(vc.history_len(), 0);
}

#[test]
fn el_modes_0_1_2() {
    let vc = run(10, 2, b"abcdefg\x1b[1;4H\x1b[0K");
    assert_eq!(trimmed(&vc, 0), "abc");
    let vc1 = run(10, 2, b"abcdefg\x1b[1;4H\x1b[1K");
    assert_eq!(vc1.glyph_at(0, 0), ' ' as u32);
    assert_eq!(vc1.glyph_at(3, 0), ' ' as u32);
    assert_eq!(vc1.glyph_at(4, 0), 'e' as u32);
    let vc2 = run(10, 2, b"abcdefg\x1b[2K");
    assert_eq!(trimmed(&vc2, 0), "");
}

#[test]
fn erase_uses_current_bg() {
    let vc = run(10, 2, b"abc\x1b[44m\x1b[2K");
    let a = vc.attr_at(5, 0).unwrap();
    assert_eq!(a.bg, crate::palette::xterm_256_rgb(4));
}

#[test]
fn ind_is_lf_without_cr() {
    let vc = run(20, 4, b"abc\x1bDx");
    assert_eq!((vc.x, vc.y), (4, 1));
    assert_eq!(vc.glyph_at(3, 1), 'x' as u32);
}

#[test]
fn ri_moves_up() {
    let vc = run(20, 4, b"\x1b[3;5H\x1bMx");
    assert_eq!(vc.y, 1);
    assert_eq!(vc.x, 5);
}

#[test]
fn nel_is_cr_lf() {
    let vc = run(20, 4, b"abc\x1bEx");
    assert_eq!((vc.x, vc.y), (1, 1));
    assert_eq!(vc.glyph_at(0, 1), 'x' as u32);
}

#[test]
fn vttest_origin_mode_scroll() {
    let mut vc = Vc::new(8, 5);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, b"\x1b[1;1Htop\x1b[5;1Hbot");
    em.feed_bytes(&mut vc, b"\x1b[2;4r\x1b[?6h");
    em.feed_bytes(&mut vc, b"\x1b[1;1HA\r\nB\r\nC\r\nD");
    assert_eq!(trimmed(&vc, 0), "top");
    assert_eq!(trimmed(&vc, 4), "bot");
    assert_eq!(trimmed(&vc, 1), "B");
    assert_eq!(trimmed(&vc, 2), "C");
    assert_eq!(trimmed(&vc, 3), "D");
}

#[test]
fn vttest_wrap_then_scroll() {
    let vc = run(3, 2, b"abcde");
    assert_eq!(trimmed(&vc, 0), "abc");
    assert_eq!(trimmed(&vc, 1), "de");
    let vc2 = run(3, 2, b"abcdefg");
    assert_eq!(trimmed(&vc2, 0), "def");
    assert_eq!(vc2.glyph_at(0, 1), 'g' as u32);
}

#[test]
fn alt_screen_saves_and_restores_main() {
    let mut vc = Vc::new(20, 5);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, b"MAIN");
    em.feed_bytes(&mut vc, b"\x1b[?1049h");
    assert_eq!(vc.glyph_at(0, 0), ' ' as u32);
    em.feed_bytes(&mut vc, b"ALT");
    assert_eq!(vc.glyph_at(0, 0), 'A' as u32);
    em.feed_bytes(&mut vc, b"\x1b[?1049l");
    assert_eq!(vc.glyph_at(0, 0), 'M' as u32);
    assert_eq!(vc.glyph_at(3, 0), 'N' as u32);
}

#[test]
fn ech_erases_n_chars_without_moving_cursor() {
    let mut vc = Vc::new(20, 2);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, b"ABCDEF");
    em.feed_bytes(&mut vc, b"\x1b[1G");
    em.feed_bytes(&mut vc, b"\x1b[3X");
    assert_eq!(vc.glyph_at(0, 0), ' ' as u32);
    assert_eq!(vc.glyph_at(2, 0), ' ' as u32);
    assert_eq!(vc.glyph_at(3, 0), 'D' as u32);
}

#[test]
fn osc4_redefines_palette_index_for_future_glyphs() {
    let mut vc = Vc::new(10, 2);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, b"\x1b]4;1;rgb:00/ff/00\x07");
    em.feed_bytes(&mut vc, b"\x1b[31mX");
    assert_eq!(vc.attr_at(0, 0).unwrap().fg, 0x00ff00);
}

#[test]
fn osc4_hash_form_and_st_terminator() {
    let mut vc = Vc::new(10, 2);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, b"\x1b]4;2;#0000ff\x1b\\");
    em.feed_bytes(&mut vc, b"\x1b[32mX");
    assert_eq!(vc.attr_at(0, 0).unwrap().fg, 0x0000ff);
}

#[test]
fn osc104_resets_palette() {
    let mut vc = Vc::new(10, 2);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, b"\x1b]4;1;rgb:00/ff/00\x07");
    em.feed_bytes(&mut vc, b"\x1b]104;1\x07");
    em.feed_bytes(&mut vc, b"\x1b[31mX");
    assert_eq!(vc.attr_at(0, 0).unwrap().fg, crate::palette::xterm_256_rgb(1));
}

#[test]
fn osc10_11_set_defaults_and_sgr_39_49_use_them() {
    let mut vc = Vc::new(10, 2);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, b"\x1b]10;rgb:11/22/33\x07");
    em.feed_bytes(&mut vc, b"\x1b]11;#445566\x07");
    em.feed_bytes(&mut vc, b"\x1b[39;49mX");
    assert_eq!(vc.attr_at(0, 0).unwrap().fg, 0x112233);
    assert_eq!(vc.attr_at(0, 0).unwrap().bg, 0x445566);
    em.feed_bytes(&mut vc, b"\x1b[0mY");
    assert_eq!(vc.attr_at(1, 0).unwrap().fg, 0x112233);
}

#[test]
fn decckm_mode_tracks_set_reset() {
    let mut vc = Vc::new(10, 2);
    let mut em = Emulator::new();
    assert!(!em.app_cursor());
    em.feed_bytes(&mut vc, b"\x1b[?1h");
    assert!(em.app_cursor());
    em.feed_bytes(&mut vc, b"\x1b[?1l");
    assert!(!em.app_cursor());
}

#[test]
fn bracketed_paste_mode_tracks_set_reset() {
    let mut vc = Vc::new(10, 2);
    let mut em = Emulator::new();
    assert!(!em.bracketed_paste());
    em.feed_bytes(&mut vc, b"\x1b[?2004h");
    assert!(em.bracketed_paste());
    em.feed_bytes(&mut vc, b"\x1b[?2004l");
    assert!(!em.bracketed_paste());
}
