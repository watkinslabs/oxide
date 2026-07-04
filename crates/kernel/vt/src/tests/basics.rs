use crate::emulator::Emulator;
use crate::palette::{rgb, xterm_256_rgb};
use crate::vc::{Attr, Cell, Vc, DEFAULT_BG, DEFAULT_BG_RGB, DEFAULT_FG, DEFAULT_FG_RGB};
use proptest::prelude::*;

use super::{run, trimmed};

#[test]
fn plain_text() {
    let vc = run(20, 4, b"hello");
    assert_eq!(trimmed(&vc, 0), "hello");
    assert_eq!((vc.x, vc.y), (5, 0));
}

#[test]
fn cr_lf() {
    let vc = run(20, 4, b"abc\r\nxy");
    assert_eq!(trimmed(&vc, 0), "abc");
    assert_eq!(trimmed(&vc, 1), "xy");
    assert_eq!((vc.x, vc.y), (2, 1));
}

#[test]
fn bare_lf_keeps_column() {
    let vc = run(20, 4, b"abc\nx");
    assert_eq!((vc.x, vc.y), (4, 1));
    assert_eq!(vc.glyph_at(3, 1), 'x' as u32);
}

#[test]
fn backspace_moves_left_no_erase() {
    let vc = run(20, 4, b"abc\x08");
    assert_eq!((vc.x, vc.y), (2, 0));
    assert_eq!(vc.glyph_at(2, 0), 'c' as u32);
}

#[test]
fn backspace_overwrite() {
    let vc = run(20, 4, b"abc\x08 \x08");
    assert_eq!((vc.x, vc.y), (2, 0));
    assert_eq!(vc.glyph_at(2, 0), ' ' as u32);
}

#[test]
fn tab_stops() {
    let vc = run(40, 4, b"a\tb\tc");
    assert_eq!(vc.glyph_at(0, 0), 'a' as u32);
    assert_eq!(vc.glyph_at(8, 0), 'b' as u32);
    assert_eq!(vc.glyph_at(16, 0), 'c' as u32);
    assert_eq!(vc.x, 17);
}

#[test]
fn autowrap_at_right_margin() {
    let vc = run(5, 3, b"abcdef");
    assert_eq!(trimmed(&vc, 0), "abcde");
    assert_eq!(vc.glyph_at(0, 1), 'f' as u32);
    assert_eq!((vc.x, vc.y), (1, 1));
}

#[test]
fn no_autowrap_clamps() {
    let vc = run(5, 3, b"\x1b[?7labcdef");
    assert_eq!(vc.y, 0);
    assert_eq!(vc.x, 4);
    assert_eq!(vc.glyph_at(4, 0), 'f' as u32);
}

#[test]
fn lf_scroll_at_bottom() {
    let vc = run(10, 3, b"r0\r\nr1\r\nr2\r\nr3");
    assert_eq!(trimmed(&vc, 0), "r1");
    assert_eq!(trimmed(&vc, 1), "r2");
    assert_eq!(trimmed(&vc, 2), "r3");
    assert_eq!(vc.y, 2);
}

#[test]
fn cup_positions() {
    let vc = run(20, 10, b"\x1b[2;3HX");
    assert_eq!(vc.glyph_at(2, 1), 'X' as u32);
    assert_eq!((vc.x, vc.y), (3, 1));
}

#[test]
fn cup_default_is_home() {
    let vc = run(20, 10, b"abc\x1b[HZ");
    assert_eq!(vc.glyph_at(0, 0), 'Z' as u32);
}

#[test]
fn cursor_moves_cuf_cub_cuu_cud() {
    let vc = run(20, 10, b"\x1b[5C\x1b[2B\x1b[1A\x1b[2D*");
    assert_eq!(vc.glyph_at(3, 1), '*' as u32);
}

#[test]
fn cha_vpa() {
    let vc = run(20, 10, b"\x1b[10G\x1b[4d#");
    assert_eq!(vc.glyph_at(9, 3), '#' as u32);
}

#[test]
fn ed_clears_screen() {
    let mut vc = run(10, 3, b"abc\ndef\nghi");
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, b"\x1b[H\x1b[2J");
    assert_eq!(trimmed(&vc, 0), "");
    assert_eq!(trimmed(&vc, 1), "");
    assert_eq!(trimmed(&vc, 2), "");
    assert_eq!((vc.x, vc.y), (0, 0));
}

#[test]
fn ed_cursor_to_end() {
    let vc = run(6, 2, b"abcdef\x1b[1;4H\x1b[0J");
    assert_eq!(trimmed(&vc, 0), "abc");
}

#[test]
fn el_erase_line_modes() {
    let vc = run(10, 2, b"abcdefg\x1b[1;4H\x1b[0K");
    assert_eq!(trimmed(&vc, 0), "abc");
    let vc2 = run(10, 2, b"abcdefg\x1b[1;4H\x1b[1K");
    assert_eq!(vc2.glyph_at(0, 0), ' ' as u32);
    assert_eq!(vc2.glyph_at(3, 0), ' ' as u32);
    assert_eq!(vc2.glyph_at(4, 0), 'e' as u32);
    let vc3 = run(10, 2, b"abcdefg\x1b[2K");
    assert_eq!(trimmed(&vc3, 0), "");
}

#[test]
fn utf8_two_byte_decode() {
    let vc = run(20, 2, &[0xc3, 0xa9]);
    assert_eq!(vc.glyph_at(0, 0), 0xe9);
    assert_eq!(vc.x, 1);
}

#[test]
fn utf8_three_byte_decode() {
    let vc = run(20, 2, &[0xe2, 0x82, 0xac]);
    assert_eq!(vc.glyph_at(0, 0), 0x20ac);
}

#[test]
fn ich_dch_insert_delete_chars() {
    let vc = run(10, 2, b"abcdef\x1b[H\x1b[2@");
    assert_eq!(vc.glyph_at(0, 0), ' ' as u32);
    assert_eq!(vc.glyph_at(2, 0), 'a' as u32);
    let vc2 = run(10, 2, b"abcdef\x1b[H\x1b[2P");
    assert_eq!(vc2.glyph_at(0, 0), 'c' as u32);
}

#[test]
fn reverse_index_scrolls_at_top() {
    let vc = run(10, 3, b"row0\x1b[2;1Hrow1\x1b[H\x1bM");
    assert_eq!(trimmed(&vc, 1), "row0");
    assert_eq!(vc.y, 0);
}

#[test]
fn scroll_region_confines_lf() {
    let vc = run(10, 4, b"\x1b[2;3r\x1b[2;1HA\nB\nC");
    assert_eq!(trimmed(&vc, 0), "");
    assert_eq!(vc.scroll_top, 1);
    assert_eq!(vc.scroll_bot, 2);
}

#[test]
fn unknown_sequence_tolerated() {
    let vc = run(20, 2, b"\x1b[99ZAb");
    assert_eq!(vc.glyph_at(0, 0), 'A' as u32);
    assert_eq!(vc.glyph_at(1, 0), 'b' as u32);
}

#[test]
fn osc_title_swallowed() {
    let vc = run(20, 2, b"\x1b]0;my title\x07ok");
    assert_eq!(trimmed(&vc, 0), "ok");
}

#[test]
fn full_reset_clears() {
    let vc = run(10, 3, b"junk\x1b[31m\x1bcZ");
    assert_eq!(vc.glyph_at(0, 0), 'Z' as u32);
    assert_eq!(vc.attr_at(0, 0).unwrap().fg, DEFAULT_FG_RGB);
    assert!(vc.autowrap);
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 4000, ..ProptestConfig::default() })]

    #[test]
    fn fuzz_no_panic_cursor_in_bounds(
        cols in 1u16..40,
        rows in 1u16..20,
        bytes in proptest::collection::vec(any::<u8>(), 0..2000),
    ) {
        let mut vc = Vc::new(cols, rows);
        let mut em = Emulator::new();
        for &b in &bytes {
            em.feed(&mut vc, b);
            prop_assert!(vc.x < vc.cols, "x {} >= cols {}", vc.x, vc.cols);
            prop_assert!(vc.y < vc.rows, "y {} >= rows {}", vc.y, vc.rows);
            prop_assert!(vc.scroll_top <= vc.scroll_bot);
            prop_assert!(vc.scroll_bot < vc.rows);
        }
        for r in 0..vc.rows {
            for c in 0..vc.cols {
                prop_assert!(vc.cell_at(c, r).is_some());
            }
        }
    }
}

#[test]
fn default_attr_resolves_to_canonical_rgb() {
    let a = Attr::default();
    assert_eq!(a.fg, DEFAULT_FG_RGB);
    assert_eq!(a.bg, DEFAULT_BG_RGB);
    assert_eq!(a.fg, xterm_256_rgb(DEFAULT_FG as u32));
    assert_eq!(a.bg, xterm_256_rgb(DEFAULT_BG as u32));
}

#[test]
fn cell_roundtrips_attr_rgb_and_flags() {
    let a = Attr {
        fg: 0x123456,
        bg: 0xabcdef,
        bold: true,
        underline: false,
        reverse: true,
        ..Attr::default()
    };
    let c = Cell::glyph('Q' as u32, a);
    assert_eq!(c.glyph, 'Q' as u32);
    assert_eq!(c.fg, 0x123456);
    assert_eq!(c.bg, 0xabcdef);
    assert_eq!(Attr::from_cell(c), a);
}
