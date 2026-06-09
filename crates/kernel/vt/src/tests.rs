// Golden emulator tests + fuzz. Feed a byte stream, assert the resulting
// `Vc` grid (rows as strings), cursor position, and attrs. Plus a
// proptest invariant suite: never panic, cursor always in bounds, no OOB.

use crate::emulator::Emulator;
use crate::vc::{Attr, Vc, DEFAULT_BG, DEFAULT_FG};
use proptest::prelude::*;

/// Build a Vc, feed bytes, return it.
fn run(cols: u16, rows: u16, bytes: &[u8]) -> Vc {
    let mut vc = Vc::new(cols, rows);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, bytes);
    vc
}

fn trimmed(vc: &Vc, row: u16) -> alloc::string::String {
    let s = vc.row_string(row);
    s.trim_end().into()
}

#[test]
fn plain_text() {
    let vc = run(20, 4, b"hello");
    assert_eq!(trimmed(&vc, 0), "hello");
    assert_eq!((vc.x, vc.y), (5, 0));
}

#[test]
fn cr_lf() {
    // \r\n: CR to col 0, LF down one row.
    let vc = run(20, 4, b"abc\r\nxy");
    assert_eq!(trimmed(&vc, 0), "abc");
    assert_eq!(trimmed(&vc, 1), "xy");
    assert_eq!((vc.x, vc.y), (2, 1));
}

#[test]
fn bare_lf_keeps_column() {
    // Raw LF moves down only (cooking is the ldisc's job).
    let vc = run(20, 4, b"abc\nx");
    assert_eq!((vc.x, vc.y), (4, 1));
    assert_eq!(vc.glyph_at(3, 1), 'x' as u32);
}

#[test]
fn backspace_moves_left_no_erase() {
    let vc = run(20, 4, b"abc\x08");
    // BS moves left; glyph 'c' still present (terminal BS is non-destructive).
    assert_eq!((vc.x, vc.y), (2, 0));
    assert_eq!(vc.glyph_at(2, 0), 'c' as u32);
}

#[test]
fn backspace_overwrite() {
    // BS then space then BS = destructive erase as a tty would emit.
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
    // 5 cols: "abcde" fills the row; "f" wraps to next row col 0.
    let vc = run(5, 3, b"abcdef");
    assert_eq!(trimmed(&vc, 0), "abcde");
    assert_eq!(vc.glyph_at(0, 1), 'f' as u32);
    assert_eq!((vc.x, vc.y), (1, 1));
}

#[test]
fn no_autowrap_clamps() {
    // DECAWM off (?7l): glyphs pile in the last column.
    let vc = run(5, 3, b"\x1b[?7labcdef");
    assert_eq!(vc.y, 0);
    assert_eq!(vc.x, 4);
    assert_eq!(vc.glyph_at(4, 0), 'f' as u32);
}

#[test]
fn lf_scroll_at_bottom() {
    // 3 rows; print row0..row2 then LF scrolls row1 up to row0.
    // Use \r\n so each label starts at col 0.
    let vc = run(10, 3, b"r0\r\nr1\r\nr2\r\nr3");
    assert_eq!(trimmed(&vc, 0), "r1");
    assert_eq!(trimmed(&vc, 1), "r2");
    assert_eq!(trimmed(&vc, 2), "r3");
    assert_eq!(vc.y, 2);
}

#[test]
fn cup_positions() {
    // CSI 2;3 H → row 2, col 3 (1-based) = (y=1,x=2).
    let vc = run(20, 10, b"\x1b[2;3HX");
    assert_eq!(vc.glyph_at(2, 1), 'X' as u32);
    // after printing X, cursor advanced to col 3.
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
    // right 5 → x=5; down 2 → y=2; up 1 → y=1; left 2 → x=3
    assert_eq!(vc.glyph_at(3, 1), '*' as u32);
}

#[test]
fn cha_vpa() {
    // CHA col 10, VPA row 4, then mark.
    let vc = run(20, 10, b"\x1b[10G\x1b[4d#");
    assert_eq!(vc.glyph_at(9, 3), '#' as u32);
}

#[test]
fn ed_clears_screen() {
    let mut vc = run(10, 3, b"abc\ndef\nghi");
    let mut em = Emulator::new();
    // home then ED 2 (whole screen).
    em.feed_bytes(&mut vc, b"\x1b[H\x1b[2J");
    assert_eq!(trimmed(&vc, 0), "");
    assert_eq!(trimmed(&vc, 1), "");
    assert_eq!(trimmed(&vc, 2), "");
    assert_eq!((vc.x, vc.y), (0, 0));
}

#[test]
fn ed_cursor_to_end() {
    // "abcdef" on a 6-col row; position at col3, ED 0 clears col3..end.
    let vc = run(6, 2, b"abcdef\x1b[1;4H\x1b[0J");
    assert_eq!(trimmed(&vc, 0), "abc");
}

#[test]
fn el_erase_line_modes() {
    // EL 0: cursor to eol.
    let vc = run(10, 2, b"abcdefg\x1b[1;4H\x1b[0K");
    assert_eq!(trimmed(&vc, 0), "abc");
    // EL 1: bol to cursor.
    let vc2 = run(10, 2, b"abcdefg\x1b[1;4H\x1b[1K");
    assert_eq!(vc2.glyph_at(0, 0), ' ' as u32);
    assert_eq!(vc2.glyph_at(3, 0), ' ' as u32);
    assert_eq!(vc2.glyph_at(4, 0), 'e' as u32);
    // EL 2: whole line.
    let vc3 = run(10, 2, b"abcdefg\x1b[2K");
    assert_eq!(trimmed(&vc3, 0), "");
}

#[test]
fn sgr_sets_color_attr() {
    // SGR 31 (red fg) then 'A'; SGR 0 reset then 'B'.
    let vc = run(20, 2, b"\x1b[31mA\x1b[0mB");
    let a = vc.attr_at(0, 0).unwrap();
    assert_eq!(a.fg, 1); // red index
    let b = vc.attr_at(1, 0).unwrap();
    assert_eq!(b.fg, DEFAULT_FG);
}

#[test]
fn sgr_bright_and_bg() {
    // 91 = bright red fg (index 9), 42 = green bg (index 2).
    let mut vc = Vc::new(20, 2);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, b"\x1b[91;42mX");
    let a = vc.attr_at(0, 0).unwrap();
    assert_eq!(a.fg, 9);
    assert_eq!(a.bg, 2);
    // live attr also carries flags
    em.feed_bytes(&mut vc, b"\x1b[1mY");
    assert!(vc.attr.bold);
}

#[test]
fn sgr_256_color() {
    let mut vc = Vc::new(20, 2);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, b"\x1b[38;5;200mZ");
    assert_eq!(vc.attr_at(0, 0).unwrap().fg, 200);
}

#[test]
fn decsc_decrc_save_restore() {
    // Move, ESC 7 (save), move away, ESC 8 (restore), mark.
    let vc = run(20, 5, b"\x1b[3;5H\x1b7\x1b[1;1H\x1b8*");
    assert_eq!(vc.glyph_at(4, 2), '*' as u32);
}

#[test]
fn csi_s_u_save_restore() {
    let vc = run(20, 5, b"\x1b[3;5H\x1b[s\x1b[1;1H\x1b[u*");
    assert_eq!(vc.glyph_at(4, 2), '*' as u32);
}

#[test]
fn decsc_restores_attr() {
    let mut vc = Vc::new(20, 2);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, b"\x1b[31m\x1b7\x1b[0m\x1b8X");
    // restored attr was red.
    assert_eq!(vc.attr_at(0, 0).unwrap().fg, 1);
    let _ = DEFAULT_BG;
}

#[test]
fn utf8_two_byte_decode() {
    // 'é' = U+00E9 = 0xC3 0xA9.
    let vc = run(20, 2, &[0xc3, 0xa9]);
    assert_eq!(vc.glyph_at(0, 0), 0xe9);
    assert_eq!(vc.x, 1);
}

#[test]
fn utf8_three_byte_decode() {
    // '€' = U+20AC = 0xE2 0x82 0xAC.
    let vc = run(20, 2, &[0xe2, 0x82, 0xac]);
    assert_eq!(vc.glyph_at(0, 0), 0x20ac);
}

#[test]
fn ich_dch_insert_delete_chars() {
    // "abcdef", home, insert 2 blanks at col0.
    let vc = run(10, 2, b"abcdef\x1b[H\x1b[2@");
    assert_eq!(vc.glyph_at(0, 0), ' ' as u32);
    assert_eq!(vc.glyph_at(2, 0), 'a' as u32);
    // delete 2 chars at home.
    let vc2 = run(10, 2, b"abcdef\x1b[H\x1b[2P");
    assert_eq!(vc2.glyph_at(0, 0), 'c' as u32);
}

#[test]
fn reverse_index_scrolls_at_top() {
    // At top row, RI scrolls content down.
    let vc = run(10, 3, b"row0\x1b[2;1Hrow1\x1b[H\x1bM");
    // row0 pushed to row1.
    assert_eq!(trimmed(&vc, 1), "row0");
    assert_eq!(vc.y, 0);
}

#[test]
fn scroll_region_confines_lf() {
    // Set region rows 1..2 (1-based 2;3 on a 4-row screen → top=1,bot=2).
    let vc = run(10, 4, b"\x1b[2;3r\x1b[2;1HA\nB\nC");
    // row0 untouched (blank), scrolling happened within rows 1..2.
    assert_eq!(trimmed(&vc, 0), "");
    assert_eq!(vc.scroll_top, 1);
    assert_eq!(vc.scroll_bot, 2);
}

#[test]
fn unknown_sequence_tolerated() {
    // Bogus CSI final (CSI 99 Z — unknown final, swallowed) then prints
    // resume; must not panic.
    let vc = run(20, 2, b"\x1b[99ZAb");
    assert_eq!(vc.glyph_at(0, 0), 'A' as u32);
    assert_eq!(vc.glyph_at(1, 0), 'b' as u32);
}

#[test]
fn osc_title_swallowed() {
    // OSC set-title terminated by BEL — no glyphs land.
    let vc = run(20, 2, b"\x1b]0;my title\x07ok");
    assert_eq!(trimmed(&vc, 0), "ok");
}

#[test]
fn full_reset_clears() {
    let vc = run(10, 3, b"junk\x1b[31m\x1bcZ");
    assert_eq!(vc.glyph_at(0, 0), 'Z' as u32);
    assert_eq!(vc.attr_at(0, 0).unwrap().fg, DEFAULT_FG);
    assert!(vc.autowrap);
}

#[test]
fn per_cell_flags_survive_bold_underline_reverse() {
    // SGR 1;4;7;33;44 → bold+underline+reverse, yellow fg, blue bg on 'A'.
    // SGR 0 reset then 'B' carries no flags and default colors.
    let vc = run(20, 2, b"\x1b[1;4;7;33;44mA\x1b[0mB");
    let a = vc.attr_at(0, 0).unwrap();
    assert!(a.bold, "bold must round-trip into the cell");
    assert!(a.underline, "underline must round-trip into the cell");
    assert!(a.reverse, "reverse must round-trip into the cell");
    assert_eq!(a.fg, 3); // yellow
    assert_eq!(a.bg, 4); // blue
    let b = vc.attr_at(1, 0).unwrap();
    assert!(!b.bold && !b.underline && !b.reverse);
    assert_eq!(b.fg, DEFAULT_FG);
    assert_eq!(b.bg, DEFAULT_BG);
}

#[test]
fn per_cell_flags_toggle_off_midline() {
    // Underline on for 'X', off (SGR 24) for 'Y'; reverse stays off both.
    let vc = run(20, 2, b"\x1b[4mX\x1b[24mY");
    let x = vc.attr_at(0, 0).unwrap();
    let y = vc.attr_at(1, 0).unwrap();
    assert!(x.underline && !x.reverse);
    assert!(!y.underline && !y.reverse);
}

#[test]
fn attr_pack_unpack_lossless_with_flags() {
    let a = Attr { fg: 200, bg: 17, bold: true, underline: false, reverse: true };
    assert_eq!(Attr::unpack(a.pack()), a);
}

#[test]
fn default_attr_pack_roundtrip() {
    let a = Attr::default();
    assert_eq!(a.fg, DEFAULT_FG);
    assert_eq!(a.bg, DEFAULT_BG);
    let p = a.pack();
    assert_eq!((p & 0xff) as u8, DEFAULT_FG);
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 4000, ..ProptestConfig::default() })]

    /// Feeding arbitrary byte streams never panics, never moves the
    /// cursor out of bounds, and never indexes the grid OOB (the latter
    /// guaranteed by cell_at's bounds check returning None — assert all
    /// in-range reads succeed and out-of-range read as blank).
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
        // Full-grid read must succeed for every in-range cell.
        for r in 0..vc.rows {
            for c in 0..vc.cols {
                prop_assert!(vc.cell_at(c, r).is_some());
            }
        }
    }
}
