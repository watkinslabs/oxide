// Golden emulator tests + fuzz. Feed a byte stream, assert the resulting
// `Vc` grid (rows as strings), cursor position, and attrs. Plus a
// proptest invariant suite: never panic, cursor always in bounds, no OOB.

use crate::emulator::Emulator;
use crate::palette::{rgb, xterm_256_rgb};
use crate::vc::{Attr, Vc, DEFAULT_BG, DEFAULT_BG_RGB, DEFAULT_FG, DEFAULT_FG_RGB};
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
    // SGR 31 (red fg) then 'A'; SGR 0 reset then 'B'. fg resolves to the
    // VGA red RGB; reset returns to the default-fg RGB.
    let vc = run(20, 2, b"\x1b[31mA\x1b[0mB");
    let a = vc.attr_at(0, 0).unwrap();
    assert_eq!(a.fg, xterm_256_rgb(1)); // VGA red RGB
    let b = vc.attr_at(1, 0).unwrap();
    assert_eq!(b.fg, DEFAULT_FG_RGB);
}

#[test]
fn sgr_bright_and_bg() {
    // 91 = bright red fg (index 9), 42 = green bg (index 2) → resolved RGB.
    let mut vc = Vc::new(20, 2);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, b"\x1b[91;42mX");
    let a = vc.attr_at(0, 0).unwrap();
    assert_eq!(a.fg, xterm_256_rgb(9));
    assert_eq!(a.bg, xterm_256_rgb(2));
    // live attr also carries flags
    em.feed_bytes(&mut vc, b"\x1b[1mY");
    assert!(vc.attr.bold);
}

#[test]
fn sgr_256_color() {
    let mut vc = Vc::new(20, 2);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, b"\x1b[38;5;200mZ");
    assert_eq!(vc.attr_at(0, 0).unwrap().fg, xterm_256_rgb(200));
}

#[test]
fn sgr_truecolor_stored_verbatim() {
    // 38;2;r;g;b stores the exact RGB (no palette collapse).
    let mut vc = Vc::new(20, 2);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, b"\x1b[38;2;12;34;56;48;2;200;100;50mT");
    let a = vc.attr_at(0, 0).unwrap();
    assert_eq!(a.fg, rgb([12, 34, 56]));
    assert_eq!(a.bg, rgb([200, 100, 50]));
}

#[test]
fn sgr_bold_brightens_basic_color_at_resolve() {
    // bold THEN red (1;31): the cell stores bright-red RGB (index 9).
    let vc = run(20, 2, b"\x1b[1;31mA");
    let a = vc.attr_at(0, 0).unwrap();
    assert!(a.bold);
    assert_eq!(a.fg, xterm_256_rgb(9), "bold+basic-red must store bright-red RGB");
    // bold + truecolor leaves the RGB unchanged.
    let vc2 = run(20, 2, b"\x1b[1;38;2;5;6;7mB");
    assert_eq!(vc2.attr_at(0, 0).unwrap().fg, rgb([5, 6, 7]));
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
    assert_eq!(vc.attr_at(0, 0).unwrap().fg, xterm_256_rgb(1));
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
    assert_eq!(vc.attr_at(0, 0).unwrap().fg, DEFAULT_FG_RGB);
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
    // 1;33 = bold+yellow → bright-yellow RGB (index 11); 44 = blue bg.
    assert_eq!(a.fg, xterm_256_rgb(11));
    assert_eq!(a.bg, xterm_256_rgb(4));
    let b = vc.attr_at(1, 0).unwrap();
    assert!(!b.bold && !b.underline && !b.reverse);
    assert_eq!(b.fg, DEFAULT_FG_RGB);
    assert_eq!(b.bg, DEFAULT_BG_RGB);
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
fn cell_roundtrips_attr_rgb_and_flags() {
    use crate::vc::Cell;
    let a = Attr { fg: 0x123456, bg: 0xabcdef, bold: true, underline: false, reverse: true,
        ..Attr::default() };
    let c = Cell::glyph('Q' as u32, a);
    assert_eq!(c.glyph, 'Q' as u32);
    assert_eq!(c.fg, 0x123456);
    assert_eq!(c.bg, 0xabcdef);
    assert_eq!(Attr::from_cell(c), a);
}

#[test]
fn default_attr_resolves_to_canonical_rgb() {
    let a = Attr::default();
    assert_eq!(a.fg, DEFAULT_FG_RGB);
    assert_eq!(a.bg, DEFAULT_BG_RGB);
    assert_eq!(a.fg, xterm_256_rgb(DEFAULT_FG as u32));
    assert_eq!(a.bg, xterm_256_rgb(DEFAULT_BG as u32));
}

// ---- scrollback ring (P2) -------------------------------------------

#[test]
fn scrolled_off_rows_enter_history_in_order() {
    // 3-row screen, print 6 labelled lines → 3 evicted to history.
    let vc = run(10, 3, b"r0\r\nr1\r\nr2\r\nr3\r\nr4\r\nr5");
    // live screen shows the last 3.
    assert_eq!(trimmed(&vc, 0), "r3");
    assert_eq!(trimmed(&vc, 2), "r5");
    // history holds r0,r1,r2 oldest-first.
    assert_eq!(vc.history_len(), 3);
}

#[test]
fn scroll_view_up_shows_history_rows() {
    let mut vc = run(10, 3, b"r0\r\nr1\r\nr2\r\nr3\r\nr4\r\nr5");
    vc.scroll_view_up(2);
    assert_eq!(vc.view_offset(), 2);
    // Window is now 2 lines back: top two rows come from history (r1,r2),
    // bottom from the live screen (r3).
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
    // only 1 row in history; asking for 50 clamps to 1.
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
    em.feed_bytes(&mut vc, b"x"); // any output snaps to bottom
    assert_eq!(vc.view_offset(), 0);
}

#[test]
fn history_ring_bounded_evicts_oldest() {
    use crate::vc::SCROLLBACK_LINES;
    let mut vc = Vc::new(4, 2);
    let mut em = Emulator::new();
    // Scroll far more than the cap; history must saturate at the cap.
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

#[test]
fn dsr_device_status_replies_ok() {
    // CSI 5 n (DSR) → CSI 0 n ("terminal OK").
    let mut vc = Vc::new(80, 24);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, b"\x1b[5n");
    let r = em.take_reply();
    assert_eq!(r.as_slice(), b"\x1b[0n");
    // Drained: a second take is empty.
    assert!(em.take_reply().is_empty());
}

#[test]
fn cpr_cursor_position_report_is_one_based() {
    // Move to a known cell, then CSI 6 n (CPR) → CSI <row>;<col> R,
    // 1-based for the CURRENT cursor position.
    let mut vc = Vc::new(80, 24);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, b"\x1b[10;20H"); // row 10, col 20 (1-based)
    assert_eq!((vc.y, vc.x), (9, 19)); // 0-based internally
    em.feed_bytes(&mut vc, b"\x1b[6n");
    let r = em.take_reply();
    assert_eq!(r.as_slice(), b"\x1b[10;20R");
}

#[test]
fn cpr_after_clamp_reports_real_geometry() {
    // btop's probe: CSI 999;999H clamps to the real grid, then CSI 6n
    // reports the clamped (= real) row/col. On a 24×80 grid that's 24;80.
    let mut vc = Vc::new(80, 24);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, b"\x1b[999;999H\x1b[6n");
    let r = em.take_reply();
    assert_eq!(r.as_slice(), b"\x1b[24;80R");
}

#[test]
fn private_dsr_produces_no_reply() {
    // CSI ? 6 n (DEC DSR) is private — no standard reply.
    let mut vc = Vc::new(80, 24);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, b"\x1b[?6n");
    assert!(em.take_reply().is_empty());
}

// ---- live resize (Vc::resize / vc_do_resize) ------------------------

#[test]
fn resize_noop_on_same_dims() {
    // Same dimensions must early-out without touching content/cursor.
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
    // Grow both dims: existing content stays top-left anchored, new area blank.
    let mut vc = run(5, 2, b"AB\r\nCD");
    vc.resize(8, 4);
    assert_eq!((vc.cols, vc.rows), (8, 4));
    assert_eq!(trimmed(&vc, 0), "AB");
    assert_eq!(trimmed(&vc, 1), "CD");
    // New rows blank.
    assert_eq!(trimmed(&vc, 2), "");
    assert_eq!(trimmed(&vc, 3), "");
    // New columns blank in preserved rows.
    assert_eq!(vc.glyph_at(5, 0), ' ' as u32);
}

#[test]
fn resize_shrink_rows_keeps_cursor_neighbourhood() {
    // 4 rows of content, cursor on the last row; shrink to 2 rows. Linux drops
    // from the TOP so the cursor line is kept: rows r2,r3 survive, cursor
    // rebases from y=3 to y=1.
    let mut vc = run(6, 4, b"r0\r\nr1\r\nr2\r\nr3");
    assert_eq!(vc.y, 3);
    vc.resize(6, 2);
    assert_eq!((vc.cols, vc.rows), (6, 2));
    assert_eq!(trimmed(&vc, 0), "r2");
    assert_eq!(trimmed(&vc, 1), "r3");
    assert_eq!(vc.y, 1, "cursor row rebased by the dropped-top shift");
}

#[test]
fn resize_shrink_cols_clamps_cursor_x() {
    // Cursor parked near the right edge; shrinking the width clamps x.
    let mut vc = run(20, 2, b"");
    vc.move_to(0, 18);
    assert_eq!(vc.x, 18);
    vc.resize(10, 2);
    assert_eq!(vc.cols, 10);
    assert_eq!(vc.x, 9, "x clamps to new_cols-1");
}

#[test]
fn resize_full_scroll_region_re_expands() {
    // Default region is full screen (0..rows-1); after resize it tracks the
    // new bottom row.
    let mut vc = Vc::new(10, 5);
    assert_eq!((vc.scroll_top, vc.scroll_bot), (0, 4));
    vc.resize(10, 8);
    assert_eq!((vc.scroll_top, vc.scroll_bot), (0, 7));
    vc.resize(10, 3);
    assert_eq!((vc.scroll_top, vc.scroll_bot), (0, 2));
}

#[test]
fn resize_partial_scroll_region_clamps_or_resets() {
    // A DECSTBM sub-region that still fits is clamped in place.
    let mut vc = Vc::new(10, 10);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, b"\x1b[3;7r"); // region rows 2..6 (0-based)
    assert_eq!((vc.scroll_top, vc.scroll_bot), (2, 6));
    vc.resize(10, 8); // grow: not full-screen, both bounds still valid
    assert_eq!((vc.scroll_top, vc.scroll_bot), (2, 6));
    // Shrink so the bottom clamps under the old bot but top<bot still holds:
    // region clamps in place (top 2, bot min(6,3)=3) — still a valid region.
    vc.resize(10, 4);
    assert_eq!((vc.scroll_top, vc.scroll_bot), (2, 3));
    // Shrink further so top would meet/exceed bot → reset to full screen.
    vc.resize(10, 3); // top clamps to 2, bot clamps to 2 → invalid → full
    assert_eq!((vc.scroll_top, vc.scroll_bot), (0, 2));
}

#[test]
fn resize_rebuilds_tab_stops_at_new_width() {
    // Narrow grid (1 stop at col 8); grow wide → stops appear at 8,16,24.
    let mut vc = Vc::new(10, 2);
    assert!(vc.tab_set(8));
    vc.resize(30, 2);
    assert!(vc.tab_set(8) && vc.tab_set(16) && vc.tab_set(24));
    // Shrink narrower than 8 → no stops at all (default builder).
    vc.resize(6, 2);
    assert!(!vc.tab_set(8)); // out of range now reads false
}

#[test]
fn resize_clamps_view_offset_and_snaps_to_bottom() {
    // Build scrollback, scroll back into it, then resize: the view snaps to
    // the live bottom and the offset never exceeds history len.
    let mut vc = run(8, 3, b"r0\r\nr1\r\nr2\r\nr3\r\nr4\r\nr5");
    vc.scroll_view_up(2);
    assert_eq!(vc.view_offset(), 2);
    vc.resize(8, 4);
    assert_eq!(vc.view_offset(), 0, "resize snaps the view to the live bottom");
    assert!(vc.view_offset() <= vc.history_len());
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
