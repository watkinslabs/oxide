// VT100/VT102 emulation-accuracy golden corpus. Each test feeds a precise
// escape sequence and asserts the exact resulting `Vc` grid (rows as
// strings), cursor (x,y), and the relevant mode/charset/tab state. The
// DEC-correct behavior is named in each comment (DEC STD 070 / VT100 user
// guide / xterm ctlseqs as implemented by Linux `vt.c`).
//
// vttest-style composite sequences are grouped at the end.

use crate::emulator::Emulator;
use crate::vc::{Charset, Vc, DEC_SPECIAL_GRAPHICS, DEFAULT_FG_RGB};

/// Build a Vc, feed bytes, return it.
fn run(cols: u16, rows: u16, bytes: &[u8]) -> Vc {
    let mut vc = Vc::new(cols, rows);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, bytes);
    vc
}

fn trimmed(vc: &Vc, row: u16) -> alloc::string::String {
    vc.row_string(row).trim_end().into()
}

// ===== 1. DECSC / DECRC — full saved state ============================

#[test]
fn decsc_decrc_saves_position_attr_charset_origin() {
    // Set red SGR + DEC graphics G0 + origin mode, move, ESC 7 (save).
    // Reset everything, move away, ESC 8 (restore): all five must come
    // back exactly (DEC STD 070: DECSC saves SGR + charset + DECOM + pos).
    let mut vc = Vc::new(20, 10);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, b"\x1b[?6h\x1b[31m\x1b(0\x1b[3;5H\x1b7");
    // Now scramble state.
    em.feed_bytes(&mut vc, b"\x1b[?6l\x1b[0m\x1b(B\x1b[1;1H");
    assert!(!vc.origin_mode);
    assert_eq!(vc.g0, Charset::Ascii);
    // Restore.
    em.feed_bytes(&mut vc, b"\x1b8");
    assert!(vc.origin_mode, "DECRC restores origin mode");
    assert_eq!(vc.g0, Charset::DecSpecial, "DECRC restores G0 charset");
    assert_eq!(vc.attr.fg, crate::palette::xterm_256_rgb(1), "DECRC restores SGR fg");
    assert_eq!((vc.x, vc.y), (4, 2), "DECRC restores cursor position");
}

#[test]
fn decsc_saves_gl_selector() {
    // SO selects G1 into GL; DECSC must capture GL and DECRC restore it.
    let mut vc = Vc::new(20, 5);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, b"\x0e\x1b7\x0f\x1b8");
    assert_eq!(vc.gl, 1, "DECRC restores GL=1 (SO/G1)");
}

#[test]
fn decrc_without_decsc_restores_defaults() {
    // No prior DECSC: DECRC restores the power-on saved state (home,
    // default attrs) — saved fields default to that.
    let vc = run(20, 5, b"\x1b[5;5H\x1b[31m\x1b8X");
    assert_eq!((vc.x, vc.y), (1, 0), "DECRC to default home then print X");
    assert_eq!(vc.attr.fg, DEFAULT_FG_RGB);
}

// ===== 2. Origin mode (DECOM) ========================================

#[test]
fn decom_cup_relative_to_region() {
    // Region rows 3..6 (1-based), origin on. CUP 1;1 addresses region-top
    // (screen row 2, 0-based). The cursor cannot leave the region.
    let vc = run(20, 10, b"\x1b[3;6r\x1b[?6h\x1b[1;1HX");
    assert_eq!(vc.glyph_at(0, 2), 'X' as u32, "CUP 1;1 under DECOM = region top");
}

#[test]
fn decom_cup_clamped_to_region_bottom() {
    // Region rows 3..6, origin on. CUP 99;1 clamps at the region bottom
    // (screen row 5, 0-based), not the screen bottom.
    let vc = run(20, 10, b"\x1b[3;6r\x1b[?6h\x1b[99;1HY");
    assert_eq!(vc.glyph_at(0, 5), 'Y' as u32, "CUP clamps to region bottom under DECOM");
}

#[test]
fn decom_off_is_absolute() {
    // Origin off: CUP 1;1 = absolute screen home regardless of region.
    let vc = run(20, 10, b"\x1b[3;6r\x1b[?6l\x1b[1;1HZ");
    assert_eq!(vc.glyph_at(0, 0), 'Z' as u32, "DECOM off → CUP absolute");
}

#[test]
fn decom_toggle_homes_cursor() {
    // Toggling DECOM homes the cursor to the (region) home position.
    let vc = run(20, 10, b"\x1b[4;8r\x1b[?6h");
    assert_eq!((vc.x, vc.y), (0, 3), "DECOM-set homes to region top");
}

// ===== 3. Autowrap + pending-wrap latch ==============================

#[test]
fn pending_wrap_exactly_cols_chars() {
    // Writing exactly `cols` chars leaves the cursor stuck at the last
    // column with the pending-wrap latch set (VT100 deferred wrap).
    let vc = run(5, 3, b"abcde");
    assert_eq!((vc.x, vc.y), (4, 0), "cursor sticks at last col");
    assert!(vc.wrap_pending, "pending-wrap latch set after filling the row");
    assert_eq!(trimmed(&vc, 0), "abcde");
}

#[test]
fn pending_wrap_next_char_wraps() {
    // The (cols+1)th printable triggers the deferred wrap to next row.
    let vc = run(5, 3, b"abcdef");
    assert_eq!(trimmed(&vc, 0), "abcde");
    assert_eq!(vc.glyph_at(0, 1), 'f' as u32);
    assert_eq!((vc.x, vc.y), (1, 1));
    assert!(!vc.wrap_pending);
}

#[test]
fn cr_clears_pending_wrap_without_wrapping() {
    // CR at the last column clears the latch; the next char overwrites
    // col 0 of the SAME row (no wrap happened).
    let vc = run(5, 2, b"abcde\rX");
    assert_eq!(vc.glyph_at(0, 0), 'X' as u32);
    assert_eq!(trimmed(&vc, 1), "", "no wrap occurred");
    assert_eq!((vc.x, vc.y), (1, 0));
}

#[test]
fn cursor_move_clears_pending_wrap() {
    // A cursor move (CUB) clears the latch without wrapping.
    let vc = run(5, 2, b"abcde\x1b[1DX");
    assert!(!vc.wrap_pending);
    assert_eq!(vc.glyph_at(3, 0), 'X' as u32);
    assert_eq!(trimmed(&vc, 1), "");
}

#[test]
fn no_autowrap_no_latch() {
    // DECAWM off: glyphs pile in the last column; no latch, no wrap.
    let vc = run(5, 3, b"\x1b[?7labcdef");
    assert_eq!((vc.x, vc.y), (4, 0));
    assert!(!vc.wrap_pending);
    assert_eq!(vc.glyph_at(4, 0), 'f' as u32);
}

// ===== 4. Scroll region (DECSTBM) ====================================

#[test]
fn ind_scrolls_only_region_at_bottom() {
    // Region rows 2..3 (1-based). IND (ESC D) at the region bottom scrolls
    // only the region; row 0 (outside) is untouched.
    // IND keeps the column (no CR), so C lands at col 1 → " C".
    let vc = run(10, 4, b"top\x1b[2;3r\x1b[2;1HA\x1b[3;1HB\x1bDC");
    assert_eq!(trimmed(&vc, 0), "top", "row outside region untouched");
    assert_eq!(trimmed(&vc, 1), "B", "region scrolled up");
    assert_eq!(vc.glyph_at(1, 2), 'C' as u32, "C at col 1 (IND keeps column)");
}

#[test]
fn ri_scrolls_only_region_at_top() {
    // Region rows 2..3. RI (ESC M) at the region top scrolls the region
    // down; row 0 outside is untouched.
    let vc = run(10, 4, b"top\x1b[2;3r\x1b[2;1HA\x1b[3;1HB\x1b[2;1H\x1bM");
    assert_eq!(trimmed(&vc, 0), "top");
    assert_eq!(trimmed(&vc, 1), "", "region top blanked by RI");
    assert_eq!(trimmed(&vc, 2), "A", "A pushed down within region");
}

#[test]
fn nel_at_region_bottom_scrolls_region() {
    // NEL (ESC E) = CR+LF; at the region bottom it scrolls the region.
    let vc = run(10, 4, b"top\x1b[2;3r\x1b[3;5HX\x1bE");
    assert_eq!(trimmed(&vc, 0), "top");
    assert_eq!((vc.x, vc.y), (0, 2), "NEL → col 0, stays at region bottom");
}

#[test]
fn cup_without_origin_can_address_outside_region() {
    // Absolute CUP (no DECOM) can place the cursor outside the region.
    let vc = run(10, 6, b"\x1b[2;3r\x1b[5;1HX");
    assert_eq!(vc.glyph_at(0, 4), 'X' as u32);
}

// ===== 5. Tab stops (HTS / TBC / HT) =================================

#[test]
fn default_tab_stops_every_eight() {
    let vc = run(40, 2, b"a\tb\tc");
    assert_eq!(vc.glyph_at(0, 0), 'a' as u32);
    assert_eq!(vc.glyph_at(8, 0), 'b' as u32);
    assert_eq!(vc.glyph_at(16, 0), 'c' as u32);
}

#[test]
fn hts_sets_custom_tab_stop() {
    // Move to col 3 (1-based 4), HTS sets a stop there; from col 0, HT
    // lands on it.
    let vc = run(40, 2, b"\x1b[1;4H\x1bH\x1b[1;1H\tX");
    assert_eq!(vc.glyph_at(3, 0), 'X' as u32, "HT stops at the HTS stop (col 3)");
}

#[test]
fn tbc_clears_one_stop() {
    // Clear the default stop at col 8 (TBC 0 at cursor col 8); HT now skips
    // to col 16.
    let vc = run(40, 2, b"\x1b[1;9H\x1b[g\x1b[1;1H\tX");
    assert_eq!(vc.glyph_at(16, 0), 'X' as u32, "after TBC at col8, HT skips to col16");
}

#[test]
fn tbc_clears_all_stops() {
    // TBC 3 clears every stop; HT then runs to the right margin.
    let vc = run(20, 2, b"\x1b[3g\t");
    assert_eq!(vc.x, 19, "no stops → HT clamps at right margin");
}

#[test]
fn ht_clamps_at_right_margin() {
    let vc = run(10, 2, b"\t\t\t");
    assert_eq!(vc.x, 9, "HT never passes the last column");
}

// ===== 6. DEC Special Graphics line-drawing charset ==================

#[test]
fn dec_special_maps_box_drawing() {
    // ESC ( 0 designates G0 = special graphics. q→─, x→│, l→┌, k→┐,
    // m→└, j→┘, n→┼.
    let vc = run(20, 2, b"\x1b(0qxlkmjn");
    assert_eq!(vc.glyph_at(0, 0), 0x2500, "q → ─");
    assert_eq!(vc.glyph_at(1, 0), 0x2502, "x → │");
    assert_eq!(vc.glyph_at(2, 0), 0x250c, "l → ┌");
    assert_eq!(vc.glyph_at(3, 0), 0x2510, "k → ┐");
    assert_eq!(vc.glyph_at(4, 0), 0x2514, "m → └");
    assert_eq!(vc.glyph_at(5, 0), 0x2518, "j → ┘");
    assert_eq!(vc.glyph_at(6, 0), 0x253c, "n → ┼");
}

#[test]
fn dec_special_back_to_ascii() {
    // ESC ( 0 then ESC ( B returns G0 to ASCII; later 'q' is literal.
    let vc = run(20, 2, b"\x1b(0q\x1b(Bq");
    assert_eq!(vc.glyph_at(0, 0), 0x2500, "first q is line-draw");
    assert_eq!(vc.glyph_at(1, 0), 'q' as u32, "after ESC ( B, q is literal");
}

#[test]
fn so_si_switch_gl_between_g0_g1() {
    // G1 = special graphics, G0 = ASCII. SO selects G1 (line draw), SI
    // back to G0 (ASCII).
    let vc = run(20, 2, b"\x1b)0a\x0eq\x0fa");
    assert_eq!(vc.glyph_at(0, 0), 'a' as u32, "G0/ASCII before SO");
    assert_eq!(vc.glyph_at(1, 0), 0x2500, "SO → G1 special graphics q");
    assert_eq!(vc.glyph_at(2, 0), 'a' as u32, "SI → back to G0 ASCII");
}

#[test]
fn dec_special_non_special_byte_passthrough() {
    // A byte outside 0x60..0x7e passes through unchanged even in special
    // graphics (e.g. 'A' = 0x41).
    let vc = run(20, 2, b"\x1b(0A");
    assert_eq!(vc.glyph_at(0, 0), 'A' as u32);
}

#[test]
fn dec_special_table_full_coverage() {
    // Feed every special-graphics byte 0x60..0x7e; each must map per the
    // canonical table.
    let mut bytes = alloc::vec::Vec::new();
    bytes.extend_from_slice(b"\x1b(0");
    for b in 0x60u8..=0x7e {
        bytes.push(b);
    }
    let vc = run(40, 2, &bytes);
    for (i, b) in (0x60u8..=0x7e).enumerate() {
        assert_eq!(
            vc.glyph_at(i as u16, 0),
            DEC_SPECIAL_GRAPHICS[(b - 0x60) as usize],
            "byte {:#x} mapped wrong",
            b
        );
    }
}

// ===== 7. DECTCEM cursor visibility ==================================

#[test]
fn dectcem_toggles_cursor_visible() {
    let vc = run(20, 2, b"\x1b[?25l");
    assert!(!vc.cursor_visible, "?25l hides cursor");
    let vc2 = run(20, 2, b"\x1b[?25l\x1b[?25h");
    assert!(vc2.cursor_visible, "?25h shows cursor");
}

// ===== 8. DECALN =====================================================

#[test]
fn decaln_fills_screen_with_e() {
    let vc = run(4, 3, b"\x1b#8");
    for r in 0..3 {
        assert_eq!(trimmed(&vc, r), "EEEE", "DECALN fills row {r} with E");
    }
    assert_eq!((vc.x, vc.y), (0, 0), "DECALN homes the cursor");
}

// ===== 9. ED / EL ====================================================

#[test]
fn ed_modes_0_1_2() {
    // ED 0: cursor→end.
    let vc = run(4, 3, b"abcdABCDwxyz\x1b[2;3H\x1b[0J");
    assert_eq!(trimmed(&vc, 0), "abcd");
    assert_eq!(trimmed(&vc, 1), "AB"); // col 2 onward (0-based col2) cleared
    assert_eq!(trimmed(&vc, 2), "");
    // ED 1: start→cursor.
    let vc1 = run(4, 3, b"abcdABCDwxyz\x1b[2;3H\x1b[1J");
    assert_eq!(trimmed(&vc1, 0), "");
    assert_eq!(vc1.glyph_at(3, 1), 'D' as u32);
    // ED 2: whole screen.
    let vc2 = run(4, 3, b"abcdABCDwxyz\x1b[2J");
    for r in 0..3 {
        assert_eq!(trimmed(&vc2, r), "");
    }
}

#[test]
fn ed_3_clears_scrollback() {
    // Build history, then ED 3. The live grid is also cleared; history
    // count is what we assert is gone (ED 3 = clear scrollback).
    let mut vc = run(4, 2, b"r0\r\nr1\r\nr2\r\nr3");
    assert!(vc.history_len() > 0);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, b"\x1b[3J");
    assert_eq!(vc.history_len(), 0, "ED 3 clears scrollback history");
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
    // EL fills with the CURRENT SGR background (color terminal). Set a blue
    // bg, then EL 2 — erased cells must carry the blue bg.
    let vc = run(10, 2, b"abc\x1b[44m\x1b[2K");
    let a = vc.attr_at(5, 0).unwrap();
    assert_eq!(a.bg, crate::palette::xterm_256_rgb(4), "erased cell carries current bg");
}

// ===== 10. IND / RI / NEL / RIS ======================================

#[test]
fn ind_is_lf_without_cr() {
    // IND moves down, keeps the column.
    let vc = run(20, 4, b"abc\x1bDx");
    assert_eq!((vc.x, vc.y), (4, 1));
    assert_eq!(vc.glyph_at(3, 1), 'x' as u32);
}

#[test]
fn ri_moves_up() {
    let vc = run(20, 4, b"\x1b[3;5H\x1bMx");
    assert_eq!(vc.y, 1, "RI moved up from row 2 to row 1");
    assert_eq!(vc.x, 5);
}

#[test]
fn nel_is_cr_lf() {
    let vc = run(20, 4, b"abc\x1bEx");
    assert_eq!((vc.x, vc.y), (1, 1), "NEL → col 0 then down, then x at col0");
    assert_eq!(vc.glyph_at(0, 1), 'x' as u32);
}

#[test]
fn ris_full_reset() {
    // Scramble everything, then RIS (ESC c) → defaults + clear + home.
    let vc = run(10, 3, b"junk\x1b[31m\x1b(0\x1b[?6h\x1b[2;2r\x1bcZ");
    assert_eq!(vc.glyph_at(0, 0), 'Z' as u32, "RIS clears then Z at home");
    assert_eq!(vc.attr_at(0, 0).unwrap().fg, DEFAULT_FG_RGB, "RIS resets attrs");
    assert!(vc.autowrap);
    assert!(!vc.origin_mode, "RIS resets DECOM");
    assert_eq!(vc.g0, Charset::Ascii, "RIS resets G0");
    assert_eq!(vc.scroll_top, 0);
    assert_eq!(vc.scroll_bot, vc.rows - 1, "RIS resets scroll region");
}

#[test]
fn ris_resets_tabs() {
    // Clear all tabs, set one custom, RIS → default 8-col stops back.
    let vc = run(40, 2, b"\x1b[3g\x1b[1;4H\x1bH\x1bc");
    assert!(vc.tab_set(8), "RIS restores default stop at col 8");
    assert!(!vc.tab_set(3), "RIS clears the custom stop");
}

// ===== 11. Control-char edge cases ===================================

#[test]
fn bs_stops_at_column_zero() {
    let vc = run(10, 2, b"\x08\x08X");
    assert_eq!((vc.x, vc.y), (1, 0), "BS at col 0 is a no-op (no wrap-back)");
    assert_eq!(vc.glyph_at(0, 0), 'X' as u32);
}

#[test]
fn control_char_mid_csi_executes_then_resumes() {
    // CR embedded in a CSI parameter executes immediately, then the CSI
    // continues and dispatches. Here: "ab" then CSI with embedded CR
    // (col 0) then the 'm' (SGR reset) finalizes; following 'X' lands col0.
    let vc = run(10, 2, b"ab\x1b[1\r0mX");
    assert_eq!(vc.glyph_at(0, 0), 'X' as u32, "embedded CR moved to col0 mid-CSI");
}

#[test]
fn can_aborts_sequence() {
    // CAN (0x18) mid-CSI aborts; following bytes print literally.
    let vc = run(10, 2, b"\x1b[12\x18AB");
    assert_eq!(vc.glyph_at(0, 0), 'A' as u32);
    assert_eq!(vc.glyph_at(1, 0), 'B' as u32);
}

#[test]
fn sub_aborts_sequence() {
    // SUB (0x1a) likewise aborts to ground.
    let vc = run(10, 2, b"\x1b[3;3\x1aCD");
    assert_eq!(vc.glyph_at(0, 0), 'C' as u32);
    assert_eq!(vc.glyph_at(1, 0), 'D' as u32);
}

// ===== 12. Default colors / attrs ====================================

#[test]
fn sgr0_resets_to_defaults() {
    let vc = run(20, 2, b"\x1b[1;4;7;31;44mA\x1b[0mB");
    let b = vc.attr_at(1, 0).unwrap();
    assert_eq!(b.fg, DEFAULT_FG_RGB);
    assert_eq!(b.bg, crate::vc::DEFAULT_BG_RGB);
    assert!(!b.bold && !b.underline && !b.reverse);
}

// ===== vttest-style composites =======================================

#[test]
fn vttest_box_drawing_frame() {
    // Draw a 4x3 box with DEC special graphics, like ncurses/dialog. Top
    // row: ┌──┐  middle: │  │  bottom: └──┘
    let mut vc = Vc::new(4, 3);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, b"\x1b(0"); // G0 = special graphics
    em.feed_bytes(&mut vc, b"lqqk"); // ┌──┐
    em.feed_bytes(&mut vc, b"\x1b[2;1Hx\x1b[2;4Hx"); // │  │
    em.feed_bytes(&mut vc, b"\x1b[3;1Hmqqj"); // └──┘
    assert_eq!(vc.glyph_at(0, 0), 0x250c); // ┌
    assert_eq!(vc.glyph_at(1, 0), 0x2500); // ─
    assert_eq!(vc.glyph_at(2, 0), 0x2500);
    assert_eq!(vc.glyph_at(3, 0), 0x2510); // ┐
    assert_eq!(vc.glyph_at(0, 1), 0x2502); // │
    assert_eq!(vc.glyph_at(3, 1), 0x2502);
    assert_eq!(vc.glyph_at(0, 2), 0x2514); // └
    assert_eq!(vc.glyph_at(3, 2), 0x2518); // ┘
}

#[test]
fn vttest_cursor_movement_pattern() {
    // CUP to (3,3), draw, relative moves form a plus. Asserts CUP +
    // CUU/CUD/CUF/CUB compose correctly (1-based addressing).
    let vc = run(10, 10, b"\x1b[3;3H*\x1b[3;3H\x1b[1A^\x1b[3;3H\x1b[1Bv\x1b[3;3H\x1b[1D<\x1b[3;3H\x1b[1C>");
    assert_eq!(vc.glyph_at(2, 2), '*' as u32);
    assert_eq!(vc.glyph_at(2, 1), '^' as u32, "up");
    assert_eq!(vc.glyph_at(2, 3), 'v' as u32, "down");
    assert_eq!(vc.glyph_at(1, 2), '<' as u32, "left");
    assert_eq!(vc.glyph_at(3, 2), '>' as u32, "right");
}

#[test]
fn vttest_origin_mode_scroll() {
    // Origin-mode scroll test: region rows 2..4 (1-based), DECOM on, fill
    // the region with rows then force a scroll; content outside the region
    // (rows 0,4 0-based) stays put.
    let mut vc = Vc::new(8, 5);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, b"\x1b[1;1Htop\x1b[5;1Hbot"); // outside-region markers
    em.feed_bytes(&mut vc, b"\x1b[2;4r\x1b[?6h"); // region rows 2..4, origin
    // Under origin mode, home is region top; print 3 lines that scroll once.
    em.feed_bytes(&mut vc, b"\x1b[1;1HA\r\nB\r\nC\r\nD");
    assert_eq!(trimmed(&vc, 0), "top", "row 0 outside region untouched");
    assert_eq!(trimmed(&vc, 4), "bot", "row 4 outside region untouched");
    // Region (rows 1..3 0-based) scrolled: should now show B,C,D.
    assert_eq!(trimmed(&vc, 1), "B");
    assert_eq!(trimmed(&vc, 2), "C");
    assert_eq!(trimmed(&vc, 3), "D");
}

#[test]
fn vttest_wrap_then_scroll() {
    // Autowrap at the bottom-right corner must scroll the screen (deferred
    // wrap then LF at the last row).
    let vc = run(3, 2, b"abcde");
    // "abc" fills row0 (latch), then d wraps to row1 col0, e → col1.
    assert_eq!(trimmed(&vc, 0), "abc");
    assert_eq!(trimmed(&vc, 1), "de");
    // fill row1, one more char scrolls.
    let vc2 = run(3, 2, b"abcdefg");
    // row0=abc latch, def fills row1 (latch), g wraps → scroll, row1=g.
    assert_eq!(trimmed(&vc2, 0), "def");
    assert_eq!(vc2.glyph_at(0, 1), 'g' as u32);
}
