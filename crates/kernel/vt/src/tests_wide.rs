// Wide-character (East-Asian width) + extended-SGR emulator tests
// (`57§6`,`57§9.2`). Feed UTF-8 byte streams, assert cell occupancy,
// cursor advance, wrap, and the rendition flags.

use crate::cell::{
    ATTR_BLINK, ATTR_CONCEAL, ATTR_FAINT, ATTR_ITALIC, ATTR_STRIKE, ATTR_WIDE,
    ATTR_WIDE_SPACER,
};
use crate::emulator::Emulator;
use crate::vc::Vc;
use alloc::vec::Vec;

fn run(cols: u16, rows: u16, bytes: &[u8]) -> Vc {
    let mut vc = Vc::new(cols, rows);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, bytes);
    vc
}

fn utf8(s: &str) -> Vec<u8> {
    s.as_bytes().to_vec()
}

#[test]
fn wide_char_occupies_primary_plus_spacer() {
    // U+4E2D '中' is width 2.
    let vc = run(10, 2, &utf8("中"));
    let p = vc.cell_at(0, 0).unwrap();
    let s = vc.cell_at(1, 0).unwrap();
    assert_eq!(p.glyph, '中' as u32);
    assert!(p.flags & ATTR_WIDE != 0, "primary wide flag");
    assert!(s.flags & ATTR_WIDE_SPACER != 0, "spacer flag");
    // Cursor advanced by 2.
    assert_eq!((vc.x, vc.y), (2, 0));
}

#[test]
fn narrow_after_wide_lands_in_column_two() {
    let vc = run(10, 2, &utf8("中A"));
    assert_eq!(vc.cell_at(0, 0).unwrap().glyph, '中' as u32);
    assert!(vc.cell_at(1, 0).unwrap().flags & ATTR_WIDE_SPACER != 0);
    assert_eq!(vc.cell_at(2, 0).unwrap().glyph, 'A' as u32);
    assert_eq!((vc.x, vc.y), (3, 0));
}

#[test]
fn overwrite_wide_primary_clears_spacer() {
    // Write wide, then home and overwrite the primary with a narrow glyph.
    let vc = run(10, 2, &{
        let mut b = utf8("中");
        b.extend_from_slice(b"\x1b[H"); // cursor home
        b.extend_from_slice(b"A");
        b
    });
    assert_eq!(vc.cell_at(0, 0).unwrap().glyph, 'A' as u32);
    // The orphaned spacer must be gone (blanked, not WIDE_SPACER).
    let s = vc.cell_at(1, 0).unwrap();
    assert!(s.flags & ATTR_WIDE_SPACER == 0, "spacer cleared");
    assert_eq!(s.glyph, ' ' as u32);
}

#[test]
fn overwrite_wide_spacer_clears_primary() {
    // Write wide at col0/1, then move to col1 and write a narrow glyph onto
    // the spacer — the primary at col0 must be torn down.
    let vc = run(10, 2, &{
        let mut b = utf8("中");
        b.extend_from_slice(b"\x1b[1;2H"); // row1 col2 (1-based) → col idx 1
        b.extend_from_slice(b"B");
        b
    });
    assert_eq!(vc.cell_at(1, 0).unwrap().glyph, 'B' as u32);
    let p = vc.cell_at(0, 0).unwrap();
    assert!(p.flags & ATTR_WIDE == 0, "primary cleared");
    assert_eq!(p.glyph, ' ' as u32);
}

#[test]
fn wide_char_wraps_at_last_column() {
    // cols=3: write "A" (col0), then a wide char — col1 would straddle the
    // margin only at the LAST column; at col1 it fits (cols-1=2 is spacer).
    // Use cols=2 so the wide char cannot fit after 'A' and must wrap.
    let vc = run(2, 3, &{
        let mut b = utf8("A");
        b.extend_from_slice(&utf8("中"));
        b
    });
    // 'A' at (0,0); wide char wrapped to row 1.
    assert_eq!(vc.cell_at(0, 0).unwrap().glyph, 'A' as u32);
    assert_eq!(vc.cell_at(0, 1).unwrap().glyph, '中' as u32);
    assert!(vc.cell_at(1, 1).unwrap().flags & ATTR_WIDE_SPACER != 0);
}

#[test]
fn combining_mark_does_not_advance() {
    // 'e' + combining acute U+0301: the mark is dropped, cursor stays at 1.
    let vc = run(10, 2, &utf8("e\u{0301}"));
    assert_eq!(vc.cell_at(0, 0).unwrap().glyph, 'e' as u32);
    assert_eq!((vc.x, vc.y), (1, 0));
}

#[test]
fn sgr_extended_flags_set_and_reset() {
    // Faint, italic, blink, conceal, strike on; then their resets off.
    let mut vc = Vc::new(10, 2);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, b"\x1b[2;3;5;8;9m");
    assert!(vc.attr.faint && vc.attr.italic && vc.attr.blink && vc.attr.conceal && vc.attr.strike);
    let _ = (ATTR_FAINT, ATTR_ITALIC, ATTR_BLINK, ATTR_CONCEAL, ATTR_STRIKE);
    em.feed_bytes(&mut vc, b"\x1b[23;25;28;29m"); // italic/blink/conceal/strike off
    assert!(!vc.attr.italic && !vc.attr.blink && !vc.attr.conceal && !vc.attr.strike);
    em.feed_bytes(&mut vc, b"\x1b[22m"); // bold+faint off
    assert!(!vc.attr.faint && !vc.attr.bold);
}

#[test]
fn sgr_flags_packed_into_cell() {
    let vc = run(10, 2, b"\x1b[3mZ"); // italic Z
    let c = vc.cell_at(0, 0).unwrap();
    assert_eq!(c.glyph, 'Z' as u32);
    assert!(c.flags & ATTR_ITALIC != 0);
}

#[test]
fn linux_acs_font_mode_draws_box_corners() {
    // Exactly what ncurses on TERM=linux emits for a box corner: smacs
    // (\E[11m), the raw CP437 corner bytes, then rmacs (\E[10m). Each byte
    // must map to the box-drawing codepoint, NOT be UTF-8-misdecoded.
    let vc = run(10, 2, &[0x1b, b'[', b'1', b'1', b'm', 0xDA, 0xC4, 0xBF, 0x1b, b'[', b'1', b'0', b'm']);
    assert_eq!(vc.cell_at(0, 0).unwrap().glyph, 0x250C, "┌ corner");
    assert_eq!(vc.cell_at(1, 0).unwrap().glyph, 0x2500, "─ line");
    assert_eq!(vc.cell_at(2, 0).unwrap().glyph, 0x2510, "┐ corner");
    assert_eq!((vc.x, vc.y), (3, 0));
}

#[test]
fn rmacs_returns_to_utf8_decoding() {
    // After \E[10m, a high byte is UTF-8 again, not CP437.
    let mut vc = Vc::new(10, 2);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, &[0x1b, b'[', b'1', b'1', b'm', 0xC4]); // CP437 ─
    assert_eq!(vc.cell_at(0, 0).unwrap().glyph, 0x2500);
    em.feed_bytes(&mut vc, b"\x1b[10m"); // rmacs
    em.feed_bytes(&mut vc, "é".as_bytes()); // 0xC3 0xA9 UTF-8 → U+00E9
    assert_eq!(vc.cell_at(1, 0).unwrap().glyph, 0x00E9, "UTF-8 decoding restored");
}
