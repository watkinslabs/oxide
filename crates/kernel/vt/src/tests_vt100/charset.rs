use crate::emulator::Emulator;
use crate::vc::{Charset, Vc, DEC_SPECIAL_GRAPHICS};

use super::{run, trimmed};

#[test]
fn default_tab_stops_every_eight() {
    let vc = run(40, 2, b"a\tb\tc");
    assert_eq!(vc.glyph_at(0, 0), 'a' as u32);
    assert_eq!(vc.glyph_at(8, 0), 'b' as u32);
    assert_eq!(vc.glyph_at(16, 0), 'c' as u32);
}

#[test]
fn hts_sets_custom_tab_stop() {
    let vc = run(40, 2, b"\x1b[1;4H\x1bH\x1b[1;1H\tX");
    assert_eq!(vc.glyph_at(3, 0), 'X' as u32);
}

#[test]
fn tbc_clears_one_stop() {
    let vc = run(40, 2, b"\x1b[1;9H\x1b[g\x1b[1;1H\tX");
    assert_eq!(vc.glyph_at(16, 0), 'X' as u32);
}

#[test]
fn tbc_clears_all_stops() {
    let vc = run(20, 2, b"\x1b[3g\t");
    assert_eq!(vc.x, 19);
}

#[test]
fn ht_clamps_at_right_margin() {
    let vc = run(10, 2, b"\t\t\t");
    assert_eq!(vc.x, 9);
}

#[test]
fn dec_special_maps_box_drawing() {
    let vc = run(20, 2, b"\x1b(0qxlkmjn");
    assert_eq!(vc.glyph_at(0, 0), 0x2500);
    assert_eq!(vc.glyph_at(1, 0), 0x2502);
    assert_eq!(vc.glyph_at(2, 0), 0x250c);
    assert_eq!(vc.glyph_at(3, 0), 0x2510);
    assert_eq!(vc.glyph_at(4, 0), 0x2514);
    assert_eq!(vc.glyph_at(5, 0), 0x2518);
    assert_eq!(vc.glyph_at(6, 0), 0x253c);
}

#[test]
fn dec_special_back_to_ascii() {
    let vc = run(20, 2, b"\x1b(0q\x1b(Bq");
    assert_eq!(vc.glyph_at(0, 0), 0x2500);
    assert_eq!(vc.glyph_at(1, 0), 'q' as u32);
}

#[test]
fn so_si_switch_gl_between_g0_g1() {
    let vc = run(20, 2, b"\x1b)0a\x0eq\x0fa");
    assert_eq!(vc.glyph_at(0, 0), 'a' as u32);
    assert_eq!(vc.glyph_at(1, 0), 0x2500);
    assert_eq!(vc.glyph_at(2, 0), 'a' as u32);
}

#[test]
fn dec_special_non_special_byte_passthrough() {
    let vc = run(20, 2, b"\x1b(0A");
    assert_eq!(vc.glyph_at(0, 0), 'A' as u32);
}

#[test]
fn dec_special_table_full_coverage() {
    let mut bytes = alloc::vec::Vec::new();
    bytes.extend_from_slice(b"\x1b(0");
    for b in 0x60u8..=0x7e {
        bytes.push(b);
    }
    let vc = run(40, 2, &bytes);
    for (i, b) in (0x60u8..=0x7e).enumerate() {
        assert_eq!(vc.glyph_at(i as u16, 0), DEC_SPECIAL_GRAPHICS[(b - 0x60) as usize], "byte {:#x} mapped wrong", b);
    }
}

#[test]
fn ris_resets_tabs() {
    let vc = run(40, 2, b"\x1b[3g\x1b[1;4H\x1bH\x1bc");
    assert!(vc.tab_set(8));
    assert!(!vc.tab_set(3));
}

#[test]
fn vttest_box_drawing_frame() {
    let mut vc = Vc::new(4, 3);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, b"\x1b(0");
    em.feed_bytes(&mut vc, b"lqqk");
    em.feed_bytes(&mut vc, b"\x1b[2;1Hx\x1b[2;4Hx");
    em.feed_bytes(&mut vc, b"\x1b[3;1Hmqqj");
    assert_eq!(vc.glyph_at(0, 0), 0x250c);
    assert_eq!(vc.glyph_at(1, 0), 0x2500);
    assert_eq!(vc.glyph_at(2, 0), 0x2500);
    assert_eq!(vc.glyph_at(3, 0), 0x2510);
    assert_eq!(vc.glyph_at(0, 1), 0x2502);
    assert_eq!(vc.glyph_at(3, 1), 0x2502);
    assert_eq!(vc.glyph_at(0, 2), 0x2514);
    assert_eq!(vc.glyph_at(3, 2), 0x2518);
}

#[test]
fn ris_full_reset() {
    let vc = run(10, 3, b"junk\x1b[31m\x1b(0\x1b[?6h\x1b[2;2r\x1bcZ");
    assert_eq!(vc.glyph_at(0, 0), 'Z' as u32);
    assert_eq!(vc.attr_at(0, 0).unwrap().fg, crate::vc::DEFAULT_FG_RGB);
    assert!(vc.autowrap);
    assert!(!vc.origin_mode);
    assert_eq!(vc.g0, Charset::Ascii);
    assert_eq!(vc.scroll_top, 0);
    assert_eq!(vc.scroll_bot, vc.rows - 1);
}
