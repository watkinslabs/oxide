use super::*;
use crate::font::parser::{build_font, serialize};
use alloc::vec::Vec;

#[test]
fn default_font_parses_8x16_256() {
    let f = parse_psf2(include_bytes!("../default8x16.psfu")).expect("parse");
    assert_eq!(f.width, 8);
    assert_eq!(f.height, 16);
    assert_eq!(f.dims().2, 256);
}

#[test]
fn ascii_maps_to_cp437_positions() {
    let f = parse_psf2(include_bytes!("../default8x16.psfu")).unwrap();
    assert_eq!(f.glyph_index('A' as u32), 65);
    assert_eq!(f.glyph_index('?' as u32), 63);
    assert_eq!(f.glyph_index(' ' as u32), 32);
}

#[test]
fn box_drawing_and_blocks_map_to_real_glyphs() {
    let f = parse_psf2(include_bytes!("../default8x16.psfu")).unwrap();
    assert_eq!(f.glyph_index(0x2500), 196);
    assert_eq!(f.glyph_index(0x2502), 179);
    assert_eq!(f.glyph_index(0x250c), 218);
    assert_eq!(f.glyph_index(0x2510), 191);
    assert_eq!(f.glyph_index(0x2514), 192);
    assert_eq!(f.glyph_index(0x2518), 217);
    assert_eq!(f.glyph_index(0x253c), 197);
    assert_eq!(f.glyph_index(0x2592), 177);
    assert_eq!(f.glyph_index(0x2588), 219);
}

#[test]
fn accented_latin_resolves() {
    let f = parse_psf2(include_bytes!("../default8x16.psfu")).unwrap();
    assert_eq!(f.glyph_index(0x00e9), 130);
    assert_eq!(f.glyph_index(0x00f1), 164);
}

#[test]
fn unmapped_falls_back_to_question_mark() {
    let f = parse_psf2(include_bytes!("../default8x16.psfu")).unwrap();
    assert_eq!(f.glyph_index(0x25c6), 63);
    assert_eq!(f.glyph_index(0x1f600), 63);
}

#[test]
fn build_font_extracts_glyphs_and_get_roundtrips() {
    let stride = 32usize;
    let mut data = alloc::vec![0u8; 2 * stride];
    data[0] = 0xAA;
    data[stride + 3] = 0x0F;
    let uni = alloc::vec![(0x41u32, 0u16), (0x42u32, 1u16)];
    let f = build_font(8, 8, 2, stride, &data, uni, 0).unwrap();
    assert_eq!(f.dims(), (8, 8, 2));
    assert_eq!(f.glyph_row(0, 0), 0xAA);
    assert_eq!(f.glyph_row(1, 3), 0x0F);
    let (w, h, c, out) = serialize(&f, stride);
    assert_eq!((w, h, c), (8, 8, 2));
    assert_eq!(out[0], 0xAA);
    assert_eq!(out[stride + 3], 0x0F);
}

#[test]
fn build_font_rejects_bad_geometry() {
    let data = alloc::vec![0u8; 32];
    assert!(build_font(0, 8, 1, 32, &data, Vec::new(), 0).is_err());
    assert!(build_font(33, 8, 1, 32, &data, Vec::new(), 0).is_err());
    assert!(build_font(8, 64, 1, 32, &data, Vec::new(), 0).is_err());
    assert!(build_font(8, 8, 0, 32, &data, Vec::new(), 0).is_err());
    assert!(build_font(8, 8, 5, 32, &data, Vec::new(), 0).is_err());
    assert!(build_font(16, 16, 1, 8, &data, Vec::new(), 0).is_err());
}

#[test]
fn glyph_bit_wide_12px_font() {
    let stride = 32usize;
    let mut data = alloc::vec![0u8; stride];
    data[0] = 0b1000_0001;
    data[1] = 0b1001_0000;
    data[2] = 0b0100_0000;
    let f = build_font(12, 2, 1, stride, &data, Vec::new(), 0).unwrap();
    let lit0: alloc::vec::Vec<usize> = (0..12).filter(|&x| f.glyph_bit(0, 0, x)).collect();
    assert_eq!(lit0, alloc::vec![0usize, 7, 8, 11]);
    let lit1: alloc::vec::Vec<usize> = (0..12).filter(|&x| f.glyph_bit(0, 1, x)).collect();
    assert_eq!(lit1, alloc::vec![1usize]);
}
