//! Ternary truth tables and stretch sampling.
use super::*;
use super::super::BltCoords;

/// Codes named by their whole thirty-two bit value, as callers pass them.
const SRCCOPY: u32 = 0x00cc_0020;
const SRCPAINT: u32 = 0x00ee_0086;
const SRCAND: u32 = 0x0088_00c6;
const SRCINVERT: u32 = 0x0066_0046;
const PATCOPY: u32 = 0x00f0_0021;
const DSTINVERT: u32 = 0x0055_0009;
const BLACKNESS: u32 = 0x0000_0042;
const WHITENESS: u32 = 0x00ff_0062;
const NOTSRCCOPY: u32 = 0x0033_0008;

fn table(code: u32) -> u8 { (code >> 16) as u8 }

#[test]
fn every_named_truth_table_computes_its_documented_expression() {
    let (p, s, d) = (0x00f0_f0f0, 0x00cc_cccc, 0x00aa_aaaa);
    assert_eq!(rop3(table(SRCCOPY), p, s, d), s);
    assert_eq!(rop3(table(PATCOPY), p, s, d), p);
    assert_eq!(rop3(table(SRCPAINT), p, s, d), s | d);
    assert_eq!(rop3(table(SRCAND), p, s, d), s & d);
    assert_eq!(rop3(table(SRCINVERT), p, s, d), s ^ d);
    assert_eq!(rop3(table(DSTINVERT), p, s, d), !d & 0x00ff_ffff);
    assert_eq!(rop3(table(NOTSRCCOPY), p, s, d), !s & 0x00ff_ffff);
    assert_eq!(rop3(table(BLACKNESS), p, s, d), 0);
    assert_eq!(rop3(table(WHITENESS), p, s, d), 0x00ff_ffff);
    // The masked-combine code the reference uses is (D & P) | (S & ~P).
    assert_eq!(rop3(0xac, p, s, d), (d & p) | (s & !p) & 0x00ff_ffff);
}

#[test]
fn a_code_reads_its_source_exactly_when_its_table_distinguishes_it() {
    for code in [SRCCOPY, SRCPAINT, SRCAND, SRCINVERT, NOTSRCCOPY] { assert!(rop_uses_source(code)); }
    for code in [PATCOPY, DSTINVERT, BLACKNESS, WHITENESS] { assert!(!rop_uses_source(code)); }
}

#[test]
fn a_negative_extent_runs_back_from_its_origin_and_clamps_to_the_bound() {
    assert_eq!(signed_span(2, 3, 0, 10), (2, 5));
    assert_eq!(signed_span(5, -3, 0, 10), (3, 6));
    assert_eq!(signed_span(-4, 6, 0, 10), (0, 2));
    assert_eq!(signed_span(8, 6, 0, 10), (8, 10));
    // An extent that never reaches the bound clamps to an empty span.
    assert_eq!(signed_span(i32::MIN, 4, 0, 10), (0, 0));
    assert_eq!(signed_span(i32::MIN, i32::MAX, 0, 10), (0, 0));
    assert_eq!(signed_span(i32::MAX, i32::MAX, 0, 10), (10, 10));
}

fn sampler(pixels: &[u32], width: i32, height: i32, mode: StretchMode) -> Sampler<'_> {
    Sampler { pixels, width, height, mode }
}

#[test]
fn equal_extents_sample_one_source_pixel_per_destination_pixel() {
    let pixels = [1, 2, 3, 4];
    let s = sampler(&pixels, 2, 2, COLORONCOLOR);
    let (dst, src) = (BltCoords { x: 10, y: 20, width: 2, height: 2 }, BltCoords { x: 0, y: 0, width: 2, height: 2 });
    assert_eq!(s.at(dst, src, 10, 20), Some(1));
    assert_eq!(s.at(dst, src, 11, 21), Some(4));
    assert_eq!(s.at(dst, src, 12, 20), None);
}

#[test]
fn growth_repeats_source_pixels_and_shrinkage_merges_them_per_stretch_mode() {
    let pixels = [0x00ff_ff00, 0x0000_ff00, 0x0000_00ff, 0x00ff_ffff];
    let (dst_big, src) = (BltCoords { x: 0, y: 0, width: 4, height: 4 }, BltCoords { x: 0, y: 0, width: 2, height: 2 });
    let s = sampler(&pixels, 2, 2, COLORONCOLOR);
    assert_eq!(s.at(dst_big, src, 0, 0), Some(0x00ff_ff00));
    assert_eq!(s.at(dst_big, src, 1, 0), Some(0x00ff_ff00));
    assert_eq!(s.at(dst_big, src, 2, 0), Some(0x0000_ff00));
    let (dst_small, src_big) = (BltCoords { x: 0, y: 0, width: 1, height: 1 }, BltCoords { x: 0, y: 0, width: 2, height: 2 });
    // Keeping dark pixels intersects, keeping light ones unions, colour on
    // colour drops all but the first, and halftone averages them.
    assert_eq!(sampler(&pixels, 2, 2, BLACKONWHITE).at(dst_small, src_big, 0, 0), Some(0));
    assert_eq!(sampler(&pixels, 2, 2, WHITEONBLACK).at(dst_small, src_big, 0, 0), Some(0x00ff_ffff));
    assert_eq!(sampler(&pixels, 2, 2, COLORONCOLOR).at(dst_small, src_big, 0, 0), Some(0x00ff_ff00));
    assert_eq!(sampler(&pixels, 2, 2, HALFTONE).at(dst_small, src_big, 0, 0), Some(0x007f_bf7f));
}

#[test]
fn a_source_position_outside_the_raster_samples_nothing() {
    let pixels = [1, 2, 3, 4];
    let s = sampler(&pixels, 2, 2, COLORONCOLOR);
    let (dst, src) = (BltCoords { x: 0, y: 0, width: 2, height: 2 }, BltCoords { x: 5, y: 5, width: 2, height: 2 });
    assert_eq!(s.at(dst, src, 0, 0), None);
    let empty = BltCoords { x: 0, y: 0, width: 0, height: 2 };
    assert_eq!(s.at(empty, src, 0, 0), None);
}
