//! EDID decode tests over blocks built byte by byte from the standard's layout.
//!
//! Test manifest:
//!   `published` — established, standard, and combined mode publication.

mod published;

use super::layout::*;
use super::*;
use crate::uapi::{
    DRM_MODE_FLAG_INTERLACE, DRM_MODE_FLAG_NHSYNC, DRM_MODE_FLAG_NVSYNC, DRM_MODE_FLAG_PHSYNC,
    DRM_MODE_FLAG_PVSYNC, DRM_MODE_TYPE_PREFERRED,
};

/// The 18 descriptor bytes a 1920x1080 60 Hz display publishes: 148.5 MHz
/// pixel clock, 2200x1125 total, 88/44 horizontal and 4/5 vertical sync,
/// 531x299 mm, separate sync positive on both axes.
const DTD_1920X1080: [u8; DTD_LEN] = [
    0x02, 0x3a, 0x80, 0x18, 0x71, 0x38, 0x2d, 0x40, 0x58, 0x2c,
    0x45, 0x00, 0x13, 0x2b, 0x21, 0x00, 0x00, 0x1e,
];

/// A block with `rev` as its structure revision, `features` as its feature
/// byte, and `dtds` placed in the detailed descriptor slots. Checksum is
/// computed last so the block is well formed by construction.
pub(crate) fn build(rev: u8, features: u8, dtds: &[&[u8; DTD_LEN]]) -> [u8; BLOCK_LEN] {
    let mut b = [0u8; BLOCK_LEN];
    b[..HEADER.len()].copy_from_slice(&HEADER);
    b[OFF_VERSION] = 1;
    b[OFF_REVISION] = rev;
    b[OFF_FEATURES] = features;
    for (i, d) in dtds.iter().enumerate().take(DTD_COUNT) {
        let at = OFF_DETAILED + i * DTD_LEN;
        b[at..at + DTD_LEN].copy_from_slice(&d[..]);
    }
    b[OFF_CHECKSUM] = computed_checksum(&b);
    b
}

fn fhd_block() -> [u8; BLOCK_LEN] { build(4, 0, &[&DTD_1920X1080]) }

/// Pack a detailed timing descriptor for an arbitrary size, with blanking and
/// sync values in the usual proportions. Used by callers that care which size
/// an EDID names rather than which bytes carry it.
pub(crate) fn dtd_for(w: u32, h: u32, interlaced: bool) -> [u8; DTD_LEN] {
    let (hblank, vblank) = (w / 8, h / 24 + 8);
    let (htotal, vtotal) = (w + hblank, h + vblank);
    let clock_units = (htotal * vtotal * 60 / 1000) / PIXEL_CLOCK_KHZ;
    let (hs_off, hs_pulse, vs_off, vs_pulse) = (hblank / 4, hblank / 8, 4u32, 5u32);
    let mut d = [0u8; DTD_LEN];
    d[DTD_PIXEL_CLOCK] = clock_units as u8;
    d[DTD_PIXEL_CLOCK + 1] = (clock_units >> 8) as u8;
    d[DTD_HACTIVE_LO] = w as u8;
    d[DTD_HBLANK_LO] = hblank as u8;
    d[DTD_HACTIVE_HBLANK_HI] = (((w >> 8) as u8) << 4) | ((hblank >> 8) as u8 & MASK_LO_NIBBLE);
    d[DTD_VACTIVE_LO] = h as u8;
    d[DTD_VBLANK_LO] = vblank as u8;
    d[DTD_VACTIVE_VBLANK_HI] = (((h >> 8) as u8) << 4) | ((vblank >> 8) as u8 & MASK_LO_NIBBLE);
    d[DTD_HSYNC_OFFSET_LO] = hs_off as u8;
    d[DTD_HSYNC_PULSE_LO] = hs_pulse as u8;
    d[DTD_VSYNC_OFFSET_PULSE_LO] = ((vs_off as u8) << 4) | vs_pulse as u8;
    d[DTD_SYNC_HI] = (((hs_off >> 8) as u8 & 3) << 6) | (((hs_pulse >> 8) as u8 & 3) << 4);
    d[DTD_MISC] = MISC_HSYNC_POSITIVE | MISC_VSYNC_POSITIVE
        | if interlaced { MISC_INTERLACED } else { 0 };
    d
}

/// A base block that also carries an established-timing bitmap and standard
/// timing entries. `est` is the three bitmap bytes; `std` the 2-byte pairs.
pub(crate) fn build_full(rev: u8, dtds: &[&[u8; DTD_LEN]], est: [u8; 3], std: &[(u8, u8)])
    -> [u8; BLOCK_LEN] {
    let mut b = build(rev, 0, dtds);
    b[OFF_ESTABLISHED..OFF_ESTABLISHED + est.len()].copy_from_slice(&est);
    for (i, (b0, b1)) in std.iter().enumerate().take(STD_TIMING_COUNT) {
        let at = OFF_STANDARD + i * STD_TIMING_LEN;
        b[at] = *b0;
        b[at + 1] = *b1;
    }
    b[OFF_CHECKSUM] = 0;
    b[OFF_CHECKSUM] = computed_checksum(&b);
    b
}

/// A revision-4 base block naming exactly one preferred size.
pub(crate) fn block_for(w: u32, h: u32, interlaced: bool) -> [u8; BLOCK_LEN] {
    build(4, 0, &[&dtd_for(w, h, interlaced)])
}

#[test]
fn the_size_fixture_round_trips_through_the_decoder() {
    for (w, h) in [(1920u32, 1080u32), (1366, 768), (2560, 1440), (800, 600)] {
        let m = preferred_mode(&block_for(w, h, false)).expect("a valid preferred timing");
        assert_eq!((m.hdisplay as u32, m.vdisplay as u32), (w, h));
    }
    let m = preferred_mode(&block_for(1920, 1080, true)).unwrap();
    assert_ne!(m.flags & DRM_MODE_FLAG_INTERLACE, 0);
}

#[test]
fn header_and_checksum_gate_validity() {
    let good = fhd_block();
    assert_eq!(header_score(&good), HEADER.len() as u32);
    assert!(header_is_valid(&good));
    assert!(checksum_is_valid(&good));
    assert!(is_valid(&good));

    let mut bad_header = good;
    bad_header[1] = 0x00;
    assert_eq!(header_score(&bad_header), HEADER.len() as u32 - 1);
    assert!(!is_valid(&bad_header));

    let mut bad_sum = good;
    bad_sum[OFF_CHECKSUM] ^= 0xff;
    assert!(!checksum_is_valid(&bad_sum));
    assert!(!is_valid(&bad_sum));
}

#[test]
fn checksum_makes_the_block_sum_to_zero() {
    let b = fhd_block();
    let total = b.iter().fold(0u8, |acc, byte| acc.wrapping_add(*byte));
    assert_eq!(total, 0, "an EDID block's bytes sum to zero modulo 256");
}

#[test]
fn a_short_blob_is_not_a_block() {
    let b = fhd_block();
    assert!(base_block(&b[..BLOCK_LEN - 1]).is_none());
    assert!(!is_valid(&b[..BLOCK_LEN - 1]));
    assert!(base_block(&b).is_some());
}

#[test]
fn extension_bytes_past_the_base_block_are_ignored() {
    let base = fhd_block();
    let mut long = [0u8; BLOCK_LEN * 2];
    long[..BLOCK_LEN].copy_from_slice(&base);
    // Trailing bytes belong to an extension block and must not affect the
    // base block's checksum or its preferred mode.
    assert!(is_valid(&long));
    let (a, b) = (preferred_mode(&long).unwrap(), preferred_mode(&base).unwrap());
    assert_eq!((a.hdisplay, a.vdisplay, a.clock), (b.hdisplay, b.vdisplay, b.clock));
}

#[test]
fn detailed_timing_decodes_every_packed_field() {
    let t = decode(&DTD_1920X1080).expect("a pixel timing decodes");
    assert_eq!(t.clock_khz, 148_500);
    assert_eq!((t.hactive, t.vactive), (1920, 1080));
    assert_eq!((t.hblank, t.vblank), (280, 45));
    assert_eq!((t.hsync_offset, t.hsync_pulse), (88, 44));
    assert_eq!((t.vsync_offset, t.vsync_pulse), (4, 5));
    assert_eq!((t.width_mm, t.height_mm), (531, 299));
    assert!(t.hsync_positive && t.vsync_positive);
    assert!(!t.interlaced);
}

#[test]
fn high_bits_of_wide_fields_come_from_the_packed_nibbles() {
    // Raise the vertical low byte so the masked value still clears MIN_ACTIVE.
    let mut d = DTD_1920X1080;
    d[DTD_VACTIVE_LO] = 0x80;
    assert_eq!(decode(&d).unwrap().vactive, 0x480);
    // Drop the high nibbles and the decoded actives lose exactly 0x700/0x400,
    // while the blanking values packed in the low nibbles are unchanged.
    d[DTD_HACTIVE_HBLANK_HI] &= MASK_LO_NIBBLE;
    d[DTD_VACTIVE_VBLANK_HI] &= MASK_LO_NIBBLE;
    let t = decode(&d).expect("still a timing");
    assert_eq!(t.hactive, 1920 - 0x700);
    assert_eq!(t.vactive, 0x480 - 0x400);
    assert_eq!((t.hblank, t.vblank), (280, 45));
}

#[test]
fn two_bit_sync_high_fields_extend_each_sync_value() {
    let mut d = DTD_1920X1080;
    // Set every 2-bit high field: hsync offset/pulse gain 0x300 each, vsync
    // offset/pulse gain 0x30 each.
    d[DTD_SYNC_HI] = MASK_HSYNC_OFFSET_HI | MASK_HSYNC_PULSE_HI
        | MASK_VSYNC_OFFSET_HI | MASK_VSYNC_PULSE_HI;
    let t = decode(&d).expect("still a timing");
    assert_eq!(t.hsync_offset, 88 + 0x300);
    assert_eq!(t.hsync_pulse, 44 + 0x300);
    assert_eq!(t.vsync_offset, 4 + 0x30);
    assert_eq!(t.vsync_pulse, 5 + 0x30);
}

#[test]
fn a_zero_pixel_clock_is_a_display_descriptor_not_a_timing() {
    let mut d = DTD_1920X1080;
    d[DTD_PIXEL_CLOCK] = 0;
    d[DTD_PIXEL_CLOCK + 1] = 0;
    assert!(!is_timing(&d));
    assert!(decode(&d).is_none());
}

#[test]
fn unusable_descriptors_are_rejected() {
    // Active area below the minimum.
    let mut tiny = DTD_1920X1080;
    tiny[DTD_HACTIVE_HBLANK_HI] &= MASK_LO_NIBBLE;
    tiny[DTD_HACTIVE_LO] = (MIN_ACTIVE - 1) as u8;
    assert!(decode(&tiny).is_none());

    // Stereo descriptors describe no single scanout mode.
    let mut stereo = DTD_1920X1080;
    stereo[DTD_MISC] |= MISC_STEREO;
    assert!(decode(&stereo).is_none());

    // A zero sync pulse cannot drive a display.
    let mut no_hsync = DTD_1920X1080;
    no_hsync[DTD_HSYNC_PULSE_LO] = 0;
    assert!(decode(&no_hsync).is_none());
    let mut no_vsync = DTD_1920X1080;
    no_vsync[DTD_VSYNC_OFFSET_PULSE_LO] &= !MASK_LO_NIBBLE;
    assert!(decode(&no_vsync).is_none());
}

#[test]
fn mode_carries_the_timing_totals_and_sync_polarity() {
    let m = decode(&DTD_1920X1080).unwrap().to_mode();
    assert_eq!(m.clock, 148_500);
    assert_eq!((m.hdisplay, m.vdisplay), (1920, 1080));
    assert_eq!((m.htotal, m.vtotal), (2200, 1125));
    assert_eq!((m.hsync_start, m.hsync_end), (2008, 2052));
    assert_eq!((m.vsync_start, m.vsync_end), (1084, 1089));
    assert_eq!(m.flags & (DRM_MODE_FLAG_PHSYNC | DRM_MODE_FLAG_PVSYNC),
        DRM_MODE_FLAG_PHSYNC | DRM_MODE_FLAG_PVSYNC);
    assert_eq!(m.flags & DRM_MODE_FLAG_INTERLACE, 0);
    assert_eq!(m.vrefresh, 60);
    assert_eq!(&m.name[..9], b"1920x1080");
}

#[test]
fn negative_sync_polarity_is_reported_as_such() {
    let mut d = DTD_1920X1080;
    d[DTD_MISC] &= !(MISC_HSYNC_POSITIVE | MISC_VSYNC_POSITIVE);
    let m = decode(&d).unwrap().to_mode();
    assert_eq!(m.flags & (DRM_MODE_FLAG_NHSYNC | DRM_MODE_FLAG_NVSYNC),
        DRM_MODE_FLAG_NHSYNC | DRM_MODE_FLAG_NVSYNC);
    assert_eq!(m.flags & (DRM_MODE_FLAG_PHSYNC | DRM_MODE_FLAG_PVSYNC), 0);
}

#[test]
fn an_interlaced_descriptor_is_flagged_and_counts_fields() {
    let mut d = DTD_1920X1080;
    d[DTD_MISC] |= MISC_INTERLACED;
    let t = decode(&d).unwrap();
    assert!(t.interlaced);
    let m = t.to_mode();
    assert_ne!(m.flags & DRM_MODE_FLAG_INTERLACE, 0);
    assert_eq!(m.vrefresh, 120, "an interlaced mode retires two fields per frame");
}

#[test]
fn sync_end_is_clamped_to_its_total() {
    // A descriptor whose sync runs past the end of the line is inconsistent;
    // the total is the largest value a scanout can honour.
    let mut d = DTD_1920X1080;
    d[DTD_HSYNC_OFFSET_LO] = 0xff;
    d[DTD_HSYNC_PULSE_LO] = 0xff;
    let m = decode(&d).unwrap().to_mode();
    assert_eq!(m.hsync_end, m.htotal);
}

#[test]
fn vrefresh_rounds_to_nearest() {
    assert_eq!(vrefresh(148_500, 2200, 1125, false), 60);
    assert_eq!(vrefresh(0, 2200, 1125, false), 0);
    assert_eq!(vrefresh(148_500, 0, 0, false), 0, "no division by a zero total");
}

#[test]
fn preferred_mode_needs_a_valid_block_and_the_preferred_marking() {
    let rev4 = fhd_block();
    let m = preferred_mode(&rev4).expect("revision 4 always marks the first descriptor");
    assert_eq!((m.hdisplay, m.vdisplay), (1920, 1080));
    assert_ne!(m.ty & DRM_MODE_TYPE_PREFERRED, 0);

    // Before revision 4 the feature byte says whether the first descriptor is
    // the preferred timing.
    let rev3_unmarked = build(3, 0, &[&DTD_1920X1080]);
    assert!(preferred_mode(&rev3_unmarked).is_none());
    let rev3_marked = build(3, FEATURE_PREFERRED_TIMING, &[&DTD_1920X1080]);
    assert!(preferred_mode(&rev3_marked).is_some());

    // A corrupt block yields nothing even though its descriptor decodes.
    let mut corrupt = rev4;
    corrupt[OFF_CHECKSUM] ^= 0xff;
    assert!(preferred_mode(&corrupt).is_none());
    assert!(preferred_mode(&[]).is_none());
}

#[test]
fn a_display_descriptor_in_the_first_slot_yields_no_preferred_mode() {
    // Monitor-name and range-limit descriptors carry a zero pixel clock.
    let name_descriptor = [0u8; DTD_LEN];
    let b = build(4, 0, &[&name_descriptor, &DTD_1920X1080]);
    assert!(is_valid(&b));
    assert!(preferred_mode(&b).is_none());
}

#[test]
fn descriptor_slots_are_bounded() {
    let b = fhd_block();
    assert!(descriptor(&b, 0).is_some());
    assert!(descriptor(&b, DTD_COUNT - 1).is_some());
    assert!(descriptor(&b, DTD_COUNT).is_none());
    assert_eq!(descriptor(&b, 0).unwrap(), &DTD_1920X1080[..]);
}

#[test]
fn version_and_revision_are_read_from_their_own_bytes() {
    let b = build(3, 0, &[&DTD_1920X1080]);
    assert_eq!(version(&b), 1);
    assert_eq!(revision(&b), 3);
    assert!(!first_detailed_is_preferred(&b));
    assert!(first_detailed_is_preferred(&fhd_block()));
}
