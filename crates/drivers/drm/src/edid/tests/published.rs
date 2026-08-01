//! Which modes a base block publishes: established bitmap, standard timing
//! entries, and the combined ranked list.

use super::super::layout::*;
use super::super::*;
use super::{build_full, dtd_for};
use crate::uapi::DRM_MODE_TYPE_PREFERRED;

const NO_EST: [u8; 3] = [0, 0, 0];
const NO_STD: &[(u8, u8)] = &[];

/// Standard timing byte pair for a horizontal size, aspect code, and rate.
fn std_pair(hsize: u32, aspect: u8, refresh_hz: u32) -> (u8, u8) {
    (((hsize - STD_HSIZE_BASE) / STD_HSIZE_STEP) as u8,
     (aspect << STD_ASPECT_SHIFT) | (refresh_hz - STD_VFREQ_BASE) as u8)
}

fn find(modes: &[crate::uapi::DrmModeModeinfo], w: u16, h: u16) -> Option<&crate::uapi::DrmModeModeinfo> {
    modes.iter().find(|m| m.hdisplay == w && m.vdisplay == h)
}

#[test]
fn the_established_bitmap_names_modes_with_the_standards_own_timings() {
    // Bit 11 is 1024x768 at 60 Hz.
    let mut est = NO_EST;
    est[1] = 1 << (11 - 8);
    let b = build_full(4, &[], est, NO_STD);
    assert_eq!(established_bits(&b), 1 << 11);
    let modes = established_modes(&b);
    assert_eq!(modes.len(), 1);
    assert_eq!((modes[0].hdisplay, modes[0].vdisplay), (1024, 768));
    assert_eq!(modes[0].clock, 65_000);
    assert_eq!((modes[0].htotal, modes[0].vtotal), (1344, 806));
    assert_eq!(modes[0].vrefresh, 60);
}

#[test]
fn the_last_established_bit_lives_in_the_reserved_byte() {
    let mut est = NO_EST;
    est[2] = 0x80;
    let b = build_full(4, &[], est, NO_STD);
    assert_eq!(established_bits(&b), 1 << 16);
    let modes = established_modes(&b);
    assert_eq!(modes.len(), 1);
    assert_eq!((modes[0].hdisplay, modes[0].vdisplay), (1152, 864));
    assert_eq!(modes[0].vrefresh, 75);
    // The reserved byte's other bits name nothing.
    let mut other = NO_EST;
    other[2] = 0x7f;
    assert_eq!(established_bits(&build_full(4, &[], other, NO_STD)), 0);
}

#[test]
fn every_established_bit_that_is_set_yields_one_mode() {
    let b = build_full(4, &[], [0xff, 0xff, 0x80], NO_STD);
    assert_eq!(established_modes(&b).len(), EST_TIMING_COUNT);
    assert!(established_modes(&build_full(4, &[], NO_EST, NO_STD)).is_empty());
}

#[test]
fn a_standard_timing_entry_names_a_size_from_its_aspect_code() {
    // Aspect codes: 0 = 16:10 from revision 3, 1 = 4:3, 2 = 5:4, 3 = 16:9.
    assert_eq!(standard_size(std_pair(1280, 0, 60).0, std_pair(1280, 0, 60).1, 4), Some((1280, 800)));
    assert_eq!(standard_size(std_pair(1024, 1, 60).0, std_pair(1024, 1, 60).1, 4), Some((1024, 768)));
    assert_eq!(standard_size(std_pair(1280, 2, 60).0, std_pair(1280, 2, 60).1, 4), Some((1280, 1024)));
    assert_eq!(standard_size(std_pair(1920, 3, 60).0, std_pair(1920, 3, 60).1, 4), Some((1920, 1080)));
    // Before revision 3 the zero aspect code means square pixels.
    let (b0, b1) = std_pair(1280, 0, 60);
    assert_eq!(standard_size(b0, b1, 2), Some((1280, 1280)));
}

#[test]
fn a_standard_timing_entrys_refresh_rate_is_its_low_six_bits_plus_sixty() {
    assert_eq!(standard_refresh(0x00), 60);
    assert_eq!(standard_refresh(0x0f), 75);
    assert_eq!(standard_refresh(0xc0 | 0x1e), 90, "the aspect bits are not part of the rate");
}

#[test]
fn the_reserved_byte_pairs_name_no_standard_timing() {
    for (b0, b1) in [(0x00u8, 0x00u8), (0x01, 0x01), (0x20, 0x20)] {
        assert_eq!(standard_size(b0, b1, 4), None);
    }
    // The whole array unused: a block with no standard timings publishes none.
    let b = build_full(4, &[], NO_EST, &[(0x01, 0x01); STD_TIMING_COUNT]);
    assert!(standard_modes(&b).is_empty());
}

#[test]
fn standard_timings_become_modes_at_the_rate_they_assert() {
    let b = build_full(4, &[], NO_EST,
        &[std_pair(1920, 3, 60), std_pair(1280, 0, 75), (0x01, 0x01)]);
    let modes = standard_modes(&b);
    assert_eq!(modes.len(), 2);
    assert_eq!((modes[0].hdisplay, modes[0].vdisplay, modes[0].vrefresh), (1920, 1080, 60));
    assert_eq!((modes[1].hdisplay, modes[1].vdisplay, modes[1].vrefresh), (1280, 800, 75));
    // A size asserted without timings still gets a coherent mode.
    assert!(modes[0].htotal > modes[0].hdisplay);
    assert!(modes[0].clock > 0);
}

#[test]
fn every_detailed_descriptor_is_published_not_only_the_first() {
    let b = build_full(4, &[&dtd_for(1920, 1080, false), &dtd_for(1280, 720, false),
        &dtd_for(2560, 1440, false)], NO_EST, NO_STD);
    let modes = detailed_modes(&b);
    assert_eq!(modes.len(), 3);
    assert_eq!((modes[0].hdisplay, modes[0].vdisplay), (1920, 1080));
    assert_eq!((modes[1].hdisplay, modes[1].vdisplay), (1280, 720));
    assert_eq!((modes[2].hdisplay, modes[2].vdisplay), (2560, 1440));
    // Only the first is the preferred timing.
    assert_ne!(modes[0].ty & DRM_MODE_TYPE_PREFERRED, 0);
    for m in modes.iter().skip(1) { assert_eq!(m.ty & DRM_MODE_TYPE_PREFERRED, 0); }
}

#[test]
fn all_modes_ranks_detailed_then_established_then_standard() {
    let mut est = NO_EST;
    est[1] = 1 << (11 - 8);                       // 1024x768@60
    let b = build_full(4, &[&dtd_for(2560, 1440, false)], est,
        &[std_pair(1920, 3, 60), (0x01, 0x01)]);  // 1920x1080@60
    let modes = all_modes(&b);
    assert_eq!((modes[0].hdisplay, modes[0].vdisplay), (2560, 1440));
    assert_ne!(modes[0].ty & DRM_MODE_TYPE_PREFERRED, 0);
    assert!(find(&modes, 1024, 768).is_some(), "the established bitmap is published");
    assert!(find(&modes, 1920, 1080).is_some(), "the standard timings are published");
    // Ranking: the established entry precedes the standard one.
    let est_at = modes.iter().position(|m| m.hdisplay == 1024).unwrap();
    let std_at = modes.iter().position(|m| m.hdisplay == 1920).unwrap();
    assert!(est_at < std_at);
}

#[test]
fn a_size_asserted_twice_is_published_once() {
    // The same size and rate named by a detailed descriptor and a standard
    // timing entry: the detailed one wins, with its real timings.
    let b = build_full(4, &[&dtd_for(1920, 1080, false)], NO_EST,
        &[std_pair(1920, 3, 60), (0x01, 0x01)]);
    let modes = all_modes(&b);
    let n = modes.iter().filter(|m| m.hdisplay == 1920 && m.vdisplay == 1080).count();
    assert_eq!(n, 1);
    assert_eq!(modes[0].htotal, 1920 + 1920 / 8, "the detailed descriptor's own total");
}

#[test]
fn an_invalid_block_publishes_nothing() {
    let mut b = build_full(4, &[&dtd_for(1920, 1080, false)], [0xff, 0xff, 0x80], NO_STD);
    b[OFF_CHECKSUM] ^= 0xff;
    assert!(all_modes(&b).is_empty());
    assert!(all_modes(&[]).is_empty());
}
