//! Established timings: a bitmap naming modes the standard itself defines.
//!
//! Bytes 35..37 of the base block are a bitmap; each set bit names one mode
//! from the standard's fixed established-timing set, with the timings the
//! standard gives it. Bit 16 lives in the manufacturer-reserved byte's top bit.

use super::layout::*;
use crate::uapi::{
    DrmModeModeinfo, DRM_MODE_FLAG_INTERLACE, DRM_MODE_FLAG_NHSYNC, DRM_MODE_FLAG_NVSYNC,
    DRM_MODE_FLAG_PHSYNC, DRM_MODE_FLAG_PVSYNC, DRM_MODE_TYPE_DRIVER,
};
use alloc::vec::Vec;

/// `(clock kHz, hdisplay, hsync_start, hsync_end, htotal,
///   vdisplay, vsync_start, vsync_end, vtotal, flags)`.
type Est = (u32, u16, u16, u16, u16, u16, u16, u16, u16, u32);

const PP: u32 = DRM_MODE_FLAG_PHSYNC | DRM_MODE_FLAG_PVSYNC;
const NN: u32 = DRM_MODE_FLAG_NHSYNC | DRM_MODE_FLAG_NVSYNC;
const NP: u32 = DRM_MODE_FLAG_NHSYNC | DRM_MODE_FLAG_PVSYNC;
const PPI: u32 = PP | DRM_MODE_FLAG_INTERLACE;

/// Established timings in bitmap order: index `i` is the mode bit `i` names.
const EST_MODES: [Est; EST_TIMING_COUNT] = [
    ( 40_000,  800,  840,  968, 1056,  600,  601,  605,  628, PP),  // 800x600@60
    ( 36_000,  800,  824,  896, 1024,  600,  601,  603,  625, PP),  // 800x600@56
    ( 31_500,  640,  656,  720,  840,  480,  481,  484,  500, NN),  // 640x480@75
    ( 31_500,  640,  664,  704,  832,  480,  489,  492,  520, NN),  // 640x480@72
    ( 30_240,  640,  704,  768,  864,  480,  483,  486,  525, NN),  // 640x480@67
    ( 25_175,  640,  656,  752,  800,  480,  490,  492,  525, NN),  // 640x480@60
    ( 35_500,  720,  738,  846,  900,  400,  421,  423,  449, NN),  // 720x400@88
    ( 28_320,  720,  738,  846,  900,  400,  412,  414,  449, NP),  // 720x400@70
    (135_000, 1280, 1296, 1440, 1688, 1024, 1025, 1028, 1066, PP),  // 1280x1024@75
    ( 78_750, 1024, 1040, 1136, 1312,  768,  769,  772,  800, PP),  // 1024x768@75
    ( 75_000, 1024, 1048, 1184, 1328,  768,  771,  777,  806, NN),  // 1024x768@70
    ( 65_000, 1024, 1048, 1184, 1344,  768,  771,  777,  806, NN),  // 1024x768@60
    ( 44_900, 1024, 1032, 1208, 1264,  768,  768,  776,  817, PPI), // 1024x768i@43
    ( 57_284,  832,  864,  928, 1152,  624,  625,  628,  667, NN),  // 832x624@75
    ( 49_500,  800,  816,  896, 1056,  600,  601,  604,  625, PP),  // 800x600@75
    ( 50_000,  800,  856,  976, 1040,  600,  637,  643,  666, PP),  // 800x600@72
    (108_000, 1152, 1216, 1344, 1600,  864,  865,  868,  900, PP),  // 1152x864@75
];

/// Bitmap of established timings the block claims. # C: O(1)
pub fn bits(block: &[u8]) -> u32 {
    let b = |off: usize| block.get(off).copied().unwrap_or(0) as u32;
    b(OFF_ESTABLISHED)
        | (b(OFF_ESTABLISHED + 1) << 8)
        | ((b(OFF_ESTABLISHED + 2) & EST_MFG_RSVD_BIT16) << EST_MFG_RSVD_SHIFT)
}

/// Mode named by bit `i`, or `None` when the bit names none. # C: O(1)
pub fn mode_at(i: usize) -> Option<DrmModeModeinfo> {
    let &(clock, hdisplay, hsync_start, hsync_end, htotal,
          vdisplay, vsync_start, vsync_end, vtotal, flags) = EST_MODES.get(i)?;
    let mut name = [0u8; 32];
    crate::core_api::write_mode_name(&mut name, hdisplay as u32, vdisplay as u32);
    Some(DrmModeModeinfo {
        clock, hdisplay, hsync_start, hsync_end, htotal, hskew: 0,
        vdisplay, vsync_start, vsync_end, vtotal, vscan: 0,
        vrefresh: super::dtd::vrefresh(clock, htotal as u32, vtotal as u32,
            flags & DRM_MODE_FLAG_INTERLACE != 0),
        flags, ty: DRM_MODE_TYPE_DRIVER, name,
    })
}

/// Every established timing the block claims. # C: O(EST_TIMING_COUNT)
pub fn modes(block: &[u8]) -> Vec<DrmModeModeinfo> {
    let set = bits(block);
    let mut out = Vec::new();
    for i in 0..EST_TIMING_COUNT {
        if set & (1 << i) == 0 { continue; }
        if let Some(m) = mode_at(i) { out.push(m); }
    }
    out
}
