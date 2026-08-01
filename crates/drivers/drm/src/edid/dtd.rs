//! Detailed timing descriptor decoding: 18 packed bytes to a mode.

use super::block;
use super::layout::*;
use crate::uapi::{
    DrmModeModeinfo, DRM_MODE_FLAG_INTERLACE, DRM_MODE_FLAG_NHSYNC, DRM_MODE_FLAG_NVSYNC,
    DRM_MODE_FLAG_PHSYNC, DRM_MODE_FLAG_PVSYNC, DRM_MODE_TYPE_DRIVER, DRM_MODE_TYPE_PREFERRED,
};

/// One decoded detailed timing, in the units a mode uses: pixel clock in kHz,
/// everything else in pixels or lines.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Timing {
    pub clock_khz: u32,
    pub hactive: u32,
    pub hblank: u32,
    pub hsync_offset: u32,
    pub hsync_pulse: u32,
    pub vactive: u32,
    pub vblank: u32,
    pub vsync_offset: u32,
    pub vsync_pulse: u32,
    pub width_mm: u32,
    pub height_mm: u32,
    pub hsync_positive: bool,
    pub vsync_positive: bool,
    pub interlaced: bool,
}

fn byte(d: &[u8], off: usize) -> u32 { d.get(off).copied().unwrap_or(0) as u32 }

fn raw_pixel_clock(d: &[u8]) -> u32 {
    byte(d, DTD_PIXEL_CLOCK) | (byte(d, DTD_PIXEL_CLOCK + 1) << 8)
}

/// A descriptor carrying pixel timings rather than display data. The two are
/// told apart by the pixel clock field: zero means display descriptor.
/// # C: O(1)
pub fn is_timing(d: &[u8]) -> bool { raw_pixel_clock(d) != 0 }

/// Decode one 18-byte descriptor, or `None` when it is a display descriptor or
/// its timings are unusable (undersized active area, stereo, or a zero sync
/// pulse, all of which name a corrupt or unshowable descriptor).
/// # C: O(1)
pub fn decode(d: &[u8]) -> Option<Timing> {
    if d.len() < DTD_LEN || !is_timing(d) { return None; }
    let hi = |off: usize, mask: u8, shift: u32| (byte(d, off) & mask as u32) << shift;
    let hactive = hi(DTD_HACTIVE_HBLANK_HI, MASK_HI_NIBBLE, SHIFT_HI_NIBBLE_TO_BYTE)
        | byte(d, DTD_HACTIVE_LO);
    let hblank = hi(DTD_HACTIVE_HBLANK_HI, MASK_LO_NIBBLE, SHIFT_LO_NIBBLE_TO_BYTE)
        | byte(d, DTD_HBLANK_LO);
    let vactive = hi(DTD_VACTIVE_VBLANK_HI, MASK_HI_NIBBLE, SHIFT_HI_NIBBLE_TO_BYTE)
        | byte(d, DTD_VACTIVE_LO);
    let vblank = hi(DTD_VACTIVE_VBLANK_HI, MASK_LO_NIBBLE, SHIFT_LO_NIBBLE_TO_BYTE)
        | byte(d, DTD_VBLANK_LO);
    let hsync_offset = hi(DTD_SYNC_HI, MASK_HSYNC_OFFSET_HI, SHIFT_HSYNC_OFFSET_HI)
        | byte(d, DTD_HSYNC_OFFSET_LO);
    let hsync_pulse = hi(DTD_SYNC_HI, MASK_HSYNC_PULSE_HI, SHIFT_HSYNC_PULSE_HI)
        | byte(d, DTD_HSYNC_PULSE_LO);
    let vsync_offset = hi(DTD_SYNC_HI, MASK_VSYNC_OFFSET_HI, SHIFT_VSYNC_OFFSET_HI)
        | (byte(d, DTD_VSYNC_OFFSET_PULSE_LO) >> SHIFT_VSYNC_OFFSET_LO);
    let vsync_pulse = hi(DTD_SYNC_HI, MASK_VSYNC_PULSE_HI, SHIFT_VSYNC_PULSE_HI)
        | (byte(d, DTD_VSYNC_OFFSET_PULSE_LO) & MASK_LO_NIBBLE as u32);
    let misc = byte(d, DTD_MISC) as u8;
    if hactive < MIN_ACTIVE || vactive < MIN_ACTIVE { return None; }
    if misc & MISC_STEREO != 0 { return None; }
    if hsync_pulse == 0 || vsync_pulse == 0 { return None; }
    let width_mm = byte(d, DTD_WIDTH_MM_LO)
        | hi(DTD_WIDTH_HEIGHT_MM_HI, MASK_HI_NIBBLE, SHIFT_HI_NIBBLE_TO_BYTE);
    let height_mm = byte(d, DTD_HEIGHT_MM_LO)
        | hi(DTD_WIDTH_HEIGHT_MM_HI, MASK_LO_NIBBLE, SHIFT_LO_NIBBLE_TO_BYTE);
    Some(Timing {
        clock_khz: raw_pixel_clock(d) * PIXEL_CLOCK_KHZ,
        hactive, hblank, hsync_offset, hsync_pulse,
        vactive, vblank, vsync_offset, vsync_pulse,
        width_mm, height_mm,
        hsync_positive: misc & MISC_HSYNC_POSITIVE != 0,
        vsync_positive: misc & MISC_VSYNC_POSITIVE != 0,
        interlaced: misc & MISC_INTERLACED != 0,
    })
}

/// Refresh rate in Hz, rounded to nearest, from the mode's clock and totals.
/// An interlaced mode retires two fields per frame, so its field rate is twice
/// the frame rate. # C: O(1)
pub fn vrefresh(clock_khz: u32, htotal: u32, vtotal: u32, interlaced: bool) -> u32 {
    let den = (htotal as u64) * (vtotal as u64);
    if den == 0 { return 0; }
    let mut num = (clock_khz as u64) * 1000;
    if interlaced { num *= 2; }
    ((num + den / 2) / den) as u32
}

impl Timing {
    /// Mode described by this timing. Sync ends are clamped to their totals:
    /// a descriptor placing a sync past the end of the line or frame is
    /// self-inconsistent and the total is the value a scanout can honour.
    /// # C: O(1)
    pub fn to_mode(&self) -> DrmModeModeinfo {
        let htotal = self.hactive + self.hblank;
        let vtotal = self.vactive + self.vblank;
        let hsync_start = self.hactive + self.hsync_offset;
        let hsync_end = (hsync_start + self.hsync_pulse).min(htotal);
        let vsync_start = self.vactive + self.vsync_offset;
        let vsync_end = (vsync_start + self.vsync_pulse).min(vtotal);
        let mut flags = if self.hsync_positive { DRM_MODE_FLAG_PHSYNC } else { DRM_MODE_FLAG_NHSYNC };
        flags |= if self.vsync_positive { DRM_MODE_FLAG_PVSYNC } else { DRM_MODE_FLAG_NVSYNC };
        if self.interlaced { flags |= DRM_MODE_FLAG_INTERLACE; }
        let mut name = [0u8; 32];
        crate::core_api::write_mode_name(&mut name, self.hactive, self.vactive);
        DrmModeModeinfo {
            clock: self.clock_khz,
            hdisplay: self.hactive as u16,
            hsync_start: hsync_start as u16,
            hsync_end: hsync_end as u16,
            htotal: htotal as u16,
            hskew: 0,
            vdisplay: self.vactive as u16,
            vsync_start: vsync_start as u16,
            vsync_end: vsync_end as u16,
            vtotal: vtotal as u16,
            vscan: 0,
            vrefresh: vrefresh(self.clock_khz, htotal, vtotal, self.interlaced),
            flags,
            ty: DRM_MODE_TYPE_DRIVER,
            name,
        }
    }
}

/// The display's preferred mode, tagged preferred, or `None` when the blob is
/// not a valid base block, does not mark its first descriptor preferred, or
/// that descriptor does not decode to a usable timing. # C: O(BLOCK_LEN)
pub fn preferred_mode(bytes: &[u8]) -> Option<DrmModeModeinfo> {
    let b = block::base_block(bytes)?;
    if !block::is_valid(b) { return None; }
    if !block::first_detailed_is_preferred(b) { return None; }
    let mut mode = decode(block::descriptor(b, 0)?)?.to_mode();
    mode.ty |= DRM_MODE_TYPE_PREFERRED;
    Some(mode)
}
