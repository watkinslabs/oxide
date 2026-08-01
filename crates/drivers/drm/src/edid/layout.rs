//! VESA E-EDID base-block byte layout: offsets, sizes, and bit masks.
//!
//! Every number here is a position or a mask in the 128-byte base block as the
//! E-EDID standard defines it. Nothing in this file decides anything; `block`
//! and `dtd` own the decisions.

/// Bytes in one EDID block (base block and every extension block).
pub const BLOCK_LEN: usize = 128;

/// The fixed 8-byte pattern every base block opens with.
pub const HEADER: [u8; 8] = [0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00];
pub const OFF_HEADER: usize = 0;

pub const OFF_VERSION: usize = 18;
pub const OFF_REVISION: usize = 19;
pub const OFF_FEATURES: usize = 24;

/// Feature byte bit 1: the first detailed descriptor carries the preferred
/// timing. Mandatory from revision 4 onward, where the bit means native format.
pub const FEATURE_PREFERRED_TIMING: u8 = 1 << 1;

/// Revision from which the first detailed descriptor is always the preferred
/// timing regardless of the feature bit.
pub const REVISION_PREFERRED_ALWAYS: u8 = 4;

/// Three-byte bitmap of the established timings the display claims.
pub const OFF_ESTABLISHED: usize = 35;
/// Bits the established-timing bitmap defines, one mode each.
pub const EST_TIMING_COUNT: usize = 17;
/// The last established-timing bit lives in the manufacturer-reserved byte.
pub const EST_MFG_RSVD_BIT16: u32 = 0x80;
pub const EST_MFG_RSVD_SHIFT: u32 = 9;

/// Eight 2-byte standard timing entries.
pub const OFF_STANDARD: usize = 38;
pub const STD_TIMING_COUNT: usize = 8;
pub const STD_TIMING_LEN: usize = 2;
/// Horizontal size is stored as `(hsize - STD_HSIZE_BASE) / STD_HSIZE_STEP`.
pub const STD_HSIZE_STEP: u32 = 8;
pub const STD_HSIZE_BASE: u32 = 248;
pub const STD_ASPECT_MASK: u8 = 0xc0;
pub const STD_ASPECT_SHIFT: u32 = 6;
/// From this revision the zero aspect code means 16:10 rather than square.
pub const STD_ASPECT_16_10_FROM_REVISION: u8 = 3;
pub const STD_VFREQ_MASK: u8 = 0x3f;
pub const STD_VFREQ_BASE: u32 = 60;
/// Byte pairs the standard reserves to mean an unused standard timing slot.
pub const STD_UNUSED_PAIRS: [(u8, u8); 3] = [(0x00, 0x00), (0x01, 0x01), (0x20, 0x20)];

/// Four 18-byte descriptors, the first of which may be the preferred timing.
pub const OFF_DETAILED: usize = 54;
pub const DTD_LEN: usize = 18;
pub const DTD_COUNT: usize = 4;

/// Last byte of a block; the block's bytes sum to zero modulo 256.
pub const OFF_CHECKSUM: usize = BLOCK_LEN - 1;

// ---- Detailed timing descriptor, offsets relative to the descriptor ----

/// Pixel clock, little-endian, in units of `PIXEL_CLOCK_KHZ`. Zero marks the
/// descriptor as a display descriptor rather than a timing.
pub const DTD_PIXEL_CLOCK: usize = 0;
pub const DTD_HACTIVE_LO: usize = 2;
pub const DTD_HBLANK_LO: usize = 3;
pub const DTD_HACTIVE_HBLANK_HI: usize = 4;
pub const DTD_VACTIVE_LO: usize = 5;
pub const DTD_VBLANK_LO: usize = 6;
pub const DTD_VACTIVE_VBLANK_HI: usize = 7;
pub const DTD_HSYNC_OFFSET_LO: usize = 8;
pub const DTD_HSYNC_PULSE_LO: usize = 9;
pub const DTD_VSYNC_OFFSET_PULSE_LO: usize = 10;
pub const DTD_SYNC_HI: usize = 11;
pub const DTD_WIDTH_MM_LO: usize = 12;
pub const DTD_HEIGHT_MM_LO: usize = 13;
pub const DTD_WIDTH_HEIGHT_MM_HI: usize = 14;
pub const DTD_MISC: usize = 17;

/// One pixel-clock unit, in kHz.
pub const PIXEL_CLOCK_KHZ: u32 = 10;

// Nibble/2-bit packings of the high bits, per the descriptor's field map.
pub const MASK_HI_NIBBLE: u8 = 0xf0;
pub const MASK_LO_NIBBLE: u8 = 0x0f;
pub const SHIFT_HI_NIBBLE_TO_BYTE: u32 = 4;
pub const SHIFT_LO_NIBBLE_TO_BYTE: u32 = 8;
pub const MASK_HSYNC_OFFSET_HI: u8 = 0xc0;
pub const SHIFT_HSYNC_OFFSET_HI: u32 = 2;
pub const MASK_HSYNC_PULSE_HI: u8 = 0x30;
pub const SHIFT_HSYNC_PULSE_HI: u32 = 4;
pub const MASK_VSYNC_OFFSET_HI: u8 = 0x0c;
pub const SHIFT_VSYNC_OFFSET_HI: u32 = 2;
pub const MASK_VSYNC_PULSE_HI: u8 = 0x03;
pub const SHIFT_VSYNC_PULSE_HI: u32 = 4;
pub const SHIFT_VSYNC_OFFSET_LO: u32 = 4;

// Misc byte bits.
pub const MISC_HSYNC_POSITIVE: u8 = 1 << 1;
pub const MISC_VSYNC_POSITIVE: u8 = 1 << 2;
pub const MISC_STEREO: u8 = 1 << 5;
pub const MISC_INTERLACED: u8 = 1 << 7;

/// Timings below this in either axis are rejected: no real display mode is
/// smaller, so such a descriptor is corrupt rather than tiny.
pub const MIN_ACTIVE: u32 = 64;
