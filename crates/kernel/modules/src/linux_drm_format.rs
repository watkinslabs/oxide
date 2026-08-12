use super::*;

const XRGB8888: u32 = 0x3432_5258;
const ARGB8888: u32 = 0x3432_5241;
const RGB565: u32 = 0x3631_4752;
const FORMAT_SIZE: usize = 24;
const FORMAT_PLANES_OFF: usize = 5;
const FORMAT_BYTES_PER_BLOCK_OFF: usize = 6;
const FORMAT_BLOCK_WIDTH_OFF: usize = 10;
const FORMAT_BLOCK_HEIGHT_OFF: usize = 14;

static XRGB: [u8; FORMAT_SIZE] = [0x58, 0x52, 0x32, 0x34, 0, 1, 4, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0];
static ARGB: [u8; FORMAT_SIZE] = [0x41, 0x52, 0x32, 0x34, 0, 1, 4, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0];
static RGB: [u8; FORMAT_SIZE] = [0x52, 0x47, 0x31, 0x36, 0, 1, 2, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0];

pub(super) fn export_symbols() { crate::symtab::export("drm_format_info", drm_format_info as *const () as usize, false); crate::symtab::export("drm_format_info_min_pitch", drm_format_info_min_pitch as *const () as usize, false); }

/// Return static metadata for one supported scanout format. # C: O(1)
pub(super) extern "C" fn drm_format_info(format: u32) -> *const c_void { match format { XRGB8888 => XRGB.as_ptr().cast(), ARGB8888 => ARGB.as_ptr().cast(), RGB565 => RGB.as_ptr().cast(), _ => core::ptr::null() } }

/// Compute block-rounded minimum pitch for one format plane. # C: O(1)
pub(super) extern "C" fn drm_format_info_min_pitch(info: *const u8, plane: i32, width: u32) -> u64 { if info.is_null() || plane < 0 || plane >= unsafe { *info.add(FORMAT_PLANES_OFF) as i32 } { return 0; } let plane = plane as usize; unsafe { let bytes = *info.add(FORMAT_BYTES_PER_BLOCK_OFF + plane) as u64; let blocks = (*info.add(FORMAT_BLOCK_WIDTH_OFF + plane) as u64).max(1) * (*info.add(FORMAT_BLOCK_HEIGHT_OFF + plane) as u64).max(1); (width as u64).saturating_mul(bytes).saturating_add(blocks - 1) / blocks } }
