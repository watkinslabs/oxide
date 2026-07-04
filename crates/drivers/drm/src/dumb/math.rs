use super::*;

const DUMB_PITCH_ALIGN: u64 = 64;
pub(super) const DUMB_PAGE_SIZE: u64 = 4096;

pub fn dumb_pitch(width: u32, bpp: u32) -> Option<u32> {
    if bpp == 0 || bpp > 32 || (bpp % 8) != 0 { return None; }
    let bytes_per_px = bpp / 8;
    let raw = (width as u64).checked_mul(bytes_per_px as u64)?;
    let aligned = align_up_u64(raw, DUMB_PITCH_ALIGN);
    if aligned > u32::MAX as u64 { return None; }
    Some(aligned as u32)
}

pub fn dumb_size(pitch: u32, height: u32) -> Option<u64> {
    let raw = (pitch as u64).checked_mul(height as u64)?;
    Some(align_up_u64(raw, DUMB_PAGE_SIZE))
}

pub fn align_up_u64(v: u64, a: u64) -> u64 { (v + (a - 1)) & !(a - 1) }

pub fn order_for_bytes(bytes: u64) -> u8 {
    let frames = (bytes + (DUMB_PAGE_SIZE - 1)) / DUMB_PAGE_SIZE;
    if frames <= 1 { return 0; }
    let mut o = 0u8;
    let mut cap = 1u64;
    while cap < frames { cap <<= 1; o += 1; }
    o
}

pub fn format_supported(fourcc: u32) -> bool {
    fourcc == DRM_FORMAT_XRGB8888 || fourcc == DRM_FORMAT_ARGB8888
}

pub fn format_cpp(fourcc: u32) -> Option<u32> {
    match fourcc {
        DRM_FORMAT_XRGB8888 | DRM_FORMAT_ARGB8888 => Some(4),
        _ => None,
    }
}

pub fn fb_plane_fits_buf(
    width: u32,
    height: u32,
    pixel_format: u32,
    pitch: u32,
    offset: u32,
    buf: &DumbBuf,
) -> bool {
    if width == 0 || height == 0 {
        return false;
    }
    let Some(cpp) = format_cpp(pixel_format) else {
        return false;
    };
    let row_bytes = match (width as u64).checked_mul(cpp as u64) {
        Some(bytes) => bytes,
        None => return false,
    };
    if (pitch as u64) < row_bytes {
        return false;
    }
    let last_row = match (pitch as u64).checked_mul((height - 1) as u64) {
        Some(bytes) => bytes,
        None => return false,
    };
    let span = match last_row.checked_add(row_bytes) {
        Some(bytes) => bytes,
        None => return false,
    };
    match (offset as u64).checked_add(span) {
        Some(end) => end <= buf.size,
        None => false,
    }
}

pub const DRM_MMAP_COOKIE_BASE: u64 = 1u64 << 48;
pub(super) const DRM_MMAP_COOKIE_HANDLE_SHIFT: u64 = 12;
pub(super) const DRM_MMAP_COOKIE_HANDLE_MASK: u64 = (u32::MAX as u64) << DRM_MMAP_COOKIE_HANDLE_SHIFT;
pub(super) const DRM_MMAP_COOKIE_VALID_MASK: u64 = DRM_MMAP_COOKIE_BASE | DRM_MMAP_COOKIE_HANDLE_MASK;

pub fn cookie_for(handle: u32) -> u64 {
    DRM_MMAP_COOKIE_BASE | ((handle as u64) << DRM_MMAP_COOKIE_HANDLE_SHIFT)
}

pub fn handle_of_cookie(cookie: u64) -> Option<u32> {
    if (cookie & DRM_MMAP_COOKIE_BASE) != DRM_MMAP_COOKIE_BASE { return None; }
    if (cookie & !DRM_MMAP_COOKIE_VALID_MASK) != 0 { return None; }
    let handle = ((cookie & DRM_MMAP_COOKIE_HANDLE_MASK) >> DRM_MMAP_COOKIE_HANDLE_SHIFT) as u32;
    if handle == 0 { return None; }
    Some(handle)
}
