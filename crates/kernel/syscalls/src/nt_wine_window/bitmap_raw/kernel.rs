//! Fetch caller bits outside every owner lock, then create the canonical object.
use alloc::vec::Vec;
use super::Operation;

/// Handle-returning calls answer NULL on failure; no status code reaches the
/// caller. # C: canonical creation cost plus one bounded usercopy
pub(crate) fn route(ordinal: u64, args: &[u64]) -> Option<u64> {
    let operation = super::decode(ordinal, args)?;
    Some(match operation {
        Operation::CreateBitmap { width, height, planes, bpp, bits } => {
            let fetched = super::caller_bits_len(width, height, planes, bpp, bits).and_then(|len| fetch(bits, len));
            crate::nt_gdi::create_bitmap_for_current(width, height, planes, bpp, fetched.as_deref()).map(u64::from).unwrap_or(0)
        }
        Operation::CreatePatternBrush { bitmap } => crate::nt_gdi::create_pattern_brush_for_current(bitmap).map(u64::from).unwrap_or(0),
        Operation::OpenDisplayDc => {
            let Some((width, height)) = super::super::metrics::virtual_screen_size(crate::nt_compositor::monitors_current) else { return Some(0); };
            crate::nt_gdi::create_display_dc_for_current(width, height).map(u64::from).unwrap_or(0)
        }
        Operation::NoDriverDc => 0,
    })
}

/// A faulting bits pointer leaves the bitmap zero-filled rather than refusing
/// it: the reference stores the bits after the object already exists.
/// # C: O(bytes)
fn fetch(address: u64, len: usize) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes.try_reserve(len).ok()?;
    bytes.resize(len, 0);
    uaccess::copy_from_user(&mut bytes, address).ok()?;
    Some(bytes)
}
