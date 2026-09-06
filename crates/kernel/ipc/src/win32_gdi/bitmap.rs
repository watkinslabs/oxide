//! Canonical device-dependent bitmap objects and their pattern projection; 31fk§4.
use alloc::vec::Vec;
use super::{GdiError, GdiManager, MAX_SURFACE_PIXELS};

pub const TYPE_BITMAP: u32 = 0x09_0000;
/// Either extent past this is refused before every other admission check.
const MAX_EXTENT: i32 = 0x7ff_ffff;
/// Device-dependent bitmaps are single-plane; any other count is refused.
const PLANES: u32 = 1;
/// Storage budget shared with device-context surfaces, expressed in bytes.
const MAX_BITMAP_BYTES: i64 = MAX_SURFACE_PIXELS as i64 * 4;
const BITS_PER_BYTE: i64 = 8;
/// Stored rows are 32-bit aligned; caller-supplied rows are 16-bit aligned.
const DIB_ALIGN_BITS: i64 = 31;
const DIB_ALIGN_MASK: i64 = !3;
const BITMAP_ALIGN_BITS: i64 = 15;
const BITMAP_ALIGN_MASK: i64 = !1;
const RGB_MASK: u32 = 0x00ff_ffff;
/// Monochrome pattern index 0 takes the destination text color, 1 its background.
const MONO_TEXT_INDEX: u8 = 0;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bitmap { pub width: i32, pub height: i32, pub planes: u32, pub bpp: u32, pub width_bytes: i32,
    stride: i32, bits: Vec<u8>, deleted: bool }

/// Immutable copy of one bitmap's bits, taken when a pattern brush is created.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BitmapPattern { pub width: i32, pub height: i32, pub bpp: u32, stride: i32, bits: Vec<u8> }

/// Row stride of stored bitmap bits: 32-bit aligned. # C: O(1)
pub fn dib_stride(width: i32, bpp: u32) -> Option<i32> {
    let bits = i64::from(width).checked_mul(i64::from(bpp))?.checked_add(DIB_ALIGN_BITS)?;
    i32::try_from((bits / BITS_PER_BYTE) & DIB_ALIGN_MASK).ok()
}

/// Row stride of caller-supplied bitmap bits: 16-bit aligned. # C: O(1)
pub fn bitmap_stride(width: i32, bpp: u32) -> Option<i32> {
    let bits = i64::from(width).checked_mul(i64::from(bpp))?.checked_add(BITMAP_ALIGN_BITS)?;
    i32::try_from((bits / BITS_PER_BYTE) & BITMAP_ALIGN_MASK).ok()
}

/// Windows stores only 1, 4, 8, 16, 24 and 32 bits per pixel; a request rounds
/// up to the next stored depth and anything deeper is refused. # C: O(1)
pub fn normalize_bpp(bpp: u32) -> Option<u32> {
    match bpp { 1 => Some(1), 0..=4 => Some(4), 5..=8 => Some(8), 9..=16 => Some(16), 17..=24 => Some(24), 25..=32 => Some(32), _ => None }
}

impl Bitmap {
    /// # C: O(1)
    pub fn bits(&self) -> &[u8] { &self.bits }
}

impl BitmapPattern {
    /// Resolve one pattern cell to XRGB. A monochrome device-dependent pattern
    /// carries no color table, so its two indices name the destination's text
    /// and background colors; indexed depths have no palette object here and
    /// resolve to nothing. # C: O(1)
    pub fn pixel(&self, x: i32, y: i32, text: u32, background: u32) -> Option<u32> {
        if x < 0 || y < 0 || x >= self.width || y >= self.height { return None; }
        let row = (y as usize).checked_mul(self.stride as usize)?;
        match self.bpp {
            1 => {
                let byte = *self.bits.get(row + (x as usize) / 8)?;
                let index = (byte >> (7 - (x as usize % 8))) & 1;
                Some(if index == MONO_TEXT_INDEX { text & RGB_MASK } else { background & RGB_MASK })
            }
            16 => {
                let at = row + (x as usize) * 2;
                let value = u32::from(u16::from_le_bytes([*self.bits.get(at)?, *self.bits.get(at + 1)?]));
                Some(expand555(value))
            }
            24 => {
                let at = row + (x as usize) * 3;
                let (b, g, r) = (*self.bits.get(at)?, *self.bits.get(at + 1)?, *self.bits.get(at + 2)?);
                Some((u32::from(r) << 16) | (u32::from(g) << 8) | u32::from(b))
            }
            32 => {
                let at = row + (x as usize) * 4;
                let value = u32::from_le_bytes([*self.bits.get(at)?, *self.bits.get(at + 1)?, *self.bits.get(at + 2)?, *self.bits.get(at + 3)?]);
                Some(value & RGB_MASK)
            }
            _ => None,
        }
    }
}

/// Five-bit channels replicate their high bits into the low bits. # C: O(1)
fn expand555(value: u32) -> u32 {
    let channel = |field: u32| { let scaled = (field & 0x1f) << 3; scaled | (scaled >> 5) };
    (channel(value >> 10) << 16) | (channel(value >> 5) << 8) | channel(value)
}

impl GdiManager {
    /// Admission order is extent, zero extent, plane count, depth, then storage
    /// size; caller bits are 16-bit aligned rows copied into 32-bit aligned
    /// storage. # C: O(width*height)
    pub fn create_bitmap(&mut self, width: i32, height: i32, planes: u32, bpp: u32, bits: Option<&[u8]>) -> Result<u32, GdiError> {
        if width > MAX_EXTENT || height > MAX_EXTENT { return Err(GdiError::InvalidDimensions); }
        if width == 0 || height == 0 { return Err(GdiError::InvalidDimensions); }
        let width = width.checked_abs().ok_or(GdiError::InvalidDimensions)?;
        let height = height.checked_abs().ok_or(GdiError::InvalidDimensions)?;
        if planes != PLANES { return Err(GdiError::InvalidDimensions); }
        let bpp = normalize_bpp(bpp).ok_or(GdiError::InvalidDimensions)?;
        // Row strides are computed in 64 bits: the width bound above admits
        // products that do not fit a 32-bit stride at 32 bits per pixel.
        let stride = dib_stride(width, bpp).ok_or(GdiError::InvalidDimensions)?;
        let width_bytes = bitmap_stride(width, bpp).ok_or(GdiError::InvalidDimensions)?;
        let size = i64::from(stride).checked_mul(i64::from(height)).ok_or(GdiError::InvalidDimensions)?;
        if size > MAX_BITMAP_BYTES { return Err(GdiError::InvalidDimensions); }
        let mut storage = Vec::new();
        storage.try_reserve(size as usize).map_err(|_| GdiError::HandleLimit)?;
        storage.resize(size as usize, 0);
        if let Some(bits) = bits { copy_rows(&mut storage, stride, width_bytes, height, bits); }
        let handle = self.allocate(TYPE_BITMAP)?;
        self.bitmaps.try_reserve(1).map_err(|_| GdiError::HandleLimit)?;
        self.bitmaps.push((handle, Bitmap { width, height, planes, bpp, width_bytes, stride, bits: storage, deleted: false }));
        Ok(handle)
    }

    /// # C: O(bitmaps)
    pub fn bitmap(&self, handle: u32) -> Result<&Bitmap, GdiError> {
        self.bitmaps.iter().find(|(id, _)| *id == handle).map(|(_, bitmap)| bitmap).ok_or(GdiError::NoSuchObject)
    }

    /// Take the immutable bits copy a pattern brush owns for its lifetime. # C: O(width*height)
    pub fn bitmap_pattern(&self, handle: u32) -> Result<BitmapPattern, GdiError> {
        let bitmap = self.bitmap(handle)?;
        let mut bits = Vec::new();
        bits.try_reserve(bitmap.bits.len()).map_err(|_| GdiError::HandleLimit)?;
        bits.extend_from_slice(&bitmap.bits);
        Ok(BitmapPattern { width: bitmap.width, height: bitmap.height, bpp: bitmap.bpp, stride: bitmap.stride, bits })
    }

    /// A bitmap named by a live pattern brush keeps its slot until that brush
    /// goes; the brush owns its own copy of the bits. # C: O(bitmaps)
    pub fn delete_bitmap(&mut self, handle: u32) -> Result<(), GdiError> {
        let bitmap = &mut self.bitmaps.iter_mut().find(|(id, _)| *id == handle).ok_or(GdiError::NoSuchObject)?.1;
        bitmap.deleted = true;
        self.bitmaps.retain(|(_, bitmap)| !bitmap.deleted);
        Ok(())
    }

    /// # C: O(bitmaps)
    pub fn contains_bitmap(&self, handle: u32) -> bool { self.bitmaps.iter().any(|(id, _)| *id == handle) }
}

/// Caller rows are 16-bit aligned and stored rows 32-bit aligned; a short
/// caller buffer fills the rows it covers and leaves the rest zeroed.
/// # C: O(width*height)
fn copy_rows(storage: &mut [u8], stride: i32, width_bytes: i32, height: i32, bits: &[u8]) {
    if width_bytes <= 0 || stride <= 0 { return; }
    let (stride, width_bytes) = (stride as usize, width_bytes as usize);
    let span = width_bytes.min(stride);
    for row in 0..height as usize {
        let (source, target) = (row * width_bytes, row * stride);
        if source + span > bits.len() || target + span > storage.len() { return; }
        storage[target..target + span].copy_from_slice(&bits[source..source + span]);
    }
}

#[cfg(test)]
#[path = "tests/bitmap.rs"]
mod tests;
