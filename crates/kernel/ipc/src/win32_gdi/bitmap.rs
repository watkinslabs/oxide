//! Canonical bitmap objects and their pattern projection; 31fk§4.
//! Module manifest: `pixels.rs` owns depth-wise pixel access and colour
//! resolution; `bits.rs` owns the caller bit transfers and the assigned
//! dimension; `dib.rs` owns DIB sections and their colour tables;
//! `select.rs` owns binding one bitmap to a memory device context;
//! `compatible.rs` owns bitmaps shaped after a device context;
//! `transfer.rs` owns device-independent image transfers.
use alloc::vec::Vec;
use super::{GdiError, GdiManager, MAX_SURFACE_PIXELS};
#[path = "bitmap/pixels.rs"]
pub mod pixels;
#[path = "bitmap/bits.rs"]
mod bits;
#[path = "bitmap/dib.rs"]
mod dib;
#[path = "bitmap/select.rs"]
mod select;
#[path = "bitmap/compatible.rs"]
mod compatible;
#[path = "bitmap/transfer.rs"]
mod transfer;
pub use transfer::{DibImage, transfer_band};
pub use dib::{DibHeader, BI_RGB, BI_RLE8, BI_RLE4, BI_BITFIELDS, DIB_RGB_COLORS, DIB_PAL_COLORS, DIB_PAL_INDICES,
    CORE_HEADER_BYTES, INFO_HEADER_BYTES, RGBQUAD_BYTES, RGBTRIPLE_BYTES, BITFIELD_BYTES};
pub use pixels::Rgb;

pub const TYPE_BITMAP: u32 = 0x09_0000;
/// Either extent past this is refused before every other admission check.
const MAX_EXTENT: i32 = 0x7ff_ffff;
/// Device-dependent bitmaps are single-plane; any other count is refused.
const PLANES: u32 = 1;
/// Storage budget shared with device-context surfaces, expressed in bytes.
pub const MAX_BITMAP_BYTES: i64 = MAX_SURFACE_PIXELS as i64 * 4;
const BITS_PER_BYTE: i64 = 8;
/// Stored rows are 32-bit aligned; caller-supplied rows are 16-bit aligned.
const DIB_ALIGN_BITS: i64 = 31;
const DIB_ALIGN_MASK: i64 = !3;
const BITMAP_ALIGN_BITS: i64 = 15;
const BITMAP_ALIGN_MASK: i64 = !1;
const RGB_MASK: u32 = 0x00ff_ffff;
/// Monochrome index 0 takes the destination text colour, 1 its background.
const MONO_TEXT_INDEX: u32 = 0;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bitmap { pub width: i32, pub height: i32, pub planes: u32, pub bpp: u32, pub width_bytes: i32,
    /// Assigned by the caller; the object is created with a zero dimension.
    pub size: (i32, i32),
    /// A DIB section carries its header, colour table and channel masks; a
    /// device-dependent bitmap carries none of them.
    pub dib: Option<DibHeader>,
    stride: i32, bits: Vec<u8>, table: Vec<Rgb>, deleted: bool }

/// Immutable copy of one bitmap's bits, taken when a pattern brush is created.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BitmapPattern { pub width: i32, pub height: i32, pub bpp: u32, stride: i32, bits: Vec<u8>, table: Vec<Rgb> }

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

/// Channel masks a depth uses when its header names none. # C: O(1)
pub fn default_masks(bpp: u32) -> [u32; 3] {
    if bpp == 16 { pixels::DEFAULT_555 } else { pixels::DEFAULT_888 }
}

impl Bitmap {
    /// # C: O(1)
    pub fn bits(&self) -> &[u8] { &self.bits }
    /// # C: O(1)
    pub fn stride(&self) -> i32 { self.stride }
    /// # C: O(1)
    pub fn color_table(&self) -> &[Rgb] { &self.table }
    /// Mutable bits beside the immutable colour table they resolve through:
    /// one borrow of the sole storage this bitmap owns. # C: O(1)
    pub fn storage_mut(&mut self) -> (&mut [u8], &[Rgb]) { (&mut self.bits, &self.table) }
    /// Channel masks this bitmap decodes with. # C: O(1)
    pub fn masks(&self) -> [u32; 3] { self.dib.as_ref().map_or_else(|| default_masks(self.bpp), |dib| dib.masks) }
    /// XRGB colour of one pixel, or none outside the bitmap. # C: O(1)
    pub fn pixel(&self, x: i32, y: i32) -> Option<u32> {
        if x >= self.width || y >= self.height { return None; }
        let raw = pixels::raw_pixel(&self.bits, self.stride, self.bpp, x, y)?;
        Some(resolve(self.bpp, raw, &self.table, self.masks()))
    }
    /// Store one XRGB colour, encoding it for this depth. # C: O(table)
    pub fn put_pixel(&mut self, x: i32, y: i32, color: u32) -> Option<()> {
        if x >= self.width || y >= self.height { return None; }
        let raw = encode(self.bpp, color, &self.table, self.masks());
        pixels::put_raw_pixel(&mut self.bits, self.stride, self.bpp, x, y, raw)
    }
}

/// Resolve a stored value to XRGB: a colour table index at indexed depths, the
/// masked channels otherwise. An indexed value with no table entry resolves to
/// black, which is what an all-zero colour table gives. # C: O(1)
pub fn resolve(bpp: u32, raw: u32, table: &[Rgb], masks: [u32; 3]) -> u32 {
    if pixels::is_indexed(bpp) { return table.get(raw as usize).map_or(0, |entry| entry.xrgb()); }
    pixels::masked_to_xrgb(raw, masks)
}

/// Encode XRGB for storage at one depth. # C: O(table)
pub fn encode(bpp: u32, color: u32, table: &[Rgb], masks: [u32; 3]) -> u32 {
    if pixels::is_indexed(bpp) { return pixels::nearest_index(table, color); }
    pixels::xrgb_to_masked(color, masks)
}

impl BitmapPattern {
    /// Resolve one pattern cell to XRGB. A monochrome pattern carries no
    /// colour table, so its two indices name the destination's text and
    /// background colours. # C: O(table)
    pub fn pixel(&self, x: i32, y: i32, text: u32, background: u32) -> Option<u32> {
        if x < 0 || y < 0 || x >= self.width || y >= self.height { return None; }
        let raw = pixels::raw_pixel(&self.bits, self.stride, self.bpp, x, y)?;
        if self.bpp == 1 && self.table.is_empty() {
            return Some(if raw == MONO_TEXT_INDEX { text & RGB_MASK } else { background & RGB_MASK });
        }
        Some(resolve(self.bpp, raw, &self.table, default_masks(self.bpp)))
    }
}

impl GdiManager {
    /// Admission order is extent, zero extent, plane count, depth, then storage
    /// size; caller bits are 16-bit aligned rows copied into 32-bit aligned
    /// storage. A device-dependent bitmap of an indexed depth takes the
    /// default colour table for that depth. # C: O(width*height)
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
        let table = if pixels::is_indexed(bpp) { pixels::default_table(bpp).ok_or(GdiError::HandleLimit)? } else { Vec::new() };
        self.push_bitmap(Bitmap { width, height, planes, bpp, width_bytes, size: (0, 0), dib: None,
            stride, bits: storage, table, deleted: false })
    }

    pub(super) fn push_bitmap(&mut self, bitmap: Bitmap) -> Result<u32, GdiError> {
        let handle = self.allocate(TYPE_BITMAP)?;
        self.bitmaps.try_reserve(1).map_err(|_| GdiError::HandleLimit)?;
        self.bitmaps.push((handle, bitmap));
        Ok(handle)
    }

    /// # C: O(bitmaps)
    pub fn bitmap(&self, handle: u32) -> Result<&Bitmap, GdiError> {
        self.bitmaps.iter().find(|(id, _)| *id == handle).map(|(_, bitmap)| bitmap).ok_or(GdiError::NoSuchObject)
    }

    /// # C: O(bitmaps)
    pub fn bitmap_mut(&mut self, handle: u32) -> Result<&mut Bitmap, GdiError> {
        self.bitmaps.iter_mut().find(|(id, _)| *id == handle).map(|(_, bitmap)| bitmap).ok_or(GdiError::NoSuchObject)
    }

    /// Take the immutable bits copy a pattern brush owns for its lifetime.
    /// A monochrome device-dependent bitmap hands over no colour table so the
    /// pattern keeps resolving through the destination's text colours.
    /// # C: O(width*height)
    pub fn bitmap_pattern(&self, handle: u32) -> Result<BitmapPattern, GdiError> {
        let bitmap = self.bitmap(handle)?;
        let mut bits = Vec::new();
        bits.try_reserve_exact(bitmap.bits.len()).map_err(|_| GdiError::HandleLimit)?;
        bits.extend_from_slice(&bitmap.bits);
        let mut table = Vec::new();
        if !(bitmap.bpp == 1 && bitmap.dib.is_none()) {
            table.try_reserve_exact(bitmap.table.len()).map_err(|_| GdiError::HandleLimit)?;
            table.extend_from_slice(&bitmap.table);
        }
        Ok(BitmapPattern { width: bitmap.width, height: bitmap.height, bpp: bitmap.bpp, stride: bitmap.stride, bits, table })
    }

    /// Duplicate one bitmap object. An icon query hands the caller bitmaps it
    /// owns and deletes, never the icon object's own. Rows are repacked from
    /// the stored stride to the caller stride `create_bitmap` expects.
    /// # C: O(width*height)
    pub fn copy_bitmap(&mut self, handle: u32) -> Result<u32, GdiError> {
        let source = self.bitmap(handle)?;
        let (width, height, planes, bpp) = (source.width, source.height, source.planes, source.bpp);
        let (stride, width_bytes) = (source.stride as usize, source.width_bytes as usize);
        let mut packed = Vec::new();
        packed.try_reserve(width_bytes.saturating_mul(height as usize)).map_err(|_| GdiError::HandleLimit)?;
        for row in 0..height as usize {
            let start = row.saturating_mul(stride);
            let end = start.saturating_add(width_bytes).min(source.bits.len());
            if start >= end { break; }
            packed.extend_from_slice(&source.bits[start..end]);
        }
        self.create_bitmap(width, height, planes, bpp, Some(&packed))
    }

    /// A pattern brush holds its own copy of the bits, so deletion frees the
    /// bitmap immediately even while such a brush still paints. A bitmap
    /// selected into a device context survives until that context releases it.
    /// # C: O(bitmaps + DCs)
    pub fn delete_bitmap(&mut self, handle: u32) -> Result<(), GdiError> {
        let bitmap = &mut self.bitmaps.iter_mut().find(|(id, _)| *id == handle).ok_or(GdiError::NoSuchObject)?.1;
        bitmap.deleted = true;
        self.collect_deleted_bitmaps();
        Ok(())
    }

    /// Deferred release for bitmaps a device context still selects. # C: O(bitmaps * DCs)
    pub fn collect_deleted_bitmaps(&mut self) {
        let dcs = &self.dcs;
        self.bitmaps.retain(|(id, bitmap)| !bitmap.deleted || dcs.iter().any(|(_, dc)| dc.bitmap == Some(*id)));
    }
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
