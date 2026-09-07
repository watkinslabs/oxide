//! Device-independent bitmap headers, admission and sections; 31fk§4.
use alloc::vec::Vec;
use super::{Bitmap, GdiError, GdiManager, Rgb, dib_stride, pixels};

/// Header compressions this owner names.
pub const BI_RGB: u32 = 0;
pub const BI_RLE8: u32 = 1;
pub const BI_RLE4: u32 = 2;
pub const BI_BITFIELDS: u32 = 3;
/// Colour-table interpretations a caller selects.
pub const DIB_RGB_COLORS: u32 = 0;
pub const DIB_PAL_COLORS: u32 = 1;
pub const DIB_PAL_INDICES: u32 = 2;
/// The two header shapes a caller may supply, by their leading size word.
pub const CORE_HEADER_BYTES: u32 = 12;
pub const INFO_HEADER_BYTES: u32 = 40;
/// One colour-table entry occupies four bytes in an info header, three in a core header.
pub const RGBQUAD_BYTES: usize = 4;
pub const RGBTRIPLE_BYTES: usize = 3;
/// Channel masks occupy three double words where a colour table would start.
pub const BITFIELD_BYTES: usize = 12;
const MAX_TABLE_DEPTH: u32 = 8;
/// A planes/depth product past this is refused when planes is not one.
const MAX_PLANAR_BITS: u32 = 16;

/// Sanitized header: `biSize` is normalized away, the image size is the real
/// one, and `masks` carries the channel fields the depth decodes with.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DibHeader { pub width: i32, pub height: i32, pub planes: u16, pub bit_count: u16,
    pub compression: u32, pub size_image: u32, pub x_ppm: i32, pub y_ppm: i32,
    pub clr_used: u32, pub clr_important: u32, pub masks: [u32; 3] }

fn word(bytes: &[u8], at: usize) -> u32 { u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]) }
fn short(bytes: &[u8], at: usize) -> u16 { u16::from_le_bytes([bytes[at], bytes[at + 1]]) }

impl DibHeader {
    /// Decode either header shape. A core header carries unsigned extents, no
    /// compression and no colour counts. # C: O(1)
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < CORE_HEADER_BYTES as usize { return None; }
        let size = word(bytes, 0);
        let mut header = if size == CORE_HEADER_BYTES {
            Self { width: i32::from(short(bytes, 4)), height: i32::from(short(bytes, 6)),
                planes: short(bytes, 8), bit_count: short(bytes, 10), compression: BI_RGB,
                size_image: 0, x_ppm: 0, y_ppm: 0, clr_used: 0, clr_important: 0, masks: [0; 3] }
        } else if size >= INFO_HEADER_BYTES && bytes.len() >= INFO_HEADER_BYTES as usize {
            Self { width: word(bytes, 4) as i32, height: word(bytes, 8) as i32, planes: short(bytes, 12),
                bit_count: short(bytes, 14), compression: word(bytes, 16), size_image: word(bytes, 20),
                x_ppm: word(bytes, 24) as i32, y_ppm: word(bytes, 28) as i32, clr_used: word(bytes, 32),
                clr_important: word(bytes, 36), masks: [0; 3] }
        } else { return None; };
        if header.compression == BI_RGB || header.compression == BI_BITFIELDS {
            header.size_image = header.image_size()?;
        }
        Some(header)
    }

    /// Rows at the 32-bit-aligned stride, for the absolute height. # C: O(1)
    pub fn image_size(&self) -> Option<u32> {
        let stride = dib_stride(self.width, u32::from(self.bit_count))?;
        u32::try_from(i64::from(stride).checked_mul(i64::from(self.height.checked_abs()?))?).ok()
    }

    /// A negative header height stores its rows top down. # C: O(1)
    pub fn top_down(&self) -> bool { self.height < 0 }

    /// Admission mirrors the reference's format check: positive width, non-zero
    /// height, a plane count, a depth the stride arithmetic survives, and a
    /// compression the depth allows. # C: O(1)
    pub fn is_valid(&self, allow_compression: bool) -> bool {
        if self.width <= 0 || self.height == 0 { return false; }
        if allow_compression && (self.compression == BI_RLE4 || self.compression == BI_RLE8) {
            if self.height < 0 || self.size_image == 0 { return false; }
            return u32::from(self.bit_count) == if self.compression == BI_RLE4 { 4 } else { 8 };
        }
        if self.planes == 0 || self.bit_count == 0 { return false; }
        let bits = u32::from(self.bit_count);
        if u32::MAX / bits < (self.width as u32) { return false; }
        let Some(stride) = dib_stride(self.width, bits) else { return false; };
        if stride <= 0 { return false; }
        let Some(height) = self.height.checked_abs() else { return false; };
        if u32::MAX / (stride as u32) < (height as u32) { return false; }
        match bits {
            1 | 4 | 8 | 24 => self.compression == BI_RGB,
            16 | 32 => self.compression == BI_BITFIELDS || self.compression == BI_RGB,
            _ => false,
        }
    }

    /// Colour-table entries a sanitized header reports: the full depth range,
    /// clamped from a caller count, and none above eight bits. # C: O(1)
    pub fn color_table_len(&self) -> u32 {
        let bits = u32::from(self.bit_count);
        if self.compression == BI_BITFIELDS || bits > MAX_TABLE_DEPTH { return 0; }
        1u32.checked_shl(bits).unwrap_or(0)
    }

    /// Entries the caller actually supplied, before the table is zero-padded
    /// to the depth's full range. # C: O(1)
    pub fn supplied_colors(&self) -> u32 {
        let max = self.color_table_len();
        if max == 0 { return 0; }
        if self.clr_used == 0 { max } else { self.clr_used.min(max) }
    }
}

impl GdiManager {
    /// A DIB section is a bitmap whose header, colour table and channel masks
    /// come from the caller. Sixteen-bit `BI_RGB` becomes explicit 5-5-5
    /// bitfields; an explicit bitfield set with a zero mask is refused, as is
    /// one requested with palette colour indices. # C: O(width*height)
    pub fn create_dib_section(&mut self, header: DibHeader, usage: u32, table: &[Rgb], masks: [u32; 3]) -> Result<u32, GdiError> {
        if usage > DIB_PAL_COLORS { return Err(GdiError::InvalidDimensions); }
        if !header.is_valid(false) { return Err(GdiError::InvalidDimensions); }
        if header.planes != 1 && u32::from(header.planes) * u32::from(header.bit_count) > MAX_PLANAR_BITS {
            return Err(GdiError::InvalidDimensions);
        }
        let bpp = u32::from(header.bit_count);
        let mut header = header;
        if bpp == 16 && header.compression == BI_RGB {
            header.compression = BI_BITFIELDS;
            header.masks = pixels::DEFAULT_555;
        } else if header.compression == BI_BITFIELDS {
            if usage == DIB_PAL_COLORS { return Err(GdiError::InvalidDimensions); }
            if masks.iter().any(|mask| *mask == 0) { return Err(GdiError::InvalidDimensions); }
            header.masks = masks;
        } else { header.masks = super::default_masks(bpp); }
        let stride = dib_stride(header.width, bpp).ok_or(GdiError::InvalidDimensions)?;
        let width_bytes = stride;
        let height = header.height.checked_abs().ok_or(GdiError::InvalidDimensions)?;
        let size = i64::from(stride).checked_mul(i64::from(height)).ok_or(GdiError::InvalidDimensions)?;
        if size > super::MAX_BITMAP_BYTES { return Err(GdiError::InvalidDimensions); }
        let mut storage = Vec::new();
        storage.try_reserve(size as usize).map_err(|_| GdiError::HandleLimit)?;
        storage.resize(size as usize, 0);
        let entries = header.color_table_len();
        let mut stored = Vec::new();
        stored.try_reserve_exact(entries as usize).map_err(|_| GdiError::HandleLimit)?;
        for index in 0..entries as usize { stored.push(table.get(index).copied().unwrap_or_default()); }
        header.clr_used = entries;
        self.push_bitmap(Bitmap { width: header.width, height, planes: u32::from(header.planes), bpp,
            width_bytes, size: (0, 0), dib: Some(header), stride, bits: storage, table: stored, deleted: false })
    }

    /// Read the colour table of the DIB selected into one device context. # C: O(DCs + count)
    pub fn get_dib_color_table(&self, dc: u32, start: u32, count: u32, out: &mut [Rgb]) -> u32 {
        let Some(bitmap) = self.dc_bitmap(dc).and_then(|handle| self.bitmap(handle).ok()) else { return 0; };
        let Some(header) = bitmap.dib.as_ref() else { return 0; };
        if start >= header.clr_used { return 0; }
        let count = count.min(header.clr_used - start);
        for index in 0..count.min(out.len() as u32) {
            out[index as usize] = bitmap.table.get((start + index) as usize).copied().unwrap_or_default();
        }
        count
    }

    /// Replace colour-table entries of the DIB selected into one device
    /// context; the stored fourth byte is always cleared. # C: O(DCs + count)
    pub fn set_dib_color_table(&mut self, dc: u32, start: u32, count: u32, colors: &[Rgb]) -> u32 {
        let Some(handle) = self.dc_bitmap(dc) else { return 0; };
        let Ok(bitmap) = self.bitmap_mut(handle) else { return 0; };
        let Some(used) = bitmap.dib.as_ref().map(|header| header.clr_used) else { return 0; };
        if start >= used { return 0; }
        let count = count.min(used - start);
        for index in 0..count {
            let Some(entry) = colors.get(index as usize) else { break; };
            bitmap.table[(start + index) as usize] = *entry;
        }
        count
    }
}

#[cfg(test)]
#[path = "../tests/bitmap_dib.rs"]
mod tests;
