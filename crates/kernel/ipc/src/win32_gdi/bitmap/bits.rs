//! Caller bit transfers and the assigned bitmap dimension; 31fk§4.
use super::{GdiError, GdiManager, bitmap_stride};

impl GdiManager {
    /// Bytes one caller buffer holds for a whole bitmap, at the 16-bit-aligned
    /// caller stride. # C: O(bitmaps)
    pub fn bitmap_bits_len(&self, handle: u32) -> Result<i64, GdiError> {
        let bitmap = self.bitmap(handle)?;
        let stride = bitmap_stride(bitmap.width, bitmap.bpp).ok_or(GdiError::InvalidDimensions)?;
        Ok(i64::from(stride) * i64::from(bitmap.height))
    }

    /// Copy stored rows out at the caller's 16-bit-aligned stride. A negative
    /// or oversized request is clamped to the whole bitmap, and the answer is
    /// the byte count actually copied. # C: O(count)
    pub fn get_bitmap_bits(&self, handle: u32, count: i64, out: &mut [u8]) -> Result<i64, GdiError> {
        let max = self.bitmap_bits_len(handle)?;
        let bitmap = self.bitmap(handle)?;
        let dst_stride = bitmap_stride(bitmap.width, bitmap.bpp).ok_or(GdiError::InvalidDimensions)? as usize;
        if dst_stride == 0 { return Ok(0); }
        let count = if count < 0 || count > max { max } else { count } as usize;
        let mut copied = 0usize;
        let mut row = 0usize;
        while copied < count {
            let span = dst_stride.min(count - copied);
            let source = row * bitmap.stride as usize;
            if source + span > bitmap.bits().len() || copied + span > out.len() { break; }
            out[copied..copied + span].copy_from_slice(&bitmap.bits()[source..source + span]);
            copied += span;
            row += 1;
        }
        Ok(count as i64)
    }

    /// Copy caller rows in at the 16-bit-aligned caller stride. A negative
    /// count is taken as its magnitude and the whole bitmap is the ceiling;
    /// a partial final row leaves the rest of that row untouched.
    /// # C: O(count)
    pub fn set_bitmap_bits(&mut self, handle: u32, count: i64, bits: &[u8]) -> Result<i64, GdiError> {
        let max = self.bitmap_bits_len(handle)?;
        let bitmap = self.bitmap_mut(handle)?;
        let src_stride = bitmap_stride(bitmap.width, bitmap.bpp).ok_or(GdiError::InvalidDimensions)? as usize;
        if src_stride == 0 { return Ok(0); }
        let count = count.checked_abs().ok_or(GdiError::InvalidDimensions)?.min(max) as usize;
        let dst_stride = bitmap.stride as usize;
        let mut consumed = 0usize;
        let mut row = 0usize;
        while consumed < count {
            let span = src_stride.min(count - consumed);
            let target = row * dst_stride;
            if target + span > bitmap.bits.len() || consumed + span > bits.len() { break; }
            bitmap.bits[target..target + span].copy_from_slice(&bits[consumed..consumed + span]);
            consumed += span;
            row += 1;
        }
        Ok(count as i64)
    }

    /// The dimension a caller assigned; a new bitmap reports zero. # C: O(bitmaps)
    pub fn bitmap_dimension(&self, handle: u32) -> Result<(i32, i32), GdiError> { Ok(self.bitmap(handle)?.size) }

    /// Assign a dimension, answering the one it replaced. # C: O(bitmaps)
    pub fn set_bitmap_dimension(&mut self, handle: u32, x: i32, y: i32) -> Result<(i32, i32), GdiError> {
        let bitmap = self.bitmap_mut(handle)?;
        Ok(core::mem::replace(&mut bitmap.size, (x, y)))
    }
}

#[cfg(test)]
#[path = "../tests/bitmap_bits.rs"]
mod tests;
