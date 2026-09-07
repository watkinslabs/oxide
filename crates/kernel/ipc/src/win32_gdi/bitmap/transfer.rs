//! Device-independent image transfers: rows in, rows out, and rows drawn
//! straight onto a device context; 31fk§4.
use alloc::vec::Vec;
use super::{DibHeader, GdiError, GdiManager, Rgb, dib_stride, pixels, resolve, encode};
use super::super::{BltCoords, SharedDcColors, StretchMode};

/// One caller image: a header, its colour resolution and its stored bits.
pub struct DibImage<'a> { pub header: &'a DibHeader, pub table: &'a [Rgb], pub masks: [u32; 3], pub bits: &'a [u8] }

impl DibImage<'_> {
    fn stride(&self) -> Option<i32> { dib_stride(self.header.width, u32::from(self.header.bit_count)) }

    /// XRGB colour at one display position, where row zero is the top row
    /// whichever way the image stores its rows. # C: O(1)
    pub fn pixel(&self, x: i32, y: i32) -> Option<u32> {
        let height = self.header.height.checked_abs()?;
        if x < 0 || y < 0 || x >= self.header.width || y >= height { return None; }
        let row = if self.header.top_down() { y } else { height - 1 - y };
        let raw = pixels::raw_pixel(self.bits, self.stride()?, u32::from(self.header.bit_count), x, row)?;
        Some(resolve(u32::from(self.header.bit_count), raw, self.table, self.masks))
    }

    /// Store one XRGB colour at a display position. # C: O(colour table)
    fn put_pixel(&self, bits: &mut [u8], x: i32, y: i32, color: u32) -> Option<()> {
        let height = self.header.height.checked_abs()?;
        if x < 0 || y < 0 || x >= self.header.width || y >= height { return None; }
        let row = if self.header.top_down() { y } else { height - 1 - y };
        let depth = u32::from(self.header.bit_count);
        pixels::put_raw_pixel(bits, self.stride()?, depth, x, row, encode(depth, color, self.table, self.masks))
    }
}

/// Rows one transfer covers and the shift between image and object rows. The
/// caller's first scan line and row count select a band of the image; a
/// bottom-up image counts that band from its last row. # C: O(1)
pub fn transfer_band(top_down: bool, height: i32, start: u32, lines: u32) -> (i32, i32, i32, u32) {
    let start = start.min(i32::MAX as u32) as i32;
    if !top_down {
        let lines = (lines as i64).min(i64::from(height - start).max(0)) as i32;
        let top = if lines < height { height - lines } else { 0 };
        (-start, top, height, lines.max(0) as u32)
    } else {
        let taken = (lines as i64).min(i64::from(height)) as i32;
        (height - lines.min(i32::MAX as u32) as i32 - start, 0, taken, lines)
    }
}

impl GdiManager {
    /// Store caller image rows into a bitmap object, answering the row count
    /// the request named. # C: O(rows*width)
    pub fn put_dib_rows(&mut self, handle: u32, header: &DibHeader, table: &[Rgb], masks: [u32; 3],
        bits: &[u8], start: u32, lines: u32) -> Result<u32, GdiError> {
        let image = DibImage { header, table, masks, bits };
        let height = header.height.checked_abs().ok_or(GdiError::InvalidDimensions)?;
        let (offset, top, bottom, result) = transfer_band(header.top_down(), height, start, lines);
        let bitmap = self.bitmap_mut(handle)?;
        let (width, object_height) = (bitmap.width.min(header.width), bitmap.height);
        for row in top..bottom {
            let Some(target) = row.checked_add(offset) else { continue; };
            if target < 0 || target >= object_height { continue; }
            for column in 0..width {
                let Some(color) = image.pixel(column, row) else { continue; };
                bitmap.put_pixel(column, target, color);
            }
        }
        Ok(result)
    }

    /// Read bitmap rows into a caller image, answering the row count the
    /// request named. # C: O(rows*width)
    pub fn take_dib_rows(&self, handle: u32, header: &DibHeader, table: &[Rgb], masks: [u32; 3],
        out: &mut [u8], start: u32, lines: u32) -> Result<u32, GdiError> {
        let image = DibImage { header, table, masks, bits: &[] };
        let height = header.height.checked_abs().ok_or(GdiError::InvalidDimensions)?;
        let (offset, top, bottom, result) = transfer_band(header.top_down(), height, start, lines);
        let bitmap = self.bitmap(handle)?;
        let width = bitmap.width.min(header.width);
        for row in top..bottom {
            let Some(source) = row.checked_add(offset) else { continue; };
            if source < 0 || source >= bitmap.height { continue; }
            for column in 0..width {
                let Some(color) = bitmap.pixel(column, source) else { continue; };
                image.put_pixel(out, column, row, color);
            }
        }
        Ok(result)
    }

    /// The header a shape query answers for one bitmap: its own extents, its
    /// depth, and the compression that depth reports. # C: O(bitmaps)
    pub fn dib_query_header(&self, handle: u32) -> Result<DibHeader, GdiError> {
        let bitmap = self.bitmap(handle)?;
        let bit_count = u16::try_from(bitmap.bpp).map_err(|_| GdiError::InvalidDimensions)?;
        let compression = if bit_count == 16 || bit_count == 32 { super::BI_BITFIELDS } else { super::BI_RGB };
        let mut header = DibHeader { width: bitmap.width, height: bitmap.height, planes: 1, bit_count,
            compression, size_image: 0, x_ppm: 0, y_ppm: 0,
            clr_used: if pixels::is_indexed(bitmap.bpp) { bitmap.color_table().len() as u32 } else { 0 },
            clr_important: 0, masks: bitmap.masks() };
        header.size_image = header.image_size().ok_or(GdiError::InvalidDimensions)?;
        Ok(header)
    }

    /// Draw caller image rows straight onto a device context, through the same
    /// raster operation and stretch sampling a context-to-context copy uses.
    /// # C: O(destination pixels)
    pub fn draw_dib(&mut self, dc: u32, dst: BltCoords, src: BltCoords, header: &DibHeader, table: &[Rgb],
        masks: [u32; 3], bits: &[u8], start: u32, lines: u32, code: u32, colors: SharedDcColors,
        mode: StretchMode) -> Result<u32, GdiError> {
        let image = DibImage { header, table, masks, bits };
        let height = header.height.checked_abs().ok_or(GdiError::InvalidDimensions)?;
        let (_, top, bottom, result) = transfer_band(header.top_down(), height, start, lines);
        let count = (header.width as usize).checked_mul(height as usize).ok_or(GdiError::InvalidDimensions)?;
        let mut raster = Vec::new();
        raster.try_reserve_exact(count).map_err(|_| GdiError::HandleLimit)?;
        for row in 0..height { for column in 0..header.width {
            let inside = row >= top && row < bottom;
            raster.push(if inside { image.pixel(column, row).unwrap_or(0) } else { 0 });
        } }
        self.blt_raster(dc, dst, src, &raster, header.width, height, code, colors, mode)?;
        Ok(result)
    }
}

#[cfg(test)]
#[path = "../tests/bitmap_transfer.rs"]
mod tests;
