//! Bitmaps created to match one device context; 31fk§4.
use super::{DibHeader, GdiError, GdiManager, Rgb};
use alloc::vec::Vec;

impl GdiManager {
    /// A bitmap the given context can select. A context that is not a memory
    /// context takes the device's own plane count and depth. A memory context
    /// takes the shape of whatever it already selected: a device-dependent
    /// bitmap's planes and depth, or a DIB section's header, colour table and
    /// masks at the new extents. A memory context that selected nothing has
    /// the stock monochrome bitmap, so it produces a monochrome bitmap.
    /// # C: O(DCs + bitmaps + width*height)
    pub fn create_compatible_bitmap(&mut self, dc: u32, width: i32, height: i32,
        device_planes: u32, device_bpp: u32) -> Result<u32, GdiError> {
        if width == 0 || height == 0 { return Err(GdiError::InvalidDimensions); }
        let state = &self.dcs.iter().find(|(id, _)| *id == dc).ok_or(GdiError::NoSuchObject)?.1;
        if !state.memory { return self.create_bitmap(width, height, device_planes, device_bpp, None); }
        let Some(selected) = state.bitmap else { return self.create_bitmap(width, height, 1, 1, None); };
        let bitmap = self.bitmap(selected)?;
        let Some(header) = bitmap.dib else {
            let (planes, bpp) = (bitmap.planes, bitmap.bpp);
            return self.create_bitmap(width, height, planes, bpp, None);
        };
        let mut table = Vec::new();
        table.try_reserve_exact(bitmap.color_table().len()).map_err(|_| GdiError::HandleLimit)?;
        table.extend_from_slice(bitmap.color_table());
        let masks = header.masks;
        let header = DibHeader { width, height, ..header };
        self.create_dib_section(header, super::DIB_RGB_COLORS, &table, masks)
    }

    /// The colour table a compatible DIB section would inherit. # C: O(bitmaps)
    pub fn dc_color_table(&self, dc: u32) -> Option<&[Rgb]> {
        self.bitmap(self.dc_bitmap(dc)?).ok().map(|bitmap| bitmap.color_table())
    }
}

#[cfg(test)]
#[path = "../tests/bitmap_compatible.rs"]
mod tests;
