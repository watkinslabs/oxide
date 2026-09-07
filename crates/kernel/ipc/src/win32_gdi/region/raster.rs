//! Region drawing into a device context: fill, frame and invert; 31fk§6.
//! Each operation paints the region's rectangles through the same clipped raster
//! path a rectangle blit uses, so device clipping applies identically.
use super::{GdiError, GdiManager, query};
use crate::win32_window::PaintRegion;

/// Pattern copy: every destination pixel becomes the brush pattern.
const PATCOPY: u32 = 0x00F0_0021;
/// Destination inversion: the fill this leaves is the bitwise complement of the surface.
const DSTINVERT: u32 = 0x0055_0009;

impl GdiManager {
    /// Paint exact region coverage with the currently selected brush. # C: O(region rectangles + pixels)
    pub fn fill_region_coverage(&mut self, dc: u32, region: &PaintRegion) -> Result<(), GdiError> {
        self.paint_region(dc, region, PATCOPY)
    }

    fn paint_region(&mut self, dc: u32, region: &PaintRegion, rop: u32) -> Result<(), GdiError> {
        for rect in region.rects() {
            let (width, height) = (rect.right - rect.left, rect.bottom - rect.top);
            self.pat_blt(dc, rect.left, rect.top, width, height, rop)?;
        }
        Ok(())
    }

    /// Paint region coverage with one brush, restoring the previously selected brush. # C: O(region rectangles + pixels)
    pub fn fill_region(&mut self, dc: u32, region: u32, brush: u32) -> Result<(), GdiError> {
        let region = self.region_snapshot(region)?;
        let previous = self.select_brush(dc, brush)?;
        let result = self.paint_region(dc, &region, PATCOPY);
        self.select_brush(dc, previous)?;
        result
    }

    /// The frame is the region minus its inward four-way intersection. # C: O(region operations + pixels)
    pub fn frame_region(&mut self, dc: u32, region: u32, brush: u32, width: i32, height: i32) -> Result<(), GdiError> {
        let region = self.region_snapshot(region)?;
        let frame = query::frame_region(&region, width, height)?;
        let previous = self.select_brush(dc, brush)?;
        let result = self.paint_region(dc, &frame, PATCOPY);
        self.select_brush(dc, previous)?;
        result
    }

    /// Inversion complements the covered pixels and selects no brush. # C: O(region rectangles + pixels)
    pub fn invert_region(&mut self, dc: u32, region: u32) -> Result<(), GdiError> {
        let region = self.region_snapshot(region)?;
        self.paint_region(dc, &region, DSTINVERT)
    }
}

#[cfg(test)]
#[path = "../tests/region_raster.rs"]
mod tests;
