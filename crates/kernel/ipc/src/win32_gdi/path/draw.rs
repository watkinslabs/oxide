//! Path drawing: interior fill and stroked outline, each consuming the path; 31fk§8.
use super::{flatten, DeviceContext, GdiError, GdiManager};
use crate::win32_gdi::region::scan::Point;
use crate::win32_window::PaintRegion;

impl GdiManager {
    /// Take the closed path as a flattened copy and its interior coverage. # C: O(path points + scan conversion)
    fn take_flat_path(&mut self, dc: u32, interior: bool) -> Result<(super::GdiPath, Option<PaintRegion>), GdiError> {
        let mode = self.poly_fill_mode(dc)?;
        let state: &mut DeviceContext = &mut self.dcs.iter_mut().find(|(id, _)| *id == dc).ok_or(GdiError::NoSuchObject)?.1;
        let path = state.paths.closed.take().ok_or(GdiError::InvalidDimensions)?;
        let flat = flatten::flatten(&path)?;
        let region = if interior { Some(flatten::to_region(&flat, mode)?) } else { None };
        Ok((flat, region))
    }

    /// Paint the path interior with the selected brush; the path is consumed. # C: O(scan conversion + pixels)
    pub fn fill_path(&mut self, dc: u32) -> Result<(), GdiError> {
        let (_, region) = self.take_flat_path(dc, true)?;
        let region = region.ok_or(GdiError::NoSuchObject)?;
        self.fill_region_coverage(dc, &region)
    }

    /// Stroke each recorded figure with the selected pen; the path is consumed. # C: O(path points + stroked pixels)
    pub fn stroke_path(&mut self, dc: u32) -> Result<(), GdiError> {
        let (flat, _) = self.take_flat_path(dc, false)?;
        self.stroke_figures(dc, &flat, false)
    }

    /// Fill the interior first, then stroke over it; the path is consumed. # C: O(scan conversion + pixels)
    pub fn stroke_and_fill_path(&mut self, dc: u32) -> Result<(), GdiError> {
        let (flat, region) = self.take_flat_path(dc, true)?;
        if let Some(region) = region { self.fill_region_coverage(dc, &region)?; }
        self.stroke_figures(dc, &flat, true)
    }

    /// A figure is stroked closed when it was closed or when its interior was filled. # C: O(path points + stroked pixels)
    fn stroke_figures(&mut self, dc: u32, path: &super::GdiPath, filled: bool) -> Result<(), GdiError> {
        let (points, flags) = (path.points(), path.flags());
        let mut state = self.pen_raster_state(dc)?;
        let mut start = 0usize;
        for index in 1..=points.len() {
            let boundary = index == points.len() || flags[index] & !super::PT_CLOSEFIGURE == super::PT_MOVETO;
            if !boundary { continue; }
            if index > start + 1 {
                let close = filled || flags[index - 1] & super::PT_CLOSEFIGURE != 0;
                self.stroke_figure(dc, &points[start..index], close, &mut state)?;
            }
            start = index;
        }
        Ok(())
    }

    fn stroke_figure(&mut self, dc: u32, points: &[Point], close: bool, state: &mut crate::win32_gdi::PenRasterState) -> Result<(), GdiError> {
        for pair in points.windows(2) {
            state.position = (pair[0].x, pair[0].y);
            self.pen_line_to(dc, (pair[1].x, pair[1].y), Some(*state))?;
        }
        if close {
            if let (Some(last), Some(first)) = (points.last(), points.first()) {
                state.position = (last.x, last.y);
                self.pen_line_to(dc, (first.x, first.y), Some(*state))?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "../tests/path_draw.rs"]
mod tests;
