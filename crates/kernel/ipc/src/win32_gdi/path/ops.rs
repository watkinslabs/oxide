//! DC-level path operations: open, close, query, convert and discard; 31fk§8.
use super::{flatten, record::{self, GdiPath}, DeviceContext, GdiError, GdiManager};
use crate::win32_gdi::region::scan::Point;
use crate::win32_window::PaintRegion;

pub const ALTERNATE: i32 = 1;
pub const WINDING: i32 = 2;

impl GdiManager {
    /// Opening discards any closed path and starts recording at the current position. # C: O(DCs)
    pub fn begin_path(&mut self, dc: u32) -> Result<(), GdiError> {
        let state = self.path_dc_mut(dc)?;
        let pos = Point { x: state.text.current_position.0, y: state.text.current_position.1 };
        state.paths.closed = None;
        state.paths.open = Some(GdiPath::open(pos));
        Ok(())
    }

    /// Ending without an open recording fails and leaves no path behind. # C: O(DCs)
    pub fn end_path(&mut self, dc: u32) -> Result<(), GdiError> {
        let state = self.path_dc_mut(dc)?;
        let path = state.paths.open.take().ok_or(GdiError::InvalidDimensions)?;
        state.paths.closed = Some(path);
        Ok(())
    }

    /// Aborting discards both the open recording and any closed path. # C: O(DCs)
    pub fn abort_path(&mut self, dc: u32) -> Result<(), GdiError> {
        let state = self.path_dc_mut(dc)?;
        state.paths.open = None; state.paths.closed = None;
        Ok(())
    }

    /// Closing a figure requires an open recording, never a finished path. # C: O(DCs)
    pub fn close_figure(&mut self, dc: u32) -> Result<(), GdiError> {
        let state = self.path_dc_mut(dc)?;
        let path = state.paths.open.as_mut().ok_or(GdiError::InvalidDimensions)?;
        if !path.is_empty() { path.close_figure(); }
        Ok(())
    }

    /// Read the closed path; an open recording is not a readable path. # C: O(DCs)
    pub fn path_points(&self, dc: u32) -> Result<(&[Point], &[u8]), GdiError> {
        let path = self.path_dc_ref(dc)?.paths.closed.as_ref().ok_or(GdiError::InvalidDimensions)?;
        Ok((path.points(), path.flags()))
    }

    /// Replace the closed path with its Bezier-free equivalent. # C: O(N_points + output points)
    pub fn flatten_path(&mut self, dc: u32) -> Result<(), GdiError> {
        let state = self.path_dc_mut(dc)?;
        let path = state.paths.closed.as_ref().ok_or(GdiError::InvalidDimensions)?;
        let flat = flatten::flatten(path)?;
        state.paths.closed = Some(flat);
        Ok(())
    }

    /// Convert and consume the closed path, leaving the DC with no path. # C: O(scan conversion)
    pub fn path_to_region(&mut self, dc: u32) -> Result<PaintRegion, GdiError> {
        let mode = self.path_dc_ref(dc)?.paths.poly_fill_mode;
        let state = self.path_dc_mut(dc)?;
        let path = state.paths.closed.take().ok_or(GdiError::InvalidDimensions)?;
        let flat = flatten::flatten(&path)?;
        flatten::to_region(&flat, mode)
    }

    /// Drawing operations consume the closed path exactly as a conversion does. # C: O(DCs)
    pub fn discard_path(&mut self, dc: u32) -> Result<(), GdiError> {
        let state = self.path_dc_mut(dc)?;
        if state.paths.closed.is_none() { return Err(GdiError::InvalidDimensions); }
        state.paths.closed = None;
        Ok(())
    }

    /// Record a device-space move while a path is open. # C: O(DCs)
    pub fn path_move_to(&mut self, dc: u32, x: i32, y: i32) -> Result<bool, GdiError> {
        let state = self.path_dc_mut(dc)?;
        let Some(path) = state.paths.open.as_mut() else { return Ok(false); };
        path.move_to(Point { x, y }); Ok(true)
    }

    /// Record a device-space line while a path is open. # C: O(DCs)
    pub fn path_line_to(&mut self, dc: u32, x: i32, y: i32) -> Result<bool, GdiError> {
        let state = self.path_dc_mut(dc)?;
        let Some(path) = state.paths.open.as_mut() else { return Ok(false); };
        path.line_to(&[Point { x, y }], record::PT_LINETO)?; Ok(true)
    }

    /// Record a closed rectangle figure while a path is open. # C: O(DCs)
    pub fn path_rectangle(&mut self, dc: u32, left: i32, top: i32, right: i32, bottom: i32) -> Result<bool, GdiError> {
        let clockwise = self.path_dc_ref(dc)?.paths.arc_clockwise;
        let state = self.path_dc_mut(dc)?;
        let Some(path) = state.paths.open.as_mut() else { return Ok(false); };
        path.rectangle(left, top, right, bottom, clockwise)?; Ok(true)
    }

    fn path_dc_mut(&mut self, dc: u32) -> Result<&mut DeviceContext, GdiError> {
        Ok(&mut self.dcs.iter_mut().find(|(id, _)| *id == dc).ok_or(GdiError::NoSuchObject)?.1)
    }
    fn path_dc_ref(&self, dc: u32) -> Result<&DeviceContext, GdiError> {
        Ok(&self.dcs.iter().find(|(id, _)| *id == dc).ok_or(GdiError::NoSuchObject)?.1)
    }

    /// Recording is open between a begin and its matching end. # C: O(DCs)
    pub fn path_recording(&self, dc: u32) -> Result<bool, GdiError> { Ok(self.path_dc_ref(dc)?.paths.open.is_some()) }

    /// Polygon fill mode selects between alternate parity and winding coverage. # C: O(DCs)
    pub fn set_poly_fill_mode(&mut self, dc: u32, mode: i32) -> Result<i32, GdiError> {
        if mode != ALTERNATE && mode != WINDING { return Err(GdiError::InvalidDimensions); }
        let state = self.path_dc_mut(dc)?;
        let previous = state.paths.poly_fill_mode;
        state.paths.poly_fill_mode = mode;
        Ok(previous)
    }

    /// # C: O(DCs)
    pub fn poly_fill_mode(&self, dc: u32) -> Result<i32, GdiError> { Ok(self.path_dc_ref(dc)?.paths.poly_fill_mode) }
}

#[cfg(test)]
#[path = "../tests/path_ops.rs"]
mod tests;
