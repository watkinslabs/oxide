//! DC clip composition: application, meta and visible regions; 31fk§1.
//! The effective clip is the intersection of every present region, so a query
//! never reads one of them in isolation.
use super::{DeviceContext, GdiError, GdiManager, Rect};
use super::region::{bands, RGN_AND, RGN_DIFF};
use crate::win32_window::{PaintRegion, WindowRect};

pub const CLIP_ERROR: u32 = 0;
pub const NULL_REGION: u32 = 1;
pub const SIMPLE_REGION: u32 = 2;
pub const COMPLEX_REGION: u32 = 3;
/// Region selectors of NtGdiGetRandomRgn: application clip, meta, their intersection, visible.
pub const RGN_CODE_CLIP: i32 = 1;
pub const RGN_CODE_META: i32 = 2;
pub const RGN_CODE_RAO: i32 = 3;
pub const RGN_CODE_SYS: i32 = 4;
const EMPTY: Rect = Rect { left: 0, top: 0, right: 0, bottom: 0 };

#[path = "clip/select.rs"]
mod select;

impl GdiManager {
    /// Install admitted paint bounds independently of application clipping. # C: O(DCs)
    pub fn set_paint_clip(&mut self, dc: u32, rect: Rect) -> Result<(), GdiError> {
        let state = &mut self.dcs.iter_mut().find(|(id, _)| *id == dc).ok_or(GdiError::NoSuchObject)?.1;
        state.ensure_active()?;
        if rect.left > rect.right || rect.top > rect.bottom { return Err(GdiError::InvalidDimensions); }
        let region = PaintRegion::from_rect(WindowRect { left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom })
            .map_err(|_| GdiError::InvalidDimensions)?;
        state.paint_clip = Some(region);
        Ok(())
    }

    /// Transfer an exact admitted region without replacing application clipping. # C: O(DCs)
    pub fn set_paint_region(&mut self, dc: u32, region: PaintRegion) -> Result<(), GdiError> {
        let state = &mut self.dcs.iter_mut().find(|(id, _)| *id == dc).ok_or(GdiError::NoSuchObject)?.1;
        state.ensure_active()?;
        state.paint_clip = Some(region); Ok(())
    }

    /// Retain application geometry independently of current surface bounds. # C: O(DCs + region operations)
    pub fn intersect_clip_rect(&mut self, dc: u32, rect: Rect) -> Result<u32, GdiError> {
        self.combine_app_clip(dc, ordered(rect), RGN_AND)
    }

    /// Removing a rectangle needs a default clip first, so the result is bounded. # C: O(DCs + region operations)
    pub fn exclude_clip_rect(&mut self, dc: u32, rect: Rect) -> Result<u32, GdiError> {
        self.combine_app_clip(dc, ordered(rect), RGN_DIFF)
    }

    /// Remove one region from the device context's paint coverage, which is
    /// what excluding a window's update region from a DC does. The result is
    /// the complexity of the coverage that remains. # C: O(DCs + N_rects²)
    pub fn exclude_clip_region(&mut self, dc: u32, region: &PaintRegion) -> Result<u32, GdiError> {
        let state = &mut self.dcs.iter_mut().find(|(id, _)| *id == dc).ok_or(GdiError::NoSuchObject)?.1;
        state.ensure_active()?;
        let mut next = state.effective_region()?;
        next.subtract(region).map_err(|_| GdiError::InvalidDimensions)?;
        let result = crate::win32_window::region_complexity(&next);
        state.paint_clip = Some(next);
        Ok(result)
    }

    /// Query effective application/surface intersection, including an initialized empty box. # C: O(DCs)
    pub fn get_app_clip_box(&self, dc: u32) -> Result<(u32, Rect), GdiError> {
        if self.dcs.iter().find(|(id, _)| *id == dc).is_some_and(|(_, state)| state.lease.is_some()) {
            return Ok(complexity_of(&self.dc_raster_clip(dc)?));
        }
        let state = &self.dcs.iter().find(|(id, _)| *id == dc).ok_or(GdiError::NoSuchObject)?.1;
        Ok(state.effective_clip_box())
    }
}

impl DeviceContext {
    fn effective_clip_box(&self) -> (u32, Rect) {
        match self.effective_region() { Ok(region) => complexity_of(&region), Err(_) => (CLIP_ERROR, EMPTY) }
    }

    pub(super) fn clip_contains(&self, x: i64, y: i64) -> bool {
        let inside = |region: &PaintRegion| region.rects().iter().any(|r|
            x >= i64::from(r.left) && x < i64::from(r.right) && y >= i64::from(r.top) && y < i64::from(r.bottom));
        let rect = self.surface_box();
        x >= i64::from(rect.left) && x < i64::from(rect.right) && y >= i64::from(rect.top) && y < i64::from(rect.bottom)
            && self.clip.as_ref().is_none_or(&inside) && self.meta_clip.as_ref().is_none_or(&inside)
            && self.paint_clip.as_ref().is_none_or(&inside)
    }
}

/// Region complexity follows canonical band count, not bounding-box area. # C: O(N_rects² log N_rects)
pub(super) fn complexity_of(region: &PaintRegion) -> (u32, Rect) {
    let Ok(bands) = bands::canonical(region) else { return (CLIP_ERROR, EMPTY); };
    let Some(bound) = bands::extents(&bands) else { return (NULL_REGION, EMPTY); };
    let kind = if bands.len() == 1 { SIMPLE_REGION } else { COMPLEX_REGION };
    (kind, Rect { left: bound.left, top: bound.top, right: bound.right, bottom: bound.bottom })
}

/// Reversed rectangles normalize; degenerate ones become the initialized empty box. # C: O(1)
fn ordered(rect: Rect) -> Rect {
    let rect = Rect { left: rect.left.min(rect.right), top: rect.top.min(rect.bottom),
        right: rect.left.max(rect.right), bottom: rect.top.max(rect.bottom) };
    if rect.left >= rect.right || rect.top >= rect.bottom { EMPTY } else { rect }
}

#[cfg(test)]
#[path = "tests/clip.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/paint_region.rs"]
mod region_tests;
