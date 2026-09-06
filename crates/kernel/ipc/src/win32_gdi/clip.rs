//! Canonical rectangular application clip and effective raster bounds; 31fk§1.
use super::{DeviceContext, GdiError, GdiManager, Rect};
use crate::win32_window::{PaintRegion, WindowRect};

pub const CLIP_ERROR: u32 = 0;
pub const NULL_REGION: u32 = 1;
pub const SIMPLE_REGION: u32 = 2;
pub const COMPLEX_REGION: u32 = 3;
const EMPTY: Rect = Rect { left: 0, top: 0, right: 0, bottom: 0 };

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

    /// Retain application geometry independently of current surface bounds. # C: O(DCs)
    pub fn intersect_clip_rect(&mut self, dc: u32, rect: Rect) -> Result<u32, GdiError> {
        let state = &mut self.dcs.iter_mut().find(|(id, _)| *id == dc).ok_or(GdiError::NoSuchObject)?.1;
        state.ensure_active()?;
        let rect = ordered(rect);
        let (next, result) = match state.clip {
            None => (rect, SIMPLE_REGION),
            Some(previous) => { let next = intersection(previous, rect); (next, complexity(next)) }
        };
        state.clip = Some(next);
        Ok(result)
    }

    /// Query effective application/surface intersection, including an initialized empty box. # C: O(DCs)
    pub fn get_app_clip_box(&self, dc: u32) -> Result<(u32, Rect), GdiError> {
        if self.dcs.iter().find(|(id, _)| *id == dc).is_some_and(|(_, state)| state.lease.is_some()) {
            let region = self.dc_raster_clip(dc)?;
            let Some(r) = region.bounds() else { return Ok((NULL_REGION, EMPTY)); };
            let area = |r: &WindowRect| (i128::from(r.right)-i128::from(r.left))*(i128::from(r.bottom)-i128::from(r.top));
            let covered: i128 = region.rects().iter().map(area).sum();
            return Ok((if covered == area(&r) { SIMPLE_REGION } else { COMPLEX_REGION },
                Rect { left:r.left, top:r.top, right:r.right, bottom:r.bottom }));
        }
        let state = &self.dcs.iter().find(|(id, _)| *id == dc).ok_or(GdiError::NoSuchObject)?.1;
        Ok(state.effective_clip_box())
    }
}

impl DeviceContext {
    pub(super) fn effective_clip(&self) -> Rect {
        self.effective_clip_box().1
    }

    fn application_bounds(&self) -> Rect {
        let surface = Rect { left: 0, top: 0, right: self.width, bottom: self.height };
        self.clip.map(|clip| intersection(surface, clip)).unwrap_or(surface)
    }

    fn effective_clip_box(&self) -> (u32, Rect) {
        let app = self.application_bounds();
        let Some(region) = &self.paint_clip else { return (complexity(app), app); };
        let mut bounds = EMPTY;
        let mut area = 0i64;
        for r in region.rects() {
            let r = intersection(app, Rect { left: r.left, top: r.top, right: r.right, bottom: r.bottom });
            if complexity(r) == NULL_REGION { continue; }
            bounds = if area == 0 { r } else { Rect { left: bounds.left.min(r.left), top: bounds.top.min(r.top),
                right: bounds.right.max(r.right), bottom: bounds.bottom.max(r.bottom) } };
            area += i64::from(r.right - r.left) * i64::from(r.bottom - r.top);
        }
        let kind = if area == 0 { NULL_REGION }
            else if area == i64::from(bounds.right - bounds.left) * i64::from(bounds.bottom - bounds.top) { SIMPLE_REGION }
            else { COMPLEX_REGION };
        (kind, bounds)
    }

    pub(super) fn clip_contains(&self, x: i64, y: i64) -> bool {
        let rect = self.application_bounds();
        x >= i64::from(rect.left) && x < i64::from(rect.right)
            && y >= i64::from(rect.top) && y < i64::from(rect.bottom)
            && self.paint_clip.as_ref().is_none_or(|region| region.rects().iter().any(|r|
                x >= i64::from(r.left) && x < i64::from(r.right) && y >= i64::from(r.top) && y < i64::from(r.bottom)))
    }
}

fn ordered(rect: Rect) -> Rect {
    let rect = Rect { left: rect.left.min(rect.right), top: rect.top.min(rect.bottom),
        right: rect.left.max(rect.right), bottom: rect.top.max(rect.bottom) };
    if complexity(rect) == NULL_REGION { EMPTY } else { rect }
}

fn intersection(a: Rect, b: Rect) -> Rect {
    let rect = Rect { left: a.left.max(b.left), top: a.top.max(b.top), right: a.right.min(b.right), bottom: a.bottom.min(b.bottom) };
    if complexity(rect) == NULL_REGION { EMPTY } else { rect }
}

fn complexity(rect: Rect) -> u32 {
    if rect.left >= rect.right || rect.top >= rect.bottom { NULL_REGION } else { SIMPLE_REGION }
}

#[cfg(test)]
#[path = "tests/clip.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/paint_region.rs"]
mod region_tests;
