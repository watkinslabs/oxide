//! Application and meta clip selection, offset and query; 31fk§1.
use super::{complexity_of, CLIP_ERROR, NULL_REGION, SIMPLE_REGION, RGN_CODE_CLIP, RGN_CODE_META, RGN_CODE_RAO, RGN_CODE_SYS};
use super::{DeviceContext, GdiError, GdiManager, Rect};
use crate::win32_gdi::region::{query, RGN_AND, RGN_COPY, RGN_DIFF, RGN_OR, RGN_XOR};
use crate::win32_window::{PaintRegion, WindowRect};

fn region_of(rect: Rect) -> Result<PaintRegion, GdiError> {
    PaintRegion::from_rect(WindowRect { left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom })
        .map_err(|_| GdiError::HandleLimit)
}

/// Apply one region operation in place, matching the canonical combine modes. # C: O(region operations)
fn combine(target: &mut PaintRegion, source: &PaintRegion, mode: i32) -> Result<(), GdiError> {
    match mode {
        RGN_AND => query::intersect_into(target, source),
        RGN_OR => target.union(source).map_err(|_| GdiError::HandleLimit),
        RGN_DIFF => target.subtract(source).map_err(|_| GdiError::HandleLimit),
        RGN_XOR => {
            let mut only_source = source.try_copy().map_err(|_| GdiError::HandleLimit)?;
            only_source.subtract(target).map_err(|_| GdiError::HandleLimit)?;
            target.subtract(source).map_err(|_| GdiError::HandleLimit)?;
            target.union(&only_source).map_err(|_| GdiError::HandleLimit)
        },
        RGN_COPY => { *target = source.try_copy().map_err(|_| GdiError::HandleLimit)?; Ok(()) },
        _ => Err(GdiError::InvalidDimensions),
    }
}

impl GdiManager {
    fn dc_mut(&mut self, dc: u32) -> Result<&mut DeviceContext, GdiError> {
        let state = &mut self.dcs.iter_mut().find(|(id, _)| *id == dc).ok_or(GdiError::NoSuchObject)?.1;
        state.ensure_active()?; Ok(state)
    }
    fn dc_ref(&self, dc: u32) -> Result<&DeviceContext, GdiError> {
        Ok(&self.dcs.iter().find(|(id, _)| *id == dc).ok_or(GdiError::NoSuchObject)?.1)
    }

    /// A rectangle reaches the application clip through the same path a region does.
    /// The first intersection installs the rectangle itself and reports one rectangle. # C: O(DCs + region operations)
    pub(super) fn combine_app_clip(&mut self, dc: u32, rect: Rect, mode: i32) -> Result<u32, GdiError> {
        let surface = { let state = self.dc_ref(dc)?; state.surface_box() };
        let state = self.dc_mut(dc)?;
        if state.clip.is_none() && mode == RGN_AND { state.clip = Some(region_of(rect)?); return Ok(SIMPLE_REGION); }
        if state.clip.is_none() { state.clip = Some(region_of(surface)?); }
        let source = region_of(rect)?;
        let target = state.clip.as_mut().ok_or(GdiError::NoSuchObject)?;
        combine(target, &source, mode)?;
        Ok(complexity_of(target).0)
    }

    /// Selecting no region in copy mode clears application clipping entirely. # C: O(DCs + region operations)
    pub fn ext_select_clip_rgn(&mut self, dc: u32, region: Option<&PaintRegion>, mode: i32) -> Result<u32, GdiError> {
        let surface = { let state = self.dc_ref(dc)?; state.surface_box() };
        let state = self.dc_mut(dc)?;
        let Some(region) = region else {
            if mode != RGN_COPY { return Err(GdiError::InvalidDimensions); }
            state.clip = None; return Ok(SIMPLE_REGION);
        };
        if state.clip.is_none() { state.clip = Some(region_of(surface)?); }
        let target = state.clip.as_mut().ok_or(GdiError::NoSuchObject)?;
        combine(target, region, mode)?;
        Ok(complexity_of(target).0)
    }

    /// Offsetting reports an empty result when no application clip exists. # C: O(DCs + region rectangles)
    pub fn offset_clip_rgn(&mut self, dc: u32, x: i32, y: i32) -> Result<u32, GdiError> {
        let state = self.dc_mut(dc)?;
        let Some(clip) = state.clip.as_ref() else { return Ok(NULL_REGION); };
        let moved = query::offset_region(clip, x, y)?;
        let kind = complexity_of(&moved).0;
        state.clip = Some(moved);
        Ok(kind)
    }

    /// Promote the application clip into the meta clip, leaving the effective clip unchanged. # C: O(DCs + region operations)
    pub fn set_meta_rgn(&mut self, dc: u32) -> Result<u32, GdiError> {
        let state = self.dc_mut(dc)?;
        if let Some(clip) = state.clip.take() {
            match state.meta_clip.as_mut() {
                Some(meta) => query::intersect_into(meta, &clip)?,
                None => state.meta_clip = Some(clip),
            }
        }
        Ok(state.meta_clip.as_ref().map_or(CLIP_ERROR, |meta| complexity_of(meta).0))
    }

    /// Copy one selected DC region; absence is reported apart from failure. # C: O(DCs + region rectangles)
    pub fn get_random_rgn(&self, dc: u32, code: i32) -> Result<Option<PaintRegion>, GdiError> {
        let state = self.dc_ref(dc)?;
        let copy = |region: &PaintRegion| region.try_copy().map_err(|_| GdiError::HandleLimit);
        match code {
            RGN_CODE_CLIP => state.clip.as_ref().map(copy).transpose(),
            RGN_CODE_META => state.meta_clip.as_ref().map(copy).transpose(),
            RGN_CODE_RAO => match (state.clip.as_ref(), state.meta_clip.as_ref()) {
                (Some(clip), Some(meta)) => { let mut out = copy(clip)?; query::intersect_into(&mut out, meta)?; Ok(Some(out)) },
                (Some(region), None) | (None, Some(region)) => copy(region).map(Some),
                (None, None) => Ok(None),
            },
            RGN_CODE_SYS => match state.paint_clip.as_ref() {
                Some(visible) => copy(visible).map(Some),
                None => {
                    let surface = state.surface_box();
                    if surface.right <= surface.left || surface.bottom <= surface.top { return Ok(None); }
                    region_of(surface).map(Some)
                },
            },
            _ => Err(GdiError::InvalidDimensions),
        }
    }

    /// A point is visible when the device surface and every clip region admit it. # C: O(DCs + region rectangles)
    pub fn pt_visible(&self, dc: u32, x: i32, y: i32) -> Result<bool, GdiError> {
        Ok(self.dc_ref(dc)?.clip_contains(i64::from(x), i64::from(y)))
    }

    /// Rectangle visibility tests overlap with the effective clip, not containment. # C: O(DCs + region rectangles)
    pub fn rect_visible(&self, dc: u32, rect: Rect) -> Result<bool, GdiError> {
        let state = self.dc_ref(dc)?;
        let region = state.effective_region()?;
        Ok(query::rect_in_region(&region, rect))
    }
}

impl DeviceContext {
    /// # C: O(1)
    pub(super) fn surface_box(&self) -> Rect { Rect { left: 0, top: 0, right: self.width, bottom: self.height } }

    /// Surface bounds narrowed by application, meta and visible regions. # C: O(region operations)
    pub(super) fn effective_region(&self) -> Result<PaintRegion, GdiError> {
        let mut region = region_of(self.surface_box())?;
        for clip in [self.clip.as_ref(), self.meta_clip.as_ref(), self.paint_clip.as_ref()].into_iter().flatten() {
            query::intersect_into(&mut region, clip)?;
        }
        Ok(region)
    }
}

#[cfg(test)]
#[path = "../tests/clip_select.rs"]
mod tests;
