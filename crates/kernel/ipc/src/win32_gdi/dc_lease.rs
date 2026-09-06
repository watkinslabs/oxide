//! Canonical DCE identities reference one window backing; 31fk§7.
use super::{DeviceContext, GdiError, GdiManager, Rect, TextAttributes, DEFAULT_DC_FONT_HANDLE, MM_TEXT, TYPE_DC};
use crate::win32_window::{PaintRegion, WindowRect};
use alloc::vec::Vec;
#[path = "dc_lease/raster.rs"]
mod raster;
pub use raster::DcRaster;
#[path = "dc_lease/lifetime.rs"]
mod lifetime;

pub const DCX_WINDOW: u32 = 0x1;
pub const DCX_CACHE: u32 = 0x2;
pub const DCX_NORESETATTRS: u32 = 0x4;
pub const DCX_CLIPCHILDREN: u32 = 0x8;
pub const DCX_CLIPSIBLINGS: u32 = 0x10;
pub const DCX_PARENTCLIP: u32 = 0x20;
pub const DCX_EXCLUDERGN: u32 = 0x40;
pub const DCX_INTERSECTRGN: u32 = 0x80;
pub const DCX_USESTYLE: u32 = 0x10000;
const WS_CLIPSIBLINGS: u32 = 0x04000000;
const WS_CLIPCHILDREN: u32 = 0x02000000;
const WS_MINIMIZE: u32 = 0x20000000;
const WS_VISIBLE: u32 = 0x10000000;
const CS_PARENTDC: u32 = 0x80;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeaseOwner { Cached, Window(u32), Class(u16) }

#[derive(Debug, Eq, PartialEq)]
pub struct DcLease {
    pub hwnd: u32, pub backing: u32, pub origin: (i32, i32), pub visible: PaintRegion,
    pub flags: u32, pub owner: LeaseOwner, pub active: bool, pub clip_handle: Option<u32>,
}

pub struct DcLeaseRequest {
    pub hwnd: u32, pub backing_hwnd: u32, pub backing: u32, pub origin: (i32, i32), pub screen_origin: (i32, i32), pub width: i32, pub height: i32,
    pub visible: PaintRegion, pub flags: u32, pub owner: LeaseOwner, pub clip_handle: u32,
}

/// Canonical style fixups precede visible-region calculation. Unknown bits are ignored by policy.
/// # C: O(1)
pub fn dc_lease_flags(mut flags: u32, style: u32, class_style: u32, parent_style: u32, top_level: bool) -> u32 {
    if flags & (DCX_WINDOW | DCX_PARENTCLIP) != 0 { flags |= DCX_CACHE; }
    if flags & DCX_USESTYLE != 0 {
        flags &= !(DCX_CLIPCHILDREN | DCX_CLIPSIBLINGS | DCX_PARENTCLIP);
        if style & WS_CLIPSIBLINGS != 0 { flags |= DCX_CLIPSIBLINGS; }
        if flags & DCX_WINDOW == 0 {
            if class_style & CS_PARENTDC != 0 { flags |= DCX_PARENTCLIP; }
            if style & WS_CLIPCHILDREN != 0 && style & WS_MINIMIZE == 0 { flags |= DCX_CLIPCHILDREN; }
        }
    }
    if flags & DCX_WINDOW != 0 { flags &= !DCX_CLIPCHILDREN; }
    if top_level { flags = (flags & !DCX_PARENTCLIP) | DCX_CLIPSIBLINGS; }
    if flags & (DCX_CLIPSIBLINGS | DCX_CLIPCHILDREN) != 0 { flags &= !DCX_PARENTCLIP; }
    if flags & DCX_PARENTCLIP != 0 && style & parent_style & WS_VISIBLE != 0 {
        flags &= !DCX_CLIPCHILDREN;
        if parent_style & WS_CLIPSIBLINGS != 0 { flags |= DCX_CLIPSIBLINGS; }
    }
    flags
}

impl GdiManager {
    /// Canonical release policy; queried before disabling the lease. # C: O(DCs)
    pub fn dc_lease_resets_on_release(&self, dc:u32)->Result<bool,GdiError>{
        let state=&self.dcs.iter().find(|(id,_)|*id==dc).ok_or(GdiError::NoSuchObject)?.1;
        let lease=state.lease.as_ref().filter(|lease|lease.active).ok_or(GdiError::NoSuchObject)?;
        Ok(lease.owner==LeaseOwner::Cached&&lease.flags&DCX_NORESETATTRS==0)
    }
    /// Drawing/query admission excludes disabled cached DCEs but preserves their object identity. # C: O(DCs)
    pub fn validate_dc(&self, dc: u32) -> Result<(), GdiError> {
        self.dcs.iter().find(|(id, _)| *id == dc).ok_or(GdiError::NoSuchObject)?.1.ensure_active()
    }
    /// Acquire independent lease attributes with no pixel allocation. Region work precedes mutation.
    /// # C: O(DCs + region operations)
    pub fn acquire_dc_lease(&mut self, mut request: DcLeaseRequest) -> Result<u32, GdiError> {
        if self.window_dc(request.backing_hwnd) != Some(request.backing) { return Err(GdiError::NoSuchObject); }
        let backing = &self.dcs.iter().find(|(id, _)| *id == request.backing).ok_or(GdiError::NoSuchObject)?.1;
        if backing.lease.is_some() || request.width < 0 || request.height < 0
            || request.origin.0.checked_add(request.width).is_none()
            || request.origin.1.checked_add(request.height).is_none() { return Err(GdiError::InvalidDimensions); }
        let consumes = request.flags & (DCX_INTERSECTRGN | DCX_EXCLUDERGN) != 0;
        let clip_handle = (consumes && request.clip_handle != 0).then_some(request.clip_handle);
        if consumes {
            let extra = match clip_handle { Some(handle) => screen_to_logical(&self.region_snapshot(handle)?, request.screen_origin)?, None => PaintRegion::default() };
            if request.flags & DCX_INTERSECTRGN != 0 { intersect(&mut request.visible, &extra)?; }
            else { request.visible.subtract(&extra).map_err(|_| GdiError::HandleLimit)?; }
        }
        let owner = if request.flags & DCX_CACHE != 0 { LeaseOwner::Cached } else { request.owner };
        if owner != LeaseOwner::Cached { request.flags |= DCX_NORESETATTRS; }
        let reuse = self.dcs.iter().position(|(_, state)| state.lease.as_ref().is_some_and(|lease|
            lease.owner == owner && (owner != LeaseOwner::Cached || !lease.active)));
        let (handle, index) = if let Some(index) = reuse { (self.dcs[index].0, index) } else {
            self.dcs.try_reserve(1).map_err(|_| GdiError::HandleLimit)?;
            let handle = self.allocate(TYPE_DC)?;
            self.dcs.push((handle, DeviceContext { width: request.width, height: request.height, map_mode: MM_TEXT,
                font: Some(DEFAULT_DC_FONT_HANDLE), brush: None, dc_brush_color: 0xffffff, pen: super::DEFAULT_DC_PEN_HANDLE, dc_pen_color: 0, text: TextAttributes::default(),
                clip: None, paint_clip: None, pixels: Vec::new(), lease: None, pending_output:Default::default() }));
            (handle, self.dcs.len() - 1)
        };
        let old_clip = self.dcs[index].1.lease.as_ref().and_then(|lease| lease.clip_handle);
        if let Some(old) = old_clip.filter(|old| Some(*old) != clip_handle) { let _ = self.delete_region(old); }
        let state = &mut self.dcs[index].1;
        state.width = request.width; state.height = request.height;
        state.lease = Some(DcLease { hwnd: request.hwnd, backing: request.backing, origin: request.origin,
            visible: request.visible, flags: request.flags, owner, active: true, clip_handle });
        Ok(handle)
    }

    /// Release disables cached attributes, never the backing surface. HWND is intentionally not a lookup key.
    /// # C: O(DCs + regions + selected objects)
    pub fn release_dc_lease(&mut self, dc: u32) -> Result<(), GdiError> {
        self.release_dc_lease_state(dc).map(|_| ())
    }

    /// Snapshot reset attributes while the lease is still valid, then disable cached access.
    /// # C: O(DCs + regions + selected objects)
    pub fn release_dc_lease_state(&mut self, dc: u32) -> Result<super::TextState, GdiError> {
        let index = self.dcs.iter().position(|(id, _)| *id == dc).ok_or(GdiError::NoSuchObject)?;
        let state = &mut self.dcs[index].1;
        let lease = state.lease.as_mut().filter(|lease| lease.active).ok_or(GdiError::NoSuchObject)?;
        if lease.owner != LeaseOwner::Cached { return self.text_state(dc); }
        let clip = lease.clip_handle.take();
        if lease.flags & DCX_NORESETATTRS == 0 {
            state.map_mode = MM_TEXT; state.font = Some(DEFAULT_DC_FONT_HANDLE); state.brush = None;
            state.pen = super::DEFAULT_DC_PEN_HANDLE; state.dc_pen_color = 0;
            state.dc_brush_color = 0xffffff; state.text = TextAttributes::default(); state.clip = None; state.paint_clip = None;
        }
        let projection = self.text_state(dc)?;
        self.dcs[index].1.lease.as_mut().ok_or(GdiError::NoSuchObject)?.active = false;
        if let Some(handle) = clip { let _ = self.delete_region(handle); }
        self.collect_deleted_fonts(); self.collect_deleted_brushes(); self.collect_deleted_pens(); Ok(projection)
    }

    /// Resolve logical coordinates to the canonical backing without copying pixels.
    /// # C: O(DCs + clip rectangles)
    pub fn dc_pixel_target(&self, dc: u32, x: i32, y: i32) -> Result<Option<(u32, usize)>, GdiError> {
        let state = &self.dcs.iter().find(|(id, _)| *id == dc).ok_or(GdiError::NoSuchObject)?.1;
        let (target, dx, dy) = match &state.lease {
            Some(lease) => {
                if !lease.active { return Err(GdiError::NoSuchObject); }
                if !contains(&lease.visible, x, y) { return Ok(None); }
                (lease.backing, x.checked_add(lease.origin.0), y.checked_add(lease.origin.1))
            }
            None => (dc, Some(x), Some(y)),
        };
        if state.lease.is_some() {
            if state.clip.is_some_and(|r| x < r.left || x >= r.right || y < r.top || y >= r.bottom)
                || state.paint_clip.as_ref().is_some_and(|r| !contains(r, x, y)) { return Ok(None); }
        } else if !state.clip_contains(i64::from(x), i64::from(y)) { return Ok(None); }
        let (Some(dx), Some(dy)) = (dx, dy) else { return Ok(None); };
        let surface = &self.dcs.iter().find(|(id, _)| *id == target).ok_or(GdiError::NoSuchObject)?.1;
        if dx < 0 || dy < 0 || dx >= surface.width || dy >= surface.height { return Ok(None); }
        Ok(Some((target, dy as usize * surface.width as usize + dx as usize)))
    }

    /// One canonical raster store shared by client and window leases. # C: O(DCs + region rectangles)
    pub fn write_dc_pixel(&mut self, dc: u32, x: i32, y: i32, color: u32) -> Result<(), GdiError> {
        self.raster_dc(dc)?.update(x,y,|_|color);
        Ok(())
    }
}

impl DeviceContext {
    pub(super) fn ensure_active(&self) -> Result<(), GdiError> {
        if self.lease.as_ref().is_some_and(|lease| !lease.active) { Err(GdiError::NoSuchObject) } else { Ok(()) }
    }
}

fn intersect(left: &mut PaintRegion, right: &PaintRegion) -> Result<(), GdiError> {
    let mut outside = left.try_copy().map_err(|_| GdiError::HandleLimit)?;
    outside.subtract(right).map_err(|_| GdiError::HandleLimit)?;
    left.subtract(&outside).map_err(|_| GdiError::HandleLimit)
}
fn contains(region: &PaintRegion, x: i32, y: i32) -> bool {
    region.rects().iter().any(|r| x >= r.left && x < r.right && y >= r.top && y < r.bottom)
}

fn screen_to_logical(region: &PaintRegion, origin: (i32, i32)) -> Result<PaintRegion, GdiError> {
    let mut rects = Vec::new();
    rects.try_reserve_exact(region.rects().len()).map_err(|_| GdiError::HandleLimit)?;
    for r in region.rects() {
        rects.push(WindowRect { left: r.left.checked_sub(origin.0).ok_or(GdiError::InvalidDimensions)?,
            top: r.top.checked_sub(origin.1).ok_or(GdiError::InvalidDimensions)?,
            right: r.right.checked_sub(origin.0).ok_or(GdiError::InvalidDimensions)?,
            bottom: r.bottom.checked_sub(origin.1).ok_or(GdiError::InvalidDimensions)? });
    }
    PaintRegion::from_rects(&rects).map_err(|_| GdiError::HandleLimit)
}

#[cfg(test)]
#[path = "tests/dc_lease.rs"]
mod tests;
