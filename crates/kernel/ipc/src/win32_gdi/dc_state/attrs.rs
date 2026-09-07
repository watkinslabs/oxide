//! Attribute reads and writes the device-context state ordinals project.
use super::{DcAttr, GdiError, GdiManager};
use crate::win32_gdi::{DeviceGeometry, Rect, Xform, Point, Size, LAYOUT_RTL, MM_ANISOTROPIC};

/// A layout query that cannot resolve its device context reports this. It is
/// the same sentinel every GDI call uses for an unusable result.
pub const GDI_ERROR: u32 = 0xffff_ffff;

impl GdiManager {
    /// Snapshot one device context's attribute block. # C: O(DCs)
    pub fn dc_attr(&self, dc: u32) -> Result<DcAttr, GdiError> {
        let state = &self.dcs.iter().find(|(handle, _)| *handle == dc).ok_or(GdiError::NoSuchObject)?.1;
        state.ensure_active()?;
        Ok(state.attr)
    }

    fn dc_attr_mut(&mut self, dc: u32) -> Result<&mut DcAttr, GdiError> {
        let index = self.dcs.iter().position(|(handle, _)| *handle == dc).ok_or(GdiError::NoSuchObject)?;
        self.dcs[index].1.ensure_active()?;
        Ok(&mut self.dcs[index].1.attr)
    }

    /// Report the previous layout and install the new one. Right-to-left
    /// layout forces the anisotropic mapping mode. # C: O(DCs)
    pub fn set_layout(&mut self, dc: u32, layout: u32) -> Result<u32, GdiError> {
        let attr = self.dc_attr_mut(dc)?;
        let previous = attr.layout;
        attr.layout = layout;
        if layout != previous {
            if layout & LAYOUT_RTL != 0 { attr.map_mode = MM_ANISOTROPIC; }
            attr.update_xforms();
        }
        Ok(previous)
    }

    /// Read the miter limit. # C: O(DCs)
    pub fn miter_limit(&self, dc: u32) -> Result<f32, GdiError> { Ok(self.dc_attr(dc)?.miter_limit) }

    /// Install a miter limit, reporting the previous one. The argument arrives
    /// as the raw bit pattern of a single-precision float. # C: O(DCs)
    pub fn set_miter_limit(&mut self, dc: u32, limit_bits: u32) -> Result<f32, GdiError> {
        let attr = self.dc_attr_mut(dc)?;
        let previous = attr.miter_limit;
        attr.miter_limit = f32::from_bits(limit_bits);
        Ok(previous)
    }

    /// Report one of the four coordinate-space transforms. # C: O(DCs)
    pub fn dc_transform(&self, dc: u32, which: u32) -> Result<Xform, GdiError> {
        self.dc_attr(dc)?.get_transform(which).ok_or(GdiError::InvalidDimensions)
    }

    /// Modify the world transform and rebuild the derived transforms. # C: O(DCs)
    pub fn modify_world_transform(&mut self, dc: u32, xform: Option<Xform>, mode: u32) -> Result<(), GdiError> {
        if self.dc_attr_mut(dc)?.modify_world_transform(xform, mode) { Ok(()) } else { Err(GdiError::InvalidDimensions) }
    }

    /// Transform a point run in place. # C: O(DCs + N_points)
    pub fn transform_points(&self, dc: u32, mode: u32, points: &mut [Point]) -> Result<(), GdiError> {
        if self.dc_attr(dc)?.transform_points(mode, points) { Ok(()) } else { Err(GdiError::InvalidDimensions) }
    }

    /// Recompute the mapping coefficients. # C: O(DCs)
    pub fn compute_xform_coefficients(&mut self, dc: u32, device: DeviceGeometry) -> Result<(), GdiError> {
        self.dc_attr_mut(dc)?.compute_xform_coefficients(device);
        Ok(())
    }

    /// Scale the viewport extent, reporting the extent before the change. # C: O(DCs)
    pub fn scale_viewport_ext(&mut self, dc: u32, ratio: [i32; 4], device: DeviceGeometry) -> Result<Size, (Size, GdiError)> {
        match self.dc_attr_mut(dc) {
            Err(error) => Err((Size::default(), error)),
            Ok(attr) => attr.scale_viewport_ext(ratio, device).map_err(|previous| (previous, GdiError::InvalidDimensions)),
        }
    }

    /// Scale the window extent, reporting the extent before the change. # C: O(DCs)
    pub fn scale_window_ext(&mut self, dc: u32, ratio: [i32; 4], device: DeviceGeometry) -> Result<Size, (Size, GdiError)> {
        match self.dc_attr_mut(dc) {
            Err(error) => Err((Size::default(), error)),
            Ok(attr) => attr.scale_window_ext(ratio, device).map_err(|previous| (previous, GdiError::InvalidDimensions)),
        }
    }

    /// Override the resolution and physical size the mapping modes read. # C: O(DCs)
    pub fn set_virtual_resolution(&mut self, dc: u32, res: Size, size: Size) -> Result<(), GdiError> {
        if self.dc_attr_mut(dc)?.set_virtual_resolution(res, size) { Ok(()) } else { Err(GdiError::InvalidDimensions) }
    }

    /// Read the accumulated drawing bounds. # C: O(DCs)
    pub fn get_bounds_rect(&mut self, dc: u32, want_rect: bool, flags: u32) -> Result<(u32, Option<Rect>), GdiError> {
        Ok(self.dc_attr_mut(dc)?.get_bounds_rect(want_rect, flags))
    }

    /// Change bounds accumulation. # C: O(DCs)
    pub fn set_bounds_rect(&mut self, dc: u32, rect: Option<Rect>, flags: u32) -> Result<u32, GdiError> {
        Ok(self.dc_attr_mut(dc)?.set_bounds_rect(rect, flags))
    }

    /// Claim a pixel format for a device context. The first claim wins; a later
    /// claim succeeds only when it names the same format. # C: O(DCs)
    pub fn set_pixel_format(&mut self, dc: u32, format: i32) -> Result<bool, GdiError> {
        let attr = self.dc_attr_mut(dc)?;
        if attr.pixel_format == 0 { attr.pixel_format = format; return Ok(true); }
        Ok(attr.pixel_format == format)
    }

    /// Reset a device context to its initial attribute state, dropping every
    /// saved level with it. # C: O(DCs + levels)
    pub fn reset_dc_state(&mut self, dc: u32) -> Result<(), GdiError> {
        let index = self.dcs.iter().position(|(handle, _)| *handle == dc).ok_or(GdiError::NoSuchObject)?;
        let state = &mut self.dcs[index].1;
        state.attr.reset();
        state.saved.clear();
        state.clip = None;
        Ok(())
    }
}

#[cfg(test)]
impl GdiManager {
    /// Mutable attribute access for tests that must stage a state the public
    /// ordinals cannot reach directly.
    pub(crate) fn dc_attr_mut_for_test(&mut self, dc: u32) -> &mut DcAttr { self.dc_attr_mut(dc).expect("test device context") }
}

#[cfg(test)]
#[path = "tests/attrs.rs"]
mod tests;
