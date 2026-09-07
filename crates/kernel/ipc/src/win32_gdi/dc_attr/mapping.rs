//! Mapping modes and the page transform they build.
use super::{DcAttr, LAYOUT_RTL};
use crate::win32_gdi::{Xform, Size, gdi_round, muldiv};

pub const MM_TEXT: u32 = 1;
pub const MM_LOMETRIC: u32 = 2;
pub const MM_HIMETRIC: u32 = 3;
pub const MM_LOENGLISH: u32 = 4;
pub const MM_HIENGLISH: u32 = 5;
pub const MM_TWIPS: u32 = 6;
pub const MM_ISOTROPIC: u32 = 7;
pub const MM_ANISOTROPIC: u32 = 8;

/// Tenths of a millimetre in one inch; the English mapping modes scale by it.
const TENTHS_MM_PER_INCH: i32 = 254;
/// Logical units per inch in the low-resolution English mapping mode.
const LOENGLISH_PER_INCH: i32 = 1000;
/// Logical units per inch in the high-resolution English mapping mode.
const HIENGLISH_PER_INCH: i32 = 10_000;
/// Twentieths of a point per inch.
const TWIPS_PER_INCH: i32 = 14_400;
/// Tenths of a millimetre per millimetre.
const LOMETRIC_PER_MM: i32 = 10;
/// Hundredths of a millimetre per millimetre.
const HIMETRIC_PER_MM: i32 = 100;

/// Device geometry the metric mapping modes read: resolution in pixels and
/// physical size in millimetres, as the capability table reports them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceGeometry { pub res: Size, pub size: Size }

impl DcAttr {
    /// Physical size the mapping modes use: the override when one is set,
    /// otherwise the device's own. # C: O(1)
    pub fn effective_size(&self, device: DeviceGeometry) -> Size {
        if self.virtual_size.cx != 0 { self.virtual_size } else { device.size }
    }

    /// Resolution the mapping modes use, with the same override rule. # C: O(1)
    pub fn effective_res(&self, device: DeviceGeometry) -> Size {
        if self.virtual_res.cx != 0 { self.virtual_res } else { device.res }
    }

    /// Shrink the larger viewport extent so one logical unit covers the same
    /// physical distance on both axes. # C: O(1)
    fn fix_isotropic(&mut self, device: DeviceGeometry) {
        let size = self.effective_size(device);
        let res = self.effective_res(device);
        let denominator = |res: i32, ext: i32| f64::from(res) * f64::from(ext);
        let xdim = abs64(f64::from(self.vport_ext.cx) * f64::from(size.cx) / denominator(res.cx, self.wnd_ext.cx));
        let ydim = abs64(f64::from(self.vport_ext.cy) * f64::from(size.cy) / denominator(res.cy, self.wnd_ext.cy));
        if xdim > ydim {
            let floor = if self.vport_ext.cx >= 0 { 1 } else { -1 };
            self.vport_ext.cx = gdi_round(f64::from(self.vport_ext.cx) * ydim / xdim);
            if self.vport_ext.cx == 0 { self.vport_ext.cx = floor; }
        } else {
            let floor = if self.vport_ext.cy >= 0 { 1 } else { -1 };
            self.vport_ext.cy = gdi_round(f64::from(self.vport_ext.cy) * xdim / ydim);
            if self.vport_ext.cy == 0 { self.vport_ext.cy = floor; }
        }
    }

    /// The window-to-viewport (page-to-device) transform the current extents
    /// and origins imply. Right-to-left layout mirrors it about the visible
    /// rectangle. # C: O(1)
    pub fn window_to_viewport(&self) -> Xform {
        let mut scale_x = f64::from(self.vport_ext.cx) / f64::from(self.wnd_ext.cx);
        let scale_y = f64::from(self.vport_ext.cy) / f64::from(self.wnd_ext.cy);
        if self.layout & LAYOUT_RTL != 0 { scale_x = -scale_x; }
        let mut dx = f64::from(self.vport_org.x) - scale_x * f64::from(self.wnd_org.x);
        let dy = f64::from(self.vport_org.y) - scale_y * f64::from(self.wnd_org.y);
        if self.layout & LAYOUT_RTL != 0 {
            dx = f64::from(self.vis_rect.right) - f64::from(self.vis_rect.left) - 1.0 - dx;
        }
        Xform { m11: scale_x as f32, m12: 0.0, m21: 0.0, m22: scale_y as f32, dx: dx as f32, dy: dy as f32 }
    }

    /// Rebuild the world-to-device transform and its inverse. Returns whether
    /// the linear part changed, which is what forces a font and pen reselect. # C: O(1)
    pub fn update_xforms(&mut self) -> bool {
        let page = self.window_to_viewport();
        let previous = self.world_to_vport;
        self.world_to_vport = Xform::combine(&self.world_to_wnd, &page);
        match self.world_to_vport.invert() {
            Some(inverse) => { self.vport_to_world = inverse; self.vport_to_world_valid = true; }
            None => { self.vport_to_world_valid = false; }
        }
        !previous.linear_eq(&self.world_to_vport)
    }

    /// Install a mapping mode, rejecting an unknown one. A right-to-left
    /// device context stays anisotropic whatever mode is asked for. # C: O(1)
    pub fn set_map_mode(&mut self, mode: u32, device: DeviceGeometry) -> bool {
        if mode == self.map_mode && (mode == MM_ISOTROPIC || mode == MM_ANISOTROPIC) { return true; }
        let metric = |attr: &mut DcAttr, per_unit: i32, divisor: i32| {
            let size = attr.effective_size(device);
            let res = attr.effective_res(device);
            attr.wnd_ext = Size { cx: muldiv(per_unit, size.cx, divisor), cy: muldiv(per_unit, size.cy, divisor) };
            attr.vport_ext = Size { cx: res.cx, cy: -res.cy };
        };
        match mode {
            MM_TEXT => { self.wnd_ext = Size { cx: 1, cy: 1 }; self.vport_ext = Size { cx: 1, cy: 1 }; }
            MM_LOMETRIC | MM_ISOTROPIC => metric(self, LOMETRIC_PER_MM, 1),
            MM_HIMETRIC => metric(self, HIMETRIC_PER_MM, 1),
            MM_LOENGLISH => metric(self, LOENGLISH_PER_INCH, TENTHS_MM_PER_INCH),
            MM_HIENGLISH => metric(self, HIENGLISH_PER_INCH, TENTHS_MM_PER_INCH),
            MM_TWIPS => metric(self, TWIPS_PER_INCH, TENTHS_MM_PER_INCH),
            MM_ANISOTROPIC => {}
            _ => return false,
        }
        if self.layout & LAYOUT_RTL == 0 { self.map_mode = mode; }
        self.update_xforms();
        true
    }

    /// Recompute the coefficients after an extent or origin change, correcting
    /// an isotropic viewport first. # C: O(1)
    pub fn compute_xform_coefficients(&mut self, device: DeviceGeometry) {
        if self.map_mode == MM_ISOTROPIC { self.fix_isotropic(device); }
        self.update_xforms();
    }

    /// Scale the viewport extent by two ratios, reporting the previous extent.
    /// A zero term is rejected only once the mode admits scaling at all. # C: O(1)
    pub fn scale_viewport_ext(&mut self, ratio: [i32; 4], device: DeviceGeometry) -> Result<Size, Size> {
        let previous = self.vport_ext;
        self.scale(previous, ratio, device, true).map(|_| previous).map_err(|_| previous)
    }

    /// Scale the window extent by two ratios, reporting the previous extent. # C: O(1)
    pub fn scale_window_ext(&mut self, ratio: [i32; 4], device: DeviceGeometry) -> Result<Size, Size> {
        let previous = self.wnd_ext;
        self.scale(previous, ratio, device, false).map(|_| previous).map_err(|_| previous)
    }

    fn scale(&mut self, _previous: Size, ratio: [i32; 4], device: DeviceGeometry, viewport: bool) -> Result<(), ()> {
        if self.map_mode != MM_ISOTROPIC && self.map_mode != MM_ANISOTROPIC { return Ok(()); }
        if ratio.iter().any(|term| *term == 0) { return Err(()); }
        let target = if viewport { &mut self.vport_ext } else { &mut self.wnd_ext };
        target.cx = (i64::from(target.cx) * i64::from(ratio[0]) / i64::from(ratio[1])) as i32;
        target.cy = (i64::from(target.cy) * i64::from(ratio[2]) / i64::from(ratio[3])) as i32;
        if target.cx == 0 { target.cx = 1; }
        if target.cy == 0 { target.cy = 1; }
        if self.map_mode == MM_ISOTROPIC { self.fix_isotropic(device); }
        self.update_xforms();
        Ok(())
    }

    /// Override the screen resolution and physical size the mapping modes read.
    /// All four terms must be non-zero together, or all four zero to restore
    /// the device's own values. # C: O(1)
    pub fn set_virtual_resolution(&mut self, res: Size, size: Size) -> bool {
        let terms = [res.cx, res.cy, size.cx, size.cy];
        if terms.iter().any(|term| *term == 0) && terms.iter().any(|term| *term != 0) { return false; }
        self.virtual_res = res;
        self.virtual_size = size;
        true
    }
}

fn abs64(value: f64) -> f64 { if value < 0.0 { -value } else { value } }

#[cfg(test)]
#[path = "tests/mapping.rs"]
mod tests;
