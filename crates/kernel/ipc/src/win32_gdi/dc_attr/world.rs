//! World transform modification and coordinate-space queries.
use super::{DcAttr, GM_ADVANCED};
use crate::win32_gdi::{Xform, Point};

pub const MWT_IDENTITY: u32 = 1;
pub const MWT_LEFTMULTIPLY: u32 = 2;
pub const MWT_RIGHTMULTIPLY: u32 = 3;
pub const MWT_SET: u32 = 4;

/// World space to page space: the world transform itself.
pub const XFORM_WORLD_TO_PAGE: u32 = 0x203;
/// Page space to device space: the mapping-mode transform.
pub const XFORM_PAGE_TO_DEVICE: u32 = 0x304;
/// World space to device space: the two combined.
pub const XFORM_WORLD_TO_DEVICE: u32 = 0x204;
/// Device space back to world space: the inverse of the combination.
pub const XFORM_DEVICE_TO_WORLD: u32 = 0x402;

/// Transform logical points into device points.
pub const LP_TO_DP: u32 = 0;
/// Transform device points back into logical points.
pub const DP_TO_LP: u32 = 1;

impl DcAttr {
    /// Apply one of the four modification modes to the world transform.
    /// `MWT_SET` is admitted only in advanced graphics mode and only for a
    /// non-singular matrix; a null matrix is admitted only by `MWT_IDENTITY`. # C: O(1)
    pub fn modify_world_transform(&mut self, xform: Option<Xform>, mode: u32) -> bool {
        if xform.is_none() && mode != MWT_IDENTITY { return false; }
        let applied = match mode {
            MWT_IDENTITY => { self.world_to_wnd = Xform::IDENTITY; true }
            MWT_LEFTMULTIPLY => {
                let Some(xform) = xform else { return false };
                self.world_to_wnd = Xform::combine(&xform, &self.world_to_wnd); true
            }
            MWT_RIGHTMULTIPLY => {
                let Some(xform) = xform else { return false };
                self.world_to_wnd = Xform::combine(&self.world_to_wnd, &xform); true
            }
            MWT_SET => {
                let Some(xform) = xform else { return false };
                let admitted = self.graphics_mode == GM_ADVANCED
                    && f64::from(xform.m11) * f64::from(xform.m22) != f64::from(xform.m12) * f64::from(xform.m21);
                if admitted { self.world_to_wnd = xform; }
                admitted
            }
            _ => false,
        };
        if applied { self.update_xforms(); }
        applied
    }

    /// Report one of the four coordinate-space transforms. # C: O(1)
    pub fn get_transform(&self, which: u32) -> Option<Xform> {
        match which {
            XFORM_WORLD_TO_PAGE => Some(self.world_to_wnd),
            XFORM_PAGE_TO_DEVICE => Some(self.window_to_viewport()),
            XFORM_WORLD_TO_DEVICE => Some(self.world_to_vport),
            XFORM_DEVICE_TO_WORLD => Some(self.vport_to_world),
            _ => None,
        }
    }

    /// Transform a point run in place. Device-to-logical is refused while the
    /// world-to-device transform has no inverse. # C: O(N_points)
    pub fn transform_points(&self, mode: u32, points: &mut [Point]) -> bool {
        let xform = match mode {
            LP_TO_DP => self.world_to_vport,
            DP_TO_LP if self.vport_to_world_valid => self.vport_to_world,
            _ => return false,
        };
        for point in points.iter_mut() { *point = xform.apply(*point); }
        true
    }

    /// Map a logical point to device space, the conversion every drawing
    /// primitive applies to its arguments. # C: O(1)
    pub fn lp_to_dp(&self, point: Point) -> Point { self.world_to_vport.apply(point) }

    /// Map a device point back to logical space, leaving it unchanged while
    /// the inverse transform is unavailable. # C: O(1)
    pub fn dp_to_lp(&self, point: Point) -> Point {
        if self.vport_to_world_valid { self.vport_to_world.apply(point) } else { point }
    }
}

#[cfg(test)]
#[path = "tests/world.rs"]
mod tests;
