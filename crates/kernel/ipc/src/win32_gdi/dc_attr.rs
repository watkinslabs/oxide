//! Device-context attribute block: mapping state, transforms and bounds; 31fk§8.
//!
//! Module manifest:
//! - `mapping`: mapping modes, window/viewport extents, isotropic correction.
//! - `world`: world transform modification and coordinate-space queries.
//! - `bounds`: accumulated drawing bounds and their enable state.

use super::{Rect, Xform, Point, Size, DcKind};

#[path = "dc_attr/mapping.rs"]
mod mapping;
#[path = "dc_attr/world.rs"]
mod world;
#[path = "dc_attr/bounds.rs"]
mod bounds;
pub use bounds::{add_bounds_rect, empty_bounds, rect_is_empty};
pub use world::{MWT_IDENTITY, MWT_LEFTMULTIPLY, MWT_RIGHTMULTIPLY, MWT_SET,
    XFORM_WORLD_TO_PAGE, XFORM_PAGE_TO_DEVICE, XFORM_WORLD_TO_DEVICE, XFORM_DEVICE_TO_WORLD,
    LP_TO_DP, DP_TO_LP};
pub use mapping::{MM_TEXT, MM_LOMETRIC, MM_HIMETRIC, MM_LOENGLISH, MM_HIENGLISH, MM_TWIPS,
    MM_ISOTROPIC, MM_ANISOTROPIC, DeviceGeometry};

/// Right-to-left layout; the only layout bit that changes the page transform.
pub const LAYOUT_RTL: u32 = 0x0000_0001;
/// Compatible graphics mode: the world transform may not be set outright.
pub const GM_COMPATIBLE: u32 = 1;
/// Advanced graphics mode admits an arbitrary world transform.
pub const GM_ADVANCED: u32 = 2;
/// Default arc sweep direction.
pub const AD_COUNTERCLOCKWISE: u32 = 1;
/// Clockwise arc sweep.
pub const AD_CLOCKWISE: u32 = 2;
/// Default miter limit for a freshly initialised device context.
pub const DEFAULT_MITER_LIMIT: f32 = 10.0;

/// Every attribute the save/restore stack, the mapping modes and the bounds
/// accumulator own. Selected objects live in the device context itself.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DcAttr {
    pub map_mode: u32,
    pub graphics_mode: u32,
    pub layout: u32,
    pub arc_direction: u32,
    pub miter_limit: f32,
    pub wnd_org: Point,
    pub wnd_ext: Size,
    pub vport_org: Point,
    pub vport_ext: Size,
    pub virtual_res: Size,
    pub virtual_size: Size,
    pub vis_rect: Rect,
    pub world_to_wnd: Xform,
    pub world_to_vport: Xform,
    pub vport_to_world: Xform,
    pub vport_to_world_valid: bool,
    pub bounds: Rect,
    pub bounds_enabled: bool,
    pub save_level: u32,
    pub pixel_format: i32,
    pub kind: DcKind,
}

impl Default for DcAttr { fn default() -> Self { Self::new() } }

impl DcAttr {
    /// The attribute block a newly created device context starts from. # C: O(1)
    pub fn new() -> Self {
        DcAttr {
            map_mode: MM_TEXT, graphics_mode: GM_COMPATIBLE, layout: 0,
            arc_direction: AD_COUNTERCLOCKWISE, miter_limit: DEFAULT_MITER_LIMIT,
            wnd_org: Point { x: 0, y: 0 }, wnd_ext: Size { cx: 1, cy: 1 },
            vport_org: Point { x: 0, y: 0 }, vport_ext: Size { cx: 1, cy: 1 },
            virtual_res: Size { cx: 0, cy: 0 }, virtual_size: Size { cx: 0, cy: 0 },
            vis_rect: Rect { left: 0, top: 0, right: 0, bottom: 0 },
            world_to_wnd: Xform::IDENTITY, world_to_vport: Xform::IDENTITY,
            vport_to_world: Xform::IDENTITY, vport_to_world_valid: true,
            bounds: empty_bounds(), bounds_enabled: false, save_level: 0, pixel_format: 0,
            kind: DcKind::Memory,
        }
    }

    /// Reset to initial state without disturbing the visible rectangle, which
    /// belongs to the surface rather than to the attribute block. # C: O(1)
    pub fn reset(&mut self) {
        let vis_rect = self.vis_rect;
        let pixel_format = self.pixel_format;
        let kind = self.kind;
        *self = DcAttr { vis_rect, pixel_format, kind, ..DcAttr::new() };
    }

    /// Publish a new surface extent as the visible rectangle and rebuild the
    /// transforms that depend on it. # C: O(1)
    pub fn set_vis_rect(&mut self, width: i32, height: i32) {
        self.vis_rect = Rect { left: 0, top: 0, right: width, bottom: height };
        self.update_xforms();
    }
}

#[cfg(test)]
#[path = "dc_attr/tests/state.rs"]
mod tests;
