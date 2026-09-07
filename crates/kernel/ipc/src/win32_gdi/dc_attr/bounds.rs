//! Accumulated drawing bounds and their enable state.
use super::DcAttr;
use crate::win32_gdi::{Rect, Point};

/// Reset the accumulated bounds; further reads clear reset.
pub const DCB_RESET: u32 = 0x0001;
/// Union the supplied rectangle into the accumulated bounds.
pub const DCB_ACCUMULATE: u32 = 0x0002;
/// Bounds have been accumulated since the last reset.
pub const DCB_SET: u32 = DCB_RESET | DCB_ACCUMULATE;
/// Start accumulating.
pub const DCB_ENABLE: u32 = 0x0004;
/// Stop accumulating.
pub const DCB_DISABLE: u32 = 0x0008;

/// An empty accumulator: inverted extremes, so the first union replaces both corners.
pub fn empty_bounds() -> Rect { Rect { left: i32::MAX, top: i32::MAX, right: i32::MIN, bottom: i32::MIN } }

/// A rectangle with no area contributes nothing. # C: O(1)
pub fn rect_is_empty(rect: &Rect) -> bool { rect.left >= rect.right || rect.top >= rect.bottom }

/// Union one rectangle into an accumulator, ignoring an empty one. # C: O(1)
pub fn add_bounds_rect(bounds: &mut Rect, rect: &Rect) {
    if rect_is_empty(rect) { return; }
    bounds.left = bounds.left.min(rect.left);
    bounds.top = bounds.top.min(rect.top);
    bounds.right = bounds.right.max(rect.right);
    bounds.bottom = bounds.bottom.max(rect.bottom);
}

impl DcAttr {
    /// Read the accumulated bounds. The device driver holds no bounds of its
    /// own, so only the accumulator answers. An empty accumulator reports a
    /// zeroed rectangle; a non-empty one is clamped to the visible rectangle
    /// and converted back to logical coordinates. # C: O(1)
    pub fn get_bounds_rect(&mut self, want_rect: bool, flags: u32) -> (u32, Option<Rect>) {
        let result = if want_rect {
            if rect_is_empty(&self.bounds) {
                (DCB_RESET, Some(Rect { left: 0, top: 0, right: 0, bottom: 0 }))
            } else {
                let mut rect = self.bounds;
                rect.left = rect.left.max(0);
                rect.top = rect.top.max(0);
                rect.right = rect.right.min(self.vis_rect.right - self.vis_rect.left);
                rect.bottom = rect.bottom.min(self.vis_rect.bottom - self.vis_rect.top);
                let top_left = self.dp_to_lp(Point { x: rect.left, y: rect.top });
                let bottom_right = self.dp_to_lp(Point { x: rect.right, y: rect.bottom });
                (DCB_SET, Some(Rect { left: top_left.x, top: top_left.y, right: bottom_right.x, bottom: bottom_right.y }))
            }
        } else { (0, None) };
        if flags & DCB_RESET != 0 { self.bounds = empty_bounds(); }
        result
    }

    /// Change bounds accumulation. Enabling and disabling at once is refused.
    /// An accumulate request converts its rectangle to device space first. # C: O(1)
    pub fn set_bounds_rect(&mut self, rect: Option<Rect>, flags: u32) -> u32 {
        if flags & DCB_ENABLE != 0 && flags & DCB_DISABLE != 0 { return 0; }
        // The driver reports no device-specific bounds, so the accumulated set
        // alone decides whether anything has been drawn.
        let mut result = if self.bounds_enabled { DCB_ENABLE } else { DCB_DISABLE };
        result |= if rect_is_empty(&self.bounds) { DCB_RESET } else { DCB_SET };
        if flags & DCB_RESET != 0 { self.bounds = empty_bounds(); }
        if flags & DCB_ACCUMULATE != 0 {
            if let Some(rect) = rect {
                let top_left = self.lp_to_dp(Point { x: rect.left, y: rect.top });
                let bottom_right = self.lp_to_dp(Point { x: rect.right, y: rect.bottom });
                add_bounds_rect(&mut self.bounds, &Rect { left: top_left.x, top: top_left.y,
                    right: bottom_right.x, bottom: bottom_right.y });
            }
        }
        if flags & DCB_ENABLE != 0 { self.bounds_enabled = true; }
        if flags & DCB_DISABLE != 0 { self.bounds_enabled = false; }
        result
    }

    /// Record a drawn device-space rectangle while accumulation is enabled. # C: O(1)
    pub fn accumulate_bounds(&mut self, rect: Rect) {
        if self.bounds_enabled { add_bounds_rect(&mut self.bounds, &rect); }
    }
}

#[cfg(test)]
#[path = "tests/bounds.rs"]
mod tests;
