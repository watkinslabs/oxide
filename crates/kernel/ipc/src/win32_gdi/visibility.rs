//! Read-only rectangular visibility in the canonical MM_TEXT effective clip; 31ge§9.
use super::{Rect, GdiManager, GdiError};
use crate::win32_window::{PaintRegion, WindowRect};

impl GdiManager {
    /// Owned exact coverage; existing effective bounds constrain, never replace paint islands. # C: O(DCs + paint rectangles)
    pub fn visibility_region(&self, dc: u32) -> Result<PaintRegion, GdiError> {
        self.dc_raster_clip(dc)
    }
}

/// Reuse canonical exact-region intersection; allocation failure never becomes visible. # C: O(paint rectangles)
pub fn rect_visible_in_clip(clip: PaintRegion, rect: Rect) -> bool {
    let query = WindowRect { left: rect.left.min(rect.right), right: rect.left.max(rect.right),
        top: rect.top.min(rect.bottom), bottom: rect.top.max(rect.bottom) };
    clip.clipped(query).is_ok_and(|region| !region.is_empty())
}

#[cfg(test)]
#[path = "tests/visibility.rs"]
mod tests;
