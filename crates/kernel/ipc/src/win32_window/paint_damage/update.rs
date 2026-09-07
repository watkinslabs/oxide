//! Pending update coverage a window reports before any paint begins.
use super::super::{WindowError, WindowId, WindowManager, WindowRect};
use super::{PaintRegion, NULL_REGION, SIMPLE_REGION, COMPLEX_REGION};

impl WindowManager {
    /// Coverage a window still owes a paint, clipped to its client area.
    /// A window with nothing pending reports an empty region. # C: O(windows + region)
    pub fn update_region(&self, id: WindowId) -> Result<PaintRegion, WindowError> {
        let client = self.client_rect(id).ok_or(WindowError::NoSuchWindow)?;
        match self.dirty.iter().find(|(window, _)| *window == id) {
            Some((_, damage)) => damage.region.clipped(client),
            None => Ok(PaintRegion::default()),
        }
    }
    /// Bounding box of the pending update coverage. # C: O(windows + region)
    pub fn update_rect(&self, id: WindowId) -> Result<Option<WindowRect>, WindowError> {
        Ok(self.update_region(id)?.bounds())
    }
}

/// Region complexity: empty, one exact rectangle, or several. # C: O(N_rects)
pub fn region_complexity(region: &PaintRegion) -> u32 {
    let Some(bounds) = region.bounds() else { return NULL_REGION; };
    let area = |rect: &WindowRect| (i128::from(rect.right) - i128::from(rect.left)) * (i128::from(rect.bottom) - i128::from(rect.top));
    let covered: i128 = region.rects().iter().map(area).sum();
    if covered == area(&bounds) { SIMPLE_REGION } else { COMPLEX_REGION }
}

#[cfg(test)]
#[path = "tests/update.rs"]
mod tests;
