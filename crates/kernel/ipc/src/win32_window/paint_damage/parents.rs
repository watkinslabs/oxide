use super::*;
use super::super::{WindowId, WindowManager};
const WS_CLIPCHILDREN: u32 = 0x0200_0000;
impl WindowManager {
    /// Prepare ancestor subtraction before committing BeginPaint; all geometry uses canonical units.
    /// # C: O(windows² + region operations)
    pub(super) fn paint_parent_validation(&self, mut child: WindowId, region: &PaintRegion) -> Result<Vec<(WindowId, PaintDamage)>, WindowError> {
        let mut updates = Vec::new(); let mut mapped = region.try_copy()?;
        if mapped.is_empty() { return Ok(updates); }
        for depth in 0..=self.windows.len() {
            let record = self.get(child).ok_or(WindowError::NoSuchWindow)?;
            let Some(parent) = record.parent else { return Ok(updates); };
            if depth == self.windows.len() { return Err(WindowError::InvalidParent); }
            let origin = record.client_rect.or_else(|| self.rect(child)).ok_or(WindowError::NoSuchWindow)?;
            mapped = mapped.translated(origin.left, origin.top)?;
            if self.get(parent).ok_or(WindowError::NoSuchWindow)?.style & WS_CLIPCHILDREN == 0 {
                if let Some((_, pending)) = self.dirty.iter().find(|(window, _)| *window == parent) {
                    let mut pending = pending.try_copy()?;
                    pending.region.subtract(&mapped)?;
                    if pending.region.is_empty() { pending.erase = false; pending.delayed_erase = false; pending.nonclient = false; }
                    updates.try_reserve(1).map_err(|_| WindowError::NoMemory)?;
                    updates.push((parent, pending));
                }
            }
            child = parent;
        }
        Err(WindowError::InvalidParent)
    }
}
