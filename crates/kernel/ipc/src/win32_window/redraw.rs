//! Live pending-paint traversal; damage remains owned by BeginPaint.
use super::{WindowError, WindowId, WindowManager};
const WS_MINIMIZE: u32 = 0x2000_0000;
const WS_CLIPCHILDREN: u32 = 0x0200_0000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PaintChildren { Default, All, None }

impl WindowManager {
    /// Auxiliary paint scan retains client damage; unclipped dirty ancestors delay nonclient work.
    /// # C: O(windows³)
    pub fn next_pending_erase(&self, root: WindowId, mut after: Option<WindowId>, mode: PaintChildren) -> Result<Option<WindowId>, WindowError> {
        let mut ancestor = self.get(root).ok_or(WindowError::NoSuchWindow)?.parent;
        for _ in 0..self.windows.len() {
            let Some(id) = ancestor else { break; };
            let record = self.get(id).ok_or(WindowError::NoSuchWindow)?;
            if record.style & WS_CLIPCHILDREN == 0 && self.dirty.iter().any(|(window, damage)| *window == id && damage.pending()) { return Ok(None); }
            ancestor = record.parent;
        }
        if let Some(previous) = after.filter(|_| mode != PaintChildren::All) {
            let mut cursor = Some(previous);
            for _ in 0..self.windows.len() {
                let Some(id) = cursor else { break; };
                let Some(record) = self.get(id) else { return Ok(None); };
                if record.style & WS_CLIPCHILDREN == 0 && self.dirty.iter().any(|(window, damage)| *window == id && damage.pending()) {
                    // Skip this ancestor's entire subtree, not just its own HWND.
                    if id == root { return Ok(None); }
                    after = self.last_paint_descendant(id);
                }
                if id == root { break; } cursor = record.parent;
            }
        }
        for _ in 0..self.windows.len() {
            let Some(id) = self.next_pending_paint(root, after, mode)? else { return Ok(None); };
            if self.dirty.iter().any(|(window, damage)| *window == id && !damage.region.is_empty() && (damage.erase || damage.nonclient)) { return Ok(Some(id)); }
            after = Some(id);
        }
        Ok(None)
    }
    fn last_paint_descendant(&self, root: WindowId) -> Option<WindowId> {
        let mut last = root;
        for _ in 0..self.windows.len() {
            let Some(next) = self.paint_next_node(root, last).ok().flatten() else { return Some(last); };
            last = next;
        }
        None
    }
    /// Re-evaluate the current tree after each completed synchronous paint.
    /// Root first, then top-to-bottom sibling order; never consumes damage.
    /// # C: O(N_windows³), bounded without recursive kernel-stack growth
    pub fn next_pending_paint(&self, root: WindowId, after: Option<WindowId>, mode: PaintChildren)
        -> Result<Option<WindowId>, WindowError> {
        self.get(root).ok_or(WindowError::NoSuchWindow)?;
        if let Some(after) = after {
            // A destroyed prior target terminates this scan, as no valid cursor remains.
            if self.get(after).is_none() { return Ok(None); }
            if !self.paint_descendant(root, after) { return Err(WindowError::InvalidParent); }
        }
        let mut cursor = Some(root);
        let mut past = after.is_none();
        for _ in 0..=self.windows.len() {
            let Some(window) = cursor else { return Ok(None); };
            if past && self.paint_eligible(root, window, mode)
                && self.dirty.iter().any(|(candidate, _)| *candidate == window) { return Ok(Some(window)); }
            if after == Some(window) { past = true; }
            cursor = self.paint_next_node(root, window)?;
        }
        Err(WindowError::InvalidParent)
    }

    fn paint_descendant(&self, root: WindowId, mut window: WindowId) -> bool {
        for _ in 0..=self.windows.len() {
            if window == root { return true; }
            let Some(parent) = self.get(window).and_then(|record| record.parent) else { return false; };
            window = parent;
        }
        false
    }

    fn paint_eligible(&self, root: WindowId, mut window: WindowId, mode: PaintChildren) -> bool {
        let mut reached_root = false;
        for _ in 0..=self.windows.len() {
            let Some(record) = self.get(window) else { return false; };
            if !record.visible { return false; }
            if window == root { reached_root = true; }
            let Some(parent) = record.parent else { return reached_root; };
            if !reached_root {
                let Some(parent_record) = self.get(parent) else { return false; };
                if mode == PaintChildren::None || parent_record.style & WS_MINIMIZE != 0
                    || mode == PaintChildren::Default && parent_record.style & WS_CLIPCHILDREN == 0 { return false; }
            }
            window = parent;
        }
        false
    }

    fn paint_next_node(&self, root: WindowId, mut window: WindowId) -> Result<Option<WindowId>, WindowError> {
        if let Some((id, _)) = self.windows.iter().rev().find(|(_, record)| record.parent == Some(window)) { return Ok(Some(*id)); }
        for _ in 0..=self.windows.len() {
            if window == root { return Ok(None); }
            let index = self.windows.iter().position(|(id, _)| *id == window).ok_or(WindowError::NoSuchWindow)?;
            let parent = self.windows[index].1.parent.ok_or(WindowError::InvalidParent)?;
            if let Some((id, _)) = self.windows[..index].iter().rev().find(|(_, record)| record.parent == Some(parent)) { return Ok(Some(*id)); }
            window = parent;
        }
        Err(WindowError::InvalidParent)
    }
}

#[cfg(test)]
#[path = "tests/redraw.rs"]
mod tests;
