//! Area a window can hold damage in, cropped through its ancestors.
use super::*;
use super::super::{WindowId, WindowManager};
const WS_MINIMIZE: u32 = 0x2000_0000;

fn intersect(a: WindowRect, b: WindowRect) -> Option<WindowRect> {
    let r = WindowRect { left: a.left.max(b.left), top: a.top.max(b.top), right: a.right.min(b.right), bottom: a.bottom.min(b.bottom) };
    (r.left < r.right && r.top < r.bottom).then_some(r)
}
fn offset(r: WindowRect, dx: i32, dy: i32) -> Option<WindowRect> {
    Some(WindowRect { left: r.left.checked_add(dx)?, top: r.top.checked_add(dy)?,
        right: r.right.checked_add(dx)?, bottom: r.bottom.checked_add(dy)? })
}

impl WindowManager {
    /// Frame or client rectangle one window can take damage in, in that
    /// window's own client coordinates. The rectangle is intersected with
    /// every ancestor's client and window rectangles, so coverage outside the
    /// area an ancestor exposes is not damage the window ever repaints.
    /// Absent means the window takes no damage at all: it or an ancestor is
    /// hidden or minimized, or nothing of it remains after the intersection.
    /// A window with no parent is the top of the tree and is not cropped
    /// further. # C: O(N_windows²)
    pub fn visible_paint_rect(&self, id: WindowId, frame: bool) -> Option<WindowRect> {
        let record = self.get(id)?;
        if !record.visible { return None; }
        let origin = self.client_rect_raw(id)?;
        // A window's client area is part of the window: a client rectangle
        // left behind by an earlier layout cannot expose area the window
        // rectangle no longer covers.
        let mut rect = if frame { self.rect(id)? } else { intersect(origin, self.rect(id)?)? };
        let (mut dx, mut dy) = (0i32, 0i32);
        let mut cursor = record.parent;
        for _ in 0..=self.windows.len() {
            let Some(parent) = cursor else {
                return offset(rect, dx.checked_neg()?.checked_sub(origin.left)?, dy.checked_neg()?.checked_sub(origin.top)?);
            };
            let ancestor = self.get(parent)?;
            if !ancestor.visible || ancestor.style & WS_MINIMIZE != 0 { return None; }
            let client = self.client_rect_raw(parent)?;
            let window = self.rect(parent)?;
            rect = offset(rect, client.left, client.top)?;
            dx = dx.checked_add(client.left)?; dy = dy.checked_add(client.top)?;
            rect = intersect(rect, client)?;
            rect = intersect(rect, window)?;
            cursor = ancestor.parent;
        }
        None
    }
}

#[cfg(test)]
#[path = "tests/visible.rs"]
mod tests;
