//! Coordinate mapping between window spaces: the offset between two windows'
//! client origins, and the point translation every screen/client conversion
//! and rectangle mapping is expressed in.
//!
//! One owner answers all of them. A right-to-left window contributes a mirror
//! about its own client width, and only the two named windows are examined for
//! it: an ancestor's layout does not mirror a descendant's points.

use super::{WindowId, WindowManager};
use super::styles::WS_EX_LAYOUTRTL;

/// Translation from one window's client space to another's, and whether the
/// pair's layouts disagree so the x axis reverses.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WindowsOffset { pub dx: i32, pub dy: i32, pub mirrored: bool }

impl WindowManager {
    /// Screen coordinates of one window's client origin, with the mirror term
    /// a right-to-left window adds. Every window from the named one up to but
    /// not including the desktop contributes its own client origin, which is
    /// parent-client-relative for a child and already screen for a top-level
    /// window. # C: O(N_windows)
    pub fn client_origin_screen(&self, id: WindowId) -> Option<(i32, i32, bool)> {
        let record = self.get(id)?;
        let mirrored = record.ex_style & WS_EX_LAYOUTRTL != 0;
        let mut x = 0i32;
        let mut y = 0i32;
        if mirrored {
            let client = self.client_rect(id)?;
            x = x.saturating_add(client.right.saturating_sub(client.left));
        }
        let mut current = id;
        // The tree is acyclic by construction; the bound keeps a corrupted
        // parent link from spinning here rather than answering.
        for _ in 0..=self.windows.len() {
            let rect = self.client_rect_raw(current)?;
            x = x.saturating_add(rect.left);
            y = y.saturating_add(rect.top);
            match self.get(current)?.parent { Some(parent) => current = parent, None => return Some((x, y, mirrored)) }
        }
        None
    }

    /// Offset carrying points from `from`'s client space to `to`'s, with the
    /// desktop named by `None` on either side. # C: O(N_windows)
    pub fn windows_offset(&self, from: Option<WindowId>, to: Option<WindowId>) -> Option<WindowsOffset> {
        let mut dx = 0i32;
        let mut dy = 0i32;
        let mut mirror_from = false;
        let mut mirror_to = false;
        if let Some(id) = from {
            let (x, y, mirrored) = self.client_origin_screen(id)?;
            dx = dx.saturating_add(x); dy = dy.saturating_add(y); mirror_from = mirrored;
        }
        if let Some(id) = to {
            let (x, y, mirrored) = self.client_origin_screen(id)?;
            dx = dx.saturating_sub(x); dy = dy.saturating_sub(y); mirror_to = mirrored;
        }
        if mirror_from { dx = dx.wrapping_neg(); }
        Some(WindowsOffset { dx, dy, mirrored: mirror_from ^ mirror_to })
    }

    /// Translate points from one window's client space to another's, answering
    /// the offset packed as the low words of dy:dx. A mirrored mapping of
    /// exactly two points swaps their x coordinates, so a rectangle passed as
    /// its two corners stays a well-ordered rectangle. # C: O(N_windows + N_points)
    pub fn map_points(&self, from: Option<WindowId>, to: Option<WindowId>, points: &mut [(i32, i32)]) -> Option<u32> {
        let offset = self.windows_offset(from, to)?;
        for point in points.iter_mut() {
            point.0 = point.0.saturating_add(offset.dx);
            point.1 = point.1.saturating_add(offset.dy);
            if offset.mirrored { point.0 = point.0.wrapping_neg(); }
        }
        if offset.mirrored && points.len() == 2 {
            let first = points[0].0;
            points[0].0 = points[1].0;
            points[1].0 = first;
        }
        Some(pack_offset(offset.dx, offset.dy))
    }
}

/// The mapping result is the two offsets' low words, y above x. # C: O(1)
pub const fn pack_offset(dx: i32, dy: i32) -> u32 { ((dy as u32 & 0xffff) << 16) | (dx as u32 & 0xffff) }

#[cfg(test)]
#[path = "tests/map_points.rs"]
mod tests;
