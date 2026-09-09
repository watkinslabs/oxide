//! Point-to-window search, in client coordinates for the child form and in
//! screen coordinates for the desktop-wide form.
use super::*;

/// Hit-test answers the screen-wide search reports alongside the window.
pub const HTERROR: i32 = -2;
pub const HTTRANSPARENT: i32 = -1;
pub const HTNOWHERE: i32 = 0;
pub const HTCLIENT: i32 = 1;

impl WindowManager {
    /// Rectangle of one window in its parent's coordinates; a window with no
    /// parent is already in screen coordinates. # C: O(N_windows)
    pub fn rect_in_parent(&self, id: WindowId) -> Option<WindowRect> {
        self.rect(id)
    }

    /// ChildWindowFromPointEx: the topmost child of `parent` covering a point
    /// given in the parent's client coordinates. A point outside the parent's
    /// client area answers nothing; a point inside that no child covers
    /// answers the parent itself. # C: O(N_windows²)
    pub fn child_from_point(&self, parent: WindowId, x: i32, y: i32, flags: u32) -> Option<WindowId> {
        let client = self.client_rect(parent)?;
        if !point_in_rect(client, x, y) { return None; }
        for child in self.siblings_top_first(Some(parent)) {
            let Some(rect) = self.rect_in_parent(child) else { continue };
            if !point_in_rect(rect, x, y) { continue; }
            let Some(record) = self.get(child) else { continue };
            if flags & CWP_SKIPINVISIBLE != 0 && record.style & WS_VISIBLE == 0 { continue; }
            if flags & CWP_SKIPDISABLED != 0 && record.style & WS_DISABLED != 0 { continue; }
            if flags & CWP_SKIPTRANSPARENT != 0 && record.ex_style & WS_EX_TRANSPARENT != 0 { continue; }
            return Some(child);
        }
        Some(parent)
    }

    /// Whether a parent-client point can land on one window at all: it must be
    /// visible, must not be a disabled child, must not be a layered
    /// transparent window, and must cover the point. # C: O(N_windows)
    fn point_reaches(&self, id: WindowId, x: i32, y: i32) -> bool {
        let Some(record) = self.get(id) else { return false };
        if record.style & WS_VISIBLE == 0 { return false; }
        if record.style & (WS_POPUP | WS_CHILD | WS_DISABLED) == (WS_CHILD | WS_DISABLED) { return false; }
        if record.ex_style & (WS_EX_LAYERED | WS_EX_TRANSPARENT) == (WS_EX_LAYERED | WS_EX_TRANSPARENT) { return false; }
        let Some(rect) = self.rect(id).filter(|rect| point_in_rect(*rect, x, y)) else { return false; };
        let Some(region) = self.window_region(id) else { return true; };
        let Some((x, y)) = x.checked_sub(rect.left).zip(y.checked_sub(rect.top)) else { return false; };
        region.iter().any(|rect| point_in_rect(*rect, x, y))
    }

    /// Candidate windows under a screen point, deepest first: each child that
    /// covers the point contributes its own covering descendants before
    /// itself, so the first entry is the innermost window. A window that is
    /// minimized or disabled hides its children from the search.
    /// # C: O(N_windows²)
    pub fn windows_from_point(&self, parent: Option<WindowId>, x: i32, y: i32) -> Vec<WindowId> {
        let mut found = Vec::new();
        let origin = match parent { Some(parent) => self.client_origin(parent), None => Some((0, 0)) };
        let Some((dx, dy)) = origin else { return found; };
        let Some((x, y)) = x.checked_sub(dx).zip(y.checked_sub(dy)) else { return found; };
        self.children_at_point(parent, x, y, &mut found);
        found
    }

    fn children_at_point(&self, parent: Option<WindowId>, x: i32, y: i32, found: &mut Vec<WindowId>) {
        for child in self.siblings_top_first(parent) {
            if !self.point_reaches(child, x, y) { continue; }
            let record = match self.get(child) { Some(record) => record, None => continue };
            if record.style & (WS_MINIMIZE | WS_DISABLED) == 0 {
                if let Some(client) = self.client_rect_raw(child).filter(|rect| point_in_rect(*rect, x, y)) {
                    if let Some((x, y)) = x.checked_sub(client.left).zip(y.checked_sub(client.top)) {
                        self.children_at_point(Some(child), x, y, found);
                    }
                }
            }
            found.push(child);
        }
    }

    /// WindowFromPoint: the innermost window under a screen point, with the
    /// hit-test answer. A disabled window ends the search with an error
    /// answer rather than passing the point to what lies below.
    /// # C: O(N_windows²)
    pub fn window_from_point(&self, parent: Option<WindowId>, x: i32, y: i32) -> (Option<WindowId>, i32) {
        let candidates = self.windows_from_point(parent, x, y);
        let Some(first) = candidates.first().copied() else { return (None, HTNOWHERE) };
        let disabled = self.get(first).is_some_and(|record| record.style & WS_DISABLED != 0);
        (Some(first), if disabled { HTERROR } else { HTCLIENT })
    }
}
