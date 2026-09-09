//! Ancestry: the parent a relationship query answers, the root walk and the
//! owner walk, plus the descendant test reparenting depends on.
use super::*;

impl WindowManager {
    /// The window a parent query answers: a child window answers its parent,
    /// a popup answers its owner, and every other window answers nothing.
    /// # C: O(N_windows)
    pub fn relative_parent(&self, id: WindowId) -> Option<WindowId> {
        let record = self.get(id)?;
        if record.style & WS_POPUP != 0 { return record.owner; }
        if record.style & WS_CHILD != 0 { return record.parent; }
        None
    }

    /// GetAncestor. `GA_PARENT` answers the tree parent whatever the style,
    /// `GA_ROOT` the topmost window below the desktop, and `GA_ROOTOWNER` the
    /// end of the parent-or-owner walk. # C: O(N_windows²)
    pub fn ancestor(&self, id: WindowId, kind: u32) -> Option<WindowId> {
        self.get(id)?;
        match kind {
            GA_PARENT => self.get(id)?.parent,
            GA_ROOT => {
                let mut current = id;
                while let Some(parent) = self.get(current).and_then(|record| record.parent) { current = parent; }
                Some(current)
            }
            GA_ROOTOWNER => {
                let mut current = id;
                while let Some(next) = self.relative_parent(current) { current = next; }
                Some(current)
            }
            _ => None,
        }
    }

    /// Whether `child` is a descendant of `parent`. # C: O(N_windows²)
    pub fn is_child(&self, parent: WindowId, child: WindowId) -> bool {
        if parent == child { return false; }
        let mut current = child;
        while let Some(record) = self.get(current) {
            // The walk stops at a window that is not a child: an owned popup
            // is not inside its owner for this test.
            if record.style & WS_CHILD == 0 { return false; }
            let Some(next) = record.parent else { return false; };
            if next == parent { return true; }
            current = next;
        }
        false
    }

    /// GetWindow. The first sibling is the top of the z-order;
    /// `GW_HWNDNEXT` walks downward and `GW_HWNDPREV` walks upward.
    /// # C: O(N_windows²)
    pub fn window_relative(&self, id: WindowId, relationship: u32) -> Option<WindowId> {
        let record = self.get(id)?;
        match relationship {
            GW_OWNER => record.owner,
            GW_CHILD => self.siblings_top_first(Some(id)).first().copied(),
            GW_HWNDFIRST => self.siblings_top_first(record.parent).first().copied(),
            GW_HWNDLAST => self.siblings_top_first(record.parent).last().copied(),
            GW_HWNDNEXT | GW_HWNDPREV => {
                let siblings = self.siblings_top_first(record.parent);
                let index = siblings.iter().position(|sibling| *sibling == id)?;
                let next = if relationship == GW_HWNDNEXT { index.checked_add(1)? } else { index.checked_sub(1)? };
                siblings.get(next).copied()
            }
            GW_ENABLEDPOPUP => {
                if self.ancestor(id, GA_ROOT) != Some(id) { return None; }
                self.siblings_top_first(None).into_iter().rev().find(|candidate| {
                    self.window_relative(*candidate, GW_OWNER) == Some(id)
                        && self.get(*candidate).is_some_and(|record| record.visible && record.style & WS_DISABLED == 0)
                })
            }
            _ => None,
        }
    }

    /// Siblings of one parent from the top of the z-order down. # C: O(N_windows)
    pub fn siblings_top_first(&self, parent: Option<WindowId>) -> Vec<WindowId> {
        let mut siblings = self.position_siblings(parent);
        siblings.reverse();
        siblings
    }
}
