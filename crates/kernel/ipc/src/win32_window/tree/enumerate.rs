//! Handle-list building, class/title search and reparenting.
use super::*;

/// What one handle-list request enumerates.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct HwndListFilter {
    /// Window whose children or siblings are listed; none lists top-level windows.
    pub window: Option<WindowId>,
    /// List descendants recursively rather than siblings from `window` onward.
    pub children: bool,
    /// Only windows owned by this thread; zero admits every thread.
    pub thread: u64,
}

impl WindowManager {
    /// Build the handle list one enumeration request names. Sibling order runs
    /// top of the z-order first, matching the order the search and hit-test
    /// walks use. # C: O(N_windows²)
    pub fn hwnd_list(&self, filter: HwndListFilter) -> Vec<WindowId> {
        let mut found = Vec::new();
        match (filter.window, filter.children) {
            (None, _) => for id in self.siblings_top_first(None) { self.append_hwnd(&mut found, id, filter.thread); },
            (Some(window), true) => self.append_descendants(&mut found, window, filter.thread),
            (Some(window), false) => {
                let Some(record) = self.get(window) else { return found };
                let siblings = self.siblings_top_first(record.parent);
                let start = siblings.iter().position(|sibling| *sibling == window).unwrap_or(siblings.len());
                for id in &siblings[start..] { self.append_hwnd(&mut found, *id, filter.thread); }
            }
        }
        found
    }

    fn append_hwnd(&self, found: &mut Vec<WindowId>, id: WindowId, thread: u64) {
        if thread != 0 && !self.get(id).is_some_and(|record| record.owner_tid == thread) { return; }
        if found.try_reserve(1).is_err() { return; }
        found.push(id);
    }

    fn append_descendants(&self, found: &mut Vec<WindowId>, window: WindowId, thread: u64) {
        for child in self.siblings_top_first(Some(window)) {
            self.append_hwnd(found, child, thread);
            self.append_descendants(found, child, thread);
        }
    }

    /// FindWindowEx: the first sibling after `after` whose class atom and
    /// title both match. A class atom of zero matches any class; a title of
    /// none matches any title, and an empty title matches only a window whose
    /// text is empty. # C: O(N_windows² + N_title)
    pub fn find_child(&self, parent: Option<WindowId>, after: Option<WindowId>, class_atom: u16,
        title: Option<&[u16]>) -> Option<WindowId> {
        let siblings = self.siblings_top_first(parent);
        let start = match after {
            None => 0,
            Some(child) => {
                if self.get(child)?.parent != parent { return None; }
                siblings.iter().position(|sibling| *sibling == child)? + 1
            }
        };
        siblings[start..].iter().copied().find(|id| {
            let Some(record) = self.get(*id) else { return false };
            if class_atom != 0 && record.class_atom != Some(class_atom) { return false; }
            match title {
                None => true,
                Some(title) => self.text(*id).unwrap_or(&[]) == title,
            }
        })
    }

    /// SetParent: move one window under a new parent, answering the parent it
    /// left. A window cannot become a descendant of itself, and the caller's
    /// own thread must own it. # C: O(N_windows²)
    pub fn set_parent(&mut self, tid: u64, id: WindowId, parent: Option<WindowId>)
        -> Result<Option<WindowId>, WindowError> {
        let record = self.get(id).ok_or(WindowError::NoSuchWindow)?;
        if record.owner_tid != tid { return Err(WindowError::WrongThread); }
        if let Some(parent) = parent {
            self.get(parent).ok_or(WindowError::InvalidParent)?;
            if parent == id || self.is_child(id, parent) { return Err(WindowError::InvalidParent); }
        }
        let old = record.parent;
        if old == parent { return Ok(old); }
        self.reparent(id, parent)?;
        Ok(old)
    }

    /// Move one window's tree entry under a new parent and place it at the top
    /// of its new siblings, the position a reparented window takes.
    /// # C: O(N_windows)
    fn reparent(&mut self, id: WindowId, parent: Option<WindowId>) -> Result<(), WindowError> {
        let index = self.windows.iter().position(|(window, _)| *window == id).ok_or(WindowError::NoSuchWindow)?;
        let mut entry = self.windows.remove(index);
        entry.1.parent = parent;
        let slot = self.windows.iter().rposition(|(_, record)| record.parent == parent)
            .map_or(self.windows.len(), |last| last + 1);
        self.windows.insert(slot, entry);
        Ok(())
    }
}
