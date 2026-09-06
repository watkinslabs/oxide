//! Desktop activation uses canonical HWND focus and one admitted notification batch.
use super::*;
const WM_ACTIVATE: u32 = 0x0006;
const WM_ACTIVATEAPP: u32 = 0x001c;
const WA_INACTIVE: u64 = 0;
const WA_ACTIVE: u64 = 1;
const WS_CHILD: u32 = 0x4000_0000;
const WS_MINIMIZE: u32 = 0x2000_0000;
const ACTIVATE_MINIMIZED: u64 = 0x0020_0000;

impl WindowManager {
    /// # C: O(1)
    pub fn active_window(&self) -> Option<WindowId> { self.active }

    fn descendant_of(&self, id: WindowId, root: WindowId) -> bool {
        let mut cursor = Some(id);
        while let Some(id) = cursor {
            if id == root { return self.get(id).is_some(); }
            cursor = self.get(id).filter(|record| record.style & WS_CHILD != 0).and_then(|record| record.parent);
        }
        false
    }

    /// Top-level activation preserves live descendant focus; loss remembers it.
    /// All affected thread queues are checked before publishing any mutation.
    /// # C: O(windows² + queues * notifications); # Sleeps: no
    pub fn compositor_focus(&mut self, root: WindowId, active: bool) -> Result<(), WindowError> {
        let record = self.get(root).ok_or(WindowError::NoSuchWindow)?;
        if record.style & WS_CHILD != 0 { return Err(WindowError::InvalidParent); }
        if active && self.active == Some(root) || !active && self.active != Some(root) { return Ok(()); }
        let previous = self.active;
        let next = active.then_some(root);
        let old_focus = self.focus;
        let new_focus = next.map(|root| {
            old_focus.filter(|id| self.descendant_of(*id, root))
                .or_else(|| self.get(root).and_then(|record| record.last_focus).filter(|id| self.descendant_of(*id, root)))
                .unwrap_or(root)
        });
        let mut messages = Vec::new();
        let mut append = |id: WindowId, message, wparam, lparam| {
            messages.push(WinMessage { hwnd: Some(id), message, wparam, lparam });
        };
        if let Some(old) = previous {
            append(old, WM_NCACTIVATE, 0, next.map_or(0, |id| id.raw() as i64));
            let minimized = self.get(old).is_some_and(|record| record.style & WS_MINIMIZE != 0);
            append(old, WM_ACTIVATE, WA_INACTIVE | if minimized { ACTIVATE_MINIMIZED } else { 0 }, next.map_or(0, |id| id.raw() as i64));
        }
        let old_thread = previous.and_then(|id| self.get(id)).map_or(0, |record| record.owner_tid);
        let new_thread = next.and_then(|id| self.get(id)).map_or(0, |record| record.owner_tid);
        if old_thread != new_thread {
            for (id, record) in &self.windows {
                if record.style & WS_CHILD != 0 { continue; }
                if old_thread != 0 && record.owner_tid == old_thread { append(*id, WM_ACTIVATEAPP, 0, new_thread as i64); }
            }
            for (id, record) in &self.windows {
                if record.style & WS_CHILD == 0 && new_thread != 0 && record.owner_tid == new_thread {
                    append(*id, WM_ACTIVATEAPP, 1, old_thread as i64);
                }
            }
        }
        if let Some(new) = next {
            append(new, WM_NCACTIVATE, 1, previous.map_or(0, |id| id.raw() as i64));
            let minimized = self.get(new).is_some_and(|record| record.style & WS_MINIMIZE != 0);
            append(new, WM_ACTIVATE, WA_ACTIVE | if minimized { ACTIVATE_MINIMIZED } else { 0 }, previous.map_or(0, |id| id.raw() as i64));
        }
        if old_focus != new_focus {
            if let Some(old) = old_focus { append(old, WM_KILLFOCUS, new_focus.map_or(0, |id| id.raw() as u64), 0); }
            if let Some(new) = new_focus { append(new, WM_SETFOCUS, old_focus.map_or(0, |id| id.raw() as u64), 0); }
        }
        for (tid, _) in &self.queues {
            let count = messages.iter().filter(|message| message.hwnd.and_then(|id| self.get(id)).is_some_and(|record| record.owner_tid == *tid)).count();
            if !self.queue_has_capacity(*tid, count) { return Err(WindowError::QueueFull); }
        }
        if let (Some(old), Some(focused)) = (previous, old_focus) {
            if self.descendant_of(focused, old) {
                if let Some((_, record)) = self.windows.iter_mut().find(|(id, _)| *id == old) { record.last_focus = Some(focused); }
            }
        }
        self.active = next; self.focus = new_focus;
        for message in messages { self.post_to_window(message.hwnd.ok_or(WindowError::NoSuchWindow)?, message)?; }
        Ok(())
    }
}
