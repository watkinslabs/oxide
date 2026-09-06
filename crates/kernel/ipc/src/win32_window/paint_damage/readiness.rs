use super::super::{WindowId, WindowManager, WinMessage, WM_PAINT, MessageFilter, message_matches_in_windows};
const WS_MINIMIZE: u32 = 0x2000_0000;
const WS_EX_TRANSPARENT: u32 = 0x0000_0020;

impl WindowManager {
    /// Non-consuming wait predicate: posted messages, quit, then canonical paint selection.
    /// Same filtering/order as retrieval; never clears internal paint. # C: O(messages + windows³)
    pub fn has_message_for_thread(&self, tid: u64, filter: MessageFilter) -> bool {
        let Some((_, queue)) = self.queues.iter().find(|(owner, _)| *owner == tid) else { return false; };
        let matches = |message| message_matches_in_windows(&self.windows, filter, message);
        if queue.messages.iter().any(|entry| matches(entry.message)) { return true; }
        if queue.quit.is_some_and(|code| matches(WinMessage { hwnd: None, message: super::super::WM_QUIT, wparam: code as u64, lparam: 0 })) { return true; }
        self.pending_paint_message(tid).is_some_and(matches)
    }
    /// Root-before-child, topmost-first paint readiness, independent of posted messages.
    /// # C: O(windows³), bounded without recursion
    pub fn pending_paint_message(&self, tid: u64) -> Option<WinMessage> {
        let mut cursor = self.windows.iter().rev().find(|(_, r)| r.parent.is_none()).map(|(id, _)| *id);
        for _ in 0..self.windows.len() {
            let id = cursor?; let record = self.get(id)?;
            if record.visible && record.owner_tid == tid && self.damage_pending(id) {
                let mut target = id;
                if record.ex_style & WS_EX_TRANSPARENT != 0 {
                    let index = self.windows.iter().position(|(candidate, _)| *candidate == id)?;
                    if let Some((sibling, _)) = self.windows[..index].iter().rev().find(|(sibling, r)|
                        r.parent == record.parent && r.visible && r.owner_tid == tid
                        && r.ex_style & WS_EX_TRANSPARENT == 0 && self.damage_pending(*sibling)) { target = *sibling; }
                }
                return Some(WinMessage { hwnd: Some(target), message: WM_PAINT, wparam: 0, lparam: 0 });
            }
            cursor = self.next_repaint_node(id);
        }
        None
    }
    /// Paint retrieval clears internal-only readiness even for Peek; region damage remains until validation.
    /// A filtered-out parent prevents skipping ahead to a child. # C: O(windows³)
    pub fn take_pending_paint(&mut self, tid: u64, filter: MessageFilter) -> Option<WinMessage> {
        let message = self.pending_paint_message(tid)?;
        if !message_matches_in_windows(&self.windows, filter, message) { return None; }
        let id = message.hwnd?;
        if let Some(index) = self.dirty.iter().position(|(window, _)| *window == id) {
            self.dirty[index].1.internal = false;
            if !self.dirty[index].1.pending() { self.dirty.remove(index); }
        }
        Some(message)
    }
    fn damage_pending(&self, id: WindowId) -> bool { self.dirty.iter().any(|(window, damage)| *window == id && damage.pending()) }
    fn next_repaint_node(&self, mut id: WindowId) -> Option<WindowId> {
        let record = self.get(id)?;
        if record.visible && record.style & WS_MINIMIZE == 0 {
            if let Some((child, _)) = self.windows.iter().rev().find(|(_, r)| r.parent == Some(id)) { return Some(*child); }
        }
        for _ in 0..self.windows.len() {
            let index = self.windows.iter().position(|(window, _)| *window == id)?;
            let parent = self.windows[index].1.parent;
            if let Some((sibling, _)) = self.windows[..index].iter().rev().find(|(_, r)| r.parent == parent) { return Some(*sibling); }
            id = parent?;
        }
        None
    }
}
