//! Canonical queue insertion, selection and retirement.
use super::*;

impl MessageQueue {
    /// Post one hardware message, which contributes its own input class. # C: O(1)
    pub fn post_input(&mut self, message: WinMessage, pos: u32) -> Result<(), QueueError> {
        self.post_input_at(message, msg_time::tick_ms(), pos)
    }
    /// # C: O(1)
    pub fn post_input_at(&mut self, message: WinMessage, time: u32, pos: u32) -> Result<(), QueueError> {
        if self.messages.len() >= MESSAGE_QUEUE_LIMIT { return Err(QueueError::Full); }
        self.messages.push_back(QueuedMessage { id: 0, message, key: None, bits: queue_status::hardware_bit(message.message), time, pos });
        Ok(())
    }
    pub fn post(&mut self, message: WinMessage, pos: u32) -> Result<(), QueueError> {
        self.post_with_bits(message, queue_status::QS_POSTED, pos)
    }
    /// Enqueue one message carrying the wake bits its origin sets. # C: O(1)
    pub fn post_with_bits(&mut self, message: WinMessage, bits: u32, pos: u32) -> Result<(), QueueError> {
        self.post_with_bits_at(message, bits, msg_time::tick_ms(), pos)
    }
    /// Enqueue one message with the tick count and position it is stamped with. # C: O(1)
    pub fn post_with_bits_at(&mut self, message: WinMessage, bits: u32, time: u32, pos: u32) -> Result<(), QueueError> {
        if self.messages.len() >= MESSAGE_QUEUE_LIMIT { return Err(QueueError::Full); }
        self.changed |= bits;
        self.messages.push_back(QueuedMessage { id: 0, message, key: None, bits, time, pos });
        Ok(())
    }
    pub fn peek(&mut self, filter: MessageFilter, remove: bool) -> Option<WinMessage> {
        let index = self.messages.iter().position(|entry| filter.matches(entry.message))?;
        self.read_entry(index, remove)
    }
    pub(super) fn peek_matching<F>(&mut self, matches: F, remove: bool) -> Option<WinMessage>
    where F: Fn(WinMessage) -> bool {
        let index = self.messages.iter().position(|entry| matches(entry.message))?;
        self.read_entry(index, remove)
    }
    pub fn len(&self) -> usize { self.messages.len() }
    pub(super) fn cleanup_window(&mut self, id: WindowId) {
        self.messages.retain(|entry| entry.message.hwnd != Some(id));
        if self.caret.hwnd == Some(id) { self.caret.destroy(); self.caret_generation = self.caret_generation.saturating_add(1); }
    }
    /// Window that owns the caret and the rectangle it occupies. # C: O(1)
    pub fn caret_placement(&self) -> Option<(WindowId, WindowRect)> {
        let hwnd = self.caret.hwnd?;
        Some((hwnd, WindowRect { left: self.caret.x, top: self.caret.y,
            right: self.caret.x.saturating_add(self.caret.width),
            bottom: self.caret.y.saturating_add(self.caret.height) }))
    }
    pub fn post_quit(&mut self, code: i32) { self.quit = Some(code); }
    pub(super) fn quit_pending(&self) -> bool { self.quit.is_some() }
    pub(super) fn quit_message(&mut self, filter: MessageFilter, remove: bool, pos: u32) -> Option<WinMessage> {
        let code = self.quit?;
        let message = WinMessage { hwnd: None, message: WM_QUIT, wparam: code as u64, lparam: 0 };
        if !filter.matches(message) { return None; }
        if remove { self.quit = None; }
        self.note_message_time(msg_time::tick_ms());
        self.note_message_pos(pos);
        self.note_message_extra(0);
        Some(message)
    }
    pub(super) fn take_quit_matching<F>(&mut self, matches: F, pos: u32) -> Option<i32>
    where F: Fn(WinMessage) -> bool {
        let code = self.quit?;
        let message = WinMessage { hwnd: None, message: WM_QUIT, wparam: code as u64, lparam: 0 };
        if !matches(message) { return None; }
        self.quit = None;
        self.note_message_time(msg_time::tick_ms());
        self.note_message_pos(pos);
        self.note_message_extra(0);
        Some(code)
    }
}

impl WindowManager {
    /// Inspect one queued entry with a stable identity across user callbacks.
    /// Posted messages retain their origin even when their number names input.
    /// # C: O(N_windows + N_queued)
    pub fn inspect_for_thread(&mut self, tid: u64, filter: MessageFilter) -> Option<(u64, WinMessage, bool)> {
        let windows = &self.windows;
        let queue = &mut self.queues.iter_mut().find(|(owner, _)| *owner == tid)?.1;
        let index = queue.messages.iter().position(|entry| message_matches_in_windows(windows, filter, entry.message))?;
        if queue.messages[index].id == 0 {
            queue.next_message_id = queue.next_message_id.checked_add(1)?;
            queue.messages[index].id = queue.next_message_id;
        }
        let entry = queue.messages[index];
        let hardware = entry.bits & (queue_status::QS_KEY | queue_status::QS_MOUSEMOVE | queue_status::QS_MOUSEBUTTON) != 0;
        queue.read_entry(index, false)?;
        Some((entry.id, entry.message, hardware))
    }

    /// Read or retire exactly the selected queue entry, never its successor.
    /// # C: O(N_queues + N_queued)
    pub fn read_selected_for_thread(&mut self, tid: u64, id: u64, remove: bool) -> Option<WinMessage> {
        if id == 0 { return None; }
        let queue = &mut self.queues.iter_mut().find(|(owner, _)| *owner == tid)?.1;
        let index = queue.messages.iter().position(|entry| entry.id == id)?;
        queue.read_entry(index, remove)
    }
}
