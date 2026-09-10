//! Canonical queue insertion, selection and retirement.
use super::*;
const WM_HOTKEY:u32=0x0312;

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
    /// # C: O(1)
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
    /// # C: O(N_queued)
    pub fn peek(&mut self, filter: MessageFilter, remove: bool) -> Option<WinMessage> {
        let index = self.messages.iter().position(|entry| filter.matches(entry.message))?;
        self.read_entry(index, remove)
    }
    pub(super) fn peek_matching<F>(&mut self, matches: F, remove: bool, hardware: bool, classes: u32) -> Option<WinMessage>
    where F: Fn(WinMessage) -> bool {
        let index = self.messages.iter().position(|entry| (hardware || !entry.hardware()) && entry.retrieval_class(classes) && matches(entry.message))?;
        self.read_entry(index, remove)
    }
    /// # C: O(1)
    pub fn len(&self) -> usize { self.messages.len() }
    pub(super) fn cleanup_window(&mut self, id: WindowId) {
        self.messages.retain(|entry| entry.message.hwnd != Some(id));
        self.clear_drained_posted();
        if self.caret.hwnd == Some(id) { self.caret.destroy(); self.caret_generation = self.caret_generation.saturating_add(1); }
    }
    /// Window that owns the caret and the rectangle it occupies. # C: O(1)
    pub fn caret_placement(&self) -> Option<(WindowId, WindowRect)> {
        let hwnd = self.caret.hwnd?;
        Some((hwnd, WindowRect { left: self.caret.x, top: self.caret.y,
            right: self.caret.x.saturating_add(self.caret.width),
            bottom: self.caret.y.saturating_add(self.caret.height) }))
    }
    /// # C: O(1)
    pub fn post_quit(&mut self, code: i32) { self.quit = Some(code); self.changed |= queue_status::QS_POSTED; }
    pub(super) fn quit_pending(&self) -> bool { self.quit.is_some() }
    pub(super) fn quit_message(&mut self, filter: MessageFilter, remove: bool, pos: u32) -> Option<WinMessage> {
        let code = self.quit?;
        let message = WinMessage { hwnd: None, message: WM_QUIT, wparam: code as u64, lparam: 0 };
        if !filter.matches(message) { return None; }
        if remove { self.take_quit_matching(|message|filter.matches(message),pos)?; return Some(message); }
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
        self.clear_drained_posted();
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
        let hardware = entry.hardware();
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

impl QueuedMessage {
    fn retrieval_class(&self,classes:u32)->bool{
        use queue_status::*;
        if self.hardware(){return classes&QS_INPUT!=0;}
        if self.bits&QS_TIMER!=0&&self.bits&QS_POSTED==0{return classes&QS_TIMER!=0;}
        classes&QS_POSTMESSAGE!=0 || (classes&QS_HOTKEY!=0&&self.message.message==WM_HOTKEY)
    }
    /// # C: O(1)
    pub(super) fn hardware(&self) -> bool {
        self.bits & (queue_status::QS_KEY | queue_status::QS_MOUSEMOVE | queue_status::QS_MOUSEBUTTON) != 0
    }
}

impl WindowManager {
    /// Admit possible input numbers before hit testing; resume after an excluded identity.
    /// Exhaustion returns the queue identity watermark used by the waiter.
    /// # C: O(N_queued * N_windows²)
    pub fn inspect_retrieval_for_thread(&mut self, tid: u64, filter: MessageFilter, after: u64)
        -> Result<(u64, WinMessage, bool), u64> {
        self.inspect_retrieval_with_flags(tid,filter,after,0)
    }
    /// Select canonical posted or hardware entries using retrieval class flags. # C: O(N_queued * N_windows²)
    pub fn inspect_retrieval_with_flags(&mut self,tid:u64,filter:MessageFilter,after:u64,flags:u32)
        ->Result<(u64,WinMessage,bool),u64>{
        let classes=queue_status::retrieval_classes(flags);
        let windows = &self.windows;
        let Some((_, queue)) = self.queues.iter_mut().find(|(owner, _)| *owner == tid) else { return Err(0); };
        for entry in &mut queue.messages {
            if entry.id == 0 {
                let Some(id) = queue.next_message_id.checked_add(1) else { return Err(queue.next_message_id); };
                queue.next_message_id = id; entry.id = id;
            }
        }
        let start = queue.messages.iter().position(|entry| after != 0 && entry.id == after).map_or(0, |index| index + 1);
        let posted=queue.messages.iter().position(|entry| !entry.hardware()&&entry.retrieval_class(classes&!queue_status::QS_TIMER)
            &&message_matches_in_windows(windows,filter,entry.message));
        if posted.is_none()&&classes&queue_status::QS_POSTMESSAGE!=0&&queue.quit_pending()&&filter.matches(WinMessage{hwnd:None,message:WM_QUIT,wparam:0,lparam:0}){return Err(queue.next_message_id);}
        let index = posted.or_else(||queue.messages.iter().enumerate().position(|(index, entry)| {
            if !entry.hardware()||!entry.retrieval_class(classes) { return false; }
            if index < start { return false; }
            if hardware::is_mouse_message(entry.message.message) {
                hardware::possible_mouse_filter(entry.message.message, filter)
            } else { message_matches_in_windows(windows, filter, entry.message) }
        })).ok_or(queue.next_message_id)?;
        let entry = queue.messages[index];
        let _ = queue.read_entry(index, false);
        Ok((entry.id, entry.message, entry.hardware()))
    }

    /// Final target filtering includes descendants of the requested window.
    /// # C: O(N_windows²)
    pub fn matches_message(&self, filter: MessageFilter, message: WinMessage) -> bool {
        message_matches_in_windows(&self.windows, filter, message)
    }
}
