//! Pure Win32 window/message state used by the native GUI adapter.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

pub const WM_CLOSE: u32 = 0x0010;
pub const WM_DESTROY: u32 = 0x0002;
pub const WM_NCHITTEST: u32 = 0x0084;
pub const HTCLIENT: i64 = 1;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct WindowId(u32);
impl WindowId {
    pub fn raw(self) -> u32 { self.0 }
    pub fn from_raw(raw: u32) -> Option<Self> { (raw != 0).then_some(Self(raw)) }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct WinMessage {
    pub hwnd: Option<WindowId>,
    pub message: u32,
    pub wparam: u64,
    pub lparam: i64,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MessageFilter { pub hwnd: Option<WindowId>, pub first: u32, pub last: u32 }

impl MessageFilter {
    fn matches(self, message: WinMessage) -> bool {
        (self.hwnd.is_none() || self.hwnd == message.hwnd)
            && message.message >= self.first && message.message <= self.last
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum QueueError { Full }

const MESSAGE_QUEUE_LIMIT: usize = 10_000;

#[derive(Default)]
pub struct MessageQueue { messages: VecDeque<WinMessage> }

impl MessageQueue {
    pub fn post(&mut self, message: WinMessage) -> Result<(), QueueError> {
        if self.messages.len() >= MESSAGE_QUEUE_LIMIT { return Err(QueueError::Full); }
        self.messages.push_back(message);
        Ok(())
    }
    pub fn peek(&mut self, filter: MessageFilter, remove: bool) -> Option<WinMessage> {
        let index = self.messages.iter().position(|message| filter.matches(*message))?;
        if remove { self.messages.remove(index) } else { self.messages.get(index).copied() }
    }
    pub fn len(&self) -> usize { self.messages.len() }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct WindowRecord { pub owner_tid: u64, pub parent: Option<WindowId>, pub wndproc: u64, pub visible: bool }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum WindowError { NoSuchWindow, InvalidParent, QueueFull }

pub struct WindowManager { next: u32, windows: Vec<(WindowId, WindowRecord)>, queues: Vec<(u64, MessageQueue)> }

impl Default for WindowManager { fn default() -> Self { Self::new() } }

impl WindowManager {
    pub fn new() -> Self { Self { next: 1, windows: Vec::new(), queues: Vec::new() } }
    pub fn create(&mut self, owner_tid: u64, parent: Option<WindowId>, wndproc: u64) -> Result<WindowId, WindowError> {
        if parent.is_some_and(|parent| self.get(parent).is_none()) { return Err(WindowError::InvalidParent); }
        let id = WindowId(self.next);
        self.next = self.next.checked_add(1).ok_or(WindowError::NoSuchWindow)?;
        self.windows.push((id, WindowRecord { owner_tid, parent, wndproc, visible: false }));
        if self.queues.iter().all(|(tid, _)| *tid != owner_tid) { self.queues.push((owner_tid, MessageQueue::default())); }
        Ok(id)
    }
    pub fn get(&self, id: WindowId) -> Option<WindowRecord> { self.windows.iter().find(|(window, _)| *window == id).map(|(_, record)| *record) }
    pub fn set_visible(&mut self, id: WindowId, visible: bool) -> Result<(), WindowError> {
        let Some((_, record)) = self.windows.iter_mut().find(|(window, _)| *window == id) else { return Err(WindowError::NoSuchWindow); };
        record.visible = visible;
        Ok(())
    }
    pub fn destroy(&mut self, id: WindowId) -> Result<WindowRecord, WindowError> {
        let index = self.windows.iter().position(|(window, _)| *window == id).ok_or(WindowError::NoSuchWindow)?;
        Ok(self.windows.remove(index).1)
    }
    pub fn post_to_window(&mut self, id: WindowId, message: WinMessage) -> Result<(), WindowError> {
        let owner = self.get(id).ok_or(WindowError::NoSuchWindow)?.owner_tid;
        let queue = self.queues.iter_mut().find(|(tid, _)| *tid == owner).map(|(_, queue)| queue)
            .ok_or(WindowError::NoSuchWindow)?;
        queue.post(message).map_err(|_| WindowError::QueueFull)
    }
    pub fn peek_for_thread(&mut self, tid: u64, filter: MessageFilter, remove: bool) -> Option<WinMessage> {
        self.queues.iter_mut().find(|(owner, _)| *owner == tid).and_then(|(_, queue)| queue.peek(filter, remove))
    }
    pub fn len(&self) -> usize { self.windows.len() }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DefaultWindowResult { Return(i64), RequestDestroy }

pub fn default_window_proc(message: u32) -> DefaultWindowResult {
    match message { WM_CLOSE => DefaultWindowResult::RequestDestroy, WM_NCHITTEST => DefaultWindowResult::Return(HTCLIENT), _ => DefaultWindowResult::Return(0) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(hwnd: Option<WindowId>, message: u32) -> WinMessage { WinMessage { hwnd, message, wparam: 1, lparam: 2 } }

    #[test]
    fn queue_filters_without_reordering_unmatched_messages() {
        let mut queue = MessageQueue::default();
        queue.post(message(None, 1)).unwrap();
        let window = WindowId(7);
        queue.post(message(Some(window), 2)).unwrap();
        queue.post(message(None, 3)).unwrap();
        let filter = MessageFilter { hwnd: Some(window), first: 2, last: 2 };
        assert_eq!(queue.peek(filter, false), Some(message(Some(window), 2)));
        assert_eq!(queue.peek(filter, true), Some(message(Some(window), 2)));
        assert_eq!(queue.peek(MessageFilter { hwnd: None, first: 0, last: u32::MAX }, true), Some(message(None, 1)));
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn windows_use_monotonic_handles_and_validate_parent_lifetime() {
        let mut manager = WindowManager::new();
        let first = manager.create(4, None, 0x1000).unwrap();
        let child = manager.create(4, Some(first), 0x2000).unwrap();
        assert_eq!(manager.create(4, Some(WindowId(99)), 0), Err(WindowError::InvalidParent));
        manager.destroy(first).unwrap();
        assert_eq!(manager.get(first), None);
        assert_eq!(manager.create(4, None, 0).unwrap().raw(), child.raw() + 1);
    }

    #[test]
    fn default_window_proc_exposes_close_and_client_hit_test_policy() {
        assert_eq!(default_window_proc(WM_CLOSE), DefaultWindowResult::RequestDestroy);
        assert_eq!(default_window_proc(WM_NCHITTEST), DefaultWindowResult::Return(HTCLIENT));
        assert_eq!(default_window_proc(WM_DESTROY), DefaultWindowResult::Return(0));
    }

    #[test]
    fn posting_routes_to_the_owner_queue_and_destroy_removes_the_window() {
        let mut manager = WindowManager::new();
        let window = manager.create(9, None, 0x1234).unwrap();
        manager.post_to_window(window, message(Some(window), WM_CLOSE)).unwrap();
        assert_eq!(manager.peek_for_thread(9, MessageFilter { hwnd: Some(window), first: WM_CLOSE, last: WM_CLOSE }, false), Some(message(Some(window), WM_CLOSE)));
        assert_eq!(manager.peek_for_thread(8, MessageFilter { hwnd: None, first: 0, last: u32::MAX }, false), None);
        assert_eq!(manager.destroy(window).unwrap().wndproc, 0x1234);
        assert_eq!(manager.post_to_window(window, message(None, 1)), Err(WindowError::NoSuchWindow));
    }

    #[test]
    fn queue_rejects_messages_after_its_bounded_capacity() {
        let mut queue = MessageQueue::default();
        for _ in 0..MESSAGE_QUEUE_LIMIT { queue.post(message(None, 1)).unwrap(); }
        assert_eq!(queue.post(message(None, 2)), Err(QueueError::Full));
        assert_eq!(queue.len(), MESSAGE_QUEUE_LIMIT);
    }

    #[test]
    fn filtered_peek_can_remove_only_the_matching_message() {
        let mut queue = MessageQueue::default();
        queue.post(message(None, 10)).unwrap();
        queue.post(message(None, 20)).unwrap();
        assert_eq!(queue.peek(MessageFilter { hwnd: None, first: 15, last: 25 }, true), Some(message(None, 20)));
        assert_eq!(queue.peek(MessageFilter { hwnd: None, first: 0, last: 100 }, true), Some(message(None, 10)));
        assert_eq!(queue.len(), 0);
    }
}
