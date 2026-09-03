//! Pure Win32 window/message state used by the native GUI adapter.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

pub const WM_CLOSE: u32 = 0x0010;
pub const WM_DESTROY: u32 = 0x0002;
pub const WM_KEYDOWN: u32 = 0x0100;
pub const WM_KEYUP: u32 = 0x0101;
pub const WM_NCHITTEST: u32 = 0x0084;
pub const WM_PAINT: u32 = 0x000f;
pub const WM_QUIT: u32 = 0x0012;
pub const WM_TIMER: u32 = 0x0113;
pub const HTCLIENT: i64 = 1;
pub const SW_HIDE: u32 = 0;

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
pub struct MessageQueue { messages: VecDeque<WinMessage>, quit: Option<i32> }

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
    pub fn post_quit(&mut self, code: i32) { self.quit = Some(code); }
    fn take_quit(&mut self) -> Option<i32> { self.quit.take() }
    fn quit_pending(&self) -> bool { self.quit.is_some() }
    fn quit_message(&mut self, filter: MessageFilter, remove: bool) -> Option<WinMessage> {
        let code = self.quit?;
        let message = WinMessage { hwnd: None, message: WM_QUIT, wparam: code as u64, lparam: 0 };
        if !filter.matches(message) { return None; }
        if remove { self.quit = None; }
        Some(message)
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct WindowRecord { pub owner_tid: u64, pub parent: Option<WindowId>, pub wndproc: u64, pub class_atom: Option<u16>, pub visible: bool }

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowClass { pub name: Vec<u16>, pub wndproc: u64, pub atom: u16 }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct WindowRect { pub left: i32, pub top: i32, pub right: i32, pub bottom: i32 }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum WindowError { NoSuchWindow, InvalidParent, ClassInUse, WrongThread, NoFocus, QueueFull }

pub struct WindowManager { next: u32, next_atom: u16, classes: Vec<WindowClass>, windows: Vec<(WindowId, WindowRecord)>, rects: Vec<(WindowId, WindowRect)>, texts: Vec<(WindowId, Vec<u16>)>, dirty: Vec<(WindowId, WindowRect)>, queues: Vec<(u64, MessageQueue)>, timers: Vec<WindowTimer>, focus: Option<WindowId> }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct WindowTimer { owner_tid: u64, hwnd: Option<WindowId>, id: u64, period_ns: u64, due_ns: u64, proc: u64 }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum QueueResult { Message(WinMessage), Quit(i32), Empty }

impl Default for WindowManager { fn default() -> Self { Self::new() } }

impl WindowManager {
    pub fn new() -> Self { Self { next: 1, next_atom: 1, classes: Vec::new(), windows: Vec::new(), rects: Vec::new(), texts: Vec::new(), dirty: Vec::new(), queues: Vec::new(), timers: Vec::new(), focus: None } }
    /// Register one process-local window class and retain its procedure. # C: O(N_classes)
    pub fn register_class(&mut self, name: &[u16], wndproc: u64) -> Result<u16, WindowError> {
        if name.is_empty() || self.classes.iter().any(|class| same_name(&class.name, name)) { return Err(WindowError::InvalidParent); }
        let atom = self.next_atom;
        self.next_atom = self.next_atom.checked_add(1).ok_or(WindowError::NoSuchWindow)?;
        self.classes.push(WindowClass { name: name.to_vec(), wndproc, atom });
        Ok(atom)
    }
    /// Resolve a registered class for native Wine window creation. # C: O(N_classes)
    pub fn class_wndproc(&self, name: &[u16]) -> Option<u64> {
        self.classes.iter().find(|class| same_name(&class.name, name)).map(|class| class.wndproc)
    }
    /// Resolve a registered class atom without leaving the canonical owner. # C: O(N_classes)
    pub fn class_wndproc_by_atom(&self, atom: u16) -> Option<u64> {
        self.classes.iter().find(|class| class.atom == atom).map(|class| class.wndproc)
    }
    /// Resolve a registered class name from its atom. # C: O(N_classes)
    pub fn class_name_by_atom(&self, atom: u16) -> Option<&[u16]> {
        self.classes.iter().find(|class| class.atom == atom).map(|class| class.name.as_slice())
    }
    pub fn create(&mut self, owner_tid: u64, parent: Option<WindowId>, wndproc: u64) -> Result<WindowId, WindowError> {
        if parent.is_some_and(|parent| self.get(parent).is_none()) { return Err(WindowError::InvalidParent); }
        let id = WindowId(self.next);
        self.next = self.next.checked_add(1).ok_or(WindowError::NoSuchWindow)?;
        self.windows.push((id, WindowRecord { owner_tid, parent, wndproc, class_atom: None, visible: false }));
        self.rects.push((id, WindowRect { left: 0, top: 0, right: 0, bottom: 0 }));
        self.texts.push((id, Vec::new()));
        if self.queues.iter().all(|(tid, _)| *tid != owner_tid) { self.queues.push((owner_tid, MessageQueue::default())); }
        Ok(id)
    }
    /// Create a window while retaining its class identity in the owner. # C: O(N_classes + N_windows)
    pub fn create_class(&mut self, owner_tid: u64, parent: Option<WindowId>, name: &[u16]) -> Result<WindowId, WindowError> {
        let class = self.classes.iter().find(|class| same_name(&class.name, name)).cloned().ok_or(WindowError::NoSuchWindow)?;
        self.create_class_atom(owner_tid, parent, class.atom, class.wndproc)
    }
    /// Create a window from a registered atom in the owner. # C: O(N_windows)
    pub fn create_class_atom(&mut self, owner_tid: u64, parent: Option<WindowId>, atom: u16, wndproc: u64) -> Result<WindowId, WindowError> {
        let window = self.create(owner_tid, parent, wndproc)?;
        self.windows.iter_mut().find(|(id, _)| *id == window).ok_or(WindowError::NoSuchWindow)?.1.class_atom = Some(atom);
        Ok(window)
    }
    /// Return the registered class name associated with one window. # C: O(N_windows + N_classes)
    pub fn class_name(&self, window: WindowId) -> Option<&[u16]> {
        let atom = self.get(window)?.class_atom?;
        self.class_name_by_atom(atom)
    }
    /// Remove a class only after all windows carrying its atom are gone. # C: O(N_classes + N_windows)
    pub fn unregister_class(&mut self, name: &[u16]) -> Result<(), WindowError> {
        let index = self.classes.iter().position(|class| same_name(&class.name, name)).ok_or(WindowError::NoSuchWindow)?;
        let atom = self.classes[index].atom;
        if self.windows.iter().any(|(_, window)| window.class_atom == Some(atom)) { return Err(WindowError::ClassInUse); }
        self.classes.remove(index);
        Ok(())
    }
    pub fn get(&self, id: WindowId) -> Option<WindowRecord> { self.windows.iter().find(|(window, _)| *window == id).map(|(_, record)| *record) }
    pub fn set_visible(&mut self, id: WindowId, visible: bool) -> Result<(), WindowError> {
        let Some((_, record)) = self.windows.iter_mut().find(|(window, _)| *window == id) else { return Err(WindowError::NoSuchWindow); };
        record.visible = visible;
        Ok(())
    }
    /// Set the current thread's focus window and return the previous focus. # C: O(N_windows)
    pub fn set_focus(&mut self, tid: u64, id: Option<WindowId>) -> Result<Option<WindowId>, WindowError> {
        if let Some(id) = id {
            let record = self.get(id).ok_or(WindowError::NoSuchWindow)?;
            if record.owner_tid != tid { return Err(WindowError::WrongThread); }
        }
        let previous = self.focus;
        self.focus = id;
        Ok(previous)
    }
    /// Return the canonical focused window. # C: O(1)
    pub fn focused(&self) -> Option<WindowId> { self.focus }
    /// Change visibility and return the previous state. # C: O(N_windows)
    pub fn show(&mut self, id: WindowId, visible: bool) -> Result<bool, WindowError> {
        let Some((_, record)) = self.windows.iter_mut().find(|(window, _)| *window == id) else { return Err(WindowError::NoSuchWindow); };
        let previous = record.visible; record.visible = visible; Ok(previous)
    }
    /// Read geometry from the canonical HWND record. # C: O(N_windows)
    pub fn rect(&self, id: WindowId) -> Option<WindowRect> { self.rects.iter().find(|(window, _)| *window == id).map(|(_, rect)| *rect) }
    /// Update geometry in the canonical HWND record. # C: O(N_windows)
    pub fn set_rect(&mut self, id: WindowId, rect: WindowRect) -> Result<(), WindowError> {
        let Some((_, current)) = self.rects.iter_mut().find(|(window, _)| *window == id) else { return Err(WindowError::NoSuchWindow); };
        *current = rect; Ok(())
    }
    /// Return the client rectangle in client coordinates. # C: O(N_windows)
    pub fn client_rect(&self, id: WindowId) -> Option<WindowRect> {
        let rect = self.rect(id)?;
        Some(WindowRect { left: 0, top: 0, right: rect.right.checked_sub(rect.left)?, bottom: rect.bottom.checked_sub(rect.top)? })
    }
    /// Mark a window client region dirty and enqueue one paint notification. # C: O(N_windows + N_dirty)
    pub fn invalidate(&mut self, id: WindowId, rect: Option<WindowRect>) -> Result<(), WindowError> {
        let area = self.client_rect(id).ok_or(WindowError::NoSuchWindow)?;
        let requested = rect.unwrap_or(area);
        if let Some((_, current)) = self.dirty.iter_mut().find(|(window, _)| *window == id) {
            current.left = current.left.min(requested.left); current.top = current.top.min(requested.top);
            current.right = current.right.max(requested.right); current.bottom = current.bottom.max(requested.bottom);
            return Ok(())
        }
        let owner = self.get(id).ok_or(WindowError::NoSuchWindow)?.owner_tid;
        let queue = self.queues.iter_mut().find(|(tid, _)| *tid == owner).map(|(_, queue)| queue).ok_or(WindowError::NoSuchWindow)?;
        queue.post(WinMessage { hwnd: Some(id), message: WM_PAINT, wparam: 0, lparam: 0 }).map_err(|_| WindowError::QueueFull)?;
        self.dirty.push((id, requested));
        Ok(())
    }
    /// Consume the current dirty region for a window. # C: O(N_dirty)
    pub fn begin_paint(&mut self, id: WindowId) -> Result<Option<WindowRect>, WindowError> {
        if self.get(id).is_none() { return Err(WindowError::NoSuchWindow); }
        Ok(self.dirty.iter().position(|(window, _)| *window == id).map(|index| self.dirty.remove(index).1))
    }
    /// Read the UTF-16 title/control text owned by one window. # C: O(N_windows)
    pub fn text(&self, id: WindowId) -> Option<&[u16]> { self.texts.iter().find(|(window, _)| *window == id).map(|(_, text)| text.as_slice()) }
    /// Replace the UTF-16 title/control text owned by one window. # C: O(N_windows + N_text)
    pub fn set_text(&mut self, id: WindowId, text: &[u16]) -> Result<(), WindowError> {
        let Some((_, current)) = self.texts.iter_mut().find(|(window, _)| *window == id) else { return Err(WindowError::NoSuchWindow); };
        current.clear(); current.extend_from_slice(text); Ok(())
    }
    pub fn destroy(&mut self, id: WindowId) -> Result<WindowRecord, WindowError> {
        let index = self.windows.iter().position(|(window, _)| *window == id).ok_or(WindowError::NoSuchWindow)?;
        self.rects.retain(|(window, _)| *window != id);
        self.texts.retain(|(window, _)| *window != id);
        self.dirty.retain(|(window, _)| *window != id);
        if self.focus == Some(id) { self.focus = None; }
        Ok(self.windows.remove(index).1)
    }
    pub fn post_to_window(&mut self, id: WindowId, message: WinMessage) -> Result<(), WindowError> {
        let owner = self.get(id).ok_or(WindowError::NoSuchWindow)?.owner_tid;
        let queue = self.queues.iter_mut().find(|(tid, _)| *tid == owner).map(|(_, queue)| queue)
            .ok_or(WindowError::NoSuchWindow)?;
        queue.post(message).map_err(|_| WindowError::QueueFull)
    }
    /// Enqueue one native keyboard transition on the focused window's owner queue. # C: O(N_windows)
    pub fn post_key(&mut self, tid: u64, key: u16, pressed: bool, repeat: bool) -> Result<(), WindowError> {
        let window = self.focus.ok_or(WindowError::NoFocus)?;
        let record = self.get(window).ok_or(WindowError::NoSuchWindow)?;
        if record.owner_tid != tid { return Err(WindowError::WrongThread); }
        self.post_to_window(window, WinMessage { hwnd: Some(window), message: if pressed { WM_KEYDOWN } else { WM_KEYUP }, wparam: key as u64, lparam: repeat as i64 })
    }
    /// Enqueue one hardware key transition on the focused window. # C: O(N_windows)
    pub fn post_focused_key(&mut self, key: u16, pressed: bool, repeat: bool) -> Result<(), WindowError> {
        let window = self.focus.ok_or(WindowError::NoFocus)?;
        self.post_to_window(window, WinMessage { hwnd: Some(window), message: if pressed { WM_KEYDOWN } else { WM_KEYUP }, wparam: key as u64, lparam: repeat as i64 })
    }
    /// Arm or replace one process-owned timer using the canonical window queue. # C: O(N_timers)
    pub fn set_timer(&mut self, owner_tid: u64, hwnd: Option<WindowId>, id: u64, timeout_ms: u32, proc: u64, now_ns: u64) -> Result<u64, WindowError> {
        if let Some(window) = hwnd { if self.get(window).is_none() { return Err(WindowError::NoSuchWindow); } }
        let period_ns = (timeout_ms as u64).saturating_mul(1_000_000).max(1_000_000);
        if let Some(timer) = self.timers.iter_mut().find(|timer| timer.hwnd == hwnd && timer.id == id) {
            timer.period_ns = period_ns; timer.due_ns = now_ns.saturating_add(period_ns); timer.proc = proc;
            return Ok(id.max(1));
        }
        let id = id.max(1);
        self.timers.push(WindowTimer { owner_tid, hwnd, id, period_ns, due_ns: now_ns.saturating_add(period_ns), proc });
        if self.queues.iter().all(|(tid, _)| *tid != owner_tid) { self.queues.push((owner_tid, MessageQueue::default())); }
        Ok(id)
    }
    /// Remove one timer by its canonical window/id identity. # C: O(N_timers)
    pub fn kill_timer(&mut self, hwnd: Option<WindowId>, id: u64) -> bool {
        let before = self.timers.len(); self.timers.retain(|timer| !(timer.hwnd == hwnd && timer.id == id)); before != self.timers.len()
    }
    /// Convert elapsed timer deadlines into queued WM_TIMER messages. # C: O(N_timers + N_queues)
    pub fn expire_timers(&mut self, now_ns: u64) -> usize {
        let mut fired = 0;
        for index in 0..self.timers.len() {
            let timer = self.timers[index];
            if now_ns < timer.due_ns { continue; }
            let owner = timer.hwnd.and_then(|window| self.get(window).map(|record| record.owner_tid)).unwrap_or(timer.owner_tid);
            let Some(queue) = self.queues.iter_mut().find(|(tid, _)| *tid == owner).map(|(_, queue)| queue) else { continue; };
            if queue.post(WinMessage { hwnd: timer.hwnd, message: WM_TIMER, wparam: timer.id, lparam: timer.proc as i64 }).is_ok() { fired += 1; }
            self.timers[index].due_ns = now_ns.saturating_add(timer.period_ns);
        }
        fired
    }
    pub fn peek_for_thread(&mut self, tid: u64, filter: MessageFilter, remove: bool) -> Option<WinMessage> {
        self.queues.iter_mut().find(|(owner, _)| *owner == tid).and_then(|(_, queue)| queue.peek(filter, remove).or_else(|| queue.quit_message(filter, remove)))
    }
    pub fn post_quit(&mut self, tid: u64, code: i32) {
        if let Some((_, queue)) = self.queues.iter_mut().find(|(owner, _)| *owner == tid) { queue.post_quit(code); }
        else { let mut queue = MessageQueue::default(); queue.post_quit(code); self.queues.push((tid, queue)); }
    }
    pub fn take_for_thread(&mut self, tid: u64, filter: MessageFilter) -> QueueResult {
        let Some((_, queue)) = self.queues.iter_mut().find(|(owner, _)| *owner == tid) else { return QueueResult::Empty; };
        if let Some(message) = queue.peek(filter, true) { QueueResult::Message(message) }
        else if let Some(code) = queue.take_quit() { QueueResult::Quit(code) }
        else { QueueResult::Empty }
    }
    pub fn quit_pending(&self, tid: u64) -> bool { self.queues.iter().find(|(owner, _)| *owner == tid).is_some_and(|(_, queue)| queue.quit_pending()) }
    pub fn len(&self) -> usize { self.windows.len() }
}

fn same_name(left: &[u16], right: &[u16]) -> bool {
    left.len() == right.len() && left.iter().zip(right).all(|(left, right)| {
        let fold = |unit: u16| if (b'A' as u16..=b'Z' as u16).contains(&unit) { unit + 32 } else { unit };
        fold(*left) == fold(*right)
    })
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
    fn quit_is_thread_owned_and_is_consumed_after_queued_messages() {
        let mut manager = WindowManager::new();
        let window = manager.create(9, None, 0).unwrap();
        manager.post_to_window(window, message(Some(window), WM_CLOSE)).unwrap();
        manager.post_quit(9, 37);
        let filter = MessageFilter { hwnd: None, first: 0, last: u32::MAX };
        assert!(matches!(manager.take_for_thread(9, filter), QueueResult::Message(_)));
        assert_eq!(manager.take_for_thread(9, filter), QueueResult::Quit(37));
        assert_eq!(manager.take_for_thread(8, filter), QueueResult::Empty);
        manager.post_quit(9, 41);
        assert_eq!(manager.peek_for_thread(9, filter, false).map(|value| value.message), Some(WM_QUIT));
        assert_eq!(manager.peek_for_thread(9, filter, true).map(|value| value.wparam), Some(41));
        assert_eq!(manager.peek_for_thread(9, filter, false), None);
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
    fn timers_replace_by_window_and_enqueue_callback_message_after_deadline() {
        let mut manager = WindowManager::new();
        let window = manager.create(7, None, 0x1000).unwrap();
        assert_eq!(manager.set_timer(7, Some(window), 3, 10, 0xfeed, 100), Ok(3));
        assert_eq!(manager.set_timer(7, Some(window), 3, 20, 0xbeef, 200), Ok(3));
        assert_eq!(manager.expire_timers(19_000_199), 0);
        assert_eq!(manager.expire_timers(20_000_200), 1);
        let filter = MessageFilter { hwnd: Some(window), first: WM_TIMER, last: WM_TIMER };
        assert_eq!(manager.peek_for_thread(7, filter, true).map(|message| (message.wparam, message.lparam)), Some((3, 0xbeef)));
        assert!(manager.kill_timer(Some(window), 3));
        assert!(!manager.kill_timer(Some(window), 3));
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
    fn focus_returns_previous_window_and_routes_key_transitions() {
        let mut manager = WindowManager::new();
        let first = manager.create(9, None, 0).unwrap();
        let second = manager.create(9, None, 0).unwrap();
        assert_eq!(manager.set_focus(9, Some(first)), Ok(None));
        assert_eq!(manager.set_focus(9, Some(second)), Ok(Some(first)));
        assert_eq!(manager.focused(), Some(second));
        manager.post_key(9, 0x41, true, false).unwrap();
        let filter = MessageFilter { hwnd: Some(second), first: WM_KEYDOWN, last: WM_KEYDOWN };
        assert_eq!(manager.peek_for_thread(9, filter, true), Some(WinMessage { hwnd: Some(second), message: WM_KEYDOWN, wparam: 0x41, lparam: 0 }));
    }

    #[test]
    fn focus_rejects_other_threads_and_clears_on_destroy() {
        let mut manager = WindowManager::new();
        let window = manager.create(9, None, 0).unwrap();
        assert_eq!(manager.set_focus(8, Some(window)), Err(WindowError::WrongThread));
        assert_eq!(manager.post_key(9, 0x41, true, false), Err(WindowError::NoFocus));
        manager.set_focus(9, Some(window)).unwrap();
        assert_eq!(manager.set_focus(9, None), Ok(Some(window)));
        assert_eq!(manager.focused(), None);
        manager.set_focus(9, Some(window)).unwrap();
        manager.destroy(window).unwrap();
        assert_eq!(manager.focused(), None);
        assert_eq!(manager.post_key(9, 0x41, true, false), Err(WindowError::NoFocus));
    }

    #[test]
    fn geometry_is_created_and_destroyed_with_the_window() {
        let mut manager = WindowManager::new();
        let window = manager.create(9, None, 0x1234).unwrap();
        assert_eq!(manager.rect(window), Some(WindowRect { left: 0, top: 0, right: 0, bottom: 0 }));
        let rect = WindowRect { left: 10, top: 20, right: 410, bottom: 320 };
        manager.set_rect(window, rect).unwrap();
        assert_eq!(manager.rect(window), Some(rect));
        manager.destroy(window).unwrap();
        assert_eq!(manager.rect(window), None);
    }

    #[test]
    fn text_parent_and_visibility_follow_window_lifetime() {
        let mut manager = WindowManager::new();
        let parent = manager.create(9, None, 0).unwrap();
        let child = manager.create(9, Some(parent), 0).unwrap();
        manager.set_text(child, &[b'c' as u16, b't' as u16]).unwrap();
        assert_eq!(manager.text(child), Some(&[b'c' as u16, b't' as u16][..]));
        assert_eq!(manager.get(child).unwrap().parent, Some(parent));
        assert_eq!(manager.show(child, true), Ok(false));
        assert!(manager.get(child).unwrap().visible);
        manager.destroy(child).unwrap();
        assert_eq!(manager.text(child), None);
    }

    #[test]
    fn classes_are_case_insensitive_and_supply_the_window_procedure() {
        let mut manager = WindowManager::new();
        let atom = manager.register_class(&[b'N' as u16, b'o' as u16, b't' as u16], 0x1400).unwrap();
        assert_eq!(atom, 1);
        assert_eq!(manager.class_wndproc(&[b'n' as u16, b'O' as u16, b'T' as u16]), Some(0x1400));
        assert_eq!(manager.class_wndproc_by_atom(atom), Some(0x1400));
        assert_eq!(manager.class_wndproc_by_atom(atom + 1), None);
        assert_eq!(manager.register_class(&[b'n' as u16, b'o' as u16, b't' as u16], 0x1500), Err(WindowError::InvalidParent));
    }

    #[test]
    fn class_unregister_waits_for_all_canonical_windows() {
        let mut manager = WindowManager::new();
        let name = [b'E' as u16, b'd' as u16, b'i' as u16, b't' as u16];
        let atom = manager.register_class(&name, 0x1400).unwrap();
        let window = manager.create_class_atom(9, None, atom, 0x1400).unwrap();
        assert_eq!(manager.unregister_class(&name), Err(WindowError::ClassInUse));
        manager.destroy(window).unwrap();
        assert_eq!(manager.unregister_class(&name), Ok(()));
        assert_eq!(manager.class_wndproc_by_atom(atom), None);
    }

    #[test]
    fn invalidation_coalesces_and_begin_paint_consumes_one_dirty_region() {
        let mut manager = WindowManager::new();
        let window = manager.create(9, None, 0).unwrap();
        manager.set_rect(window, WindowRect { left: 10, top: 20, right: 110, bottom: 120 }).unwrap();
        let first = WindowRect { left: 2, top: 3, right: 20, bottom: 30 };
        manager.invalidate(window, Some(first)).unwrap();
        manager.invalidate(window, Some(WindowRect { left: 10, top: 1, right: 40, bottom: 50 })).unwrap();
        assert_eq!(manager.begin_paint(window), Ok(Some(WindowRect { left: 2, top: 1, right: 40, bottom: 50 })));
        assert_eq!(manager.peek_for_thread(9, MessageFilter { hwnd: Some(window), first: WM_PAINT, last: WM_PAINT }, true).is_some(), true);
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
