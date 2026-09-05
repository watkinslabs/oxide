//! Pure Win32 window/message state used by the native GUI adapter.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

pub const WM_CLOSE: u32 = 0x0010;
pub const WM_DESTROY: u32 = 0x0002;
pub const WM_KILLFOCUS: u32 = 0x0008;
pub const WM_KEYDOWN: u32 = 0x0100;
pub const WM_KEYUP: u32 = 0x0101;
pub const WM_MOUSEMOVE: u32 = 0x0200;
pub const WM_NCHITTEST: u32 = 0x0084;
pub const WM_NCACTIVATE: u32 = 0x0086;
pub const WM_PAINT: u32 = 0x000f;
pub const WM_QUIT: u32 = 0x0012;
pub const WM_SETFOCUS: u32 = 0x0007;
pub const WM_TIMER: u32 = 0x0113;
const KEY_REPEAT_COUNT_MASK: u32 = 0xffff;
const KEY_PREVIOUS_STATE: u32 = 1 << 30;
const KEY_TRANSITION_STATE: u32 = 1 << 31;
pub const HTCLIENT: i64 = 1;
pub const HTNOWHERE: i64 = 0;
pub const SW_HIDE: u32 = 0;

/// Encode signed client coordinates in the Win32 mouse-message lParam. # C: O(1)
pub const fn mouse_lparam(x: i32, y: i32) -> i64 {
    (((y as u16 as u32) << 16) | x as u16 as u32) as i64
}

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

/// Encode the fixed Windows keyboard `lParam` fields for one transition.
/// # C: O(1)
pub const fn key_lparam(pressed: bool, repeat: bool) -> i64 {
    let count = if repeat { 2 } else { 1 };
    let mut value = count & KEY_REPEAT_COUNT_MASK;
    if repeat || !pressed { value |= KEY_PREVIOUS_STATE; }
    if !pressed { value |= KEY_TRANSITION_STATE; }
    value as i64
}

impl MessageFilter {
    fn matches(self, message: WinMessage) -> bool {
        let last = if self.first == 0 && self.last == 0 { u32::MAX } else { self.last };
        (self.hwnd.is_none() || self.hwnd == message.hwnd)
            && message.message >= self.first && message.message <= last
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
    fn peek_matching<F>(&mut self, matches: F, remove: bool) -> Option<WinMessage>
    where F: Fn(WinMessage) -> bool {
        let index = self.messages.iter().position(|message| matches(*message))?;
        if remove { self.messages.remove(index) } else { self.messages.get(index).copied() }
    }
    pub fn len(&self) -> usize { self.messages.len() }
    fn cleanup_window(&mut self, id: WindowId) { self.messages.retain(|message| message.hwnd != Some(id)); }
    pub fn post_quit(&mut self, code: i32) { self.quit = Some(code); }
    fn quit_pending(&self) -> bool { self.quit.is_some() }
    fn quit_message(&mut self, filter: MessageFilter, remove: bool) -> Option<WinMessage> {
        let code = self.quit?;
        let message = WinMessage { hwnd: None, message: WM_QUIT, wparam: code as u64, lparam: 0 };
        if !filter.matches(message) { return None; }
        if remove { self.quit = None; }
        Some(message)
    }
    fn take_quit_matching<F>(&mut self, matches: F) -> Option<i32>
    where F: Fn(WinMessage) -> bool {
        let code = self.quit?;
        let message = WinMessage { hwnd: None, message: WM_QUIT, wparam: code as u64, lparam: 0 };
        if !matches(message) { return None; }
        self.quit = None;
        Some(code)
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct WindowRecord { pub owner_tid: u64, pub parent: Option<WindowId>, pub wndproc: u64, pub class_atom: Option<u16>, pub visible: bool, pub menu: Option<u32> }

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowClass { pub name: Vec<u16>, pub wndproc: u64, pub atom: u16 }

const USER_ATOM_BASE: u16 = 0xc000;
const USER_ATOM_CAPACITY: usize = 0x4000;
const USER_ATOM_MAX_LENGTH: usize = 255;

/// System-wide string atoms used by RegisterWindowMessageW and the Win32
/// window-station boundary. GUI process state remains separate from this table.
pub struct UserAtomTable { names: Vec<Vec<u16>> }

impl UserAtomTable {
    /// Create an empty system-wide user atom table. # C: O(1)
    pub const fn new() -> Self { Self { names: Vec::new() } }

    /// Add one message name or return its existing atom. # C: O(N_atoms * N_name)
    pub fn register(&mut self, name: &[u16]) -> Option<u16> {
        if name.is_empty() || name.len() > USER_ATOM_MAX_LENGTH { return None; }
        if let Some(index) = self.names.iter().position(|entry| same_name(entry, name)) {
            return USER_ATOM_BASE.checked_add(index as u16 + 1);
        }
        if self.names.len() >= USER_ATOM_CAPACITY - 1 { return None; }
        self.names.push(name.to_vec());
        USER_ATOM_BASE.checked_add(self.names.len() as u16)
    }
}

impl Default for UserAtomTable { fn default() -> Self { Self::new() } }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct WindowRect { pub left: i32, pub top: i32, pub right: i32, pub bottom: i32 }

/// Canonical compositor input for one visible window paint transaction.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct WindowPresentRecord { pub window: WindowId, pub bounds: WindowRect, pub damage: Option<WindowRect> }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum WindowError { NoSuchWindow, InvalidParent, ClassInUse, WrongThread, NoFocus, QueueFull, PaintActive, PaintNotActive, NotVisible }

pub struct WindowManager { next: u32, next_atom: u16, classes: Vec<WindowClass>, windows: Vec<(WindowId, WindowRecord)>, rects: Vec<(WindowId, WindowRect)>, texts: Vec<(WindowId, Vec<u16>)>, dirty: Vec<(WindowId, WindowRect)>, painting: Vec<(WindowId, Option<WindowRect>)>, queues: Vec<(u64, MessageQueue)>, timers: Vec<WindowTimer>, focus: Option<WindowId>, cursor: (i32, i32), destroying: Vec<WindowId> }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct WindowTimer { owner_tid: u64, hwnd: Option<WindowId>, id: u64, period_ns: u64, due_ns: u64, proc: u64 }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum QueueResult { Message(WinMessage), Quit(i32), Empty }

impl Default for WindowManager { fn default() -> Self { Self::new() } }

impl WindowManager {
    pub fn new() -> Self { Self { next: 1, next_atom: 1, classes: Vec::new(), windows: Vec::new(), rects: Vec::new(), texts: Vec::new(), dirty: Vec::new(), painting: Vec::new(), queues: Vec::new(), timers: Vec::new(), focus: None, cursor: (0, 0), destroying: Vec::new() } }
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
    /// Return the canonical class tuple for a name. # C: O(N_classes)
    pub fn class_info(&self, name: &[u16]) -> Option<(u16, u64, &[u16])> {
        self.classes.iter().find(|class| same_name(&class.name, name)).map(|class| (class.atom, class.wndproc, class.name.as_slice()))
    }
    /// Return the canonical class tuple for an atom. # C: O(N_classes)
    pub fn class_info_by_atom(&self, atom: u16) -> Option<(u16, u64, &[u16])> {
        self.classes.iter().find(|class| class.atom == atom).map(|class| (class.atom, class.wndproc, class.name.as_slice()))
    }
    pub fn create(&mut self, owner_tid: u64, parent: Option<WindowId>, wndproc: u64) -> Result<WindowId, WindowError> {
        if parent.is_some_and(|parent| self.get(parent).is_none()) { return Err(WindowError::InvalidParent); }
        let id = WindowId(self.next);
        self.next = self.next.checked_add(1).ok_or(WindowError::NoSuchWindow)?;
        self.windows.push((id, WindowRecord { owner_tid, parent, wndproc, class_atom: None, visible: false, menu: None }));
        self.rects.push((id, WindowRect { left: 0, top: 0, right: 0, bottom: 0 }));
        self.texts.push((id, Vec::new()));
        if self.queues.iter().all(|(tid, _)| *tid != owner_tid) { self.queues.push((owner_tid, MessageQueue::default())); }
        Ok(id)
    }
    /// Create a window while retaining its class identity in the owner. # C: O(N_classes + N_windows)
    pub fn create_class(&mut self, owner_tid: u64, parent: Option<WindowId>, name: &[u16]) -> Result<WindowId, WindowError> {
        let class = self.classes.iter().find(|class| same_name(&class.name, name)).cloned().ok_or(WindowError::NoSuchWindow)?;
        self.create_class_atom(owner_tid, parent, class.atom)
    }
    /// Create a window from a registered atom in the owner. # C: O(N_windows)
    pub fn create_class_atom(&mut self, owner_tid: u64, parent: Option<WindowId>, atom: u16) -> Result<WindowId, WindowError> {
        let wndproc = self.class_wndproc_by_atom(atom).ok_or(WindowError::NoSuchWindow)?;
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
    /// Associate one canonical HMENU with a window and return the prior one. # C: O(N_windows)
    pub fn set_menu(&mut self, id: WindowId, menu: Option<u32>) -> Result<Option<u32>, WindowError> {
        let Some((_, record)) = self.windows.iter_mut().find(|(window, _)| *window == id) else { return Err(WindowError::NoSuchWindow); };
        let previous = record.menu;
        record.menu = menu;
        Ok(previous)
    }
    /// Detach a destroyed HMENU from every canonical HWND. # C: O(N_windows)
    pub fn clear_menu(&mut self, menu: u32) { for (_, record) in &mut self.windows { if record.menu == Some(menu) { record.menu = None; } } }
    pub fn menu(&self, id: WindowId) -> Option<u32> { self.get(id)?.menu }
    /// Set the current thread's focus window and return the previous focus. # C: O(N_windows)
    pub fn set_focus(&mut self, tid: u64, id: Option<WindowId>) -> Result<Option<WindowId>, WindowError> {
        if let Some(id) = id {
            let record = self.get(id).ok_or(WindowError::NoSuchWindow)?;
            if record.owner_tid != tid { return Err(WindowError::WrongThread); }
        }
        let previous = self.focus;
        if previous == id { return Ok(previous); }
        let old_owner = previous.and_then(|window| self.get(window).map(|record| record.owner_tid));
        let new_owner = id.and_then(|window| self.get(window).map(|record| record.owner_tid));
        if let Some(owner) = old_owner {
            let needed = 1 + usize::from(new_owner == Some(owner));
            if !self.queue_has_capacity(owner, needed) { return Err(WindowError::QueueFull); }
        }
        if let Some(owner) = new_owner {
            if new_owner != old_owner && !self.queue_has_capacity(owner, 1) { return Err(WindowError::QueueFull); }
        }
        self.focus = id;
        if let Some(old) = previous {
            self.post_to_window(old, WinMessage { hwnd: Some(old), message: WM_KILLFOCUS, wparam: id.map_or(0, |window| window.raw() as u64), lparam: 0 })?;
        }
        if let Some(new) = id {
            self.post_to_window(new, WinMessage { hwnd: Some(new), message: WM_SETFOCUS, wparam: previous.map_or(0, |window| window.raw() as u64), lparam: 0 })?;
        }
        Ok(previous)
    }

    fn queue_has_capacity(&self, tid: u64, additional: usize) -> bool {
        self.queues.iter().find(|(owner, _)| *owner == tid).is_some_and(|(_, queue)| queue.len().saturating_add(additional) <= MESSAGE_QUEUE_LIMIT)
    }
    /// Return the canonical focused window. # C: O(1)
    pub fn focused(&self) -> Option<WindowId> { self.focus }
    /// Change visibility and return the previous state. # C: O(N_windows)
    pub fn show(&mut self, tid: u64, id: WindowId, visible: bool) -> Result<bool, WindowError> {
        let Some(record) = self.get(id) else { return Err(WindowError::NoSuchWindow); };
        if record.owner_tid != tid { return Err(WindowError::WrongThread); }
        let previous = record.visible;
        if previous == visible { return Ok(previous); }
        let Some((_, record)) = self.windows.iter_mut().find(|(window, _)| *window == id) else { return Err(WindowError::NoSuchWindow); };
        record.visible = visible;
        if visible {
            let area = self.client_rect(id);
            if area.is_some_and(|rect| rect.right > rect.left && rect.bottom > rect.top) {
                if let Err(error) = self.invalidate(id, None) {
                    if let Some((_, record)) = self.windows.iter_mut().find(|(window, _)| *window == id) { record.visible = previous; }
                    return Err(error);
                }
            }
        }
        Ok(previous)
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
        let requested = rect.map_or(Some(area), |rect| clip_rect(rect, area)).ok_or(WindowError::InvalidParent)?;
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
        if self.painting.iter().any(|(window, _)| *window == id) { return Err(WindowError::PaintActive); }
        let region = self.dirty.iter().position(|(window, _)| *window == id).map(|index| self.dirty.remove(index).1);
        self.painting.push((id, region));
        Ok(region)
    }
    /// Return the validated visible-window record for the active paint. # C: O(N_windows)
    pub fn present_record(&self, id: WindowId) -> Result<WindowPresentRecord, WindowError> {
        let record = self.get(id).ok_or(WindowError::NoSuchWindow)?;
        if !record.visible { return Err(WindowError::NotVisible); }
        let bounds = self.rect(id).ok_or(WindowError::NoSuchWindow)?;
        if bounds.right <= bounds.left || bounds.bottom <= bounds.top { return Err(WindowError::NoSuchWindow); }
        let damage = self.painting.iter().find(|(window, _)| *window == id).map(|(_, damage)| *damage).ok_or(WindowError::PaintNotActive)?;
        Ok(WindowPresentRecord { window: id, bounds, damage })
    }
    /// Close one canonical paint transaction and reject unmatched EndPaint calls. # C: O(N_painting)
    pub fn end_paint(&mut self, id: WindowId) -> Result<(), WindowError> {
        let Some(index) = self.painting.iter().position(|(window, _)| *window == id) else { return Err(WindowError::PaintNotActive); };
        self.painting.remove(index);
        Ok(())
    }
    /// Read the UTF-16 title/control text owned by one window. # C: O(N_windows)
    pub fn text(&self, id: WindowId) -> Option<&[u16]> { self.texts.iter().find(|(window, _)| *window == id).map(|(_, text)| text.as_slice()) }
    /// Replace the UTF-16 title/control text owned by one window. # C: O(N_windows + N_text)
    pub fn set_text(&mut self, id: WindowId, text: &[u16]) -> Result<(), WindowError> {
        let Some((_, current)) = self.texts.iter_mut().find(|(window, _)| *window == id) else { return Err(WindowError::NoSuchWindow); };
        current.clear(); current.extend_from_slice(text); Ok(())
    }
    fn remove_window(&mut self, id: WindowId) -> Result<WindowRecord, WindowError> {
        let index = self.windows.iter().position(|(window, _)| *window == id).ok_or(WindowError::NoSuchWindow)?;
        for (_, queue) in &mut self.queues { queue.cleanup_window(id); }
        self.timers.retain(|timer| timer.hwnd != Some(id));
        self.rects.retain(|(window, _)| *window != id);
        self.texts.retain(|(window, _)| *window != id);
        self.dirty.retain(|(window, _)| *window != id);
        self.painting.retain(|(window, _)| *window != id);
        self.destroying.retain(|window| *window != id);
        if self.focus == Some(id) { self.focus = None; }
        Ok(self.windows.remove(index).1)
    }
    /// Destroy a window subtree, children before their parent, as required by
    /// the Win32 window lifetime contract. # C: O(N_windows²)
    pub fn destroy(&mut self, id: WindowId) -> Result<WindowRecord, WindowError> {
        if self.get(id).is_none() { return Err(WindowError::NoSuchWindow); }
        let children: Vec<WindowId> = self.windows.iter().filter_map(|(window, record)| (record.parent == Some(id)).then_some(*window)).collect();
        for child in children { let _ = self.destroy(child); }
        self.remove_window(id)
    }
    /// Reserve one live window for a synchronous destruction transaction. # C: O(N_windows)
    pub fn begin_destroy(&mut self, owner_tid: u64, id: WindowId) -> Result<bool, WindowError> {
        let record = self.get(id).ok_or(WindowError::NoSuchWindow)?;
        if record.owner_tid != owner_tid { return Err(WindowError::WrongThread); }
        let order = self.destruction_order(id).ok_or(WindowError::NoSuchWindow)?;
        if order.iter().any(|window| self.destroying.contains(window)) { return Ok(false); }
        self.destroying.extend(order); Ok(true)
    }
    /// Cancel a destruction reservation after callback setup fails. # C: O(N_windows)
    pub fn cancel_destroy(&mut self, id: WindowId) {
        let order = self.destruction_order(id).unwrap_or_default();
        self.destroying.retain(|window| !order.contains(window));
    }
    /// Return a stable preorder of a live window subtree for callback phases. # C: O(N_windows²)
    pub fn destruction_order(&self, id: WindowId) -> Option<Vec<WindowId>> {
        if self.get(id).is_none() { return None; }
        let mut order = Vec::new();
        self.append_destruction_order(id, &mut order);
        Some(order)
    }
    fn append_destruction_order(&self, id: WindowId, order: &mut Vec<WindowId>) {
        order.push(id);
        let children: Vec<WindowId> = self.windows.iter().filter_map(|(window, record)| (record.parent == Some(id)).then_some(*window)).collect();
        for child in children { self.append_destruction_order(child, order); }
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
        self.post_to_window(window, WinMessage { hwnd: Some(window), message: if pressed { WM_KEYDOWN } else { WM_KEYUP }, wparam: key as u64, lparam: key_lparam(pressed, repeat) })
    }
    /// Enqueue one hardware key transition on the focused window. # C: O(N_windows)
    pub fn post_focused_key(&mut self, key: u16, pressed: bool, repeat: bool) -> Result<(), WindowError> {
        let window = self.focus.ok_or(WindowError::NoFocus)?;
        self.post_to_window(window, WinMessage { hwnd: Some(window), message: if pressed { WM_KEYDOWN } else { WM_KEYUP }, wparam: key as u64, lparam: key_lparam(pressed, repeat) })
    }
    /// Enqueue one relative mouse transition on the focused window. # C: O(N_windows)
    pub fn post_focused_mouse(&mut self, code: u16, delta: i32) -> Result<(), WindowError> {
        let window = self.focus.ok_or(WindowError::NoFocus)?;
        let rect = self.client_rect(window).ok_or(WindowError::NoSuchWindow)?;
        if code != 0 && code != 1 { return Ok(()); }
        let axis = if code == 0 { &mut self.cursor.0 } else { &mut self.cursor.1 };
        *axis = axis.saturating_add(delta);
        let limit = if code == 0 { rect.right } else { rect.bottom };
        if limit > 0 { *axis = (*axis).clamp(0, limit - 1); }
        self.post_to_window(window, WinMessage { hwnd: Some(window), message: WM_MOUSEMOVE, wparam: 0, lparam: mouse_lparam(self.cursor.0, self.cursor.1) })
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
        let queue_index = self.queues.iter().position(|(owner, _)| *owner == tid)?;
        let windows = &self.windows;
        let matches = |message| message_matches_in_windows(windows, filter, message);
        let queue = &mut self.queues[queue_index].1;
        queue.peek_matching(matches, remove).or_else(|| queue.quit_message(filter, remove))
    }
    /// Validate the optional HWND filter before a queue lookup. # C: O(N_windows)
    pub fn validate_message_filter(&self, window: Option<WindowId>) -> Result<(), WindowError> {
        if window.is_some_and(|window| self.get(window).is_none()) { return Err(WindowError::NoSuchWindow); }
        Ok(())
    }
    pub fn post_quit(&mut self, tid: u64, code: i32) {
        if let Some((_, queue)) = self.queues.iter_mut().find(|(owner, _)| *owner == tid) { queue.post_quit(code); }
        else { let mut queue = MessageQueue::default(); queue.post_quit(code); self.queues.push((tid, queue)); }
    }
    pub fn take_for_thread(&mut self, tid: u64, filter: MessageFilter) -> QueueResult {
        let Some(queue_index) = self.queues.iter().position(|(owner, _)| *owner == tid) else { return QueueResult::Empty; };
        let windows = &self.windows;
        let matches = |message| message_matches_in_windows(windows, filter, message);
        let queue = &mut self.queues[queue_index].1;
        if let Some(message) = queue.peek_matching(matches, true) { QueueResult::Message(message) }
        else if let Some(code) = queue.take_quit_matching(matches) { QueueResult::Quit(code) }
        else { QueueResult::Empty }
    }
    pub fn quit_pending(&self, tid: u64) -> bool { self.queues.iter().find(|(owner, _)| *owner == tid).is_some_and(|(_, queue)| queue.quit_pending()) }
    pub fn len(&self) -> usize { self.windows.len() }

}

fn message_matches_in_windows(windows: &[(WindowId, WindowRecord)], filter: MessageFilter, message: WinMessage) -> bool {
    let range = MessageFilter { hwnd: None, first: filter.first, last: filter.last };
    if !range.matches(message) { return false; }
    let Some(filter_window) = filter.hwnd else { return true; };
    let Some(message_window) = message.hwnd else { return false; };
    let mut current = Some(message_window);
    while let Some(window) = current {
        if window == filter_window { return true; }
        current = windows.iter().find(|(candidate, _)| *candidate == window).and_then(|(_, record)| record.parent);
    }
    false
}

fn same_name(left: &[u16], right: &[u16]) -> bool {
    left.len() == right.len() && left.iter().zip(right).all(|(left, right)| {
        let fold = |unit: u16| if (b'A' as u16..=b'Z' as u16).contains(&unit) { unit + 32 } else { unit };
        fold(*left) == fold(*right)
    })
}

fn clip_rect(rect: WindowRect, area: WindowRect) -> Option<WindowRect> {
    let left = rect.left.max(area.left); let top = rect.top.max(area.top);
    let right = rect.right.min(area.right); let bottom = rect.bottom.min(area.bottom);
    (right > left && bottom > top).then_some(WindowRect { left, top, right, bottom })
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DefaultWindowResult { Return(i64), RequestDestroy }

pub fn default_window_proc(message: u32) -> DefaultWindowResult {
    match message { WM_CLOSE => DefaultWindowResult::RequestDestroy, WM_NCHITTEST => DefaultWindowResult::Return(HTCLIENT), WM_NCACTIVATE => DefaultWindowResult::Return(1), _ => DefaultWindowResult::Return(0) }
}

/// Apply default handling that depends on canonical window geometry. # C: O(1)
pub fn default_window_proc_for_rect(message: u32, rect: WindowRect, lparam: i64) -> DefaultWindowResult {
    if message != WM_NCHITTEST { return default_window_proc(message); }
    let point = lparam as u64;
    let x = (point as u16 as i16) as i32;
    let y = ((point >> 16) as u16 as i16) as i32;
    let inside = x >= rect.left && x < rect.right && y >= rect.top && y < rect.bottom;
    DefaultWindowResult::Return(if inside { HTCLIENT } else { HTNOWHERE })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn user_message_atoms_are_case_insensitive_and_stable() {
        let mut atoms = UserAtomTable::new();
        assert_eq!(atoms.register(&[b'F' as u16, b'i' as u16, b'n' as u16]), Some(USER_ATOM_BASE + 1));
        assert_eq!(atoms.register(&[b'f' as u16, b'I' as u16, b'N' as u16]), Some(USER_ATOM_BASE + 1));
        assert_eq!(atoms.register(&[b'P' as u16, b'a' as u16, b'i' as u16, b'n' as u16]), Some(USER_ATOM_BASE + 2));
    }

    #[test]
    fn user_message_atoms_reject_invalid_and_exhausted_names() {
        let mut atoms = UserAtomTable::new();
        assert_eq!(atoms.register(&[]), None);
        assert_eq!(atoms.register(&[b'x' as u16; USER_ATOM_MAX_LENGTH + 1]), None);
        for index in 0..USER_ATOM_CAPACITY - 1 {
            assert_eq!(atoms.register(&[0x0100 + index as u16]), Some(USER_ATOM_BASE + index as u16 + 1));
        }
        assert_eq!(atoms.register(&[u16::MAX]), None);
    }

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
    fn zero_message_bounds_select_the_entire_queue() {
        let mut queue = MessageQueue::default();
        queue.post(message(None, 0x0042)).unwrap();
        queue.post(message(None, WM_PAINT)).unwrap();
        let filter = MessageFilter { hwnd: None, first: 0, last: 0 };
        assert_eq!(queue.peek(filter, true).map(|value| value.message), Some(0x0042));
        assert_eq!(queue.peek(filter, true).map(|value| value.message), Some(WM_PAINT));
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
        assert_eq!(default_window_proc(WM_NCACTIVATE), DefaultWindowResult::Return(1));
    }

    #[test]
    fn default_hit_test_uses_canonical_window_bounds() {
        let rect = WindowRect { left: 10, top: 20, right: 110, bottom: 120 };
        let inside = ((40u16 as u64) | ((60u16 as u64) << 16)) as i64;
        let outside = ((9u16 as u64) | ((60u16 as u64) << 16)) as i64;
        assert_eq!(default_window_proc_for_rect(WM_NCHITTEST, rect, inside), DefaultWindowResult::Return(HTCLIENT));
        assert_eq!(default_window_proc_for_rect(WM_NCHITTEST, rect, outside), DefaultWindowResult::Return(HTNOWHERE));
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
    fn message_filter_accepts_null_and_live_hwnd_but_rejects_stale_hwnd() {
        let mut manager = WindowManager::new();
        let window = manager.create(9, None, 0).unwrap();
        assert_eq!(manager.validate_message_filter(None), Ok(()));
        assert_eq!(manager.validate_message_filter(Some(window)), Ok(()));
        manager.destroy(window).unwrap();
        assert_eq!(manager.validate_message_filter(Some(window)), Err(WindowError::NoSuchWindow));
    }

    #[test]
    fn parent_hwnd_filter_includes_descendant_messages_but_not_siblings() {
        let mut manager = WindowManager::new();
        let parent = manager.create(9, None, 0).unwrap();
        let child = manager.create(9, Some(parent), 0).unwrap();
        let sibling = manager.create(9, None, 0).unwrap();
        manager.post_to_window(child, message(Some(child), WM_KEYDOWN)).unwrap();
        manager.post_to_window(sibling, message(Some(sibling), WM_KEYUP)).unwrap();
        let filter = MessageFilter { hwnd: Some(parent), first: 0, last: u32::MAX };
        assert_eq!(manager.peek_for_thread(9, filter, false).map(|value| value.hwnd), Some(Some(child)));
        assert_eq!(manager.take_for_thread(9, filter), QueueResult::Message(message(Some(child), WM_KEYDOWN)));
        assert_eq!(manager.take_for_thread(9, filter), QueueResult::Empty);
        assert_eq!(manager.peek_for_thread(9, MessageFilter { hwnd: None, first: 0, last: u32::MAX }, true).map(|value| value.hwnd), Some(Some(sibling)));
    }

    #[test]
    fn hwnd_filtered_get_does_not_consume_thread_quit_until_unfiltered() {
        let mut manager = WindowManager::new();
        let window = manager.create(9, None, 0).unwrap();
        manager.post_quit(9, 23);
        let filtered = MessageFilter { hwnd: Some(window), first: 0, last: u32::MAX };
        assert_eq!(manager.take_for_thread(9, filtered), QueueResult::Empty);
        assert!(manager.quit_pending(9));
        let unfiltered = MessageFilter { hwnd: None, first: 0, last: u32::MAX };
        assert_eq!(manager.take_for_thread(9, unfiltered), QueueResult::Quit(23));
        assert!(!manager.quit_pending(9));
    }

    #[test]
    fn destroying_a_parent_removes_children_before_the_parent() {
        let mut manager = WindowManager::new();
        let parent = manager.create(9, None, 0x1234).unwrap();
        let child = manager.create(9, Some(parent), 0x5678).unwrap();
        manager.destroy(parent).unwrap();
        assert_eq!(manager.get(child), None);
        assert_eq!(manager.get(parent), None);
    }

    #[test]
    fn destroying_a_window_cleans_its_queue_messages_and_timers() {
        let mut manager = WindowManager::new();
        let window = manager.create(9, None, 0x1234).unwrap();
        manager.post_to_window(window, message(Some(window), WM_CLOSE)).unwrap();
        manager.post_to_window(window, message(Some(window), WM_PAINT)).unwrap();
        manager.set_timer(9, Some(window), 3, 10, 0xfeed, 100).unwrap();
        manager.destroy(window).unwrap();
        let filter = MessageFilter { hwnd: None, first: 0, last: u32::MAX };
        assert_eq!(manager.peek_for_thread(9, filter, false), None);
        assert_eq!(manager.expire_timers(u64::MAX), 0);
    }

    #[test]
    fn destroying_menu_owner_can_detach_its_window_association() {
        let mut manager = WindowManager::new();
        let window = manager.create(9, None, 0).unwrap();
        assert_eq!(manager.set_menu(window, Some(4)), Ok(None));
        manager.clear_menu(4);
        assert_eq!(manager.get(window).unwrap().menu, None);
    }

    #[test]
    fn destruction_reservation_is_idempotent_and_cancelable() {
        let mut manager = WindowManager::new();
        let window = manager.create(9, None, 0x1234).unwrap();
        assert_eq!(manager.begin_destroy(9, window), Ok(true));
        assert_eq!(manager.begin_destroy(9, window), Ok(false));
        manager.cancel_destroy(window);
        assert_eq!(manager.begin_destroy(9, window), Ok(true));
        manager.destroy(window).unwrap();
        assert_eq!(manager.begin_destroy(9, window), Err(WindowError::NoSuchWindow));
    }

    #[test]
    fn destruction_order_is_parent_first_and_children_before_parent_cleanup() {
        let mut manager = WindowManager::new();
        let parent = manager.create(9, None, 0x1).unwrap();
        let first = manager.create(9, Some(parent), 0x2).unwrap();
        let second = manager.create(9, Some(parent), 0x3).unwrap();
        let grandchild = manager.create(9, Some(first), 0x4).unwrap();
        assert_eq!(manager.destruction_order(parent), Some(vec![parent, first, grandchild, second]));
    }

    #[test]
    fn subtree_reservation_rejects_reentry_for_every_descendant_and_rolls_back() {
        let mut manager = WindowManager::new();
        let parent = manager.create(9, None, 0x1).unwrap();
        let child = manager.create(9, Some(parent), 0x2).unwrap();
        let sibling = manager.create(9, Some(parent), 0x3).unwrap();
        assert_eq!(manager.begin_destroy(9, parent), Ok(true));
        assert_eq!(manager.begin_destroy(9, child), Ok(false));
        assert_eq!(manager.begin_destroy(9, sibling), Ok(false));
        manager.cancel_destroy(parent);
        assert_eq!(manager.begin_destroy(9, child), Ok(true));
        manager.cancel_destroy(child);
        assert_eq!(manager.begin_destroy(9, parent), Ok(true));
    }

    #[test]
    fn destruction_reservation_rejects_a_non_owner_without_mutating_the_window() {
        let mut manager = WindowManager::new();
        let window = manager.create(9, None, 0x1234).unwrap();
        assert_eq!(manager.begin_destroy(8, window), Err(WindowError::WrongThread));
        assert_eq!(manager.get(window).unwrap().owner_tid, 9);
        assert_eq!(manager.begin_destroy(9, window), Ok(true));
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
        assert_eq!(manager.peek_for_thread(9, filter, true), Some(WinMessage { hwnd: Some(second), message: WM_KEYDOWN, wparam: 0x41, lparam: 1 }));
    }

    #[test]
    fn focus_transition_notifies_old_and_new_windows_in_order() {
        let mut manager = WindowManager::new();
        let old = manager.create(9, None, 0).unwrap();
        let new = manager.create(9, None, 0).unwrap();
        assert_eq!(manager.set_focus(9, Some(old)), Ok(None));
        assert_eq!(manager.peek_for_thread(9, MessageFilter { hwnd: Some(old), first: WM_SETFOCUS, last: WM_SETFOCUS }, true), Some(WinMessage { hwnd: Some(old), message: WM_SETFOCUS, wparam: 0, lparam: 0 }));
        assert_eq!(manager.set_focus(9, Some(new)), Ok(Some(old)));
        assert_eq!(manager.peek_for_thread(9, MessageFilter { hwnd: Some(old), first: WM_KILLFOCUS, last: WM_KILLFOCUS }, true), Some(WinMessage { hwnd: Some(old), message: WM_KILLFOCUS, wparam: new.raw() as u64, lparam: 0 }));
        assert_eq!(manager.peek_for_thread(9, MessageFilter { hwnd: Some(new), first: WM_SETFOCUS, last: WM_SETFOCUS }, true), Some(WinMessage { hwnd: Some(new), message: WM_SETFOCUS, wparam: old.raw() as u64, lparam: 0 }));
        assert_eq!(manager.set_focus(9, None), Ok(Some(new)));
        assert_eq!(manager.peek_for_thread(9, MessageFilter { hwnd: Some(new), first: WM_KILLFOCUS, last: WM_KILLFOCUS }, true), Some(WinMessage { hwnd: Some(new), message: WM_KILLFOCUS, wparam: 0, lparam: 0 }));
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
    fn key_lparam_encodes_transition_and_repeat_state() {
        assert_eq!(key_lparam(true, false), 1);
        assert_eq!(key_lparam(true, true), 0x4000_0002);
        assert_eq!(key_lparam(false, false), 0xc000_0001);
        assert_eq!(key_lparam(false, true), 0xc000_0002);
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
        assert_eq!(manager.show(9, child, true), Ok(false));
        assert_eq!(manager.show(8, child, false), Err(WindowError::WrongThread));
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
        assert_eq!(manager.class_info(&[b'n' as u16, b'O' as u16, b'T' as u16]).map(|value| (value.0, value.1)), Some((atom, 0x1400)));
        assert_eq!(manager.class_info_by_atom(atom).map(|value| value.2), Some(&[b'N' as u16, b'o' as u16, b't' as u16][..]));
        assert_eq!(manager.class_wndproc_by_atom(atom + 1), None);
        assert_eq!(manager.register_class(&[b'n' as u16, b'o' as u16, b't' as u16], 0x1500), Err(WindowError::InvalidParent));
    }

    #[test]
    fn class_unregister_waits_for_all_canonical_windows() {
        let mut manager = WindowManager::new();
        let name = [b'E' as u16, b'd' as u16, b'i' as u16, b't' as u16];
        let atom = manager.register_class(&name, 0x1400).unwrap();
        let window = manager.create_class_atom(9, None, atom).unwrap();
        assert_eq!(manager.unregister_class(&name), Err(WindowError::ClassInUse));
        manager.destroy(window).unwrap();
        assert_eq!(manager.unregister_class(&name), Ok(()));
        assert_eq!(manager.class_wndproc_by_atom(atom), None);
    }

    #[test]
    fn top_level_class_window_owns_visibility_and_message_delivery() {
        let mut manager = WindowManager::new();
        let atom = manager.register_class(&[b'N' as u16, b'o' as u16, b't' as u16], 0x1400).unwrap();
        let window = manager.create_class_atom(9, None, atom).unwrap();
        assert_eq!(manager.get(window).unwrap().wndproc, 0x1400);
        assert_eq!(manager.show(9, window, true), Ok(false));
        assert!(manager.get(window).unwrap().visible);
        let message = WinMessage { hwnd: Some(window), message: WM_CLOSE, wparam: 7, lparam: -9 };
        manager.post_to_window(window, message).unwrap();
        assert_eq!(manager.take_for_thread(9, MessageFilter { hwnd: Some(window), first: WM_CLOSE, last: WM_CLOSE }), QueueResult::Message(message));
        manager.destroy(window).unwrap();
        assert_eq!(manager.post_to_window(window, message), Err(WindowError::NoSuchWindow));
    }

    #[test]
    fn showing_sized_window_admits_one_full_paint_and_hide_does_not_repaint() {
        let mut manager = WindowManager::new();
        let window = manager.create(9, None, 0).unwrap();
        let rect = WindowRect { left: 80, top: 60, right: 720, bottom: 540 };
        manager.set_rect(window, rect).unwrap();
        assert_eq!(manager.show(9, window, true), Ok(false));
        assert_eq!(manager.begin_paint(window), Ok(Some(WindowRect { left: 0, top: 0, right: 640, bottom: 480 })));
        assert_eq!(manager.end_paint(window), Ok(()));
        assert_eq!(manager.begin_paint(window), Ok(None));
        assert_eq!(manager.peek_for_thread(9, MessageFilter { hwnd: Some(window), first: WM_PAINT, last: WM_PAINT }, true).map(|message| message.message), Some(WM_PAINT));
        assert_eq!(manager.peek_for_thread(9, MessageFilter { hwnd: Some(window), first: WM_PAINT, last: WM_PAINT }, true), None);
        assert_eq!(manager.show(9, window, false), Ok(true));
        assert_eq!(manager.peek_for_thread(9, MessageFilter { hwnd: Some(window), first: WM_PAINT, last: WM_PAINT }, true), None);
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
    fn paint_transaction_requires_begin_before_end_and_closes_once() {
        let mut manager = WindowManager::new();
        let window = manager.create(9, None, 0).unwrap();
        assert_eq!(manager.end_paint(window), Err(WindowError::PaintNotActive));
        assert_eq!(manager.begin_paint(window), Ok(None));
        assert_eq!(manager.begin_paint(window), Err(WindowError::PaintActive));
        assert_eq!(manager.end_paint(window), Ok(()));
        assert_eq!(manager.end_paint(window), Err(WindowError::PaintNotActive));
    }

    #[test]
    fn visible_paint_exposes_one_canonical_compositor_record() {
        let mut manager = WindowManager::new();
        let window = manager.create(9, None, 0).unwrap();
        let bounds = WindowRect { left: 80, top: 60, right: 720, bottom: 540 };
        manager.set_rect(window, bounds).unwrap();
        manager.show(9, window, true).unwrap();
        manager.begin_paint(window).unwrap();
        manager.end_paint(window).unwrap();
        let damage = WindowRect { left: 12, top: 8, right: 40, bottom: 24 };
        manager.invalidate(window, Some(damage)).unwrap();
        manager.begin_paint(window).unwrap();
        assert_eq!(manager.present_record(window), Ok(WindowPresentRecord { window, bounds, damage: Some(damage) }));
        manager.end_paint(window).unwrap();
        assert_eq!(manager.present_record(window), Err(WindowError::PaintNotActive));
    }

    #[test]
    fn compositor_record_rejects_hidden_windows_and_clips_damage() {
        let mut manager = WindowManager::new();
        let window = manager.create(9, None, 0).unwrap();
        manager.set_rect(window, WindowRect { left: 0, top: 0, right: 20, bottom: 20 }).unwrap();
        manager.invalidate(window, Some(WindowRect { left: -4, top: 2, right: 30, bottom: 40 })).unwrap();
        assert_eq!(manager.begin_paint(window), Ok(Some(WindowRect { left: 0, top: 2, right: 20, bottom: 20 })));
        assert_eq!(manager.present_record(window), Err(WindowError::NotVisible));
        manager.end_paint(window).unwrap();
        manager.show(9, window, true).unwrap();
        assert_eq!(manager.begin_paint(window), Ok(Some(WindowRect { left: 0, top: 0, right: 20, bottom: 20 })));
    }

    #[test]
    fn destroying_window_closes_an_open_paint_transaction() {
        let mut manager = WindowManager::new();
        let window = manager.create(9, None, 0).unwrap();
        manager.begin_paint(window).unwrap();
        manager.destroy(window).unwrap();
        assert_eq!(manager.end_paint(window), Err(WindowError::PaintNotActive));
    }

    #[test]
    fn queue_rejects_messages_after_its_bounded_capacity() {
        let mut queue = MessageQueue::default();
        for _ in 0..MESSAGE_QUEUE_LIMIT { queue.post(message(None, 1)).unwrap(); }
        assert_eq!(queue.post(message(None, 2)), Err(QueueError::Full));
        assert_eq!(queue.len(), MESSAGE_QUEUE_LIMIT);
    }

    #[test]
    fn focused_relative_motion_posts_bounded_client_coordinates() {
        let mut manager = WindowManager::new();
        let window = manager.create(9, None, 0).unwrap();
        manager.set_rect(window, WindowRect { left: 40, top: 50, right: 140, bottom: 130 }).unwrap();
        manager.set_focus(9, Some(window)).unwrap();
        manager.post_focused_mouse(0, 120).unwrap();
        manager.post_focused_mouse(1, 90).unwrap();
        let filter = MessageFilter { hwnd: Some(window), first: WM_MOUSEMOVE, last: WM_MOUSEMOVE };
        assert_eq!(manager.take_for_thread(9, filter), QueueResult::Message(WinMessage { hwnd: Some(window), message: WM_MOUSEMOVE, wparam: 0, lparam: mouse_lparam(99, 0) }));
        assert_eq!(manager.take_for_thread(9, filter), QueueResult::Message(WinMessage { hwnd: Some(window), message: WM_MOUSEMOVE, wparam: 0, lparam: mouse_lparam(99, 79) }));
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
