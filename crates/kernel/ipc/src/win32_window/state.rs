//! Canonical HWND lifetime, geometry, painting and message work.
use super::*;
impl WindowManager {
    pub fn new() -> Self { Self { next: 1, next_atom: 1, classes: Vec::new(), windows: Vec::new(), rects: Vec::new(), texts: Vec::new(), dirty: Vec::new(), painting: Vec::new(), queues: Vec::new(), timers: Vec::new(), focus: None, capture: None, cursor: (0, 0), buttons: 0, destroying: Vec::new(), keyboard: KeyboardState::default(), active: None } }
    pub fn create(&mut self, owner_tid: u64, parent: Option<WindowId>, wndproc: u64) -> Result<WindowId, WindowError> {
        if parent.is_some_and(|parent| self.get(parent).is_none()) { return Err(WindowError::InvalidParent); }
        let id = WindowId(self.next);
        self.next = self.next.checked_add(1).ok_or(WindowError::NoSuchWindow)?;
        self.windows.push((id, OwnedWindow::new(WindowRecord { owner_tid, parent, owner: None, wndproc, unicode: true, class_atom: None, visible: false, menu: None, id_menu: 0, presentation_ready: false, style: 0, ex_style: 0, last_focus: None, client_rect: None }, 0, 0).map_err(|_| WindowError::NoMemory)?));
        self.rects.push((id, WindowRect { left: 0, top: 0, right: 0, bottom: 0 }));
        self.texts.push((id, Vec::new()));
        if self.queues.iter().all(|(tid, _)| *tid != owner_tid) { self.queues.push((owner_tid, MessageQueue::default())); }
        Ok(id)
    }
    pub fn get(&self, id: WindowId) -> Option<WindowRecord> { self.windows.iter().find(|(window, _)| *window == id).map(|(_, entry)| entry.record) }
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

    pub(super) fn queue_has_capacity(&self, tid: u64, additional: usize) -> bool {
        self.queues.iter().find(|(owner, _)| *owner == tid).is_some_and(|(_, queue)| queue.len().saturating_add(additional) <= MESSAGE_QUEUE_LIMIT)
    }
    /// Return the canonical focused window. # C: O(1)
    pub fn focused(&self) -> Option<WindowId> { self.focus }
    /// Set pointer capture and return the previous window. # C: O(1)
    pub fn set_capture(&mut self, tid: u64, id: WindowId) -> Result<Option<WindowId>, WindowError> {
        let record = self.get(id).ok_or(WindowError::NoSuchWindow)?;
        if record.owner_tid != tid { return Err(WindowError::WrongThread); }
        let previous = self.capture;
        self.capture = Some(id);
        Ok(previous)
    }
    /// Release pointer capture from its owning thread. # C: O(1)
    pub fn release_capture(&mut self, tid: u64) -> Result<bool, WindowError> {
        let Some(id) = self.capture else { return Ok(false); };
        let record = self.get(id).ok_or(WindowError::NoSuchWindow)?;
        if record.owner_tid != tid { return Err(WindowError::WrongThread); }
        self.capture = None;
        Ok(true)
    }
    /// Return the live pointer-capture window. # C: O(1)
    pub const fn captured(&self) -> Option<WindowId> { self.capture }
    /// Change visibility and return the previous state. # C: O(N_windows)
    pub fn show(&mut self, tid: u64, id: WindowId, visible: bool) -> Result<bool, WindowError> {
        let Some(record) = self.get(id) else { return Err(WindowError::NoSuchWindow); };
        if record.owner_tid != tid { return Err(WindowError::WrongThread); }
        let previous = record.visible;
        let previous_style = record.style;
        let Some((_, record)) = self.windows.iter_mut().find(|(window, _)| *window == id) else { return Err(WindowError::NoSuchWindow); };
        if visible { record.style |= WS_VISIBLE; } else { record.style &= !WS_VISIBLE; }
        if previous == visible { return Ok(previous); }
        record.visible = visible;
        if visible {
            let area = self.client_rect(id);
            if area.is_some_and(|rect| rect.right > rect.left && rect.bottom > rect.top) {
                if let Err(error) = self.invalidate(id, None) {
                    if let Some((_, record)) = self.windows.iter_mut().find(|(window, _)| *window == id) { record.visible = previous; record.style = previous_style; }
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
        let rect = self.get(id)?.client_rect.or_else(|| self.rect(id))?;
        Some(WindowRect { left: 0, top: 0, right: rect.right.checked_sub(rect.left)?, bottom: rect.bottom.checked_sub(rect.top)? })
    }
    /// Read the UTF-16 title/control text owned by one window. # C: O(N_windows)
    pub fn text(&self, id: WindowId) -> Option<&[u16]> { self.texts.iter().find(|(window, _)| *window == id).map(|(_, text)| text.as_slice()) }
    /// Replace the UTF-16 title/control text owned by one window. # C: O(N_windows + N_text)
    pub fn set_text(&mut self, id: WindowId, text: &[u16]) -> Result<(), WindowError> {
        let Some((_, current)) = self.texts.iter_mut().find(|(window, _)| *window == id) else { return Err(WindowError::NoSuchWindow); };
        current.clear(); current.extend_from_slice(text); Ok(())
    }
    pub(super) fn remove_window(&mut self, id: WindowId) -> Result<WindowRecord, WindowError> {
        let index = self.windows.iter().position(|(window, _)| *window == id).ok_or(WindowError::NoSuchWindow)?;
        for (_, queue) in &mut self.queues { queue.cleanup_window(id); }
        self.timers.retain(|timer| timer.hwnd != Some(id));
        self.rects.retain(|(window, _)| *window != id);
        self.texts.retain(|(window, _)| *window != id);
        self.dirty.retain(|(window, _)| *window != id);
        self.painting.retain(|(window, _)| *window != id);
        self.destroying.retain(|window| *window != id);
        if self.capture == Some(id) { self.capture = None; }
        if self.focus == Some(id) { self.focus = None; }
        if self.active == Some(id) { self.active = None; }
        for (_, record) in &mut self.windows { if record.last_focus == Some(id) { record.last_focus = None; } }
        Ok(self.windows.remove(index).1.record)
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
    pub(super) fn append_destruction_order(&self, id: WindowId, order: &mut Vec<WindowId>) {
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
    /// Convert one accepted Linux pointer event into a capture-aware message. # C: O(N_windows)
    pub fn post_hardware_mouse(&mut self, ev_type: u16, code: u16, value: i32) -> Result<(), WindowError> {
        if ev_type == EV_REL && (code == REL_X || code == REL_Y) {
            let axis = if code == REL_X { &mut self.cursor.0 } else { &mut self.cursor.1 };
            *axis = axis.saturating_add(value);
            return self.post_pointer(WM_MOUSEMOVE);
        }
        if ev_type == EV_REL && code == REL_WHEEL {
            let delta = value.saturating_mul(120).clamp(i16::MIN as i32, i16::MAX as i32) as i16;
            return self.post_pointer_with(WM_MOUSEWHEEL, self.buttons as u32 | ((delta as u16 as u32) << 16));
        }
        if ev_type != EV_KEY { return Ok(()); }
        let (message, bit) = match code {
            BTN_LEFT => (if value != 0 { WM_LBUTTONDOWN } else { WM_LBUTTONUP }, MK_LBUTTON),
            BTN_RIGHT => (if value != 0 { WM_RBUTTONDOWN } else { WM_RBUTTONUP }, MK_RBUTTON),
            BTN_MIDDLE => (if value != 0 { WM_MBUTTONDOWN } else { WM_MBUTTONUP }, MK_MBUTTON),
            _ => return Ok(()),
        };
        if value != 0 { self.buttons |= bit; } else { self.buttons &= !bit; }
        self.post_pointer_with(message, self.buttons as u32)
    }
    pub(super) fn post_pointer(&mut self, message: u32) -> Result<(), WindowError> { self.post_pointer_with(message, self.buttons as u32) }
    pub(super) fn post_pointer_with(&mut self, message: u32, wparam: u32) -> Result<(), WindowError> {
        let window = self.capture.or_else(|| self.windows.iter().rev().find_map(|(id, record)| {
            if !record.visible { return None; }
            let rect = self.rect(*id)?;
            (self.cursor.0 >= rect.left && self.cursor.0 < rect.right && self.cursor.1 >= rect.top && self.cursor.1 < rect.bottom).then_some(*id)
        }));
        let Some(window) = window else { return Err(WindowError::NoFocus); };
        let rect = self.rect(window).ok_or(WindowError::NoSuchWindow)?;
        let point = if message == WM_MOUSEWHEEL { self.cursor }
            else { (self.cursor.0.saturating_sub(rect.left), self.cursor.1.saturating_sub(rect.top)) };
        self.post_to_window(window, WinMessage { hwnd: Some(window), message, wparam: wparam as u64, lparam: mouse_lparam(point.0, point.1) })
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
            .or_else(|| self.take_pending_paint(tid, filter))
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
        else if let Some(message) = self.take_pending_paint(tid, filter) { QueueResult::Message(message) }
        else { QueueResult::Empty }
    }
    pub fn quit_pending(&self, tid: u64) -> bool { self.queues.iter().find(|(owner, _)| *owner == tid).is_some_and(|(_, queue)| queue.quit_pending()) }
    pub fn len(&self) -> usize { self.windows.len() }

}
