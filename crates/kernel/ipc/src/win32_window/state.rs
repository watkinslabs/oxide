//! Canonical HWND lifetime, geometry, painting and message work.
use super::*;
impl WindowManager {
    pub fn new() -> Self { Self { next: 1, next_atom: 1, classes: Vec::new(), windows: Vec::new(), rects: Vec::new(), texts: Vec::new(), dirty: Vec::new(), painting: Vec::new(), queues: Vec::new(), timers: Vec::new(), focus: None, capture: None, cursor: (0, 0), buttons: 0, destroying: Vec::new(), keyboard: KeyboardState::default(), active: None, cursors: cursor_object::CursorIcons::new(), current_cursor: 0, cursor_count: 0, cursor_clip: None, cursor_change: 0, cursor_history: [cursor_pos::CursorPos { x: 0, y: 0, time: 0, info: 0 }; cursor_pos::CURSOR_HISTORY], cursor_latest: 0, menu_owner: None, move_size: None, hotkeys: hotkey::Hotkeys::new(), inputs: thread_input::ThreadInputs::new(), tracks: mouse_track::MouseTracks::new(), raw_input: rawinput::RawRegistrations::new(), layouts: Vec::new(), icons: window_icon::WindowIconTable::new(), attributes: Vec::new(), pointer_frame: 0 } }
    pub fn create(&mut self, owner_tid: u64, parent: Option<WindowId>, wndproc: u64) -> Result<WindowId, WindowError> {
        if parent.is_some_and(|parent| self.get(parent).is_none()) { return Err(WindowError::InvalidParent); }
        let id = WindowId(self.next);
        self.next = self.next.checked_add(1).ok_or(WindowError::NoSuchWindow)?;
        self.windows.push((id, OwnedWindow::new(WindowRecord { owner_tid, parent, owner: None, wndproc, unicode: true, class_atom: None, visible: false, sys_menu: None, id_menu: 0, presentation_ready: false, style: 0, ex_style: 0, last_focus: None, client_rect: None, imc: None, fnid: 0 }, 0, 0).map_err(|_| WindowError::NoMemory)?));
        self.rects.push((id, WindowRect { left: 0, top: 0, right: 0, bottom: 0 }));
        self.texts.push((id, Vec::new()));
        if self.queues.iter().all(|(tid, _)| *tid != owner_tid) { self.queues.push((owner_tid, MessageQueue::default())); }
        Ok(id)
    }
    /// Every live window, in creation order. # C: O(N_windows)
    pub fn window_handles(&self) -> Vec<WindowId> { self.windows.iter().map(|(id, _)| *id).collect() }
    pub fn get(&self, id: WindowId) -> Option<WindowRecord> { self.windows.iter().find(|(window, _)| *window == id).map(|(_, entry)| entry.record) }
    pub fn set_visible(&mut self, id: WindowId, visible: bool) -> Result<(), WindowError> {
        let Some((_, record)) = self.windows.iter_mut().find(|(window, _)| *window == id) else { return Err(WindowError::NoSuchWindow); };
        record.visible = visible;
        Ok(())
    }
    /// Associate one canonical HMENU with a window and return the prior one.
    /// An effective child owns a control identifier in this slot, not a menu,
    /// so it is refused rather than silently overwritten. # C: O(N_windows)
    pub fn set_menu(&mut self, id: WindowId, menu: Option<u32>) -> Result<Option<u32>, WindowError> {
        let Some((_, record)) = self.windows.iter_mut().find(|(window, _)| *window == id) else { return Err(WindowError::NoSuchWindow); };
        if is_effective_child(record.style) { return Err(WindowError::InvalidParent); }
        let previous = menu_of(record.style, record.id_menu);
        record.id_menu = menu.map_or(0, u64::from);
        Ok(previous)
    }
    /// Detach a destroyed HMENU from every canonical HWND. A child's identifier
    /// that happens to equal the handle is not a menu and stays. # C: O(N_windows)
    pub fn clear_menu(&mut self, menu: u32) { for (_, record) in &mut self.windows { if menu_of(record.style, record.id_menu) == Some(menu) { record.id_menu = 0; } } }
    /// The menu named by the shared identifier slot, for a window whose style
    /// makes that slot a menu handle. # C: O(N_windows)
    pub fn menu(&self, id: WindowId) -> Option<u32> { let record = self.get(id)?; menu_of(record.style, record.id_menu) }
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
    /// Set pointer capture and return the previous window.
    /// # C: O(N_windows + N_queues)
    pub fn set_capture(&mut self, tid: u64, id: WindowId) -> Result<Option<WindowId>, WindowError> {
        self.set_capture_window(tid, Some(id), 0)
    }
    /// Release pointer capture, answering whether one was held. Clearing the
    /// capture is admitted from any thread. # C: O(N_windows + N_queues)
    pub fn release_capture(&mut self, tid: u64) -> Result<bool, WindowError> {
        if self.capture.is_none() { return Ok(false); }
        self.set_capture_window(tid, None, 0).map(|previous| previous.is_some())
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
            let area = self.rect(id);
            if area.is_some_and(|rect| rect.right > rect.left && rect.bottom > rect.top) {
                if let Err(error) = self.redraw_tree(id, None, FRAME_REDRAW, |_, _, region| region.try_copy()) {
                    if let Some((_, record)) = self.windows.iter_mut().find(|(window, _)| *window == id) { record.visible = previous; record.style = previous_style; }
                    return Err(error);
                }
            }
        }
        Ok(previous)
    }
    /// Read geometry from the canonical HWND record. # C: O(N_windows)
    pub fn rect(&self, id: WindowId) -> Option<WindowRect> { self.rects.iter().find(|(window, _)| *window == id).map(|(_, rect)| *rect) }
    /// Update geometry in the canonical HWND record. A move carries the client
    /// rectangle with it: the nonclient insets are unchanged by a move, and a
    /// client rectangle left at the old position names a different space than
    /// the window rectangle, against which a child's own client coordinates
    /// crop to nothing. A resize leaves the client rectangle to the nonclient
    /// size calculation that follows it. # C: O(N_windows)
    pub fn set_rect(&mut self, id: WindowId, rect: WindowRect) -> Result<(), WindowError> {
        let Some((_, current)) = self.rects.iter_mut().find(|(window, _)| *window == id) else { return Err(WindowError::NoSuchWindow); };
        let (dx, dy) = (rect.left.wrapping_sub(current.left), rect.top.wrapping_sub(current.top));
        *current = rect;
        if (dx, dy) == (0, 0) { return Ok(()); }
        let Some((_, record)) = self.windows.iter_mut().find(|(window, _)| *window == id) else { return Ok(()); };
        if let Some(client) = record.client_rect {
            record.client_rect = Some(WindowRect { left: client.left.wrapping_add(dx), top: client.top.wrapping_add(dy),
                right: client.right.wrapping_add(dx), bottom: client.bottom.wrapping_add(dy) });
        }
        Ok(())
    }
    /// Return the client rectangle in client coordinates. # C: O(N_windows)
    pub fn client_rect(&self, id: WindowId) -> Option<WindowRect> {
        let rect = self.get(id)?.client_rect.or_else(|| self.rect(id))?;
        Some(WindowRect { left: 0, top: 0, right: rect.right.checked_sub(rect.left)?, bottom: rect.bottom.checked_sub(rect.top)? })
    }
    /// The client rectangle in the same coordinates the window rectangle uses,
    /// before the origin normalisation `client_rect` applies. # C: O(N_windows)
    pub fn client_rect_raw(&self, id: WindowId) -> Option<WindowRect> {
        let record = self.get(id)?;
        record.client_rect.or_else(|| self.rect(id))
    }
    /// Adopt the client rectangle one nonclient size calculation produced.
    /// # C: O(N_windows)
    pub fn set_client_rect(&mut self, id: WindowId, rect: WindowRect) -> Result<(), WindowError> {
        let record = self.windows.iter_mut().find(|(window, _)| *window == id).ok_or(WindowError::NoSuchWindow)?;
        record.1.client_rect = Some(rect); Ok(())
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
        self.icons.remove(id);
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
        self.post_to_window_with_bits(id, message, queue_status::QS_POSTED)
    }
    /// Enqueue one post stamped with the tick count it carries. # C: O(N_windows + N_queues)
    pub fn post_to_window_at(&mut self, id: WindowId, message: WinMessage, time: u32) -> Result<(), WindowError> {
        let pos = self.queue_pos_default();
        let owner = self.get(id).ok_or(WindowError::NoSuchWindow)?.owner_tid;
        let queue = self.queues.iter_mut().find(|(tid, _)| *tid == owner).map(|(_, queue)| queue)
            .ok_or(WindowError::NoSuchWindow)?;
        queue.post_with_bits_at(message, queue_status::QS_POSTED, time, pos).map_err(|_| WindowError::QueueFull)
    }
    /// Enqueue on the owning thread's queue with the wake bits the origin sets.
    /// # C: O(N_windows + N_queues)
    pub fn post_to_window_with_bits(&mut self, id: WindowId, message: WinMessage, bits: u32) -> Result<(), WindowError> {
        let pos = self.queue_pos_default();
        let owner = self.get(id).ok_or(WindowError::NoSuchWindow)?.owner_tid;
        let queue = self.queues.iter_mut().find(|(tid, _)| *tid == owner).map(|(_, queue)| queue)
            .ok_or(WindowError::NoSuchWindow)?;
        queue.post_with_bits(message, bits, pos).map_err(|_| WindowError::QueueFull)
    }
    /// Enqueue one hardware message, which counts as input rather than as a post. # C: O(N_windows)
    pub fn post_input_to_window(&mut self, id: WindowId, message: WinMessage) -> Result<(), WindowError> {
        let pos = self.queue_pos_default();
        let owner = self.get(id).ok_or(WindowError::NoSuchWindow)?.owner_tid;
        let queue = self.queues.iter_mut().find(|(tid, _)| *tid == owner).map(|(_, queue)| queue)
            .ok_or(WindowError::NoSuchWindow)?;
        queue.post_input(message, pos).map_err(|_| WindowError::QueueFull)
    }
    /// Enqueue one native keyboard transition on the focused window's owner queue. # C: O(N_windows)
    pub fn post_key(&mut self, tid: u64, key: u16, pressed: bool, repeat: bool) -> Result<(), WindowError> {
        let window = self.focus.ok_or(WindowError::NoFocus)?;
        let record = self.get(window).ok_or(WindowError::NoSuchWindow)?;
        if record.owner_tid != tid { return Err(WindowError::WrongThread); }
        self.post_input_to_window(window, WinMessage { hwnd: Some(window), message: if pressed { WM_KEYDOWN } else { WM_KEYUP }, wparam: key as u64, lparam: key_lparam(pressed, repeat) })
    }
    /// Enqueue one hardware key transition on the focused window. # C: O(N_windows)
    pub fn post_focused_key(&mut self, key: u16, pressed: bool, repeat: bool) -> Result<(), WindowError> {
        let window = self.focus.ok_or(WindowError::NoFocus)?;
        self.post_input_to_window(window, WinMessage { hwnd: Some(window), message: if pressed { WM_KEYDOWN } else { WM_KEYUP }, wparam: key as u64, lparam: key_lparam(pressed, repeat) })
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
        self.post_input_to_window(window, WinMessage { hwnd: Some(window), message: WM_MOUSEMOVE, wparam: 0, lparam: mouse_lparam(self.cursor.0, self.cursor.1) })
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
        // Raw input is queued in screen coordinates: the hit test that decides
        // whether the point is over the client area or the frame runs at
        // retrieval, and it is what translates the ones that are.
        self.post_input_to_window(window, WinMessage { hwnd: Some(window), message, wparam: wparam as u64, lparam: mouse_lparam(self.cursor.0, self.cursor.1) })
    }
    pub fn peek_for_thread(&mut self, tid: u64, filter: MessageFilter, remove: bool) -> Option<WinMessage> {
        let now = self.queue_pos_default();
        let queue_index = self.queues.iter().position(|(owner, _)| *owner == tid)?;
        let windows = &self.windows;
        let matches = |message| message_matches_in_windows(windows, filter, message);
        let queue = &mut self.queues[queue_index].1;
        if let Some(message) = queue.peek_matching(matches, remove).or_else(|| queue.quit_message(filter, remove, now)) {
            self.note_retrieved_message(tid, message, timekeeper::monotonic_ns());
            return Some(message);
        }
        // A deferred paint is synthesised by the retrieval, so it carries the
        // tick count of the retrieval rather than a queued stamp.
        let pos = self.queue_pos_default();
        let message = self.take_pending_paint(tid, filter, remove)?;
        self.note_thread_message_time(tid, msg_time::tick_ms());
        self.note_thread_message_pos(tid, pos);
        Some(message)
    }
    /// Replace one queued message with the form a retrieval prepared: the
    /// nonclient renumbering and the double-click promotion belong to the
    /// message the application receives, not to a second copy of the queue.
    /// # C: O(N_queued + N_windows)
    pub fn replace_for_thread(&mut self, tid: u64, filter: MessageFilter, message: WinMessage) -> bool {
        let Some(queue_index) = self.queues.iter().position(|(owner, _)| *owner == tid) else { return false; };
        let windows = &self.windows;
        let matches = |candidate| message_matches_in_windows(windows, filter, candidate);
        self.queues[queue_index].1.replace_matching(matches, message)
    }
    /// # C: O(1)
    pub fn window_count(&self) -> usize { self.windows.len() }
    /// Validate the optional HWND filter before a queue lookup. # C: O(N_windows)
    pub fn validate_message_filter(&self, window: Option<WindowId>) -> Result<(), WindowError> {
        if window.is_some_and(|window| self.get(window).is_none()) { return Err(WindowError::NoSuchWindow); }
        Ok(())
    }
    /// Store one window's system-menu bar and report the one it replaced.
    /// # C: O(N_windows)
    pub fn set_sys_menu(&mut self, id: WindowId, menu: Option<u32>) -> Result<Option<u32>, WindowError> {
        let (_, record) = self.windows.iter_mut().find(|(window, _)| *window == id).ok_or(WindowError::NoSuchWindow)?;
        let previous = record.sys_menu;
        record.sys_menu = menu;
        Ok(previous)
    }
    /// # C: O(N_windows)
    pub fn sys_menu(&self, id: WindowId) -> Option<u32> { self.get(id).and_then(|record| record.sys_menu) }

    /// Post one message on a named thread's queue; a thread without a queue
    /// takes no message. # C: O(N_queues)
    pub fn post_to_thread(&mut self, tid: u64, message: WinMessage) -> Result<(), WindowError> {
        let pos = self.queue_pos_default();
        let queue = self.queues.iter_mut().find(|(owner, _)| *owner == tid).map(|(_, queue)| queue)
            .ok_or(WindowError::NoSuchWindow)?;
        queue.post(message, pos).map_err(|_| WindowError::QueueFull)
    }
    pub fn post_quit(&mut self, tid: u64, code: i32) {
        if let Some((_, queue)) = self.queues.iter_mut().find(|(owner, _)| *owner == tid) { queue.post_quit(code); }
        else { let mut queue = MessageQueue::default(); queue.post_quit(code); self.queues.push((tid, queue)); }
    }
    pub fn take_for_thread(&mut self, tid: u64, filter: MessageFilter) -> QueueResult {
        let now = self.queue_pos_default();
        let Some(queue_index) = self.queues.iter().position(|(owner, _)| *owner == tid) else { return QueueResult::Empty; };
        let windows = &self.windows;
        let matches = |message| message_matches_in_windows(windows, filter, message);
        let queue = &mut self.queues[queue_index].1;
        if let Some(message) = queue.peek_matching(matches, true) {
            self.note_retrieved_message(tid, message, timekeeper::monotonic_ns());
            QueueResult::Message(message)
        }
        else if let Some(code) = queue.take_quit_matching(matches, now) { QueueResult::Quit(code) }
        else if let Some(message) = self.take_pending_paint(tid, filter, true) {
            let pos = self.queue_pos_default();
            self.note_thread_message_time(tid, msg_time::tick_ms());
            self.note_thread_message_pos(tid, pos);
            QueueResult::Message(message)
        }
        else { QueueResult::Empty }
    }
    pub fn quit_pending(&self, tid: u64) -> bool { self.queues.iter().find(|(owner, _)| *owner == tid).is_some_and(|(_, queue)| queue.quit_pending()) }
    pub fn len(&self) -> usize { self.windows.len() }

}
