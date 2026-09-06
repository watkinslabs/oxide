//! Canonical HWND snapshots and compositor event delivery; no backend window registry.
use alloc::{string::String, vec::Vec};
use ipc::win32_window::{self as gui, WindowId, WindowManager, WindowRect, WinMessage};
use syscall::nt_compositor::{self as wire, Opcode, Record};

#[cfg(test)]
use gui::{WM_MOVE, WM_SIZE};
const WM_CHAR: u32 = 0x0102;
const WM_SYSKEYDOWN: u32 = 0x0104;
const WM_SYSKEYUP: u32 = 0x0105;
const KEY_EXTENDED: u32 = 1 << 24;
const KEY_ALT: u32 = 1 << 29;
const KEY_PREVIOUS: u32 = 1 << 30;
const KEY_RELEASE: u32 = 1 << 31;
// Wire modifiers use Win32 key-lParam bits, not X11 modifier masks.
const KEY_FLAGS: u32 = KEY_EXTENDED | KEY_ALT | KEY_PREVIOUS;
const POINTER_FLAGS: u32 = 0x007f;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Snapshot { rect: wire::Rect, parent: u64, title: Vec<u8>, visible: bool, ready: bool }

fn window(hwnd: u64) -> Option<WindowId> { WindowId::from_raw(u32::try_from(hwnd).ok()?) }

fn wire_rect(rect: WindowRect) -> Option<wire::Rect> {
    let rect = wire::Rect { x: rect.left, y: rect.top,
        width: u32::try_from(rect.right.checked_sub(rect.left)?).ok()?,
        height: u32::try_from(rect.bottom.checked_sub(rect.top)?).ok()? };
    rect.validate_window().ok()?; Some(rect)
}

/// Owned copy; caller releases GUI lock before encoding or transport. # C: O(windows + title)
pub(super) fn snapshot(state: &WindowManager, hwnd: u64) -> Option<Snapshot> {
    let window = window(hwnd)?;
    let record = state.get(window)?;
    let title = String::from_utf16_lossy(state.text(window)?).into_bytes();
    if title.len() > wire::MAX_TITLE || title.contains(&0) { return None; }
    Some(Snapshot { rect: wire_rect(state.rect(window)?)?,
        parent: record.parent.or(record.owner).map_or(0, |id| id.raw() as u64), title, visible: record.visible, ready: record.presentation_ready })
}

fn update_snapshot(state: &WindowManager, hwnd: u64) -> Result<Option<Snapshot>, ()> {
    let id = window(hwnd).ok_or(())?;
    if !state.presentation_ready(id).ok_or(())? { return Ok(None); }
    snapshot(state, hwnd).map(Some).ok_or(())
}

fn create_snapshot(state: &mut WindowManager, hwnd: u64, style: u32, ex_style: u32) -> Option<Snapshot> {
    state.set_window_styles(window(hwnd)?, style, ex_style).ok()?;
    snapshot(state, hwnd)
}

impl Snapshot {
    fn create_payload(&self, style: u32, exstyle: u32) -> Option<Vec<u8>> {
        let mut payload = self.rect.encode_window().ok()?.to_vec();
        payload.extend_from_slice(&self.parent.to_le_bytes());
        payload.extend_from_slice(&style.to_le_bytes()); payload.extend_from_slice(&exstyle.to_le_bytes());
        Some(payload)
    }
}

fn post(state: &mut WindowManager, id: WindowId, message: u32, wparam: u64, lparam: i64) -> bool {
    state.post_to_window(id, WinMessage { hwnd: Some(id), message, wparam, lparam }).is_ok()
}

fn keyboard_target(state: &WindowManager, source: WindowId) -> WindowId {
    let Some(focused) = state.focused() else { return source; };
    let mut cursor = Some(focused);
    // HWND parentage is canonical and acyclic. Never retarget into an unrelated top-level window.
    while let Some(id) = cursor {
        if id == source { return focused; }
        cursor = state.get(id).and_then(|record| record.parent);
    }
    source
}

/// Process ownership was checked before supplying this canonical manager.
/// Pointer mutation is delegated to that manager, never retained in the adapter.
/// # C: O(windows + text + queued messages)
pub(super) fn apply_event(
    state: &mut WindowManager, record: &Record,
    pointer: impl FnOnce(&mut WindowManager, WindowId, i32, i32, u32, i32) -> bool,
) -> bool {
    if record.validate().is_err() { return false; }
    let Some(id) = window(record.header.hwnd) else { return false; };
    if state.get(id).is_none() { return false; }
    let p = &record.payload;
    match record.header.opcode {
        Opcode::Configure => {
            let Ok(rect) = wire::Rect::decode_window(p) else { return false; };
            let next = WindowRect { left: rect.x, top: rect.y,
                right: rect.x + rect.width as i32, bottom: rect.y + rect.height as i32 };
            state.configure_compositor_window(id, next).is_ok()
        }
        Opcode::Key => {
            let key = wire::u32_at(p, 0).unwrap_or(u32::MAX);
            let scan = wire::u32_at(p, 4).unwrap_or(u32::MAX);
            let pressed = wire::u32_at(p, 8) == Ok(1);
            let modifiers = wire::u32_at(p, 12).unwrap_or(u32::MAX);
            if key == 0 || key > 0xff || scan > 0xff || modifiers & !KEY_FLAGS != 0 { return false; }
            let flags = 1 | (scan << 16) | modifiers | if pressed { 0 } else { KEY_PREVIOUS | KEY_RELEASE };
            let message = match (modifiers & KEY_ALT != 0, pressed) {
                (true, true) => WM_SYSKEYDOWN, (true, false) => WM_SYSKEYUP,
                (false, true) => gui::WM_KEYDOWN, (false, false) => gui::WM_KEYUP,
            };
            let target = keyboard_target(state, id);
            state.post_compositor_key(target, WinMessage { hwnd: Some(target), message, wparam: key as u64, lparam: flags as i64 }).is_ok()
        }
        Opcode::Text => {
            let Ok(text) = core::str::from_utf8(p) else { return false; };
            let target = keyboard_target(state, id);
            if state.check_message_capacity(target, text.encode_utf16().count()).is_err() { return false; }
            for unit in text.encode_utf16() { if !post(state, target, WM_CHAR, unit as u64, 1) { return false; } }
            true
        }
        Opcode::Pointer => {
            let x = wire::u32_at(p, 0).unwrap_or(0) as i32;
            let y = wire::u32_at(p, 4).unwrap_or(0) as i32;
            let buttons = wire::u32_at(p, 8).unwrap_or(u32::MAX);
            let wheel = wire::u32_at(p, 12).unwrap_or(0) as i32;
            if buttons & !POINTER_FLAGS != 0 || i16::try_from(wheel).is_err() { return false; }
            pointer(state, id, x, y, buttons, wheel)
        }
        Opcode::Focus => state.compositor_focus(id, wire::u32_at(p, 0) == Ok(1)).is_ok(),
        Opcode::Close => post(state, id, gui::WM_CLOSE, 0, 0),
        _ => false,
    }
}

#[cfg(target_os = "oxide-kernel")]
mod live {
    use super::*;
    use alloc::sync::Arc;
    use sched::thread_group::ThreadGroup;
    use crate::nt_compositor::{self as transport, Completion, TransportError};
    const CONTROL_TIMEOUT_NS: u64 = 5_000_000_000;

    fn current_snapshot(hwnd: u64, style: u32, ex_style: u32) -> Result<(Arc<ThreadGroup>, Snapshot), TransportError> {
        let cur = sched::live::current().ok_or(TransportError::Disconnected)?;
        if !cur.is_nt_personality() { return Err(TransportError::Invalid); }
        let group = Arc::clone(&cur.thread_group);
        let value = {
            let mut entries = super::super::GUI.lock();
            let entry = entries.iter_mut().find(|e| e.group.ptr_eq(&Arc::downgrade(&group))).ok_or(TransportError::Unknown)?;
            create_snapshot(&mut entry.state, hwnd, style, ex_style).ok_or(TransportError::Unknown)?
        };
        Ok((group, value))
    }

    fn publish(group: &Arc<ThreadGroup>, opcode: Opcode, hwnd: u64, payload: Vec<u8>) -> Result<(), TransportError> {
        let ticket = transport::enqueue(group, opcode, hwnd, payload)?;
        match transport::wait_completion_current(ticket, CONTROL_TIMEOUT_NS)? {
            Completion::Presented => Ok(()),
            Completion::Failed(_) => Err(TransportError::Invalid),
            Completion::Pending => Err(TransportError::Timeout),
        }
    }

    fn set_ready(group: &Arc<ThreadGroup>, hwnd: u64, ready: bool) -> Result<(), TransportError> {
        let mut entries = super::super::GUI.lock();
        let entry = entries.iter_mut().find(|e| e.group.ptr_eq(&Arc::downgrade(group))).ok_or(TransportError::Unknown)?;
        entry.state.set_presentation_ready(window(hwnd).ok_or(TransportError::Invalid)?, ready).map_err(|_| TransportError::Unknown)
    }

    fn current_update(hwnd: u64) -> Result<Option<(Arc<ThreadGroup>, Snapshot)>, TransportError> {
        let cur = sched::live::current().ok_or(TransportError::Disconnected)?;
        if !cur.is_nt_personality() { return Err(TransportError::Invalid); }
        let group = Arc::clone(&cur.thread_group);
        let value = {
            let entries = super::super::GUI.lock();
            let entry = entries.iter().find(|e| e.group.ptr_eq(&Arc::downgrade(&group))).ok_or(TransportError::Unknown)?;
            update_snapshot(&entry.state, hwnd).map_err(|_| TransportError::Unknown)?
        };
        Ok(value.map(|value| (group, value)))
    }

    /// Invoke before WM_NCCREATE/WM_CREATE, outside GUI lock so callbacks can paint.
    /// Backend Create ACK precedes canonical readiness; rejection calls destruction.
    /// # C: O(windows + title) + bounded ACK wait; # Sleeps: yes
    pub(crate) fn publish_create_current(hwnd: u64, style: u32, exstyle: u32) -> Result<(), TransportError> {
        let (group, value) = current_snapshot(hwnd, style, exstyle)?;
        if value.ready { return Ok(()); }
        publish(&group, Opcode::Create, hwnd, value.create_payload(style, exstyle).ok_or(TransportError::Invalid)?)?;
        let result = set_ready(&group, hwnd, true)
            .and_then(|()| publish(&group, Opcode::Title, hwnd, value.title))
            .and_then(|()| publish(&group, Opcode::Visibility, hwnd, (value.visible as u32).to_le_bytes().to_vec()));
        if result.is_err() {
            let _ = set_ready(&group, hwnd, false);
            // A partially initialized XID is not a successful Windows creation.
            if publish(&group, Opcode::Destroy, hwnd, Vec::new()).is_err() { transport::disconnect(&group); }
        }
        result
    }

    /// Invoke after canonical visibility mutation and GUI unlock. # C: O(windows) + ACK; # Sleeps: yes
    pub(crate) fn publish_visibility_current(hwnd: u64) -> Result<(), TransportError> {
        let Some((group, value)) = current_update(hwnd)? else { return Ok(()); };
        publish(&group, Opcode::Visibility, hwnd, (value.visible as u32).to_le_bytes().to_vec())
    }
    /// Invoke after canonical text mutation and GUI unlock. # C: O(windows + title) + ACK; # Sleeps: yes
    pub(crate) fn publish_title_current(hwnd: u64) -> Result<(), TransportError> {
        let Some((group, value)) = current_update(hwnd)? else { return Ok(()); };
        publish(&group, Opcode::Title, hwnd, value.title)
    }
    /// Invoke only on application geometry mutations, never incoming Configure. # C: O(windows) + ACK; # Sleeps: yes
    pub(crate) fn publish_geometry_current(hwnd: u64) -> Result<(), TransportError> {
        let Some((group, value)) = current_update(hwnd)? else { return Ok(()); };
        publish(&group, Opcode::Geometry, hwnd, value.rect.encode_window().map_err(|_| TransportError::Invalid)?.to_vec())
    }
    /// Canonical positioning owns ordering; this only projects its admitted request.
    /// # C: O(windows) + ACK; # Sleeps: yes
    pub(crate) fn publish_position_current(hwnd: u64, insertion: Option<u64>, activate: bool) -> Result<(), TransportError> {
        let Some((group, _)) = current_update(hwnd)? else { return Ok(()); };
        let flags = if insertion.is_some() { wire::POSITION_ORDER } else { 0 }
            | if activate { wire::POSITION_ACTIVATE } else { 0 };
        let mut payload = insertion.unwrap_or(0).to_le_bytes().to_vec();
        payload.extend_from_slice(&flags.to_le_bytes()); payload.extend_from_slice(&0u32.to_le_bytes());
        publish(&group, Opcode::Position, hwnd, payload)
    }
    /// Cleanup list is captured from canonical destruction order before removal.
    /// HWND may already be gone; caller must not use this as an unvalidated syscall.
    /// # C: O(bindings) + ACK; # Sleeps: yes
    pub(crate) fn publish_destroy_current(hwnd: u64) -> Result<(), TransportError> {
        if window(hwnd).is_none() { return Err(TransportError::Invalid); }
        let cur = sched::live::current().ok_or(TransportError::Disconnected)?;
        if !cur.is_nt_personality() { return Err(TransportError::Invalid); }
        let _ = set_ready(&cur.thread_group, hwnd, false);
        publish(&cur.thread_group, Opcode::Destroy, hwnd, Vec::new())
    }

    /// Register with transport before binding. Process identity precedes HWND lookup.
    /// Wake executes after GUI unlock, including partial queue-full delivery.
    /// # C: O(processes + windows + payload); # Sleeps: no
    pub(crate) fn handle_event(group: &Arc<ThreadGroup>, record: &Record) -> bool {
        let (accepted, wait) = {
            let mut entries = super::super::GUI.lock();
            let Some(entry) = entries.iter_mut().find(|e| e.group.ptr_eq(&Arc::downgrade(group))) else { return false; };
            let accepted = apply_event(&mut entry.state, record, |state, id, x, y, buttons, wheel| {
                state.post_compositor_pointer(id, x, y, buttons, wheel).is_ok()
            });
            if accepted && record.header.opcode == Opcode::Focus { entry.foreground = entry.state.active_window().is_some(); }
            (accepted, Arc::clone(&entry.wait))
        };
        wait.wake_all(); accepted
    }
}

#[cfg(target_os = "oxide-kernel")]
pub(crate) use live::{handle_event, publish_create_current, publish_destroy_current,
    publish_geometry_current, publish_position_current, publish_title_current, publish_visibility_current};

#[cfg(test)]
#[path = "bridge/tests/events.rs"]
mod tests;
#[cfg(test)]
#[path = "bridge/tests/focus.rs"]
mod focus_tests;
