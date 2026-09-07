//! Window-station clipboard access. The store is the canonical owner; this
//! module resolves the caller, validates windows against the real window tree
//! and delivers the notifications a transaction owes.
use super::super::*;
use ipc::win32_window::{ClipboardError, ClipboardNotify, WinMessage, WindowId};

const WM_DESTROYCLIPBOARD: u32 = 0x0307;
const WM_DRAWCLIPBOARD: u32 = 0x0308;
const WM_CHANGECBCHAIN: u32 = 0x030d;
const WM_CLIPBOARDUPDATE: u32 = 0x031d;

fn current_thread() -> Option<u64> {
    sched::live::current().filter(|task| task.is_nt_personality()).map(|task| task.tid as u64)
}

/// Resolve a caller-supplied HWND against the real window tree. Zero is the
/// absent window; anything else must name a live window. # C: O(N_processes + N_windows)
fn window(hwnd: u64) -> Result<Option<WindowId>, ClipboardError> {
    if hwnd == 0 { return Ok(None); }
    let id = valid_window(hwnd).ok_or(ClipboardError::InvalidParameter)?;
    if !access::window_exists(id) { return Err(ClipboardError::InvalidParameter); }
    Ok(Some(id))
}

fn post(id: WindowId, message: u32, wparam: u64, lparam: i64) {
    let _ = access::with_window_mut(id, |state| state.post_to_window(id, WinMessage {
        hwnd: Some(id), message, wparam, lparam }));
}

/// Deliver what a close or release transaction owes: the listeners learn the
/// contents changed and the viewer redraws. # C: O(N_listeners * N_windows)
fn deliver(notify: ClipboardNotify) {
    let listeners = CLIPBOARD.lock().listeners().to_vec();
    for listener in listeners { post(listener, WM_CLIPBOARDUPDATE, 0, 0); }
    if let Some(viewer) = notify.viewer {
        post(viewer, WM_DRAWCLIPBOARD, notify.owner.map_or(0, |owner| owner.raw() as u64), 0);
    }
}

/// Admit one open request against the shared window-station owner.
/// # C: O(N_processes + N_windows)
pub fn open_clipboard_for_current(hwnd: u64) -> bool {
    let Some(thread) = current_thread() else { return false; };
    let Ok(window) = window(hwnd) else { return false; };
    CLIPBOARD.lock().open(thread, window).is_ok()
}

/// Close the transaction and notify the viewer when the contents changed.
/// # C: O(N_listeners * N_windows)
pub fn close_clipboard_for_current() -> bool {
    let Some(thread) = current_thread() else { return false; };
    let notify = { let mut clipboard = CLIPBOARD.lock(); clipboard.close(thread) };
    let Ok(notify) = notify else { return false; };
    deliver(notify);
    true
}

/// Empty the clipboard, telling the previous owner first. # C: O(N_processes + N_windows)
pub fn empty_clipboard_for_current() -> bool {
    let Some(thread) = current_thread() else { return false; };
    if let Some(owner) = CLIPBOARD.lock().owner() { post(owner, WM_DESTROYCLIPBOARD, 0, 0); }
    CLIPBOARD.lock().empty(thread).is_ok()
}

/// Count of offered formats. # C: O(1)
pub fn clipboard_format_count() -> u64 { CLIPBOARD.lock().count() as u64 }

/// Whether one format is offered. # C: O(N_formats)
pub fn clipboard_format_available(format: u32) -> bool { CLIPBOARD.lock().is_available(format) }

/// Every offered format identifier. # C: O(N_formats)
pub fn clipboard_format_ids() -> alloc::vec::Vec<u32> { CLIPBOARD.lock().format_ids() }

/// Highest-priority available format, zero for an empty clipboard and -1 when
/// none of the list is offered. # C: O(N_list * N_formats)
pub fn clipboard_priority_format(list: &[u32]) -> i32 { CLIPBOARD.lock().priority_format(list) }

/// Walk the offer order. # C: O(N_formats)
pub fn clipboard_enum_format(previous: u32) -> Option<u32> {
    let thread = current_thread()?;
    CLIPBOARD.lock().enum_formats(thread, previous).ok()
}

/// Store one format's bytes, answering the stamped sequence number.
/// # C: O(N_formats + N_bytes)
pub fn clipboard_set_data(format: u32, data: Option<&[u8]>, lcid: u32) -> Result<u32, ClipboardError> {
    CLIPBOARD.lock().set_data(format, data, lcid)
}

/// Copy one format's bytes out, answering the stored size and sequence number.
/// A delay-rendered format answers no bytes. # C: O(N_formats + N_bytes)
pub fn clipboard_data(format: u32, out: &mut alloc::vec::Vec<u8>) -> Result<(u32, u32, usize), ClipboardError> {
    let thread = current_thread().ok_or(ClipboardError::NotOpen)?;
    let clipboard = CLIPBOARD.lock();
    let stored = clipboard.data(thread, format)?;
    let bytes = stored.data.as_deref().unwrap_or(&[]);
    out.try_reserve_exact(bytes.len()).map_err(|_| ClipboardError::NoMemory)?;
    out.extend_from_slice(bytes);
    Ok((stored.from, stored.seqno, bytes.len()))
}

/// Window that owns the current contents. # C: O(1)
pub fn clipboard_owner() -> u64 { CLIPBOARD.lock().owner().map_or(0, |id| id.raw() as u64) }
/// Window that holds the clipboard open. # C: O(1)
pub fn clipboard_open_window() -> u64 { CLIPBOARD.lock().open_window().map_or(0, |id| id.raw() as u64) }
/// First viewer in the chain. # C: O(1)
pub fn clipboard_viewer() -> u64 { CLIPBOARD.lock().viewer().map_or(0, |id| id.raw() as u64) }
/// Change sequence number. # C: O(1)
pub fn clipboard_sequence() -> u64 { CLIPBOARD.lock().sequence() as u64 }

/// Install a viewer and hand it the first redraw. # C: O(N_processes + N_windows)
pub fn clipboard_set_viewer(hwnd: u64) -> Result<u64, ClipboardError> {
    let viewer = window(hwnd)?;
    let (previous, owner) = CLIPBOARD.lock().set_viewer(viewer, None)?;
    if let Some(viewer) = viewer {
        post(viewer, WM_DRAWCLIPBOARD, owner.map_or(0, |owner| owner.raw() as u64), 0);
    }
    Ok(previous.map_or(0, |id| id.raw() as u64))
}

/// Remove one window from the viewer chain. A caller whose belief about the
/// current viewer is stale is asked to walk the chain by message instead.
/// # C: O(N_processes + N_windows)
pub fn clipboard_change_chain(hwnd: u64, next: u64) -> Result<bool, ClipboardError> {
    let Some(removed) = window(hwnd)? else { return Ok(false) };
    let next = window(next)?;
    match CLIPBOARD.lock().set_viewer(next, Some(removed)) {
        Ok(_) => Ok(true),
        Err(ClipboardError::Pending) => {
            if let Some(viewer) = CLIPBOARD.lock().viewer() {
                post(viewer, WM_CHANGECBCHAIN, removed.raw() as u64, next.map_or(0, |id| id.raw() as i64));
            }
            Ok(true)
        }
        Err(error) => Err(error),
    }
}

/// Register or remove one format listener. # C: O(N_listeners + N_windows)
pub fn clipboard_listener(hwnd: u64, add: bool) -> Result<(), ClipboardError> {
    let id = window(hwnd)?.ok_or(ClipboardError::InvalidParameter)?;
    let mut clipboard = CLIPBOARD.lock();
    if add { clipboard.add_listener(id) } else { clipboard.remove_listener(id) }
}

/// Retire every clipboard reference to a destroyed window. # C: O(N_formats² + N_listeners)
pub fn clipboard_forget_window(id: WindowId) {
    let notify = { let mut clipboard = CLIPBOARD.lock(); clipboard.cleanup_window(id) };
    if notify.viewer.is_some() { deliver(notify); }
}
