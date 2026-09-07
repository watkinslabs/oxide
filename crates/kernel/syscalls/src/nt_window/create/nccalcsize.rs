//! The nonclient size calculation one window runs while it is being created.
//! The reference sends it between `WM_NCCREATE` and `WM_CREATE`, with the
//! window's own rectangle, and adopts the reply as the client rectangle: that
//! is where a menu bar takes its band off the top of the client area.
use super::super::*;
use ipc::win32_window::{nonclient_create, WindowId, WindowRect};

/// `WM_NCCALCSIZE` computing a client rectangle from scratch carries FALSE and
/// a bare rectangle, not the three-rectangle parameter block a reposition uses.
const NCCALCSIZE_CREATE_WPARAM: u64 = 0;
const WM_NCCALCSIZE: u64 = 0x0083;
const RECT_BYTES: usize = 16;

fn encode(rect: WindowRect) -> [u8; RECT_BYTES] {
    let mut out = [0u8; RECT_BYTES];
    for (index, value) in [rect.left, rect.top, rect.right, rect.bottom].iter().enumerate() {
        out[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
    out
}

fn decode(bytes: [u8; RECT_BYTES]) -> WindowRect {
    let value = |index: usize| i32::from_le_bytes(bytes[index * 4..index * 4 + 4].try_into().unwrap());
    WindowRect { left: value(0), top: value(1), right: value(2), bottom: value(3) }
}

/// The window rectangle one pending creation is calculating from. # C: O(processes + windows)
fn window_rect_for_current(hwnd: u64) -> Option<WindowRect> {
    let cur = sched::live::current()?;
    let window = WindowId::from_raw(u32::try_from(hwnd).ok()?)?;
    let entries = GUI.lock();
    entries.iter().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))?.state.rect(window)
}

/// Begin the creation-time nonclient calculation. Absent means this window
/// runs none and keeps a client area equal to its window rectangle.
/// # C: O(processes + windows); # Sleeps: yes
pub(super) fn begin(hwnd: u64, wndproc: u64, token: u64) -> Option<(u64, u64)> {
    let window = window_rect_for_current(hwnd)?;
    let handed = nonclient_create::creation_nccalcsize(wndproc, window)?;
    let completion = sched::nt_callback::Completion { kind: CALLBACK_CREATE_NCCALCSIZE, argument: token };
    match crate::nt_rtl::begin_wndproc_payload_callback(hwnd, WM_NCCALCSIZE, NCCALCSIZE_CREATE_WPARAM, wndproc, &encode(handed), &[], completion) {
        Ok(pointer) => Some((STATUS_PENDING, pointer)),
        Err(_) => None,
    }
}

/// Adopt the reply as the window's client rectangle. # C: O(processes + windows)
pub(super) fn apply_for_current(hwnd: u64, pointer: u64) {
    let Some(window) = window_rect_for_current(hwnd) else { return; };
    let mut bytes = [0u8; RECT_BYTES];
    if pointer == 0 || uaccess::copy_from_user(&mut bytes, pointer).is_err() { return; }
    let client = nonclient_create::creation_client_rect(window, decode(bytes));
    let Some(cur) = sched::live::current() else { return; };
    let Some(id) = u32::try_from(hwnd).ok().and_then(WindowId::from_raw) else { return; };
    let mut entries = GUI.lock();
    let Some(entry) = entries.iter_mut().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group))) else { return; };
    let _ = entry.state.set_client_rect(id, client);
}
