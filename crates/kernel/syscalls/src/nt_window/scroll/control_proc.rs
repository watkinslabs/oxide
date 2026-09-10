//! Native scrollbar procedure; KI-0885 retains the still-unimplemented messages.
use alloc::sync::Arc;
use ipc::win32_window::{WindowId, WindowRect, WM_PAINT, WM_SETCURSOR, WM_LBUTTONDOWN};
use ipc::win32_window::hardware::WM_LBUTTONDBLCLK;
use ipc::win32_window::{WM_KEYDOWN,WM_KEYUP};
use crate::nt_window::{GUI, position};
use super::proc_abi::*;
const STATUS_NOT_IMPLEMENTED: u64 = 0xc0000002;
const STATUS_INVALID_PARAMETER: u64 = 0xc000000d;
const STATUS_PENDING: u64 = 0x103;
const MOVE_FLAGS: u32 = 0x0004 | 0x0008 | 0x0010;
const CREATE_PREFIX_BYTES: usize = 52;

/// None delegates to the existing default-procedure path. Missing control
/// messages remain explicit failures until their owned continuations are wired.
/// # C: O(windows + selected operation); # Sleeps: yes
pub(crate) fn for_current(hwnd: u64, message: u32, wparam: u64, lparam: u64) -> Option<u64> {
    let Some(cur) = sched::live::current().filter(|cur| cur.is_nt_personality()) else { return Some(0); };
    let Some(window) = u32::try_from(hwnd).ok().and_then(WindowId::from_raw) else { return Some(0); };
    let (style, ex_style, parent) = {
        let entries = GUI.lock();
        let Some(entry) = entries.iter().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group))) else { return Some(0); };
        let Some(record) = entry.state.get(window) else { return Some(0); };
        (record.style, record.ex_style, entry.state.relative_parent(window))
    };
    match message {
        WM_CREATE => Some(create(hwnd, lparam)),
        WM_PAINT => Some(super::control_paint::for_current(hwnd, wparam)),
        WM_ERASEBKGND => Some(1),
        WM_GETDLGCODE => Some(DLGC_WANTARROWS),
        WM_ENABLE => Some(super::control_refresh::enabled(hwnd, wparam != 0)),
        WM_KEYDOWN => Some(super::control_input::key_down(hwnd, parent, style, wparam, lparam)),
        WM_KEYUP => Some(super::control_input::key_up(hwnd)),
        SBM_GETPOS => Some(super::control_query::position(hwnd)),
        SBM_GETRANGE => Some(super::control_query::range(hwnd, wparam, lparam)),
        SBM_GETSCROLLINFO => Some(super::live::get_scroll_info_for_current(hwnd, ipc::win32_window::SB_CTL, lparam)),
        WM_SETCURSOR if style & SBS_SIZEGRIP == 0 => None,
        WM_SETCURSOR => Some(super::control_input::sizegrip_cursor(ex_style)),
        WM_LBUTTONDOWN | WM_LBUTTONDBLCLK if style & SBS_SIZEGRIP != 0 =>
            Some(super::control_input::sizegrip_click(parent, ex_style, lparam)),
        message if RESERVED_MESSAGES.contains(&message) => Some(0),
        message if PENDING_MESSAGES.contains(&message) => { trace_missing(hwnd, message); Some(STATUS_NOT_IMPLEMENTED) }
        _ => None,
    }
}
fn create(hwnd: u64, pointer: u64) -> u64 {
    let mut bytes = [0; CREATE_PREFIX_BYTES];
    if uaccess::copy_from_user(&mut bytes, pointer).is_err() { return STATUS_INVALID_PARAMETER; }
    let word = |offset| i32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
    let (x, y, width, height, style) = (word(44), word(40), word(36), word(32), word(48) as u32);
    let Some(right) = x.checked_add(width) else { return STATUS_INVALID_PARAMETER; };
    let Some(bottom) = y.checked_add(height) else { return STATUS_INVALID_PARAMETER; };
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    let Some(window) = WindowId::from_raw(hwnd as u32) else { return STATUS_INVALID_PARAMETER; };
    {
        let mut entries = GUI.lock();
        let Some(entry) = entries.iter_mut().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group))) else { return STATUS_INVALID_PARAMETER; };
        if entry.state.initialize_scroll_control_style(window, style).is_err() { return STATUS_INVALID_PARAMETER; }
    }
    let Some(cx) = ipc::win32_gdi::system_metric_default(SM_CXVSCROLL).and_then(|value| value.checked_add(1)) else { return STATUS_INVALID_PARAMETER; };
    let Some(cy) = ipc::win32_gdi::system_metric_default(SM_CYHSCROLL).and_then(|value| value.checked_add(1)) else { return STATUS_INVALID_PARAMETER; };
    let Some(rect) = aligned_creation(WindowRect { left: x, top: y, right, bottom }, style, cx, cy) else { return 0; };
    let request = crate::nt_wine_window::position::Request { hwnd, rect, order: None, visible: None, flags: MOVE_FLAGS };
    match position::position_apply_resumable_for_current(request, Some(position::Continuation { token: 0, resume: created })) {
        position::Outcome::Pending => STATUS_PENDING,
        _ => 0,
    }
}
fn created(_: u64, _: position::Outcome) -> u64 { 0 }
fn trace_missing(hwnd: u64, message: u32) {
    use core::sync::atomic::{AtomicU32, Ordering};
    static LEFT: AtomicU32 = AtomicU32::new(16);
    if LEFT.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |left| left.checked_sub(1)).is_err() { return; }
    klog::write_raw(b"[WINDOWS-SCROLL-PROC-UNHANDLED] hwnd="); klog::write_hex_u64(hwnd);
    klog::write_raw(b" msg="); klog::write_hex_u64(message as u64); klog::write_raw(b"
");
}
