//! Raw Wine callback and message-loop entry points.

use super::*;
/// Message-call traces one boot emits before the marker goes quiet.
const MESSAGE_CALL_TRACES: u32 = 64;

/// Deliver one MSG through the registered window procedure.
/// # C: O(1) plus bounded usercopy
pub(super) fn dispatch_message(pointer: u64) -> u64 {
    let Ok(hwnd) = uaccess::get_user_u64(pointer) else { return STATUS_INVALID_PARAMETER; };
    let Some(message_address) = message_field(pointer, 8) else { return STATUS_INVALID_PARAMETER; };
    let Some(wparam_address) = message_field(pointer, 16) else { return STATUS_INVALID_PARAMETER; };
    let Some(lparam_address) = message_field(pointer, 24) else { return STATUS_INVALID_PARAMETER; };
    let Ok(message) = uaccess::get_user_u32(message_address) else { return STATUS_INVALID_PARAMETER; };
    let Ok(wparam) = uaccess::get_user_u64(wparam_address) else { return STATUS_INVALID_PARAMETER; };
    let Ok(lparam) = uaccess::get_user_u64(lparam_address) else { return STATUS_INVALID_PARAMETER; };
    // Every DispatchMessage, not only the ones that fail. A message retrieved
    // by the loop but never dispatched leaves no trace at all otherwise, and
    // that is indistinguishable from one dispatched and ignored.
    klog::write_raw(b"[WINDOWS-DISPATCH] hwnd=");
    klog::write_hex_u64(hwnd);
    klog::write_raw(b" msg=");
    klog::write_hex_u64(message as u64);
    klog::write_raw(b"\n");
    if !ipc::win32_window::dispatches_to_window_proc(message) { return STATUS_SUCCESS; }
    if message == WM_TIMER as u32 && lparam != 0 {
        let tick_ms = timekeeper::monotonic_ns().saturating_div(1_000_000);
        return crate::nt_rtl::begin_wndproc_callback(hwnd, message as u64, wparam, tick_ms, lparam);
    }
    let Some(wndproc) = crate::nt_window::window_wndproc_for_current(hwnd) else {
        // Without a window procedure the message is dropped and, if it was
        // WM_PAINT, its damage is never validated and it repeats forever.
        klog::write_raw(b"[WINDOWS-DISPATCH-DROP] reason=no-wndproc hwnd=");
        klog::write_hex_u64(hwnd);
        klog::write_raw(b" msg=");
        klog::write_hex_u64(message as u64);
        klog::write_raw(b"\n");
        return STATUS_INVALID_PARAMETER;
    };
    let status = crate::nt_rtl::begin_wndproc_callback(hwnd, message as u64, wparam, lparam, wndproc);
    // STATUS_PENDING means the callback was armed; anything else dropped it.
    if status != 0x0000_0103 {
        klog::write_raw(b"[WINDOWS-DISPATCH-DROP] reason=callback-refused hwnd=");
        klog::write_hex_u64(hwnd);
        klog::write_raw(b" msg=");
        klog::write_hex_u64(message as u64);
        klog::write_raw(b" status=");
        klog::write_hex_u64(status);
        klog::write_raw(b"\n");
    }
    status
}

/// Which callback type DispatchMessage arrives with decides whether the window
/// procedure is ever entered. Bounded: every console line costs milliseconds of
/// serial time, and an unbounded per-message trace starves the pump it watches.
fn trace_message_call(hwnd: u64, message: u64, callback_type: u64) {
    use core::sync::atomic::{AtomicU32, Ordering};
    static BUDGET: AtomicU32 = AtomicU32::new(0);
    if BUDGET.fetch_add(1, Ordering::Relaxed) >= MESSAGE_CALL_TRACES { return; }
    klog::write_raw(b"[WINDOWS-MESSAGE-CALL] hwnd="); klog::write_hex_u64(hwnd);
    klog::write_raw(b" msg="); klog::write_hex_u64(message);
    klog::write_raw(b" type="); klog::write_hex_u64(callback_type);
    klog::write_raw(b"\n");
}

/// Execute a raw NtUserMessageCall using its Wine callback selector.
/// # C: O(1) plus bounded usercopy
pub(super) fn message_call(a: &[u64; 17]) -> u64 {
    let Some((callback_type, ansi)) = crate::nt_message_call_abi::tail(a[5], |index| a.get(index).copied()) else { return STATUS_INVALID_PARAMETER; };
    let mut callback_type = callback_type as u64;
    trace_message_call(a[0], a[1], callback_type);
    let hwnd = a[0];
    let message = a[1];
    let wparam = a[2];
    let lparam = a[3];
    if let Some(result) = super::message_send::prepare_current(hwnd, message as u32, wparam, lparam, a[4], ansi, callback_type) { return result; }
    if callback_type == crate::nt_message_params::SEND_MESSAGE { return crate::nt_window::send::send_for_current(hwnd, message as u32, wparam, lparam); }
    if callback_type == WINE_POPUP_MENU_WND_PROC {
        return crate::nt_window::menu_raw::popup_menu_window_proc(hwnd, message as u32, wparam, lparam);
    }
    if callback_type == crate::nt_window::scroll::proc_abi::WNDPROC_SELECTOR {
        if let Some(result) = crate::nt_window::scroll::control_proc::for_current(hwnd, message as u32, wparam, lparam) { return result; }
        callback_type = WINE_DEF_WINDOW_PROC;
    }
    if callback_type == WINE_DEF_WINDOW_PROC {
        if message == WM_NCCREATE { return (lparam != 0) as u64; }
        if message == WM_NCDESTROY { return STATUS_SUCCESS; }
        // WM_NCHITTEST is not answered here: the canonical default window
        // procedure answers it, and it is the only one that knows about the
        // menu bar's band of the nonclient area.
        if message == WM_NCACTIVATE { return 1; }
        if message == WM_SETTEXT {
            return win_bool(native(NtService::SetWindowText, SyscallArgs { a0: hwnd, a1: lparam, a2: 0, a3: 0, a4: 0, a5: 0 }));
        }
        if message == WM_GETTEXT {
            return native(NtService::GetWindowText, SyscallArgs { a0: hwnd, a1: lparam, a2: wparam, a3: 0, a4: 0, a5: 0 });
        }
        if message == WM_GETTEXTLENGTH { return crate::nt_window::window_text_length_for_current(hwnd).unwrap_or(STATUS_INVALID_PARAMETER); }
        return native(NtService::DefaultWindowProc, SyscallArgs { a0: hwnd, a1: message, a2: wparam, a3: lparam, a4: 0, a5: 0 });
    }
    if callback_type != WINE_CALL_WINDOW_PROC { return STATUS_NOT_IMPLEMENTED; }
    super::initialize_window_proc_params(a[4], hwnd, message, wparam, lparam,
                                         ansi as u64)
}

fn native(service: NtService, args: SyscallArgs) -> u64 {
    crate::nt_window::dispatch(NtCall { service, args }).unwrap_or(STATUS_INVALID_PARAMETER)
}
