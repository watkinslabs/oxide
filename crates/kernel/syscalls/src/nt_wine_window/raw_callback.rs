//! Raw Wine callback and message-loop entry points.

use super::*;

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
    if !ipc::win32_window::dispatches_to_window_proc(message) { return STATUS_SUCCESS; }
    if message == WM_TIMER as u32 && lparam != 0 {
        let tick_ms = timekeeper::monotonic_ns().saturating_div(1_000_000);
        return crate::nt_rtl::begin_wndproc_callback(hwnd, message as u64, wparam, tick_ms, lparam);
    }
    let Some(wndproc) = crate::nt_window::window_wndproc_for_current(hwnd) else { return STATUS_INVALID_PARAMETER; };
    crate::nt_rtl::begin_wndproc_callback(hwnd, message as u64, wparam, lparam, wndproc)
}

/// Execute a raw NtUserMessageCall using its Wine callback selector.
/// # C: O(1) plus bounded usercopy
pub(super) fn message_call(args: SyscallArgs) -> u64 {
    let Some((callback_type, ansi)) = crate::nt_message_call_abi::tail(args.a5, crate::nt_dispatch::stack_argument) else { return STATUS_INVALID_PARAMETER; };
    let callback_type = callback_type as u64;
    let hwnd = args.a0;
    let message = args.a1;
    let wparam = args.a2;
    let lparam = args.a3;
    if let Some(result) = super::message_send::prepare_current(hwnd, message as u32, wparam, lparam, args.a4, ansi, callback_type) { return result; }
    if callback_type == crate::nt_message_params::SEND_MESSAGE { return crate::nt_window::send::send_for_current(hwnd, message as u32, wparam, lparam); }
    if callback_type == WINE_DEF_WINDOW_PROC {
        if message == WM_NCCREATE { return (lparam != 0) as u64; }
        if message == WM_NCDESTROY { return STATUS_SUCCESS; }
        if message == WM_NCHITTEST {
            if hwnd > u32::MAX as u64 { return STATUS_INVALID_PARAMETER; }
            let Some((rect, _)) = crate::nt_window::window_rect_for_current(hwnd as u32) else { return STATUS_INVALID_PARAMETER; };
            return match ipc::win32_window::default_window_proc_for_rect(WM_NCHITTEST as u32, rect, lparam as i64) {
                ipc::win32_window::DefaultWindowResult::Return(value) => value as u64,
                ipc::win32_window::DefaultWindowResult::RequestDestroy => STATUS_SUCCESS,
            };
        }
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
    super::initialize_window_proc_params(args.a4, hwnd, message, wparam, lparam,
                                         ansi as u64)
}

fn native(service: NtService, args: SyscallArgs) -> u64 {
    crate::nt_window::dispatch(NtCall { service, args }).unwrap_or(STATUS_INVALID_PARAMETER)
}
