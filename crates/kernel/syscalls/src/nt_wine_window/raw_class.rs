//! Raw Wine class and window entry points.

use super::*;

fn raw_arg(args: SyscallArgs, index: usize) -> Option<u64> {
    match index {
        0 => Some(args.a0), 1 => Some(args.a1), 2 => Some(args.a2),
        3 => Some(args.a3), 4 => Some(args.a4), 5 => Some(args.a5),
        _ => crate::nt_dispatch::stack_argument(index),
    }
}

/// Register a raw Wine WNDCLASSEXW through the process-local canonical owner.
/// # C: O(N_process_gui_states + N_classes) plus bounded usercopy
pub(super) fn register_class(args: SyscallArgs) -> u64 {
    if args.a0 == 0 || uaccess::get_user_u32(args.a0).ok() != Some(80) { return 0; }
    let Some(name) = read_unicode_string(args.a1) else { return 0; };
    let Some(wndproc_address) = args.a0.checked_add(8) else { return 0; };
    let Some(wndproc) = uaccess::get_user_u64(wndproc_address).ok() else { return 0; };
    crate::nt_window::register_class_for_current(&name, wndproc).unwrap_or(0)
}

/// Create a raw Wine window after resolving its class in the canonical owner.
/// # C: O(N_process_gui_states + N_classes + N_windows) plus bounded usercopy
pub(super) fn create_window(args: SyscallArgs) -> u64 {
    let Some(version) = raw_arg(args, 2) else { return STATUS_INVALID_PARAMETER; };
    let _ = version;
    let Some(title_pointer) = raw_arg(args, 3) else { return STATUS_INVALID_PARAMETER; };
    let Some(style) = raw_arg(args, 4) else { return STATUS_INVALID_PARAMETER; };
    let Some(x) = raw_arg(args, 5) else { return STATUS_INVALID_PARAMETER; };
    let Some(y) = raw_arg(args, 6) else { return STATUS_INVALID_PARAMETER; };
    let Some(width) = raw_arg(args, 7) else { return STATUS_INVALID_PARAMETER; };
    let Some(height) = raw_arg(args, 8) else { return STATUS_INVALID_PARAMETER; };
    let Some(parent) = raw_arg(args, 9) else { return STATUS_INVALID_PARAMETER; };
    let Some(menu) = raw_arg(args, 10) else { return STATUS_INVALID_PARAMETER; };
    let _ = style;
    let Some(title) = read_optional_unicode_string(title_pointer) else { return STATUS_INVALID_PARAMETER; };
    let hwnd = if args.a1 <= u16::MAX as u64 {
        crate::nt_window::create_class_window_by_atom_for_current(args.a1 as u16, parent)
    } else {
        let Some(class) = read_unicode_string(args.a1) else { return STATUS_INVALID_PARAMETER; };
        crate::nt_window::create_class_window_for_current(&class, parent)
    }.unwrap_or(STATUS_INVALID_PARAMETER);
    if hwnd == STATUS_INVALID_PARAMETER || hwnd == 0 { return hwnd; }
    if menu > u32::MAX as u64 || (menu != 0 && crate::nt_window::set_window_menu_for_current(hwnd, Some(menu as u32)).is_err()) {
        let _ = destroy_window(hwnd);
        return STATUS_INVALID_PARAMETER;
    }
    if crate::nt_window::set_window_text_for_current(hwnd, &title).is_err() {
        let _ = destroy_window(hwnd);
        return STATUS_INVALID_PARAMETER;
    }
    let right = (x as i32).checked_add(width as i32);
    let bottom = (y as i32).checked_add(height as i32);
    match (right, bottom) {
        (Some(right), Some(bottom)) => {
            let status = crate::nt_window::dispatch(NtCall { service: NtService::SetWindowRectValues, args: SyscallArgs { a0: hwnd, a1: x, a2: y, a3: right as u64, a4: bottom as u64, a5: 0 } }).unwrap_or(STATUS_INVALID_PARAMETER);
            if status == STATUS_SUCCESS { hwnd } else { let _ = destroy_window(hwnd); STATUS_INVALID_PARAMETER }
        }
        _ => { let _ = destroy_window(hwnd); STATUS_INVALID_PARAMETER }
    }
}

fn destroy_window(hwnd: u64) -> u64 {
    crate::nt_window::dispatch(NtCall { service: NtService::DestroyWindow, args: SyscallArgs { a0: hwnd, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 } }).unwrap_or(STATUS_INVALID_PARAMETER)
}
