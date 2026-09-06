//! Raw Wine class and window entry points.

use super::*;
const WS_CHILD: u32 = 0x4000_0000;
const WS_POPUP: u32 = 0x8000_0000;
const CLASS_STYLE_OFFSET: u64 = 4;
const CLASS_BACKGROUND_OFFSET: u64 = 48;

#[path = "create_abi.rs"]
mod create_abi;

macro_rules! wine_window_diag {
    ($($body:tt)*) => {
        { $($body)* }
    };
}

fn raw_arg(args: SyscallArgs, index: usize) -> Option<u64> {
    let value = match index {
        0 => Some(args.a0), 1 => Some(args.a1), 2 => Some(args.a2),
        3 => Some(args.a3), 4 => Some(args.a4), 5 => Some(args.a5),
        _ => crate::nt_dispatch::stack_argument(index),
    }?;
    Some(create_abi::argument(index, value))
}

/// Register a raw Wine WNDCLASSEXW through the process-local canonical owner.
/// # C: O(N_process_gui_states + N_classes) plus bounded usercopy
pub(super) fn register_class(args: SyscallArgs) -> u64 {
    if args.a0 == 0 || uaccess::get_user_u32(args.a0).ok() != Some(80) {
        wine_window_diag! { klog::write_raw(b"[WINDOWS-PE-WINE-CLASS] reject-wndclass ptr="); klog::write_hex_u64(args.a0); klog::write_raw(b"\n"); }
        return 0;
    }
    let Some(name) = read_unicode_string(args.a1) else {
        wine_window_diag! { klog::write_raw(b"[WINDOWS-PE-WINE-CLASS] reject-name ptr="); klog::write_hex_u64(args.a1); klog::write_raw(b"\n"); }
        return 0;
    };
    let Some(wndproc_address) = args.a0.checked_add(8) else { return 0; };
    let Some(wndproc) = uaccess::get_user_u64(wndproc_address).ok() else { return 0; };
    let Some(extra_address) = args.a0.checked_add(20) else { return 0; };
    let Ok(extra) = uaccess::get_user_u32(extra_address) else { return 0; };
    let Some(style_address) = args.a0.checked_add(CLASS_STYLE_OFFSET) else { return 0; };
    let Ok(style) = uaccess::get_user_u32(style_address) else { return 0; };
    let Some(background_address) = args.a0.checked_add(CLASS_BACKGROUND_OFFSET) else { return 0; };
    let Ok(background) = uaccess::get_user_u64(background_address) else { return 0; };
    let result = crate::nt_window::register_class_with_background_for_current(&name, wndproc, extra as i32, args.a5 as u32 == 0, style, background).unwrap_or(0);
    wine_window_diag! { klog::write_raw(b"[WINDOWS-PE-WINE-CLASS] result="); klog::write_hex_u64(result); klog::write_raw(b" wndproc="); klog::write_hex_u64(wndproc); klog::write_raw(b"\n"); }
    result
}

/// Create a raw Wine window after resolving its class in the canonical owner.
/// # C: O(N_process_gui_states + N_classes + N_windows) plus bounded usercopy
pub(super) fn create_window(args: SyscallArgs) -> u64 {
    create_window_with(args, |index| raw_arg(args, index))
}

/// Descriptor and raw entries share the same creation transaction.
/// # C: same as create_window
pub(super) fn create_window_descriptor(values: &[u64; 17]) -> u64 {
    let args = SyscallArgs { a0: values[0], a1: values[1], a2: values[2], a3: values[3], a4: values[4], a5: values[5] };
    create_window_with(args, |index| values.get(index).copied().map(|value| create_abi::argument(index, value)))
}

fn create_window_with(args: SyscallArgs, read_arg: impl Fn(usize) -> Option<u64>) -> u64 {
    // Creating a window resolves the desktop window first, and that is where
    // the reference registers the builtin classes; a control class named by
    // this very creation must already exist.
    super::builtin_classes::kernel::ensure_registered();
    // HWND failures are NULL; backend statuses never share the handle channel.
    klog::write_raw(b"[WINDOWS-PE-WINE-CREATE] a0="); klog::write_hex_u64(args.a0);
    klog::write_raw(b" a1="); klog::write_hex_u64(args.a1);
    klog::write_raw(b" a2="); klog::write_hex_u64(args.a2);
    klog::write_raw(b" a3="); klog::write_hex_u64(args.a3);
    klog::write_raw(b" a4="); klog::write_hex_u64(args.a4);
    klog::write_raw(b" a5="); klog::write_hex_u64(args.a5); klog::write_raw(b"\n");
    for index in 4..17 {
        klog::write_raw(b"[WINDOWS-PE-WINE-CREATE-ARG] i=");
        klog::write_hex_u64(index as u64); klog::write_raw(b" v=");
        match read_arg(index) {
            Some(value) => klog::write_hex_u64(value),
            None => klog::write_raw(b"<fault>"),
        }
        klog::write_raw(b"\n");
    }
    let Some(version) = read_arg(2) else { klog::write_raw(b"[WINDOWS-PE-WINE-CREATE] reject=version\n"); return 0; };
    let _ = version;
    let Some(title_pointer) = read_arg(3) else { klog::write_raw(b"[WINDOWS-PE-WINE-CREATE] reject=title-arg\n"); return 0; };
    let Some(style) = read_arg(4) else { klog::write_raw(b"[WINDOWS-PE-WINE-CREATE] reject=style\n"); return 0; };
    let Some(x) = read_arg(5) else { klog::write_raw(b"[WINDOWS-PE-WINE-CREATE] reject=x\n"); return 0; };
    let Some(y) = read_arg(6) else { klog::write_raw(b"[WINDOWS-PE-WINE-CREATE] reject=y\n"); return 0; };
    let Some(width) = read_arg(7) else { klog::write_raw(b"[WINDOWS-PE-WINE-CREATE] reject=width\n"); return 0; };
    let Some(height) = read_arg(8) else { klog::write_raw(b"[WINDOWS-PE-WINE-CREATE] reject=height\n"); return 0; };
    let Some(parent) = read_arg(9) else { klog::write_raw(b"[WINDOWS-PE-WINE-CREATE] reject=parent\n"); return 0; };
    let Some(menu) = read_arg(10) else { klog::write_raw(b"[WINDOWS-PE-WINE-CREATE] reject=menu\n"); return 0; };
    let (Some(class_instance), Some(create_params), Some(instance), Some(class_pointer)) =
        (read_arg(11), read_arg(12), read_arg(14), read_arg(15)) else { return 0; };
    let coordinates = geometry::Coordinates { x: x as i32, y: y as i32,
        width: width as i32, height: height as i32 };
    let (coordinates, _show_command) = match geometry::fix(style as u32, coordinates, create_context::defaults) {
        Ok(placement) => placement,
        Err(geometry::Error::MissingWorkArea) => {
            klog::write_raw(b"[WINDOWS-PE-WINE-CREATE] reject=missing-work-area\n"); return 0;
        }
        Err(geometry::Error::Arithmetic) => {
            klog::write_raw(b"[WINDOWS-PE-WINE-CREATE] reject=default-arithmetic\n"); return 0;
        }
    };
    let Some(title) = read_optional_unicode_string(title_pointer) else {
        klog::write_raw(b"[WINDOWS-PE-WINE-CREATE] reject-title-pointer ptr=");
        klog::write_hex_u64(title_pointer); klog::write_raw(b"\n");
        return 0;
    };
    let title_buffer = if title_pointer == 0 { 0 } else {
        let Some(address) = title_pointer.checked_add(8) else { return 0; };
        let Ok(buffer) = uaccess::get_user_u64(address) else { return 0; };
        buffer
    };
    let child = style as u32 & (WS_CHILD | WS_POPUP) == WS_CHILD;
    let child_parent = if child { parent } else { 0 };
    let hwnd = if args.a1 <= u16::MAX as u64 {
        crate::nt_window::create_class_window_by_atom_for_current(args.a1 as u16, child_parent)
    } else {
        let Some(class) = read_unicode_string(args.a1) else {
            klog::write_raw(b"[WINDOWS-PE-WINE-CREATE] reject=class-pointer ptr=");
            klog::write_hex_u64(args.a1); klog::write_raw(b"\n");
            return 0;
        };
        crate::nt_window::create_class_window_for_current(&class, child_parent)
    }.unwrap_or(0);
    klog::write_raw(b"[WINDOWS-PE-WINE-CREATE] class-result="); klog::write_hex_u64(hwnd); klog::write_raw(b"\n");
    if hwnd == 0 {
        wine_window_diag! { klog::write_raw(b"[WINDOWS-PE-WINE-WINDOW] reject-class class="); klog::write_hex_u64(args.a1); klog::write_raw(b" parent="); klog::write_hex_u64(parent); klog::write_raw(b" result="); klog::write_hex_u64(hwnd); klog::write_raw(b"\n"); }
        return hwnd;
    }
    if crate::nt_window::set_creation_metadata_current(hwnd, style as u32, args.a0 as u32, if child { 0 } else { parent }, if instance != 0 { instance } else { class_instance }).is_err() {
        // The only step on this path that destroyed the window and answered
        // NULL without saying so. An application whose main window is NULL
        // exits at once, so this was indistinguishable from a crash.
        klog::write_raw(b"[WINDOWS-PE-WINE-WINDOW] reject-metadata hwnd=");
        klog::write_hex_u64(hwnd);
        klog::write_raw(b" style=");
        klog::write_hex_u64(style);
        klog::write_raw(b" parent=");
        klog::write_hex_u64(parent);
        klog::write_raw(b"\n");
        let _ = destroy_window(hwnd); return 0;
    }
    let menu_failed = if child {
        crate::nt_window::set_control_id_for_current(hwnd, menu).is_err()
    } else {
        menu > u32::MAX as u64 || (menu != 0 && crate::nt_window::set_window_menu_for_current(hwnd, Some(menu as u32)).is_err())
    };
    if menu_failed {
        let _ = destroy_window(hwnd);
        wine_window_diag! { klog::write_raw(b"[WINDOWS-PE-WINE-WINDOW] reject-menu hwnd="); klog::write_hex_u64(hwnd); klog::write_raw(b" menu="); klog::write_hex_u64(menu); klog::write_raw(b"\n"); }
        return 0;
    }
    if crate::nt_window::set_window_text_for_current(hwnd, &title).is_err() {
        let _ = destroy_window(hwnd);
        wine_window_diag! { klog::write_raw(b"[WINDOWS-PE-WINE-WINDOW] reject-title hwnd="); klog::write_hex_u64(hwnd); klog::write_raw(b"\n"); }
        return 0;
    }
    let rect = geometry::rect(coordinates);
    let status = crate::nt_window::dispatch(NtCall { service: NtService::SetWindowRectValues,
        args: SyscallArgs { a0: hwnd, a1: rect.left as u64, a2: rect.top as u64,
            a3: rect.right as u64, a4: rect.bottom as u64, a5: 0 } }).unwrap_or(STATUS_INVALID_PARAMETER);
    if status == STATUS_SUCCESS {
        crate::nt_window::begin_create_lifecycle_for_current(hwnd, crate::nt_window::CreateStructArgs {
            lp_create_params: create_params, instance: if instance != 0 { instance } else { class_instance },
            menu, parent, cy: coordinates.height, cx: coordinates.width, y: coordinates.y, x: coordinates.x,
            style: style as i32, name: title_buffer, class: class_pointer, ex_style: args.a0 as u32,
        }, crate::nt_window::CreateReturnConvention::RawHandle)
    } else {
        let _ = destroy_window(hwnd);
        wine_window_diag! { klog::write_raw(b"[WINDOWS-PE-WINE-WINDOW] reject-rect hwnd="); klog::write_hex_u64(hwnd); klog::write_raw(b" status="); klog::write_hex_u64(status); klog::write_raw(b"\n"); }
        0
    }
}

fn destroy_window(hwnd: u64) -> u64 {
    crate::nt_window::dispatch(NtCall { service: NtService::DestroyWindow, args: SyscallArgs { a0: hwnd, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 } }).unwrap_or(STATUS_INVALID_PARAMETER)
}

#[cfg(test)]
#[path = "tests/create_abi.rs"]
mod tests;
