//! Wine x86-64 win32u syscall ordinal adapter.

use syscall::{nt::{NtCall, NtService}, SyscallArgs};

const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_NOT_IMPLEMENTED: u64 = 0xc000_0002;
const STATUS_SUCCESS: u64 = 0;
const PAINTSTRUCT_RECT_OFFSET: u64 = 12;
const PAINTSTRUCT_HDC_OFFSET: u64 = 0;
const DEFAULT_WINDOW_SURFACE_WIDTH: u64 = 800;
const DEFAULT_WINDOW_SURFACE_HEIGHT: u64 = 600;

const WINE_CREATE_WINDOW_EX: u64 = 0x136b;
const WINE_GET_MESSAGE: u64 = 0x141b;
const WINE_PEEK_MESSAGE: u64 = 0x14ca;
const WINE_POST_MESSAGE: u64 = 0x14d0;
const WINE_SHOW_WINDOW: u64 = 0x15bd;
const WINE_BEGIN_PAINT: u64 = 0x1327;
const WINE_END_PAINT: u64 = 0x13bc;
const WINE_GET_DC: u64 = 0x13eb;
const WINE_INVALIDATE_RECT: u64 = 0x148c;
const WINE_RELEASE_DC: u64 = 0x1509;
const WINE_SET_WINDOW_POS: u64 = 0x15a7;
const WINE_CREATE_COMPATIBLE_DC: u64 = 0x10ae;
const WINE_DELETE_OBJECT: u64 = 0x118f;
const WINE_GET_TEXT_METRICS: u64 = 0x1229;
const WINE_GET_TEXT_EXTENT_EX: u64 = 0x1227;
const WINE_REGISTER_CLASS_EX: u64 = 0x14eb;
const WINE_DISPATCH_MESSAGE: u64 = 0x138b;
const WM_TIMER: u32 = 0x0113;

#[cfg(target_os = "oxide-kernel")]
fn read_args(pointer: u64) -> Option<[u64; 17]> {
    let mut args = [0u64; 17];
    for (index, value) in args.iter_mut().enumerate() {
        let address = pointer.checked_add((index * 8) as u64)?;
        *value = uaccess::get_user_u64(address).ok()?;
    }
    Some(args)
}

#[cfg(target_os = "oxide-kernel")]
fn read_unicode_string(pointer: u64) -> Option<alloc::vec::Vec<u16>> {
    let length = read_user_u16(pointer)? as usize;
    if length == 0 || length & 1 != 0 || length > 512 { return None; }
    let buffer = uaccess::get_user_u64(pointer.checked_add(8)?).ok()?;
    if buffer == 0 { return None; }
    let mut value = alloc::vec::Vec::new();
    value.try_reserve_exact(length / 2).ok()?;
    for index in 0..length / 2 {
        value.push(read_user_u16(buffer.checked_add((index * 2) as u64)?)?);
    }
    Some(value)
}

#[cfg(target_os = "oxide-kernel")]
fn read_user_u16(address: u64) -> Option<u16> {
    let mut bytes = [0u8; 2];
    uaccess::copy_from_user(&mut bytes, address).ok()?;
    Some(u16::from_le_bytes(bytes))
}

/// Translate one Wine ordinal into the existing native window-state owner.
/// # C: O(1) dispatch plus bounded usercopy
#[cfg(target_os = "oxide-kernel")]
pub fn dispatch(call: NtCall) -> u64 {
    if call.service != NtService::WineSyscall { return STATUS_INVALID_PARAMETER; }
    let ordinal = call.args.a0;
    let Some(args) = read_args(call.args.a1) else { return STATUS_INVALID_PARAMETER; };
    let native = |service: NtService, args: SyscallArgs| crate::nt_window::dispatch(NtCall { service, args }).unwrap_or(STATUS_INVALID_PARAMETER);
    let gdi = |service: NtService, args: SyscallArgs| crate::nt_gdi::dispatch(NtCall { service, args }).unwrap_or(STATUS_INVALID_PARAMETER);
    match ordinal {
        WINE_DISPATCH_MESSAGE => {
            let msg = args[0];
            let Ok(hwnd) = uaccess::get_user_u64(msg) else { return STATUS_INVALID_PARAMETER; };
            let Ok(message) = uaccess::get_user_u32(msg.saturating_add(8)) else { return STATUS_INVALID_PARAMETER; };
            let Ok(wparam) = uaccess::get_user_u64(msg.saturating_add(16)) else { return STATUS_INVALID_PARAMETER; };
            let Ok(lparam) = uaccess::get_user_u64(msg.saturating_add(24)) else { return STATUS_INVALID_PARAMETER; };
            if message == WM_TIMER && lparam != 0 {
                let tick_ms = timekeeper::monotonic_ns().saturating_div(1_000_000);
                return crate::nt_rtl::begin_wndproc_callback(hwnd, message as u64, wparam, tick_ms, lparam);
            }
            let Some(wndproc) = crate::nt_window::window_wndproc_for_current(hwnd) else { return STATUS_INVALID_PARAMETER; };
            crate::nt_rtl::begin_wndproc_callback(hwnd, message as u64, wparam, lparam, wndproc)
        }
        WINE_REGISTER_CLASS_EX => {
            if args[0] == 0 || uaccess::get_user_u32(args[0]).ok() != Some(80) { return 0; }
            let Some(name) = read_unicode_string(args[1]) else { return 0; };
            let Some(wndproc) = uaccess::get_user_u64(args[0].saturating_add(8)).ok() else { return 0; };
            crate::nt_window::register_class_for_current(&name, wndproc).unwrap_or(0)
        }
        WINE_CREATE_WINDOW_EX => {
            let Some(class) = read_unicode_string(args[1]) else { return STATUS_INVALID_PARAMETER; };
            let hwnd = crate::nt_window::create_class_window_for_current(&class, args[9]).unwrap_or(STATUS_INVALID_PARAMETER);
            if hwnd == STATUS_INVALID_PARAMETER || hwnd == 0 { return hwnd; }
            let right = (args[5] as i32).checked_add(args[7] as i32);
            let bottom = (args[6] as i32).checked_add(args[8] as i32);
            match (right, bottom) {
                (Some(right), Some(bottom)) => {
                    let result = native(NtService::SetWindowRectValues, SyscallArgs { a0: hwnd, a1: args[5], a2: args[6], a3: right as u64, a4: bottom as u64, a5: 0 });
                    if result == STATUS_SUCCESS { hwnd } else { let _ = native(NtService::DestroyWindow, SyscallArgs { a0: hwnd, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 }); STATUS_INVALID_PARAMETER }
                }
                _ => { let _ = native(NtService::DestroyWindow, SyscallArgs { a0: hwnd, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 }); STATUS_INVALID_PARAMETER }
            }
        }
        WINE_POST_MESSAGE => win_bool(native(NtService::PostMessage, SyscallArgs { a0: args[0], a1: args[1], a2: args[2], a3: args[3], a4: 0, a5: 0 })),
        WINE_PEEK_MESSAGE => win_bool(native(NtService::PeekMessage, SyscallArgs { a0: args[0], a1: args[1], a2: args[2], a3: args[3], a4: args[4], a5: 0 })),
        WINE_GET_MESSAGE => win_bool(native(NtService::GetMessage, SyscallArgs { a0: args[0], a1: args[1], a2: args[2], a3: args[3], a4: 0, a5: 0 })),
        WINE_SHOW_WINDOW => native(NtService::ShowWindow, SyscallArgs { a0: args[0], a1: args[1], a2: 0, a3: 0, a4: 0, a5: 0 }),
        WINE_INVALIDATE_RECT => win_bool(native(NtService::InvalidateWindow, SyscallArgs { a0: args[0], a1: args[1], a2: args[2], a3: 0, a4: 0, a5: 0 })),
        WINE_SET_WINDOW_POS => {
            let right = (args[2] as i32).checked_add(args[4] as i32);
            let bottom = (args[3] as i32).checked_add(args[5] as i32);
            match (right, bottom) {
                (Some(right), Some(bottom)) => win_bool(native(NtService::SetWindowRectValues, SyscallArgs { a0: args[0], a1: args[2], a2: args[3], a3: right as u64, a4: bottom as u64, a5: 0 })),
                _ => STATUS_INVALID_PARAMETER,
            }
        }
        WINE_BEGIN_PAINT => begin_paint(&args, native, gdi),
        WINE_END_PAINT => end_paint(&args, native, gdi),
        WINE_GET_DC | WINE_CREATE_COMPATIBLE_DC => gdi(NtService::CreateCompatibleDc, SyscallArgs { a0: DEFAULT_WINDOW_SURFACE_WIDTH, a1: DEFAULT_WINDOW_SURFACE_HEIGHT, a2: 0, a3: 0, a4: 0, a5: 0 }),
        WINE_RELEASE_DC => win_bool(gdi(NtService::DeleteGdiObject, SyscallArgs { a0: args[1], a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 })),
        WINE_DELETE_OBJECT => gdi(NtService::DeleteGdiObject, SyscallArgs { a0: args[0], a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 }),
        WINE_GET_TEXT_METRICS => win_bool(gdi(NtService::GetGdiTextMetrics, SyscallArgs { a0: args[0], a1: args[1], a2: 0, a3: 0, a4: 0, a5: 0 })),
        WINE_GET_TEXT_EXTENT_EX => win_bool(gdi(NtService::GetGdiTextExtent, SyscallArgs { a0: args[0], a1: args[1], a2: args[2], a3: args[6], a4: 0, a5: 0 })),
        _ => STATUS_NOT_IMPLEMENTED,
    }
}

#[cfg(target_os = "oxide-kernel")]
fn win_bool(status: u64) -> u64 { (status == STATUS_SUCCESS) as u64 }

#[cfg(target_os = "oxide-kernel")]
fn begin_paint<F, G>(args: &[u64; 17], native: F, gdi: G) -> u64
where F: Fn(NtService, SyscallArgs) -> u64, G: Fn(NtService, SyscallArgs) -> u64 {
    let Some(rect) = args[1].checked_add(PAINTSTRUCT_RECT_OFFSET) else { return STATUS_INVALID_PARAMETER; };
    let hdc = gdi(NtService::CreateCompatibleDc, SyscallArgs { a0: DEFAULT_WINDOW_SURFACE_WIDTH, a1: DEFAULT_WINDOW_SURFACE_HEIGHT, a2: 0, a3: 0, a4: 0, a5: 0 });
    if hdc == STATUS_INVALID_PARAMETER || hdc == 0 { return hdc; }
    if native(NtService::BeginWindowPaint, SyscallArgs { a0: args[0], a1: rect, a2: 0, a3: 0, a4: 0, a5: 0 }) != STATUS_SUCCESS { let _ = gdi(NtService::DeleteGdiObject, SyscallArgs { a0: hdc, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 }); return STATUS_INVALID_PARAMETER; }
    if uaccess::copy_to_user(args[1].saturating_add(PAINTSTRUCT_HDC_OFFSET), &hdc.to_le_bytes()).is_err() { return STATUS_INVALID_PARAMETER; }
    hdc
}

#[cfg(target_os = "oxide-kernel")]
fn end_paint<F, G>(args: &[u64; 17], native: F, gdi: G) -> u64
where F: Fn(NtService, SyscallArgs) -> u64, G: Fn(NtService, SyscallArgs) -> u64 {
    let Ok(hdc) = uaccess::get_user_u64(args[1]) else { return STATUS_INVALID_PARAMETER; };
    let present = if hdc != 0 { gdi(NtService::PresentGdiWindow, SyscallArgs { a0: args[0], a1: hdc, a2: 0, a3: 0, a4: 0, a5: 0 }) } else { STATUS_INVALID_PARAMETER };
    let result = native(NtService::EndWindowPaint, SyscallArgs { a0: args[0], a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 });
    if hdc != 0 { let _ = gdi(NtService::DeleteGdiObject, SyscallArgs { a0: hdc, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 }); }
    win_bool(if result == STATUS_SUCCESS { present } else { result })
}
