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
const WINE_DESTROY_WINDOW: u64 = 0x1384;
const WINE_PEEK_MESSAGE: u64 = 0x14ca;
const WINE_POST_MESSAGE: u64 = 0x14d0;
const WINE_SHOW_WINDOW: u64 = 0x15bd;
const WINE_BEGIN_PAINT: u64 = 0x1327;
const WINE_END_PAINT: u64 = 0x13bc;
const WINE_GET_DC: u64 = 0x13eb;
const WINE_GET_DC_EX: u64 = 0x13ec;
const WINE_INVALIDATE_RECT: u64 = 0x148c;
const WINE_RELEASE_DC: u64 = 0x1509;
const WINE_SET_WINDOW_POS: u64 = 0x15a7;
const WINE_CREATE_COMPATIBLE_DC: u64 = 0x10ae;
const WINE_DELETE_OBJECT: u64 = 0x118f;
const WINE_GET_TEXT_METRICS: u64 = 0x1229;
const WINE_GET_TEXT_EXTENT_EX: u64 = 0x1227;
const WINE_REGISTER_CLASS_EX: u64 = 0x14eb;
const WINE_DISPATCH_MESSAGE: u64 = 0x138b;
const WINE_MESSAGE_CALL: u64 = 0x14b5;
const WINE_GET_CLASS_NAME: u64 = 0x13d9;
const WINE_GET_CLASS_INFO_EX: u64 = 0x13d8;
const WINE_UNREGISTER_CLASS: u64 = 0x15df;
// Wine's NtUserCallWindowProc selector, passed as the NtUserMessageCall type.
const WINE_CALL_WINDOW_PROC: u64 = 0x02ab;
// Wine's builtin DefWindowProc selector, passed through the same syscall.
const WINE_DEF_WINDOW_PROC: u64 = 0x029e;
// Wine's generated win32u syscall table assigns this ordinal to the raw
// four-argument client-table publication entry.
const WINE_NTUSER_INITIALIZE_CLIENT_PFN_ARRAYS: u64 = 0x147a;
const WINE_NTUSER_GET_SYSTEM_DPI_FOR_PROCESS: u64 = 0x144b;
const WINE_GET_WINDOW_PLACEMENT: u64 = 0x1463;
const WINE_CALL_NO_PARAM: u64 = 0x133c;
const WINE_CHECK_MENU_ITEM: u64 = 0x1347;
const WINE_CREATE_MENU: u64 = 0x1366;
const WINE_CREATE_POPUP_MENU: u64 = 0x1368;
const WINE_DELETE_MENU: u64 = 0x1378;
const WINE_REMOVE_MENU: u64 = 0x151d;
const WINE_GET_MENU_BAR_INFO: u64 = 0x1418;
const WINE_GET_MENU_ITEM_RECT: u64 = 0x141a;
const WINE_DRAW_MENU_BAR: u64 = 0x139b;
const WINE_DRAW_MENU_BAR_TEMP: u64 = 0x139c;
const WINE_DESTROY_MENU: u64 = 0x1382;
const WINE_ENABLE_MENU_ITEM: u64 = 0x13a7;
const WINE_SET_MENU: u64 = 0x1569;
const WINE_THUNKED_MENU_ITEM_INFO: u64 = 0x15d0;
const WINE_CALL_ONE_PARAM: u64 = 0x133d;
const CALL_ONE_PARAM_GET_MENU_ITEM_COUNT: u64 = 4;
const DCX_WINDOW: u64 = 0x0000_0001;
const WINDOWPLACEMENT_BYTES: u64 = 44;
const CALL_NO_PARAM_GET_DIALOG_BASE_UNITS: u64 = 1;
const WM_TIMER: u32 = 0x0113;
const WM_SETTEXT: u64 = 0x000c;
const WM_GETTEXT: u64 = 0x000d;
const WM_GETTEXTLENGTH: u64 = 0x000e;
const WM_NCCREATE: u64 = 0x0081;
const WM_NCDESTROY: u64 = 0x0082;
const WM_NCHITTEST: u64 = 0x0084;
const WM_NCACTIVATE: u64 = 0x0086;

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
fn read_optional_unicode_string(pointer: u64) -> Option<alloc::vec::Vec<u16>> {
    if pointer == 0 { return Some(alloc::vec::Vec::new()); }
    let length = read_user_u16(pointer)? as usize;
    if length & 1 != 0 || length > 512 { return None; }
    if length == 0 { return Some(alloc::vec::Vec::new()); }
    let buffer = uaccess::get_user_u64(pointer.checked_add(8)?).ok()?;
    if buffer == 0 { return None; }
    let mut value = alloc::vec::Vec::new();
    value.try_reserve_exact(length / 2).ok()?;
    for index in 0..length / 2 { value.push(read_user_u16(buffer.checked_add((index * 2) as u64)?)?); }
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
        WINE_MESSAGE_CALL => {
            let hwnd = args[0];
            let message = args[1];
            let wparam = args[2];
            let lparam = args[3];
            // Wine uses NtUserMessageCall for CallWindowProcW/A.  The
            // result-info record begins with the requested WNDPROC; when it
            // is absent, the canonical window record supplies the procedure.
            if args[5] == WINE_DEF_WINDOW_PROC {
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
                if message == WM_GETTEXTLENGTH {
                    return crate::nt_window::window_text_length_for_current(hwnd).unwrap_or(STATUS_INVALID_PARAMETER);
                }
                return native(NtService::DefaultWindowProc, SyscallArgs { a0: hwnd, a1: message, a2: wparam, a3: lparam, a4: 0, a5: 0 });
            }
            if args[5] != WINE_CALL_WINDOW_PROC { return STATUS_NOT_IMPLEMENTED; }
            let wndproc = if args[4] != 0 {
                uaccess::get_user_u64(args[4]).ok().filter(|value| *value != 0)
            } else { None };
            let wndproc = wndproc.or_else(|| crate::nt_window::window_wndproc_for_current(hwnd));
            let Some(wndproc) = wndproc else { return STATUS_INVALID_PARAMETER; };
            crate::nt_rtl::begin_wndproc_callback(hwnd, message, wparam, lparam, wndproc)
        }
        WINE_GET_CLASS_NAME => get_class_name(&args),
        WINE_GET_CLASS_INFO_EX => get_class_info_ex(&args),
        WINE_CREATE_MENU => crate::nt_window::create_menu_for_current(false),
        WINE_CREATE_POPUP_MENU => crate::nt_window::create_menu_for_current(true),
        WINE_DELETE_MENU => win_bool(crate::nt_window::delete_menu_item_for_current(args[0], args[1], args[2])),
        WINE_REMOVE_MENU => win_bool(crate::nt_window::remove_menu_item_for_current(args[0], args[1], args[2])),
        WINE_DESTROY_MENU => win_bool(crate::nt_window::destroy_menu_for_current(args[0])),
        WINE_CHECK_MENU_ITEM => crate::nt_window::check_menu_item_for_current(args[0], args[1], args[2]),
        WINE_ENABLE_MENU_ITEM => crate::nt_window::enable_menu_item_for_current(args[0], args[1], args[2]),
        WINE_SET_MENU => win_bool(crate::nt_window::set_window_menu_for_current(args[0], (args[1] != 0).then_some(args[1] as u32)).map(|_| STATUS_SUCCESS).unwrap_or(STATUS_INVALID_PARAMETER)),
        WINE_THUNKED_MENU_ITEM_INFO => crate::nt_window::thunked_menu_item_info(args[0], args[1], args[2], args[3], args[4]),
        WINE_UNREGISTER_CLASS => {
            let Some(name) = read_unicode_string(args[0]) else { return 0; };
            win_bool(crate::nt_window::unregister_class_for_current(&name).then_some(STATUS_SUCCESS).unwrap_or(STATUS_INVALID_PARAMETER))
        }
        WINE_REGISTER_CLASS_EX => {
            if args[0] == 0 || uaccess::get_user_u32(args[0]).ok() != Some(80) { return 0; }
            let Some(name) = read_unicode_string(args[1]) else { return 0; };
            let Some(wndproc) = uaccess::get_user_u64(args[0].saturating_add(8)).ok() else { return 0; };
            crate::nt_window::register_class_for_current(&name, wndproc).unwrap_or(0)
        }
        WINE_CREATE_WINDOW_EX => {
            let Some(title) = read_optional_unicode_string(args[3]) else { return STATUS_INVALID_PARAMETER; };
            let hwnd = if args[1] <= u16::MAX as u64 {
                crate::nt_window::create_class_window_by_atom_for_current(args[1] as u16, args[9])
            } else {
                let Some(class) = read_unicode_string(args[1]) else { return STATUS_INVALID_PARAMETER; };
                crate::nt_window::create_class_window_for_current(&class, args[9])
            }.unwrap_or(STATUS_INVALID_PARAMETER);
            if hwnd == STATUS_INVALID_PARAMETER || hwnd == 0 { return hwnd; }
            if args[10] > u32::MAX as u64 || (args[10] != 0 && crate::nt_window::set_window_menu_for_current(hwnd, Some(args[10] as u32)).is_err()) {
                let _ = native(NtService::DestroyWindow, SyscallArgs { a0: hwnd, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 });
                return STATUS_INVALID_PARAMETER;
            }
            if crate::nt_window::set_window_text_for_current(hwnd, &title).is_err() {
                let _ = native(NtService::DestroyWindow, SyscallArgs { a0: hwnd, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 });
                return STATUS_INVALID_PARAMETER;
            }
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
        WINE_DESTROY_WINDOW => win_bool(native(NtService::DestroyWindow, SyscallArgs { a0: args[0], a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 })),
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
        WINE_GET_DC => create_window_dc(args[0], 0, gdi),
        WINE_GET_DC_EX => create_window_dc(args[0], args[2], gdi),
        WINE_CREATE_COMPATIBLE_DC => gdi(NtService::CreateCompatibleDc, SyscallArgs { a0: DEFAULT_WINDOW_SURFACE_WIDTH, a1: DEFAULT_WINDOW_SURFACE_HEIGHT, a2: 0, a3: 0, a4: 0, a5: 0 }),
        WINE_RELEASE_DC => win_bool(gdi(NtService::DeleteGdiObject, SyscallArgs { a0: args[1], a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 })),
        WINE_DELETE_OBJECT => gdi(NtService::DeleteGdiObject, SyscallArgs { a0: args[0], a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 }),
        WINE_GET_TEXT_METRICS => win_bool(gdi(NtService::GetGdiTextMetrics, SyscallArgs { a0: args[0], a1: args[1], a2: 0, a3: 0, a4: 0, a5: 0 })),
        WINE_GET_TEXT_EXTENT_EX => win_bool(gdi(NtService::GetGdiTextExtent, SyscallArgs { a0: args[0], a1: args[1], a2: args[2], a3: args[6], a4: 0, a5: 0 })),
        _ => STATUS_NOT_IMPLEMENTED,
    }
}

#[cfg(target_os = "oxide-kernel")]
fn create_window_dc<F>(hwnd: u64, flags: u64, gdi: F) -> u64
where F: Fn(NtService, SyscallArgs) -> u64 {
    // Wine's GetDCEx accepts a null clip region; region ownership is not
    // represented by the native GDI surface yet, so reject that shape rather
    // than silently drawing with the wrong clipping contract.
    if flags & !DCX_WINDOW != 0 { return STATUS_NOT_IMPLEMENTED; }
    let (width, height) = if hwnd == 0 { (DEFAULT_WINDOW_SURFACE_WIDTH, DEFAULT_WINDOW_SURFACE_HEIGHT) }
    else {
        let Some(hwnd) = u32::try_from(hwnd).ok() else { return STATUS_INVALID_PARAMETER; };
        let Some((rect, _)) = crate::nt_window::window_rect_for_current(hwnd) else { return STATUS_INVALID_PARAMETER; };
        let width = rect.right.checked_sub(rect.left).filter(|value| *value > 0).map(|value| value as u64);
        let height = rect.bottom.checked_sub(rect.top).filter(|value| *value > 0).map(|value| value as u64);
        let (Some(width), Some(height)) = (width, height) else { return STATUS_INVALID_PARAMETER; };
        (width, height)
    };
    gdi(NtService::CreateCompatibleDc, SyscallArgs { a0: width, a1: height, a2: 0, a3: 0, a4: 0, a5: 0 })
}

#[cfg(target_os = "oxide-kernel")]
fn get_class_name(args: &[u64; 17]) -> u64 {
    let Some(name) = crate::nt_window::window_class_name_for_current(args[0]) else { return STATUS_INVALID_PARAMETER; };
    if args[2] == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(maximum) = read_user_u16(args[2].saturating_add(2)) else { return STATUS_INVALID_PARAMETER; };
    let Ok(buffer) = uaccess::get_user_u64(args[2].saturating_add(8)) else { return STATUS_INVALID_PARAMETER; };
    if buffer == 0 || maximum < 2 { return STATUS_INVALID_PARAMETER; }
    let capacity = (maximum as usize / 2).saturating_sub(1);
    let copied = name.len().min(capacity);
    for (index, unit) in name.iter().take(copied).enumerate() {
        if uaccess::copy_to_user(buffer.saturating_add(index as u64 * 2), &unit.to_le_bytes()).is_err() { return STATUS_INVALID_PARAMETER; }
    }
    if uaccess::copy_to_user(buffer.saturating_add(copied as u64 * 2), &[0, 0]).is_err() { return STATUS_INVALID_PARAMETER; }
    if uaccess::copy_to_user(args[2], &(copied as u16 * 2).to_le_bytes()).is_err() { return STATUS_INVALID_PARAMETER; }
    copied as u64
}

#[cfg(target_os = "oxide-kernel")]
fn get_class_info_ex(args: &[u64; 17]) -> u64 {
    let info = if args[1] <= u16::MAX as u64 {
        crate::nt_window::class_info_by_atom_for_current(args[1] as u16)
    } else {
        let Some(name) = read_unicode_string(args[1]) else { return 0; };
        crate::nt_window::class_info_for_current(&name)
    };
    let Some((_, wndproc, _)) = info else { return 0; };
    if args[2] == 0 { return 0; }
    let mut bytes = [0u8; 80];
    bytes[0..4].copy_from_slice(&80u32.to_le_bytes());
    bytes[8..16].copy_from_slice(&wndproc.to_le_bytes());
    bytes[32..40].copy_from_slice(&args[0].to_le_bytes());
    if uaccess::copy_to_user(args[2], &bytes).is_err() { return 0; }
    1
}

/// Dispatch the raw win32u syscall used by the real Wine PE module. Unlike
/// the synthetic `WineSyscall` adapter above, this path receives the Windows
/// register ABI directly and has no descriptor/argument-array envelope.
/// # C: O(NTUSER_NB_PROCS + NTUSER_NB_WORKERS)
#[cfg(target_os = "oxide-kernel")]
pub fn dispatch_raw(ordinal: u64, args: SyscallArgs) -> Option<u64> {
    if ordinal == WINE_GET_MENU_ITEM_RECT {
        let Some(rect) = crate::nt_window::menu_item_rect_for_current(args.a0, args.a1, args.a2) else { return Some(0); };
        let bytes = [rect.left.to_le_bytes(), rect.top.to_le_bytes(), rect.right.to_le_bytes(), rect.bottom.to_le_bytes()];
        let mut raw = [0u8; 16];
        for (index, field) in bytes.iter().enumerate() { raw[index * 4..index * 4 + 4].copy_from_slice(field); }
        return Some(if uaccess::copy_to_user(args.a3, &raw).is_ok() { 1 } else { 0 });
    }
    if ordinal == WINE_GET_MENU_BAR_INFO {
        const OBJID_MENU: u64 = 0xffff_ffff_ffff_fffd;
        const MENUBARINFO_BYTES: u32 = 48;
        if args.a1 != OBJID_MENU || args.a3 == 0 || uaccess::get_user_u32(args.a3).ok() != Some(MENUBARINFO_BYTES) { return Some(0); }
        let Some(menu) = crate::nt_window::window_menu_for_current(args.a0) else { return Some(0); };
        let Some(rect) = (if args.a2 == 0 { crate::nt_window::menu_bar_rect_for_current(args.a0) } else { crate::nt_window::menu_item_rect_for_current(args.a0, menu, args.a2 - 1) }) else { return Some(0); };
        let mut raw = [0u8; MENUBARINFO_BYTES as usize];
        raw[0..4].copy_from_slice(&MENUBARINFO_BYTES.to_le_bytes());
        raw[8..12].copy_from_slice(&rect.left.to_le_bytes()); raw[12..16].copy_from_slice(&rect.top.to_le_bytes()); raw[16..20].copy_from_slice(&rect.right.to_le_bytes()); raw[20..24].copy_from_slice(&rect.bottom.to_le_bytes());
        raw[24..32].copy_from_slice(&menu.to_le_bytes());
        return Some(if uaccess::copy_to_user(args.a3, &raw).is_ok() { 1 } else { 0 });
    }
    if ordinal == WINE_DRAW_MENU_BAR {
        return Some(crate::nt_window::draw_menu_bar_for_current(args.a0));
    }
    if ordinal == WINE_DRAW_MENU_BAR_TEMP {
        if args.a2 == 0 { return Some(0); }
        let menu = if args.a3 != 0 { args.a3 } else { crate::nt_window::window_menu_for_current(args.a0).unwrap_or(0) };
        let Some(rect) = crate::nt_window::menu_bar_rect_for_current_menu(args.a0, menu) else { return Some(0); };
        let mut raw = [0u8; 16];
        for (index, value) in [rect.left, rect.top, rect.right, rect.bottom].iter().enumerate() {
            raw[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
        }
        return Some(if uaccess::copy_to_user(args.a2, &raw).is_ok() {
            rect.bottom.saturating_sub(rect.top) as u64
        } else { 0 });
    }
    if ordinal == WINE_CREATE_MENU { return Some(crate::nt_window::create_menu_for_current(false)); }
    if ordinal == WINE_CREATE_POPUP_MENU { return Some(crate::nt_window::create_menu_for_current(true)); }
    if ordinal == WINE_DESTROY_MENU { return Some(win_bool(crate::nt_window::destroy_menu_for_current(args.a0))); }
    if ordinal == WINE_CHECK_MENU_ITEM { return Some(crate::nt_window::check_menu_item_for_current(args.a0, args.a1, args.a2)); }
    if ordinal == WINE_ENABLE_MENU_ITEM { return Some(crate::nt_window::enable_menu_item_for_current(args.a0, args.a1, args.a2)); }
    if ordinal == WINE_DELETE_MENU { return Some(win_bool(crate::nt_window::delete_menu_item_for_current(args.a0, args.a1, args.a2))); }
    if ordinal == WINE_REMOVE_MENU { return Some(win_bool(crate::nt_window::remove_menu_item_for_current(args.a0, args.a1, args.a2))); }
    if ordinal == WINE_SET_MENU { return Some(win_bool(crate::nt_window::set_window_menu_for_current(args.a0, (args.a1 != 0).then_some(args.a1 as u32)).map(|_| STATUS_SUCCESS).unwrap_or(STATUS_INVALID_PARAMETER))); }
    if ordinal == WINE_CALL_ONE_PARAM {
        let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
        if !cur.is_nt_personality() { return Some(STATUS_INVALID_PARAMETER); }
        if args.a1 != CALL_ONE_PARAM_GET_MENU_ITEM_COUNT { return Some(STATUS_NOT_IMPLEMENTED); }
        return Some(crate::nt_window::menu_item_count_for_current(args.a0));
    }
    if ordinal == WINE_THUNKED_MENU_ITEM_INFO {
        return Some(crate::nt_window::thunked_menu_item_info(args.a0, args.a1, args.a2, args.a3, args.a4));
    }
    if ordinal == WINE_CALL_NO_PARAM {
        let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
        if !cur.is_nt_personality() { return Some(STATUS_INVALID_PARAMETER); }
        if args.a0 != CALL_NO_PARAM_GET_DIALOG_BASE_UNITS { return Some(STATUS_NOT_IMPLEMENTED); }
        let Some((width, height)) = crate::nt_gdi::dialog_base_units() else { return Some(STATUS_INVALID_PARAMETER); };
        let dpi = drm::primary_system_dpi() as i32;
        let scale = |value: i32| value.saturating_mul(dpi).checked_div(96).unwrap_or(value).max(1) as u32;
        return Some((scale(width) as u64) | ((scale(height) as u64) << 16));
    }
    if ordinal == WINE_NTUSER_GET_SYSTEM_DPI_FOR_PROCESS {
        let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
        if !cur.is_nt_personality() { return Some(STATUS_INVALID_PARAMETER); }
        let _ = args;
        return Some(drm::primary_system_dpi() as u64);
    }
    if ordinal == WINE_GET_WINDOW_PLACEMENT {
        let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
        if !cur.is_nt_personality() || args.a0 > u32::MAX as u64 || args.a1 == 0 { return Some(STATUS_INVALID_PARAMETER); }
        if uaccess::get_user_u32(args.a1).ok() != Some(WINDOWPLACEMENT_BYTES as u32) { return Some(STATUS_INVALID_PARAMETER); }
        let Some((rect, visible)) = crate::nt_window::window_rect_for_current(args.a0 as u32) else { return Some(STATUS_INVALID_PARAMETER); };
        let mut bytes = [0u8; WINDOWPLACEMENT_BYTES as usize];
        bytes[0..4].copy_from_slice(&(WINDOWPLACEMENT_BYTES as u32).to_le_bytes());
        bytes[12..16].copy_from_slice(&(visible as u32).to_le_bytes());
        bytes[28..32].copy_from_slice(&rect.left.to_le_bytes());
        bytes[32..36].copy_from_slice(&rect.top.to_le_bytes());
        bytes[36..40].copy_from_slice(&rect.right.to_le_bytes());
        bytes[40..44].copy_from_slice(&rect.bottom.to_le_bytes());
        return Some(if uaccess::copy_to_user(args.a1, &bytes).is_ok() { STATUS_SUCCESS } else { STATUS_INVALID_PARAMETER });
    }
    if ordinal != WINE_NTUSER_INITIALIZE_CLIENT_PFN_ARRAYS { return None; }
    let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
    if !cur.is_nt_personality() || args.a0 == 0 || args.a1 == 0 || args.a2 == 0 || args.a3 == 0 {
        return Some(STATUS_INVALID_PARAMETER);
    }
    if !crate::nt_rtl::validate_nt_user_pfn_tables(args.a0, args.a1, args.a2) {
        return Some(STATUS_INVALID_PARAMETER);
    }
    let mut module = cur.thread_group.nt_user_module.lock();
    if module.is_some() { return Some(STATUS_INVALID_PARAMETER); }
    *module = Some(args.a3);
    Some(STATUS_SUCCESS)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wine_user32_ordinals_match_the_generated_table() {
        assert_eq![(WINE_CREATE_WINDOW_EX, 0x136b), (WINE_DESTROY_WINDOW, 0x1384), (WINE_GET_MESSAGE, 0x141b), (WINE_PEEK_MESSAGE, 0x14ca), (WINE_POST_MESSAGE, 0x14d0), (WINE_SHOW_WINDOW, 0x15bd), (WINE_BEGIN_PAINT, 0x1327), (WINE_END_PAINT, 0x13bc), (WINE_GET_DC, 0x13eb), (WINE_GET_DC_EX, 0x13ec), (WINE_INVALIDATE_RECT, 0x148c), (WINE_RELEASE_DC, 0x1509), (WINE_SET_WINDOW_POS, 0x15a7), (WINE_GET_TEXT_METRICS, 0x1229), (WINE_GET_TEXT_EXTENT_EX, 0x1227), (WINE_REGISTER_CLASS_EX, 0x14eb), (WINE_DISPATCH_MESSAGE, 0x138b), (WINE_MESSAGE_CALL, 0x14b5), (WINE_GET_CLASS_NAME, 0x13d9), (WINE_GET_CLASS_INFO_EX, 0x13d8), (WINE_UNREGISTER_CLASS, 0x15df), (WINE_NTUSER_INITIALIZE_CLIENT_PFN_ARRAYS, 0x147a), (WINE_NTUSER_GET_SYSTEM_DPI_FOR_PROCESS, 0x144b), (WINE_GET_WINDOW_PLACEMENT, 0x1463), (WINE_CALL_NO_PARAM, 0x133c), (WINE_CALL_ONE_PARAM, 0x133d), (WINE_CREATE_MENU, 0x1366), (WINE_CREATE_POPUP_MENU, 0x1368), (WINE_DELETE_MENU, 0x1378), (WINE_REMOVE_MENU, 0x151d), (WINE_DRAW_MENU_BAR, 0x139b), (WINE_DRAW_MENU_BAR_TEMP, 0x139c), (WINE_THUNKED_MENU_ITEM_INFO, 0x15d0)] .iter().for_each(|(actual, expected)| assert_eq!(*actual, *expected));
        assert_eq!(WINE_DEF_WINDOW_PROC, 0x029e);
        assert_eq!(WINE_CALL_WINDOW_PROC, 0x02ab);
    }

    #[test]
    fn wine_menuiteminfo_masks_match_win32_contract() {
        assert_eq!(crate::nt_window::MENUITEMINFO_MASK_STATE, 0x0000_0001);
        assert_eq!(crate::nt_window::MENUITEMINFO_MASK_ID, 0x0000_0002);
        assert_eq!(crate::nt_window::MENUITEMINFO_MASK_SUBMENU, 0x0000_0004);
        assert_eq!(crate::nt_window::MENUITEMINFO_MASK_STRING, 0x0000_0040);
    }
}
