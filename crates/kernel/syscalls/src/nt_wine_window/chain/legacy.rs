//! The code-selected tail of the chain: ordinals whose work is written here
//! rather than owned by a family router. One body per ordinal, shared by both
//! entries; the two entries previously carried separate, divergent copies.
use super::super::super::*;
use super::Args;

/// # C: O(1) dispatch plus the selected ordinal's own cost
pub(super) fn route(ordinal: u64, a: &Args) -> Option<u64> {
    if !raw_ordinal_claimed(ordinal) { return None; }
    let native = |service: NtService, args: SyscallArgs| crate::nt_window::dispatch(NtCall { service, args }).unwrap_or(STATUS_INVALID_PARAMETER);
    let gdi = |service: NtService, args: SyscallArgs| crate::nt_gdi::dispatch(NtCall { service, args }).unwrap_or(STATUS_INVALID_PARAMETER);
    let registers = SyscallArgs { a0: a[0], a1: a[1], a2: a[2], a3: a[3], a4: a[4], a5: a[5] };
    Some(match ordinal {
        WINE_DISPATCH_MESSAGE => raw_callback::dispatch_message(a[0]),
        WINE_TRANSLATE_MESSAGE => translate_raw_message(a[0]),
        WINE_MESSAGE_CALL => raw_callback::message_call(a),
        WINE_GET_CLASS_NAME => get_class_name(a),
        WINE_GET_CLASS_INFO_EX => {
            let result = get_class_info_ex(a);
            klog::write_raw(b"[WINDOWS-PE-WINE-CLASS-INFO] result=");
            klog::write_hex_u64(result); klog::write_raw(b" instance=");
            klog::write_hex_u64(a[0]); klog::write_raw(b" name=");
            klog::write_hex_u64(a[1]); klog::write_raw(b" out=");
            klog::write_hex_u64(a[2]); klog::write_raw(b" menu-name=");
            klog::write_hex_u64(if a[2] == 0 { 0 } else { uaccess::get_user_u64(a[2] + 56).unwrap_or(u64::MAX) });
            klog::write_raw(b"\n");
            result
        }
        WINE_REGISTER_CLASS_EX => raw_class::register_class(registers),
        WINE_CREATE_WINDOW_EX => raw_class::create_window_descriptor(a),
        WINE_UNREGISTER_CLASS => {
            let Some(name) = read_unicode_string(a[0]) else { return Some(0); };
            // The call hands back the client's own menu-name handle so the
            // caller can free it, and only once the class is gone: a refused
            // removal leaves the class holding the handle it was registered
            // with, and a caller that freed it would leave that dangling.
            let handed = class_menu_name(&name, a[1]);
            // A class another module registered is not this caller's to
            // remove, and the module argument is what says so.
            if !crate::nt_window::unregister_class_for_current(&name, a[1]) { return Some(win_bool(STATUS_INVALID_PARAMETER)); }
            if a[2] != 0 && uaccess::put_user_u64(a[2], handed).is_err() { return Some(0); }
            win_bool(STATUS_SUCCESS)
        }
        WINE_REGISTER_WINDOW_MESSAGE => {
            let Some(name) = read_unicode_string(a[0]) else { return Some(0); };
            crate::nt_window::register_window_message_for_current(&name).map(u64::from).unwrap_or(0)
        }
        WINE_OPEN_CLIPBOARD => crate::nt_window::open_clipboard_for_current(a[0]) as u64,
        WINE_CLOSE_CLIPBOARD => crate::nt_window::close_clipboard_for_current() as u64,
        WINE_POST_MESSAGE => win_bool(native(NtService::PostMessage, SyscallArgs { a0: a[0], a1: a[1], a2: a[2], a3: a[3], a4: 0, a5: 0 })),
        WINE_DESTROY_WINDOW => win_bool(native(NtService::DestroyWindow, SyscallArgs { a0: a[0], a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 })),
        WINE_PEEK_MESSAGE => crate::nt_window::retrieve_raw(NtCall { service: NtService::PeekMessage, args: registers }),
        WINE_GET_MESSAGE => crate::nt_window::retrieve_raw(NtCall { service: NtService::GetMessage, args: registers }),
        WINE_SHOW_WINDOW => placement::show(a[0], a[1]),
        WINE_SET_WINDOW_PLACEMENT => placement::set(a[0], a[1]),
        WINE_GET_WINDOW_PLACEMENT => placement::get(a[0], a[1]),
        WINE_SET_WINDOW_POS => position::set(&[a[0], a[1], a[2], a[3], a[4], a[5], a[6]]),
        WINE_MOVE_WINDOW => position::set(&position::move_window_args(&[a[0], a[1], a[2], a[3], a[4], a[5]])),
        WINE_BEGIN_PAINT => begin_paint(a, native, gdi),
        WINE_END_PAINT => end_paint(a, native, gdi),
        WINE_SET_ACTIVE_WINDOW | WINE_SET_FOCUS => native(NtService::SetFocusWindow, SyscallArgs { a0: a[0], a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 }),
        WINE_CREATE_MENU => crate::nt_window::create_menu_for_current(false),
        WINE_CREATE_POPUP_MENU => crate::nt_window::create_menu_for_current(true),
        WINE_DRAW_MENU_BAR => crate::nt_window::draw_menu_bar_for_current(a[0]),
        WINE_DRAW_MENU_BAR_TEMP => draw_menu_bar_temp(a),
        WINE_DELETE_MENU => win_bool(crate::nt_window::delete_menu_item_for_current(a[0], a[1], a[2])),
        WINE_REMOVE_MENU => win_bool(crate::nt_window::remove_menu_item_for_current(a[0], a[1], a[2])),
        WINE_DESTROY_MENU => win_bool(crate::nt_window::destroy_menu_for_current(a[0])),
        WINE_CHECK_MENU_ITEM => crate::nt_window::check_menu_item_for_current(a[0], a[1], a[2]),
        WINE_ENABLE_MENU_ITEM => crate::nt_window::enable_menu_item_for_current(a[0], a[1], a[2]),
        WINE_SET_MENU => win_bool(crate::nt_window::set_window_menu_for_current(a[0], (a[1] != 0).then_some(a[1] as u32)).map(|_| STATUS_SUCCESS).unwrap_or(STATUS_INVALID_PARAMETER)),
        WINE_THUNKED_MENU_ITEM_INFO => crate::nt_window::thunked_menu_item_info(a[0], a[1], a[2], a[3], a[4]),
        WINE_GET_MENU_ITEM_RECT => menu_item_rect(a),
        WINE_GET_MENU_BAR_INFO => menu_bar_info(a),
        WINE_NTUSER_GET_SYSTEM_DPI_FOR_PROCESS => {
            let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
            if !cur.is_nt_personality() { return Some(STATUS_INVALID_PARAMETER); }
            drm::primary_system_dpi() as u64
        }
        WINE_NTUSER_INITIALIZE_CLIENT_PFN_ARRAYS => return Some(initialize_client_pfn_arrays(a)),
        _ => return None,
    })
}

/// # C: O(N_menu_items) plus bounded usercopy
fn menu_item_rect(a: &Args) -> u64 {
    let Some(rect) = crate::nt_window::menu_item_rect_for_current(a[0], a[1], a[2]) else { return 0; };
    let bytes = [rect.left.to_le_bytes(), rect.top.to_le_bytes(), rect.right.to_le_bytes(), rect.bottom.to_le_bytes()];
    let mut raw = [0u8; 16];
    for (index, field) in bytes.iter().enumerate() { raw[index * 4..index * 4 + 4].copy_from_slice(field); }
    if uaccess::copy_to_user(a[3], &raw).is_ok() { 1 } else { 0 }
}

/// `MENUBARINFO` for the window's own bar or one of its items.
/// # C: O(N_menu_items) plus bounded usercopy
fn menu_bar_info(a: &Args) -> u64 {
    const OBJID_MENU: u64 = 0xffff_ffff_ffff_fffd;
    const MENUBARINFO_BYTES: u32 = 48;
    if a[1] != OBJID_MENU || a[3] == 0 || uaccess::get_user_u32(a[3]).ok() != Some(MENUBARINFO_BYTES) { return 0; }
    let Some(menu) = crate::nt_window::window_menu_for_current(a[0]) else { return 0; };
    let Some(rect) = (if a[2] == 0 { crate::nt_window::menu_bar_rect_for_current(a[0]) }
        else { crate::nt_window::menu_item_rect_for_current(a[0], menu, a[2] - 1) }) else { return 0; };
    let mut raw = [0u8; MENUBARINFO_BYTES as usize];
    raw[0..4].copy_from_slice(&MENUBARINFO_BYTES.to_le_bytes());
    raw[8..12].copy_from_slice(&rect.left.to_le_bytes()); raw[12..16].copy_from_slice(&rect.top.to_le_bytes());
    raw[16..20].copy_from_slice(&rect.right.to_le_bytes()); raw[20..24].copy_from_slice(&rect.bottom.to_le_bytes());
    raw[24..32].copy_from_slice(&menu.to_le_bytes());
    if uaccess::copy_to_user(a[3], &raw).is_ok() { 1 } else { 0 }
}

/// Publish the client procedure tables and bind the GDI client.
/// # C: O(NTUSER_NB_PROCS + NTUSER_NB_WORKERS)
fn initialize_client_pfn_arrays(a: &Args) -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    klog::write_raw(b"[WINDOWS-USER32-INIT] pfn-arrays a=");
    klog::write_hex_u64(a[0]); klog::write_raw(b" w=");
    klog::write_hex_u64(a[1]); klog::write_raw(b" workers=");
    klog::write_hex_u64(a[2]); klog::write_raw(b" module=");
    klog::write_hex_u64(a[3]); klog::write_raw(b"\n");
    if !cur.is_nt_personality() || a[0] == 0 || a[1] == 0 || a[2] == 0 || a[3] == 0 {
        klog::write_raw(b"[WINDOWS-USER32-INIT] rejected=shape\n");
        return STATUS_INVALID_PARAMETER;
    }
    if !crate::nt_rtl::validate_nt_user_pfn_tables(a[0], a[1], a[2]) {
        klog::write_raw(b"[WINDOWS-USER32-INIT] rejected=table\n");
        return STATUS_INVALID_PARAMETER;
    }
    // The builtin class procedures occupy the first window-procedure slots, so
    // a builtin handle resolves before the client allocates anything of its own.
    if !crate::nt_window::publish_builtin_winprocs_for_current(a[0], a[1]) {
        klog::write_raw(b"[WINDOWS-USER32-INIT] rejected=winproc-table\n");
        return STATUS_INVALID_PARAMETER;
    }
    if crate::nt_gdi::initialize_client_for_current().is_err() {
        klog::write_raw(b"[WINDOWS-USER32-INIT] rejected=gdi-client\n");
        return STATUS_INVALID_PARAMETER;
    }
    let mut module = cur.thread_group.nt_user_module.lock();
    if module.is_some() { klog::write_raw(b"[WINDOWS-USER32-INIT] rejected=duplicate\n"); return STATUS_INVALID_PARAMETER; }
    *module = Some(a[3]);
    drop(module);
    // The reference registers the builtin classes when the thread's desktop
    // window comes up, not when the procedure arrays are published; retain
    // the W array here and register from it at that trigger.
    if !crate::nt_window::publish_client_procs_for_current(a[1]) {
        klog::write_raw(b"[WINDOWS-USER32-INIT] rejected=client-procs\n");
        return STATUS_INVALID_PARAMETER;
    }
    STATUS_SUCCESS
}
