use super::*;

/// Translate one Wine ordinal into the existing native window-state owner.
/// # C: O(1) dispatch plus bounded usercopy
#[cfg(target_os = "oxide-kernel")]
pub fn dispatch(call: NtCall) -> u64 {
    if call.service != NtService::WineSyscall { return STATUS_INVALID_PARAMETER; }
    let ordinal = call.args.a0;
    let Some(args) = read_args(call.args.a1) else { return STATUS_INVALID_PARAMETER; };
    if let Some(result) = caret_raw::dispatch(ordinal, [args[0], args[1], args[2], args[3]]) { return result; }
    if let Some(result) = multiplexers(ordinal, &args) { return result; }
    if let Some(result) = crate::nt_window::scroll::dispatch(ordinal, [args[0], args[1], args[2], args[3]]) { return result; }
    if let Some(result) = crate::nt_visibility_raw::kernel::route(ordinal, &args) { return result; }
    if let Some(result) = crate::nt_region_raw::kernel::route(ordinal, &args) { return result; }
    if let Some(result) = crate::nt_dc_query_raw::kernel::route(ordinal, &args) { return result; }
    if let Some(result) = crate::nt_pen_raw::kernel::route(ordinal, &args) { return result; }
    if let Some(result) = crate::nt_set_rect_rgn_raw::kernel::route(ordinal, &args) { return result; }
    if let Some(result) = crate::nt_dc_raw::kernel::route(ordinal, &args) { return result; }
    if ordinal == crate::nt_window::redraw::ORDINAL { return crate::nt_window::redraw::for_current(args[0], args[1], args[2], args[3] as u32); }
    if let Some(result) = crate::nt_system_color_raw::route(ordinal, &args, crate::nt_gdi::system_color_brush_for_current) { return result; }
    if let Some(result) = crate::nt_nonclient_raw::route(ordinal, &args, |pointer| uaccess::get_user_u32(pointer).ok(), crate::nt_native_gdi::begin_nonclient) { return result; }
    if let Some(result) = crate::nt_wine_font_query_contract::route(ordinal, &args,
        |dc| crate::nt_gdi::text_snapshot_for_current(dc).ok().and_then(|state| state.font), crate::nt_native_gdi::begin_query) { return result; }
    if let Some(result) = property_raw::dispatch(ordinal, [args[0], args[1], args[2]]) { return result; }
    if ordinal == object_raw::GET_DC_OBJECT { return crate::nt_gdi::selected_object_current(args[0], args[1] as u32); }
    if let Some(result) = long_raw::dispatch(ordinal, [args[0], args[1], args[2], args[3]]) { return result; }
    if ordinal == hwnd_param::ORDINAL {
        if let Some(hwnd_param::Request::GetWindowLong { offset, width }) = hwnd_param::decode_request(args[2] as u32, args[1]) {
            return long_raw::get(args[0], offset, width);
        }
    }
    if ordinal == hwnd_param::ORDINAL && args[2] as u32 == hwnd_param::GET_WINDOW_RECTS {
        return hwnd_param::dispatch_get_window_rects(args[0], args[1]);
    }
    if let Some(result) = gdi_route::descriptor(ordinal, &args) { return result; }
    if let Some(query) = object_raw::decode(ordinal, &args) { return object_raw::kernel::dispatch(query); }
    if let Some(operation) = brush_raw::decode(ordinal, &args) { return brush_raw::kernel::dispatch(operation); }
    if let Some(operation) = clip_raw::decode(ordinal, &args) { return clip_raw::kernel::dispatch(operation); }
    if let Some(result) = keyboard_query(ordinal, args[0]) { return result; }
    let native = |service: NtService, args: SyscallArgs| crate::nt_window::dispatch(NtCall { service, args }).unwrap_or(STATUS_INVALID_PARAMETER);
    let gdi = |service: NtService, args: SyscallArgs| crate::nt_gdi::dispatch(NtCall { service, args }).unwrap_or(STATUS_INVALID_PARAMETER);
    match ordinal {
        WINE_DISPATCH_MESSAGE => {
            let msg = args[0];
            let Ok(hwnd) = uaccess::get_user_u64(msg) else { return STATUS_INVALID_PARAMETER; };
            let Some(message_address) = message_field(msg, 8) else { return STATUS_INVALID_PARAMETER; };
            let Some(wparam_address) = message_field(msg, 16) else { return STATUS_INVALID_PARAMETER; };
            let Some(lparam_address) = message_field(msg, 24) else { return STATUS_INVALID_PARAMETER; };
            let Ok(message) = uaccess::get_user_u32(message_address) else { return STATUS_INVALID_PARAMETER; };
            let Ok(wparam) = uaccess::get_user_u64(wparam_address) else { return STATUS_INVALID_PARAMETER; };
            let Ok(lparam) = uaccess::get_user_u64(lparam_address) else { return STATUS_INVALID_PARAMETER; };
            if message == WM_TIMER && lparam != 0 {
                let tick_ms = timekeeper::monotonic_ns().saturating_div(1_000_000);
                return crate::nt_rtl::begin_wndproc_callback(hwnd, message as u64, wparam, tick_ms, lparam);
            }
            let Some(wndproc) = crate::nt_window::window_wndproc_for_current(hwnd) else { return STATUS_INVALID_PARAMETER; };
            crate::nt_rtl::begin_wndproc_callback(hwnd, message as u64, wparam, lparam, wndproc)
        }
        // The descriptor-backed path is used by the synthetic Wine probe;
        // keep keyboard translation on the same canonical MSG decoder as
        // the raw win32u entry above.
        WINE_TRANSLATE_MESSAGE => translate_raw_message(args[0]),
        WINE_MESSAGE_CALL => {
            let hwnd = args[0];
            let message = args[1];
            let wparam = args[2];
            let lparam = args[3];
            if let Some(result) = message_send::prepare_current(hwnd, message as u32, wparam, lparam, args[4], args[6] != 0, args[5]) { return result; }
            if args[5] == crate::nt_message_params::SEND_MESSAGE { return crate::nt_window::send::send_for_current(hwnd, message as u32, wparam, lparam); }
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
                        // This asks specifically about a hit test, which never
                        // validates a window.
                        ipc::win32_window::DefaultWindowResult::ValidatePaint => STATUS_SUCCESS,
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
            initialize_window_proc_params(args[4], hwnd, message, wparam, lparam, args[6])
        }
        WINE_GET_CLASS_NAME => get_class_name(&args),
        WINE_GET_CLASS_INFO_EX => {
            let result = get_class_info_ex(&args);
            klog::write_raw(b"[WINDOWS-PE-WINE-DESCRIPTOR-CLASS-INFO] result=");
            klog::write_hex_u64(result); klog::write_raw(b" instance=");
            klog::write_hex_u64(args[0]); klog::write_raw(b" name=");
            klog::write_hex_u64(args[1]); klog::write_raw(b" out=");
            klog::write_hex_u64(args[2]); klog::write_raw(b"\n");
            result
        }
        WINE_CREATE_MENU => crate::nt_window::create_menu_for_current(false),
        WINE_CREATE_POPUP_MENU => crate::nt_window::create_menu_for_current(true),
        WINE_DRAW_MENU_BAR => crate::nt_window::draw_menu_bar_for_current(args[0]),
        WINE_DRAW_MENU_BAR_TEMP => draw_menu_bar_temp(&args),
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
        WINE_REGISTER_CLASS_EX => raw_class::register_class(SyscallArgs { a0: args[0], a1: args[1], a2: args[2], a3: args[3], a4: args[4], a5: args[5] }),
        WINE_CREATE_WINDOW_EX => raw_class::create_window_descriptor(&args),
        WINE_POST_MESSAGE => win_bool(native(NtService::PostMessage, SyscallArgs { a0: args[0], a1: args[1], a2: args[2], a3: args[3], a4: 0, a5: 0 })),
        WINE_DESTROY_WINDOW => win_bool(native(NtService::DestroyWindow, SyscallArgs { a0: args[0], a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 })),
        WINE_PEEK_MESSAGE => crate::nt_window::retrieve_raw(NtCall { service: NtService::PeekMessage, args: SyscallArgs { a0: args[0], a1: args[1], a2: args[2], a3: args[3], a4: args[4], a5: 0 } }),
        WINE_GET_MESSAGE => crate::nt_window::retrieve_raw(NtCall { service: NtService::GetMessage, args: SyscallArgs { a0: args[0], a1: args[1], a2: args[2], a3: args[3], a4: 0, a5: 0 } }),
        WINE_SHOW_WINDOW => placement::show(args[0], args[1]),
        WINE_SET_WINDOW_PLACEMENT => placement::set(args[0], args[1]),
        WINE_GET_WINDOW_PLACEMENT => placement::get(args[0], args[1]),
        WINE_INVALIDATE_RECT => win_bool(native(NtService::InvalidateWindow, SyscallArgs { a0: args[0], a1: args[1], a2: args[2], a3: 0, a4: 0, a5: 0 })),
        WINE_SET_WINDOW_POS => {
            position::set(&[args[0], args[1], args[2], args[3], args[4], args[5], args[6]])
        }
        WINE_BEGIN_PAINT => begin_paint(&args, native, gdi),
        WINE_END_PAINT => end_paint(&args, native, gdi),
        _ => STATUS_NOT_IMPLEMENTED,
    }
}


/// Code-selected multiplexers and accelerator objects; every arm answers in
/// Windows parameter order. # C: O(1) dispatch plus the arm's own cost
#[cfg(target_os = "oxide-kernel")]
fn multiplexers(ordinal: u64, args: &[u64]) -> Option<u64> {
    if let Some(result) = hwnd_call::kernel::route(ordinal, args) { return Some(result); }
    if let Some(result) = msg_filter::route(ordinal, || false) { return Some(result); }
    if let Some(result) = two_param::kernel::route(ordinal, args) { return Some(result); }
    if let Some(result) = dpi_context::kernel::route(ordinal, args) { return Some(result); }
    accel_raw::kernel::route(ordinal, args)
}

/// Dispatch a raw win32u ordinal with arguments already in Windows parameter
/// order. The entry router owns register conversion; this path has no
/// descriptor/argument-array envelope and must not convert arguments again.
/// # C: O(NTUSER_NB_PROCS + NTUSER_NB_WORKERS)
#[cfg(target_os = "oxide-kernel")]
pub fn dispatch_raw(ordinal: u64, args: SyscallArgs) -> Option<u64> {
    if let Some(result) = caret_raw::dispatch(ordinal, [args.a0, args.a1, args.a2, args.a3]) { return Some(result); }
    if let Some(result) = multiplexers(ordinal, &[args.a0, args.a1, args.a2, args.a3]) { return Some(result); }
    if let Some(result) = crate::nt_window::scroll::dispatch(ordinal, [args.a0, args.a1, args.a2, args.a3]) { return Some(result); }
    if let Some(result) = crate::nt_visibility_raw::kernel::route(ordinal, &[args.a0, args.a1]) { return Some(result); }
    if let Some(result) = crate::nt_region_raw::kernel::route(ordinal, &[args.a0, args.a1, args.a2, args.a3]) { return Some(result); }
    if let Some(result) = crate::nt_dc_query_raw::kernel::route(ordinal, &[args.a0, args.a1, args.a2]) { return Some(result); }
    if let Some(result) = crate::nt_pen_raw::kernel::route(ordinal, &[args.a0, args.a1, args.a2, args.a3, args.a4]) { return Some(result); }
    if let Some(result) = crate::nt_set_rect_rgn_raw::kernel::route(ordinal, &[args.a0, args.a1, args.a2, args.a3, args.a4]) { return Some(result); }
    if let Some(result) = crate::nt_dc_raw::kernel::route(ordinal, &[args.a0, args.a1, args.a2]) { return Some(result); }
    if ordinal == crate::nt_window::redraw::ORDINAL { return Some(crate::nt_window::redraw::for_current(args.a0, args.a1, args.a2, args.a3 as u32)); }
    if let Some(result) = crate::nt_system_color_raw::route(ordinal, &[args.a0, args.a1], crate::nt_gdi::system_color_brush_for_current) { return Some(result); }
    if let Some(result) = crate::nt_nonclient_raw::route(ordinal, &[args.a0, args.a1, args.a2, args.a3], |pointer| uaccess::get_user_u32(pointer).ok(), crate::nt_native_gdi::begin_nonclient) { return Some(result); }
    if let Some(result) = crate::nt_wine_font_query_contract::route(ordinal, &[args.a0, args.a1, args.a2, args.a3, args.a4, args.a5],
        |dc| crate::nt_gdi::text_snapshot_for_current(dc).ok().and_then(|state| state.font), crate::nt_native_gdi::begin_query) { return Some(result); }
    if let Some(result) = property_raw::dispatch(ordinal, [args.a0, args.a1, args.a2]) { return Some(result); }
    if let Some(operation) = clip_raw::decode(ordinal, &[args.a0, args.a1, args.a2, args.a3, args.a4]) { return Some(clip_raw::kernel::dispatch(operation)); }
    if ordinal == object_raw::GET_DC_OBJECT { return Some(crate::nt_gdi::selected_object_current(args.a0, args.a1 as u32)); }
    if let Some(result) = long_raw::dispatch(ordinal, [args.a0, args.a1, args.a2, args.a3]) { return Some(result); }
    if ordinal == hwnd_param::ORDINAL {
        if let Some(hwnd_param::Request::GetWindowLong { offset, width }) = hwnd_param::decode_request(args.a2 as u32, args.a1) {
            return Some(long_raw::get(args.a0, offset, width));
        }
    }
    if ordinal == hwnd_param::ORDINAL && args.a2 as u32 == hwnd_param::GET_WINDOW_RECTS {
        return Some(hwnd_param::dispatch_get_window_rects(args.a0, args.a1));
    }
    if let Some(query) = object_raw::decode(ordinal, &[args.a0, args.a1, args.a2]) { return Some(object_raw::kernel::dispatch(query)); }
    if let Some(result) = gdi_route::raw(ordinal, args) { return Some(result); }
    if let Some(operation) = brush_raw::decode(ordinal, &[args.a0, args.a1, args.a2, args.a3, args.a4, args.a5]) {
        return Some(brush_raw::kernel::dispatch(operation));
    }
    if !raw_ordinal_claimed(ordinal) { return None; }
    if let Some(result) = keyboard_query(ordinal, args.a0) { return Some(result); }
    if ordinal == WINE_SET_WINDOW_PLACEMENT { return Some(placement::set(args.a0, args.a1)); }
    if ordinal == WINE_GET_WINDOW_PLACEMENT { return Some(placement::get(args.a0, args.a1)); }
    if ordinal == WINE_SHOW_WINDOW { return Some(placement::show(args.a0, args.a1)); }
    if ordinal == WINE_REGISTER_CLASS_EX { return Some(raw_class::register_class(args)); }
    if ordinal == WINE_REGISTER_WINDOW_MESSAGE {
        let Some(name) = read_unicode_string(args.a0) else { return Some(0); };
        return Some(crate::nt_window::register_window_message_for_current(&name).map(u64::from).unwrap_or(0));
    }
    if ordinal == WINE_OPEN_CLIPBOARD { return Some(crate::nt_window::open_clipboard_for_current(args.a0) as u64); }
    if ordinal == WINE_CLOSE_CLIPBOARD { return Some(crate::nt_window::close_clipboard_for_current() as u64); }
    if ordinal == WINE_GET_CLASS_INFO_EX {
        let packed = [args.a0, args.a1, args.a2, args.a3, args.a4, args.a5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let result = get_class_info_ex(&packed);
        klog::write_raw(b"[WINDOWS-PE-WINE-CLASS-INFO] result="); klog::write_hex_u64(result);
        klog::write_raw(b" instance="); klog::write_hex_u64(args.a0);
        klog::write_raw(b" name="); klog::write_hex_u64(args.a1);
        klog::write_raw(b" out="); klog::write_hex_u64(args.a2); klog::write_raw(b"\n");
        return Some(result);
    }
    if ordinal == WINE_GET_CLASS_NAME {
        let packed = [args.a0, args.a1, args.a2, args.a3, args.a4, args.a5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        return Some(get_class_name(&packed));
    }
    if ordinal == WINE_CREATE_WINDOW_EX { return Some(raw_class::create_window(args)); }
    if ordinal == WINE_DISPATCH_MESSAGE { return Some(raw_callback::dispatch_message(args.a0)); }
    if ordinal == WINE_MESSAGE_CALL { return Some(raw_callback::message_call(args)); }
    let native = |service: NtService, call_args: SyscallArgs| crate::nt_window::dispatch(NtCall { service, args: call_args }).unwrap_or(STATUS_INVALID_PARAMETER);
    let gdi = |service: NtService, call_args: SyscallArgs| crate::nt_gdi::dispatch(NtCall { service, args: call_args }).unwrap_or(STATUS_INVALID_PARAMETER);
    if ordinal == WINE_DESTROY_WINDOW { return Some(win_bool(native(NtService::DestroyWindow, SyscallArgs { a0: args.a0, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 }))); }
    if ordinal == WINE_POST_MESSAGE { return Some(win_bool(native(NtService::PostMessage, SyscallArgs { a0: args.a0, a1: args.a1, a2: args.a2, a3: args.a3, a4: 0, a5: 0 }))); }
    if ordinal == WINE_PEEK_MESSAGE { return Some(crate::nt_window::retrieve_raw(NtCall { service: NtService::PeekMessage, args })); }
    if ordinal == WINE_GET_MESSAGE { return Some(crate::nt_window::retrieve_raw(NtCall { service: NtService::GetMessage, args })); }
    if ordinal == WINE_INVALIDATE_RECT { return Some(win_bool(native(NtService::InvalidateWindow, SyscallArgs { a0: args.a0, a1: args.a1, a2: args.a2, a3: 0, a4: 0, a5: 0 }))); }
    if ordinal == WINE_BEGIN_PAINT {
        let packed = [args.a0, args.a1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        return Some(begin_paint(&packed, native, gdi));
    }
    if ordinal == WINE_END_PAINT {
        let packed = [args.a0, args.a1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        return Some(end_paint(&packed, native, gdi));
    }
    if ordinal == WINE_SET_WINDOW_POS {
        let Some(flags) = crate::nt_dispatch::stack_argument(6) else { return Some(0); };
        return Some(position::set(&[args.a0, args.a1, args.a2, args.a3, args.a4, args.a5, flags]));
    }
    if ordinal == WINE_MOVE_WINDOW {
        return Some(position::set(&position::move_window_args(&[args.a0, args.a1, args.a2, args.a3, args.a4, args.a5])));
    }
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
    if ordinal == WINE_SET_ACTIVE_WINDOW || ordinal == WINE_SET_FOCUS {
        return Some(crate::nt_window::dispatch(NtCall { service: NtService::SetFocusWindow, args: SyscallArgs { a0: args.a0, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 } }).unwrap_or(STATUS_INVALID_PARAMETER));
    }
    if ordinal == WINE_TRANSLATE_MESSAGE { return Some(translate_raw_message(args.a0)); }
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
        let code = args.a1 as u32 as u64;
        if code == CALL_ONE_PARAM_GET_MENU_ITEM_COUNT { return Some(crate::nt_window::menu_item_count_for_current(args.a0)); }
        if code == crate::nt_window_policy::CALL_ONE_PARAM_GET_SYSTEM_METRICS {
            return Some(metrics::get(args.a0));
        }
        klog::write_raw(b"[WINDOWS-RAW-UNHANDLED] ordinal=133d code="); klog::write_hex_u64(code); klog::write_raw(b"\n");
        return Some(STATUS_NOT_IMPLEMENTED);
    }
    if ordinal == WINE_THUNKED_MENU_ITEM_INFO {
        return Some(crate::nt_window::thunked_menu_item_info(args.a0, args.a1, args.a2, args.a3, args.a4));
    }
    if ordinal == WINE_CALL_NO_PARAM {
        let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
        if !cur.is_nt_personality() { return Some(STATUS_INVALID_PARAMETER); }
        if args.a0 != CALL_NO_PARAM_GET_DIALOG_BASE_UNITS {
            klog::write_raw(b"[WINDOWS-RAW-UNHANDLED] ordinal=133c code="); klog::write_hex_u64(args.a0); klog::write_raw(b"\n");
            return Some(STATUS_NOT_IMPLEMENTED);
        }
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
    if ordinal != WINE_NTUSER_INITIALIZE_CLIENT_PFN_ARRAYS { return None; }
    let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
    klog::write_raw(b"[WINDOWS-USER32-INIT] pfn-arrays a=");
    klog::write_hex_u64(args.a0);
    klog::write_raw(b" w=");
    klog::write_hex_u64(args.a1);
    klog::write_raw(b" workers=");
    klog::write_hex_u64(args.a2);
    klog::write_raw(b" module=");
    klog::write_hex_u64(args.a3);
    klog::write_raw(b"\n");
    if !cur.is_nt_personality() || args.a0 == 0 || args.a1 == 0 || args.a2 == 0 || args.a3 == 0 {
        klog::write_raw(b"[WINDOWS-USER32-INIT] rejected=shape\n");
        return Some(STATUS_INVALID_PARAMETER);
    }
    if !crate::nt_rtl::validate_nt_user_pfn_tables(args.a0, args.a1, args.a2) {
        klog::write_raw(b"[WINDOWS-USER32-INIT] rejected=table\n");
        return Some(STATUS_INVALID_PARAMETER);
    }
    if crate::nt_gdi::initialize_client_for_current().is_err() {
        klog::write_raw(b"[WINDOWS-USER32-INIT] rejected=gdi-client\n");
        return Some(STATUS_INVALID_PARAMETER);
    }
    let mut module = cur.thread_group.nt_user_module.lock();
    if module.is_some() { klog::write_raw(b"[WINDOWS-USER32-INIT] rejected=duplicate\n"); return Some(STATUS_INVALID_PARAMETER); }
    *module = Some(args.a3);
    drop(module);
    // The reference registers the builtin classes from win32u when the
    // thread's desktop window comes up; the W procedure array is the only
    // input, so they are registered as soon as it is published.
    let registered = builtin_classes::kernel::register_for_current(args.a1);
    klog::write_raw(b"[WINDOWS-USER32-INIT] published builtin-classes=");
    klog::write_hex_u64(registered as u64);
    klog::write_raw(b"\n");
    Some(STATUS_SUCCESS)
}

/// Decode a raw Wine syscall after the architectural entry has captured the
/// Linux syscall register snapshot. On x86-64 Wine's direct `syscall` path
/// preserves the Windows arguments in R10,RDX,R8,R9; the Linux entry exposes
/// them as RDI,RSI,RDX,R10. Keep that conversion at the ABI boundary so the
/// ordinal handlers always receive Windows parameter order.
#[cfg(target_os = "oxide-kernel")]
pub fn dispatch_raw_linux(ordinal: u64, linux: SyscallArgs) -> Option<u64> {
    if ordinal == WINE_GET_CLASS_INFO_EX || ordinal == WINE_GET_CLASS_NAME {
        klog::write_raw(b"[WINDOWS-PE-WINE-RAW-CLASS-ROUTE] ordinal=");
        klog::write_hex_u64(ordinal); klog::write_raw(b"\n");
    }
    #[cfg(target_arch = "x86_64")]
    {
        return match raw_args::decode_x64(
            ordinal,
            [linux.a0, linux.a1, linux.a2, linux.a3, linux.a4, linux.a5],
            crate::nt_dispatch::stack_argument,
        ) {
            raw_args::Decoded::Ready(args) => {
                dispatch_raw(ordinal, SyscallArgs {
                    a0: args[0], a1: args[1], a2: args[2], a3: args[3],
                    a4: args[4], a5: args[5],
                })
            },
            raw_args::Decoded::StackFault(index) => {
                klog::write_raw(b"[WINDOWS-PE-WINE-RAW-STACK-FAULT] ordinal=");
                klog::write_hex_u64(ordinal);
                klog::write_raw(b" index=");
                klog::write_hex_u64(index as u64);
                klog::write_raw(b"\n");
                Some(STATUS_INVALID_PARAMETER)
            },
            raw_args::Decoded::Unclaimed => None,
        };
    }
    #[cfg(not(target_arch = "x86_64"))]
    { dispatch_raw(ordinal, linux) }
}
