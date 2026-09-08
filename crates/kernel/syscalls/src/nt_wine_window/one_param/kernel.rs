//! Kernel binding: the canonical owners each `NtUserCallOneParam` code reads.
use super::*;
use super::super::*;
use crate::nt_system_color_raw as system_color_raw;

/// # C: O(1)
fn unhandled(code: u64) -> u64 {
    klog::write_raw(b"[WINDOWS-RAW-UNHANDLED] ordinal=133d code=");
    klog::write_hex_u64(code);
    klog::write_raw(b"\n");
    UNHANDLED
}

/// # C: O(N_monitors) plus bounded usercopy and the selected code's own cost
pub(crate) fn route(ordinal: u64, args: &[u64]) -> Option<u64> {
    if ordinal != ORDINAL || args.len() < 2 { return None; }
    let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
    if !cur.is_nt_personality() { return Some(STATUS_INVALID_PARAMETER); }
    let (arg, raw) = (args[0], args[1]);
    let Some(code) = code(raw) else { return Some(unhandled(raw)); };
    Some(match code {
        Code::CreateCursorIcon => crate::nt_window::user_input::create_cursor_icon_for_current(arg != 0),
        Code::EnableDc => u64::from(crate::nt_gdi::enable_dc_for_current(arg as u32)),
        // The thunk-lock callback belongs to the caller's 16-bit lock; it is
        // retained for the process and the call answers nothing.
        Code::EnableThunkLock => { crate::nt_window::set_thunk_lock_for_current(arg); 0 }
        Code::GetIconParam => crate::nt_window::user_input::icon_param_for_current(arg),
        Code::GetMenuItemCount => crate::nt_window::menu_item_count_for_current(arg),
        Code::GetPrimaryMonitorRect => primary_monitor_rect(arg),
        Code::GetSysColor | Code::GetSysColorBrush | Code::GetSysColorPen =>
            return system_color_raw::route(ordinal, args, crate::nt_gdi::system_color_value,
                crate::nt_gdi::system_color_brush_for_current, crate::nt_gdi::system_color_pen_for_current),
        Code::GetSystemMetrics => metrics::get(arg),
        // The reference's router carries no arm for this code: the virtual
        // screen rectangle is fetched through the two-parameter multiplexer,
        // which takes the DPI-awareness type the one-parameter form has no
        // room for. The code reaching here answers nothing, as it does there.
        Code::GetVirtualScreenRect => unhandled(raw),
        Code::SetKeyboardAutoRepeat => u64::from(crate::nt_window::set_keyboard_auto_repeat(arg != 0)),
        Code::SetThreadDpiAwarenessContext => u64::from(crate::nt_window::set_thread_dpi_context_for_current(arg as u32)),
        Code::D3dkmtOpenAdapterFromGdiDisplayName => open_adapter(arg),
        Code::GetAsyncKeyboardState => crate::nt_window::async_keyboard_state_current(arg),
        Code::GetDeskPattern => crate::nt_window::desk_pattern_to_user(arg, DESK_PATTERN_CHARS),
    })
}

/// Publish the primary monitor's rectangle. The answer is TRUE once the
/// rectangle is written, as the reference's unconditional TRUE is once its
/// copy has happened. # C: O(N_monitors) plus bounded usercopy
fn primary_monitor_rect(destination: u64) -> u64 {
    let Some(monitors) = crate::nt_compositor::monitors_current() else { return 0; };
    let Some(primary) = metrics::primary(&monitors) else { return 0; };
    let rect = two_param::Rect { left: primary.monitor.x, top: primary.monitor.y,
        right: primary.monitor.x.saturating_add(primary.monitor.width as i32),
        bottom: primary.monitor.y.saturating_add(primary.monitor.height as i32) };
    u64::from(uaccess::copy_to_user(destination, &rect.encode()).is_ok())
}

/// Resolve a GDI display-device name to its adapter record. The answer is an
/// `NTSTATUS`: success once the record is published, and the invalid-parameter
/// status for a name no display owns. # C: O(N_monitors) plus bounded usercopy
fn open_adapter(descriptor: u64) -> u64 {
    let mut name = [0u16; D3DKMT_NAME_CHARS];
    for (index, unit) in name.iter_mut().enumerate() {
        let Ok(value) = uaccess::get_user_u16(descriptor.saturating_add((index * 2) as u64)) else { return STATUS_INVALID_PARAMETER; };
        *unit = value;
    }
    let Some(index) = display_index(&name) else { return STATUS_INVALID_PARAMETER; };
    let Some(monitors) = crate::nt_compositor::monitors_current() else { return STATUS_INVALID_PARAMETER; };
    if index as usize > monitors.len() { return STATUS_INVALID_PARAMETER; }
    let record = adapter_record(index, drm::primary_adapter_luid());
    if uaccess::copy_to_user(descriptor, &record).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}
