//! Live display and DPI routing over the primary display and the process's
//! DPI awareness context.
use super::devmode::*;
use super::raw::*;
use crate::nt_window::{new_entry, rect_query, GUI};
use alloc::sync::Arc;
use ipc::win32_window::{WindowId, WindowRect};

/// The single display source this kernel presents, and its monitor.
const DISPLAY_NAME: [u16; 12] = [b'\\' as u16, b'\\' as u16, b'.' as u16, b'\\' as u16,
    b'D' as u16, b'I' as u16, b'S' as u16, b'P' as u16, b'L' as u16, b'A' as u16, b'Y' as u16, b'1' as u16];
const DISPLAY_STRING: [u16; 7] = [b'D' as u16, b'i' as u16, b's' as u16, b'p' as u16, b'l' as u16, b'a' as u16, b'y' as u16];
/// The one monitor handle the display owner reports.
const PRIMARY_MONITOR: u64 = 1;
/// Colour depth of the composed desktop surface.
const DESKTOP_BITS_PER_PEL: u32 = 32;
/// Right-to-left process layout is the only bit the layout query carries.
const LAYOUT_RTL: u32 = 0x0000_0001;

/// Route one display or DPI ordinal. # C: O(1) plus the arm's own cost
pub(crate) fn route(ordinal: u64, args: &[u64]) -> Option<u64> {
    let arg = |index: usize| args.get(index).copied().unwrap_or(0);
    match ordinal {
        IS_CHILD_WINDOW_DPI_MESSAGE_ENABLED => Some(0),
        GET_PROCESS_DEFAULT_LAYOUT => Some(get_layout(arg(0))),
        SET_PROCESS_DEFAULT_LAYOUT => Some(set_layout(arg(0) as u32)),
        GET_DPI_FOR_MONITOR => Some(dpi_for_monitor(arg(0), arg(1) as u32, arg(2), arg(3))),
        LOGICAL_TO_PHYSICAL_POINT => Some(convert_point(arg(0), arg(1), true)),
        PHYSICAL_TO_LOGICAL_POINT => Some(convert_point(arg(0), arg(1), false)),
        ENUM_DISPLAY_DEVICES => Some(enum_devices(arg(0), arg(1) as u32, arg(2))),
        ENUM_DISPLAY_SETTINGS => Some(enum_settings(arg(1) as u32, arg(2))),
        ENUM_DISPLAY_MONITORS => Some(enum_monitors(arg(1), arg(2), arg(3))),
        CHANGE_DISPLAY_SETTINGS => Some(change_settings(arg(1), arg(3) as u32)),
        GET_DISPLAY_CONFIG_BUFFER_SIZES => Some(config_buffer_sizes(arg(1), arg(2))),
        QUERY_DISPLAY_CONFIG => Some(query_config(arg(1), arg(3))),
        DISPLAY_CONFIG_GET_DEVICE_INFO => Some(config_device_info()),
        SYSTEM_PARAMETERS_INFO_FOR_DPI => Some(parameters_for_dpi(arg(0) as u32, arg(1) as u32, arg(2), arg(4) as u32)),
        _ => None,
    }
}

/// The primary display's current mode. # C: O(1)
fn primary_mode() -> DisplayMode {
    let dpi = drm::primary_system_dpi();
    let (width, height) = screen_size();
    DisplayMode { width: width.max(0) as u32, height: height.max(0) as u32, bits: DESKTOP_BITS_PER_PEL, frequency: drm::primary_refresh_hz(), dpi }
}

fn with_entry<R>(f: impl FnOnce(&mut crate::nt_window::GuiEntry) -> R) -> Option<R> {
    let cur = sched::live::current().filter(|cur| cur.is_nt_personality())?;
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)))
        .unwrap_or_else(|| { entries.push(new_entry(&group)); entries.len() - 1 });
    Some(f(&mut entries[index]))
}

fn get_layout(output: u64) -> u64 {
    if output == 0 { crate::nt_rtl::set_last_win32_error(ERROR_NOACCESS as u64); return 0; }
    let layout = with_entry(|entry| entry.process_layout).unwrap_or(0);
    if uaccess::put_user_u32(output, layout).is_err() { crate::nt_rtl::set_last_win32_error(ERROR_NOACCESS as u64); return 0; }
    1
}

fn set_layout(layout: u32) -> u64 {
    let _ = with_entry(|entry| entry.process_layout = layout & LAYOUT_RTL);
    1
}

/// The process DPI awareness the caller's context names. # C: O(1)
fn awareness() -> u32 {
    let stored = with_entry(|entry| entry.dpi_context).unwrap_or(0);
    let context = crate::nt_wine_window::dpi_context::get(stored, 0);
    context & 0x0f
}

fn dpi_for_monitor(monitor: u64, kind: u32, x: u64, y: u64) -> u64 {
    if kind > MDT_MAXIMUM { crate::nt_rtl::set_last_win32_error(ERROR_BAD_ARGUMENTS as u64); return 0; }
    if x == 0 || y == 0 { crate::nt_rtl::set_last_win32_error(ERROR_INVALID_ADDRESS as u64); return 0; }
    let _ = monitor;
    let system = drm::primary_system_dpi();
    let value = monitor_dpi(awareness(), system, system);
    if uaccess::put_user_u32(x, value).is_err() || uaccess::put_user_u32(y, value).is_err() { return 0; }
    1
}

/// Convert a point between the window's own DPI and the thread's, refusing a
/// point outside the window. # C: O(N_windows)
fn convert_point(hwnd: u64, point: u64, to_physical: bool) -> u64 {
    let Some(window) = u32::try_from(hwnd).ok().and_then(WindowId::from_raw) else { return 0; };
    if point == 0 { return 0; }
    let (Ok(x), Ok(y)) = (uaccess::get_user_u32(point), uaccess::get_user_u32(point + 4)) else { return 0; };
    let (x, y) = (x as i32, y as i32);
    let system = drm::primary_system_dpi();
    let thread = if awareness() == 0 { USER_DEFAULT_SCREEN_DPI } else { system };
    let (source, target) = if to_physical { (thread, system) } else { (system, thread) };
    let Some(rect) = rect_query::query_current(window.raw(), rect_query::RectKind::Window, source) else { return 0; };
    if !point_inside((x, y), rect) { return 0; }
    let mapped = rect_query::map_rect(WindowRect { left: x, top: y, right: x, bottom: y }, source, target);
    if uaccess::put_user_u32(point, mapped.left as u32).is_err() { return 0; }
    if uaccess::put_user_u32(point + 4, mapped.top as u32).is_err() { return 0; }
    1
}

/// One display device is present; any further index reports the end of the list.
/// # C: O(1)
fn enum_devices(device: u64, index: u32, output: u64) -> u64 {
    if device != 0 || index != 0 { crate::nt_rtl::set_last_win32_error(ERROR_NO_MORE_FILES as u64); return 0; }
    if output == 0 || uaccess::get_user_u32(output).ok().is_none() { return 0; }
    let mut bytes = [0u8; DISPLAY_DEVICE_BYTES];
    encode_device(&mut bytes, &DISPLAY_NAME, &DISPLAY_STRING, &DISPLAY_NAME, &DISPLAY_NAME,
        DISPLAY_DEVICE_ATTACHED_TO_DESKTOP | DISPLAY_DEVICE_PRIMARY_DEVICE | DISPLAY_DEVICE_VGA_COMPATIBLE);
    let Ok(size) = uaccess::get_user_u32(output) else { return 0; };
    let length = (size as usize).min(DISPLAY_DEVICE_BYTES);
    if length < 4 || uaccess::copy_to_user(output + 4, &bytes[4..length]).is_err() { return 0; }
    1
}

/// The display produces exactly its current mode. `ENUM_CURRENT_SETTINGS` and
/// `ENUM_REGISTRY_SETTINGS` both name that mode. # C: O(1)
fn enum_settings(index: u32, output: u64) -> u64 {
    const ENUM_CURRENT_SETTINGS: u32 = u32::MAX;
    const ENUM_REGISTRY_SETTINGS: u32 = u32::MAX - 1;
    if !matches!(index, 0 | ENUM_CURRENT_SETTINGS | ENUM_REGISTRY_SETTINGS) {
        crate::nt_rtl::set_last_win32_error(ERROR_NO_MORE_FILES as u64);
        return 0;
    }
    if output == 0 { return 0; }
    let Ok(size) = uaccess::get_user_u16(output + DEVMODE_SIZE as u64) else { return 0; };
    let mut bytes = [0u8; DEVMODE_BYTES];
    encode_mode(&mut bytes, &DISPLAY_NAME, primary_mode());
    let length = (size as usize).min(DEVMODE_BYTES);
    if length <= DEVMODE_FIELDS { return 0; }
    if uaccess::copy_to_user(output, &bytes[..length]).is_err() { return 0; }
    1
}

/// Call the caller's enumeration procedure once, for the single monitor.
/// # C: O(1); # Sleeps: yes
fn enum_monitors(rect: u64, proc: u64, lparam: u64) -> u64 {
    if proc == 0 { return 0; }
    let (width, height) = screen_size();
    let monitor = WindowRect { left: 0, top: 0, right: width, bottom: height };
    if let Some(limit) = read_rect(rect) {
        if limit.left.max(monitor.left) >= limit.right.min(monitor.right)
            || limit.top.max(monitor.top) >= limit.bottom.min(monitor.bottom) { return 1; }
    }
    let mut record = [0u8; 16];
    for (index, value) in [monitor.left, monitor.top, monitor.right, monitor.bottom].into_iter().enumerate() {
        record[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
    crate::nt_rtl::begin_callback_with_record(PRIMARY_MONITOR, 0, &record, lparam, proc);
    1
}

/// Primary-monitor resolution from the canonical monitor snapshot. # C: O(monitors)
fn screen_size() -> (i32, i32) {
    crate::nt_wine_window::metrics::screen_size(crate::nt_compositor::monitors_current).unwrap_or((0, 0))
}

fn read_rect(address: u64) -> Option<WindowRect> {
    if address == 0 { return None; }
    let mut bytes = [0u8; 16];
    uaccess::copy_from_user(&mut bytes, address).ok()?;
    let field = |index: usize| i32::from_le_bytes(bytes[index * 4..index * 4 + 4].try_into().unwrap());
    Some(WindowRect { left: field(0), top: field(1), right: field(2), bottom: field(3) })
}

/// The display produces one mode; a request naming it succeeds and any other
/// request names a mode the display cannot produce. # C: O(1)
fn change_settings(devmode: u64, flags: u32) -> u64 {
    let current = primary_mode();
    if devmode == 0 { return DISP_CHANGE_SUCCESSFUL; }
    let mut bytes = [0u8; DEVMODE_BYTES];
    if uaccess::copy_from_user(&mut bytes, devmode).is_err() { return DISP_CHANGE_BADPARAM; }
    let requested = decode_mode(&bytes);
    if !mode_matches(requested, (current.width, current.height, current.bits, current.frequency)) { return DISP_CHANGE_BADMODE; }
    let _ = applies_mode(flags);
    DISP_CHANGE_SUCCESSFUL
}

/// One active path over one source and one target, each with its own mode.
const CONFIG_PATH_COUNT: u32 = 1;
const CONFIG_MODE_COUNT: u32 = 2;

fn config_buffer_sizes(paths: u64, modes: u64) -> u64 {
    if paths == 0 || modes == 0 { return ERROR_INVALID_PARAMETER as u64; }
    if uaccess::put_user_u32(paths, CONFIG_PATH_COUNT).is_err() { return ERROR_INVALID_PARAMETER as u64; }
    if uaccess::put_user_u32(modes, CONFIG_MODE_COUNT).is_err() { return ERROR_INVALID_PARAMETER as u64; }
    ERROR_SUCCESS as u64
}

/// The path and mode records are not composed here; the query reports that the
/// caller's buffers are too small so it asks for the sizes again. # C: O(1)
fn query_config(paths: u64, modes: u64) -> u64 {
    if paths == 0 || modes == 0 { return ERROR_INVALID_PARAMETER as u64; }
    ERROR_NOT_SUPPORTED as u64
}

fn config_device_info() -> u64 { ERROR_NOT_SUPPORTED as u64 }

/// The DPI-scaled system parameters share the unscaled owner; only the
/// nonclient metrics record is scaled, by the ratio the caller names.
/// # C: O(1)
fn parameters_for_dpi(action: u32, value: u32, ptr: u64, dpi: u32) -> u64 {
    crate::nt_nonclient_raw::kernel::route_for_dpi(action, value, ptr, 0, dpi)
}
