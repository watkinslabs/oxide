//! Cursor position, clip rectangle, show-count and cursor/icon objects for the
//! calling NT process.
use alloc::vec::Vec;
use ipc::win32_window::{CursorFrame, CursorIconDesc, CursorPos, FrameInfo, IconInfo, WindowRect};
use super::super::owner::{with_state, with_state_mut};
use super::super::valid_window;

/// Virtual screen rectangle the cursor is bounded by. An absent compositor
/// leaves an empty desktop, which clamps every position to its origin.
/// # C: O(N_monitors)
pub(crate) fn virtual_screen() -> WindowRect {
    crate::nt_wine_window::metrics::virtual_screen_rect(crate::nt_compositor::monitors_current)
        .unwrap_or(WindowRect { left: 0, top: 0, right: 0, bottom: 0 })
}

/// Tick count the cursor owner stamps position changes with. # C: O(1)
fn now_ms() -> u32 { timekeeper::monotonic_ns().saturating_div(1_000_000) as u32 }

/// # C: O(N_nt_processes)
pub(crate) fn cursor_pos_for_current() -> Option<(i32, i32)> { with_state(|state| state.cursor_pos()) }

/// # C: O(N_nt_processes)
pub(crate) fn set_cursor_pos_for_current(x: i32, y: i32) -> bool {
    let screen = virtual_screen();
    with_state_mut(|state| { state.set_cursor_pos(x, y, screen, now_ms()); true }).unwrap_or(false)
}

/// # C: O(N_nt_processes)
pub(crate) fn clip_cursor_for_current(rect: Option<WindowRect>) -> bool {
    let screen = virtual_screen();
    with_state_mut(|state| state.clip_cursor(rect, screen, now_ms())).unwrap_or(false)
}

/// # C: O(N_nt_processes)
pub(crate) fn clip_cursor_rect_for_current() -> Option<WindowRect> {
    let screen = virtual_screen();
    with_state(|state| state.clip_cursor_rect(screen))
}

/// # C: O(N_nt_processes)
pub(crate) fn show_cursor_for_current(show: bool) -> Option<i32> { with_state_mut(|state| state.show_cursor(show)) }

/// # C: O(N_nt_processes)
pub(crate) fn cursor_showing_for_current() -> bool { with_state(|state| state.cursor_showing()).unwrap_or(false) }

/// # C: O(N_nt_processes)
pub(crate) fn cursor_history_for_current() -> Option<Vec<CursorPos>> {
    with_state(|state| state.cursor_history().to_vec())
}

/// # C: O(N_nt_processes + N_cursor_objects)
pub(crate) fn create_cursor_icon_for_current(is_icon: bool) -> u64 {
    with_state_mut(|state| state.create_cursor_icon(is_icon).unwrap_or(0)).unwrap_or(0)
}

/// # C: O(N_nt_processes + N_cursor_objects * N_steps)
pub(crate) fn set_cursor_icon_data_for_current(handle: u64, module: &[u16], res_name: Option<&[u16]>,
    res_id: Option<u16>, desc: &CursorIconDesc<'_>) -> bool {
    with_state_mut(|state| state.set_cursor_icon_data(handle, module, res_name, res_id, desc).is_ok()).unwrap_or(false)
}

/// # C: O(N_nt_processes + N_cursor_objects)
pub(crate) fn find_existing_cursor_icon_for_current(module: &[u16], rsrc: u64) -> u64 {
    with_state(|state| state.find_existing_cursor_icon(module, rsrc).unwrap_or(0)).unwrap_or(0)
}

/// # C: O(N_nt_processes + N_cursor_objects)
pub(crate) fn icon_info_for_current(handle: u64) -> Option<IconInfo> { with_state(|state| state.icon_info(handle))? }

/// Module name, resource name and integer resource id of one object.
/// # C: O(N_nt_processes + N_cursor_objects)
pub(crate) fn icon_resource_for_current(handle: u64) -> Option<(Vec<u16>, Vec<u16>, Option<u16>)> {
    with_state(|state| state.icon_resource(handle).map(|(module, name, id)| (module.to_vec(), name.to_vec(), id)))?
}

/// # C: O(N_nt_processes + N_cursor_objects)
pub(crate) fn icon_size_for_current(handle: u64, step: u32) -> Option<(i32, i32)> {
    with_state(|state| state.icon_size(handle, step))?
}

/// # C: O(N_nt_processes + N_cursor_objects)
pub(crate) fn icon_frame_for_current(handle: u64, step: u32) -> Option<CursorFrame> {
    with_state(|state| state.icon_frame(handle, step))?
}

/// # C: O(N_nt_processes + N_cursor_objects)
pub(crate) fn cursor_frame_info_for_current(handle: u64, step: u32) -> Option<FrameInfo> {
    with_state(|state| state.cursor_frame_info(handle, step))?
}

/// # C: O(N_nt_processes + N_cursor_objects)
pub(crate) fn destroy_cursor_for_current(handle: u64) -> bool {
    with_state_mut(|state| state.destroy_cursor(handle)).unwrap_or(false)
}

/// # C: O(N_nt_processes + N_cursor_objects)
pub(crate) fn icon_param_for_current(handle: u64) -> u64 { with_state(|state| state.icon_param(handle)).unwrap_or(0) }

/// # C: O(N_nt_processes + N_cursor_objects)
#[allow(dead_code)] // KI-0673
/// Install the free-icon callback and its parameter together, answering the
/// parameter they replaced. The pair is one record: whoever replaces the
/// parameter replaces the callback that will free it. # C: O(N_nt_processes)
pub(crate) fn set_icon_free_params_for_current(handle: u64, callback: u64, param: u64) -> u64 {
    with_state_mut(|state| state.set_icon_free_params(handle, callback, param)).unwrap_or(0)
}


/// Icon a window presents: its own, falling back to its class icon. The small
/// class icon answers the small request. # C: O(N_nt_processes + N_windows)
pub(crate) fn window_icon_for_current(hwnd: u64, kind: u64) -> Option<u64> {
    let id = valid_window(hwnd)?;
    let offset = if kind == ipc::win32_window::ICON_BIG { ipc::win32_window::GCLP_HICON } else { ipc::win32_window::GCLP_HICONSM };
    with_state(|state| {
        state.get(id)?;
        let own = state.window_icon(id, kind);
        if own != 0 { return Some(own); }
        state.class_long(id, offset, 8).ok().filter(|value| *value != 0)
    })?
}

/// Install one window icon, answering the replaced one. The derived small
/// icon the reference keeps beside a large icon is recorded so a later small
/// request can answer it. # C: O(N_nt_processes + N_windows)
#[allow(dead_code)] // KI-0673
pub(crate) fn set_window_icon_for_current(hwnd: u64, kind: u64, icon: u64) -> Option<u64> {
    let id = valid_window(hwnd)?;
    with_state_mut(|state| {
        let (previous, effect) = state.set_window_icon(id, kind, icon)?;
        match effect {
            ipc::win32_window::IconSideEffect::ReleaseDerived(derived) => { state.destroy_cursor(derived); state.set_derived_window_icon(id, 0); }
            // A derived small icon is a scaled copy of the large one. Until a
            // scaler exists the large object itself answers the small request,
            // which is the same object the reference copies from.
            ipc::win32_window::IconSideEffect::DeriveSmall(source) => state.set_derived_window_icon(id, source),
            ipc::win32_window::IconSideEffect::None => {}
        }
        Some(previous)
    })?
}
