//! Execute one decoded `NtUserCallHwndParam` request against the canonical
//! owners. The decoder above chose the request; nothing is selected here.
//!
//! Module manifest:
//! - `geometry.rs` — rectangles, point mapping, monitors and surface exposure.
//! - `state.rs`    — window and class longs, descriptive record, marks, input.
use super::*;
use crate::nt_wine_window::{class_raw, long_raw};

#[path = "kernel/geometry.rs"]
mod geometry;
#[path = "kernel/state.rs"]
mod state;

/// The one route for the ordinal. Every family that reaches this ordinal
/// arrives here, so no second chain can admit a method this one refuses.
/// # C: O(1) plus the selected request's own cost
pub(crate) fn route(ordinal: u64, args: &[u64]) -> Option<u64> {
    if ordinal != ORDINAL { return None; }
    let hwnd = args.first().copied().unwrap_or(0);
    let param = args.get(1).copied().unwrap_or(0);
    let method = args.get(METHOD_ARG).copied().unwrap_or(0) as u32;
    let Some(request) = decode(method, param) else {
        klog::write_raw(b"[WINDOWS-RAW-UNHANDLED] ordinal=1336 method=");
        klog::write_hex_u64(u64::from(method));
        klog::write_raw(b"\n");
        return Some(0);
    };
    Some(dispatch(hwnd, request))
}

/// # C: O(selected request)
fn dispatch(hwnd: u64, request: Request) -> u64 {
    match request {
        Request::ClientToScreen { point } => geometry::convert_point(hwnd, point, true),
        Request::ScreenToClient { point } => geometry::convert_point(hwnd, point, false),
        Request::GetRect { kind, params } => geometry::rect(hwnd, kind, params),
        Request::MapWindowPoints { params } => geometry::map_window_points(hwnd, params),
        Request::MirrorRgn { region } => geometry::mirror_rgn(hwnd, region),
        Request::MonitorFromWindow { flags } => geometry::monitor_from_window(hwnd, flags),
        Request::GetWinMonitorDpi { kind } => geometry::monitor_dpi(hwnd, kind),
        Request::ExposeWindowSurface { params } => geometry::expose_surface(hwnd, params),
        Request::SetRawWindowPos { params } => geometry::set_raw_window_pos(hwnd, params),
        Request::ClassLong { offset, width, ansi } => class_raw::get(class_raw::ClassLong { hwnd, offset, width, ansi }),
        Request::GetWindowLong { offset, width, .. } => long_raw::get(hwnd, offset, width),
        Request::GetWindowWord { offset } => state::window_word(hwnd, offset),
        Request::GetWindowInfo { info } => state::window_info(hwnd, info),
        Request::GetScrollInfo { params } => state::scroll_info(hwnd, params),
        Request::GetWindowRelative { relationship } => state::window_relative(hwnd, relationship),
        Request::GetWindowThread { process } => state::window_thread(hwnd, process),
        Request::IsChild { child } => u64::from(state::is_child(hwnd, child)),
        Request::SetDialogInfo { info } => state::set_dialog_info(hwnd, info),
        Request::SetMdiClientInfo { info } => state::set_mdi_client_info(hwnd, info),
        Request::GetPrivateData { params } => state::private_data(hwnd, params),
        Request::SetPrivateData { params } => state::set_private_data(hwnd, params),
        Request::SendHardwareInput { params } => state::send_hardware_input(hwnd, params),
    }
}
