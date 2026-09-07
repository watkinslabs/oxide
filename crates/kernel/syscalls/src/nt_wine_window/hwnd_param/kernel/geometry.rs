//! The geometry half: rectangles, point mapping, monitors, surface exposure
//! and the raw position write. Every coordinate decision belongs to the window
//! owner or the rectangle policy; this file copies and converts.
use super::super::*;
use super::super::params::{Expose, MapPoints, RawWindowPos, Rect, WindowRects};
use super::super::params::{EXPOSE_BYTES, MAP_POINTS_BYTES, POINT_BYTES, RAW_WINDOW_POS_BYTES, WINDOW_RECTS_BYTES};
use crate::nt_window::rect_query;
use crate::nt_wine_window::{position, two_param};

const FALSE: u64 = 0;
const TRUE: u64 = 1;
/// A dpi ratio of zero means the calling thread's, which is the system's here.
const THREAD_DPI: u32 = 0;
/// `MDT_EFFECTIVE_DPI`; every other type reports the raw monitor dpi, which is
/// the same value while no monitor carries a scale of its own.
const MDT_EFFECTIVE_DPI: u32 = 0;
/// The show command a raw internal position write carries.
const SW_SHOW: u64 = 5;
/// The largest point run one mapping call converts.
const MAX_POINTS: u32 = 4096;

fn kind_of(kind: RectKind) -> rect_query::RectKind {
    match kind {
        RectKind::Window => rect_query::RectKind::Window,
        RectKind::Parent => rect_query::RectKind::Parent,
        RectKind::Client => rect_query::RectKind::Client,
        RectKind::Present => rect_query::RectKind::Present,
    }
}

fn window_rect(hwnd: u64, kind: rect_query::RectKind, dpi: u32) -> Option<Rect> {
    if hwnd > u32::MAX as u64 { return None; }
    let rect = rect_query::query_current(hwnd as u32, kind, dpi)?;
    Some(Rect { left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom })
}

/// One of the four rectangle queries. Which rectangle is the method's choice;
/// the caller's record carries only the destination and the dpi.
/// # C: O(N_processes + N_windows)
pub(super) fn rect(hwnd: u64, kind: RectKind, params_ptr: u64) -> u64 {
    if params_ptr == 0 { return FALSE; }
    let mut bytes = [0u8; WINDOW_RECTS_BYTES];
    if uaccess::copy_from_user(&mut bytes, params_ptr).is_err() { return FALSE; }
    let params = WindowRects::decode(bytes);
    if params.rect == 0 { return FALSE; }
    let Some(rect) = window_rect(hwnd, kind_of(kind), params.dpi) else { return FALSE; };
    // A present rectangle that is empty is no rectangle at all.
    if matches!(kind, RectKind::Present) && (rect.right <= rect.left || rect.bottom <= rect.top) { return FALSE; }
    if uaccess::copy_to_user(params.rect, &rect.encode()).is_err() { return FALSE; }
    TRUE
}

/// ClientToScreen and ScreenToClient, which map one point between a window's
/// client space and the desktop. # C: O(N_processes + N_windows)
pub(super) fn convert_point(hwnd: u64, point_ptr: u64, to_screen: bool) -> u64 {
    if hwnd == 0 || point_ptr == 0 { return FALSE; }
    let mut bytes = [0u8; POINT_BYTES];
    if uaccess::copy_from_user(&mut bytes, point_ptr).is_err() { return FALSE; }
    let mut points = [(i32::from_le_bytes(bytes[0..4].try_into().unwrap()),
        i32::from_le_bytes(bytes[4..8].try_into().unwrap()))];
    let (from, to) = if to_screen { (hwnd, 0) } else { (0, hwnd) };
    if crate::nt_window::map_points_for_current(from, to, &mut points).is_none() { return FALSE; }
    bytes[0..4].copy_from_slice(&points[0].0.to_le_bytes());
    bytes[4..8].copy_from_slice(&points[0].1.to_le_bytes());
    if uaccess::copy_to_user(point_ptr, &bytes).is_err() { return FALSE; }
    TRUE
}

/// MapWindowPoints. The answer is the packed offset, and every point is
/// rewritten only after the whole run converts.
/// # C: O(N_processes + N_windows + N_points)
pub(super) fn map_window_points(hwnd: u64, params_ptr: u64) -> u64 {
    if params_ptr == 0 { return 0; }
    let mut bytes = [0u8; MAP_POINTS_BYTES];
    if uaccess::copy_from_user(&mut bytes, params_ptr).is_err() { return 0; }
    let params = MapPoints::decode(bytes);
    if params.count > MAX_POINTS { return 0; }
    let mut points = alloc::vec::Vec::new();
    if points.try_reserve_exact(params.count as usize).is_err() { return 0; }
    for index in 0..u64::from(params.count) {
        let Some(address) = params.points.checked_add(index * POINT_BYTES as u64) else { return 0; };
        let (Ok(x), Ok(y)) = (uaccess::get_user_u32(address), uaccess::get_user_u32(address + 4)) else { return 0; };
        points.push((x as i32, y as i32));
    }
    let Some(packed) = crate::nt_window::map_points_for_current(hwnd, params.hwnd_to, &mut points) else { return 0; };
    for (index, point) in points.iter().enumerate() {
        let Some(address) = params.points.checked_add(index as u64 * POINT_BYTES as u64) else { return 0; };
        if uaccess::put_user_u32(address, point.0 as u32).is_err()
            || uaccess::put_user_u32(address + 4, point.1 as u32).is_err() { return 0; }
    }
    u64::from(packed)
}

/// MirrorRgn reflects a region about the window's own width.
/// # C: O(N_processes + N_windows + N_rectangles²)
pub(super) fn mirror_rgn(hwnd: u64, region: u64) -> u64 {
    let Some(rect) = window_rect(hwnd, rect_query::RectKind::Window, THREAD_DPI) else { return FALSE; };
    let Ok(handle) = u32::try_from(region) else { return FALSE; };
    let width = rect.right.saturating_sub(rect.left);
    u64::from(crate::nt_gdi::shape::mirror_region(handle, width).is_ok())
}

/// MonitorFromWindow answers the monitor the window's rectangle sits on, and
/// falls back to the flags' default over a one-pixel origin rectangle when the
/// window resolves to none. # C: O(N_processes + N_windows + N_monitors)
pub(super) fn monitor_from_window(hwnd: u64, flags: u32) -> u64 {
    let Some(monitors) = crate::nt_compositor::monitors_current() else { return 0; };
    let primary = two_param::kernel::primary(&monitors);
    let rect = window_rect(hwnd, rect_query::RectKind::Window, THREAD_DPI)
        .map(|rect| two_param::Rect { left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom })
        .unwrap_or(two_param::Rect { left: 0, top: 0, right: 1, bottom: 1 });
    two_param::monitor_from_rect(rect, u64::from(flags), &monitors, primary)
}

/// The dpi of the monitor a window sits on. No monitor carries a scale of its
/// own, so the effective form and every raw form report the same value.
/// # C: O(1)
pub(super) fn monitor_dpi(hwnd: u64, kind: u32) -> u64 {
    let _unscaled = (hwnd, kind == MDT_EFFECTIVE_DPI);
    u64::from(drm::primary_system_dpi())
}

/// Expose one window's surface. With no surface distinct from the window, the
/// exposure is the redraw the reference performs for exactly that case.
/// # C: O(redraw work)
pub(super) fn expose_surface(hwnd: u64, params_ptr: u64) -> u64 {
    if params_ptr == 0 { return FALSE; }
    let mut bytes = [0u8; EXPOSE_BYTES];
    if uaccess::copy_from_user(&mut bytes, params_ptr).is_err() { return FALSE; }
    let params = Expose::decode(bytes);
    // The rectangle travels back to the redraw owner through user memory, as
    // every other redraw caller hands it over.
    let rect = if params.whole { 0 } else { params_ptr + 8 };
    crate::nt_window::redraw::for_current(hwnd, rect, 0, params.flags);
    TRUE
}

/// The raw position write, which either drives the internal placement or the
/// ordinary position transaction. # C: O(position transaction)
pub(super) fn set_raw_window_pos(hwnd: u64, params_ptr: u64) -> u64 {
    if params_ptr == 0 { return FALSE; }
    let mut bytes = [0u8; RAW_WINDOW_POS_BYTES];
    if uaccess::copy_from_user(&mut bytes, params_ptr).is_err() { return FALSE; }
    let params = RawWindowPos::decode(bytes);
    if params.internal {
        crate::nt_wine_window::placement::apply_internal(hwnd, SW_SHOW as u32,
            Some(ipc::win32_window::WindowRect { left: params.rect.left, top: params.rect.top,
                right: params.rect.right, bottom: params.rect.bottom }), None);
        return TRUE;
    }
    let width = params.rect.right.saturating_sub(params.rect.left);
    let height = params.rect.bottom.saturating_sub(params.rect.top);
    position::set(&[hwnd, 0, params.rect.left as u32 as u64, params.rect.top as u32 as u64,
        width as u32 as u64, height as u32 as u64, u64::from(params.flags)])
}
