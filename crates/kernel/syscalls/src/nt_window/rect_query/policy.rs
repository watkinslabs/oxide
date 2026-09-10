//! Canonical rectangle queries and geometry used by default window handling.

/// Which rectangle a query names. The method decides it; no flag inside the
/// caller's parameter record does.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RectKind {
    /// Window rectangle in screen coordinates.
    Window,
    /// Window rectangle in the parent's client coordinates, which is what the
    /// canonical record already holds.
    Parent,
    /// Client rectangle at its own origin.
    Client,
    /// Client rectangle in screen coordinates.
    ClientScreen,
    /// The rectangle the window's contents are presented through. With no
    /// surface rectangle distinct from the window's own, it is the window
    /// rectangle, which is also what the reference falls back to.
    Present,
}

fn map_dpi(value: i32, source: u32, target: u32) -> i32 {
    if source == 0 || target == 0 || source == target { return value; }
    let product = i64::from(value).saturating_mul(i64::from(target));
    let half = i64::from(source / 2);
    let rounded = if product < 0 { product - half } else { product + half };
    rounded.checked_div(i64::from(source))
        .map(|value| value.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32)
        .unwrap_or(value)
}

pub(crate) fn map_rect(rect: ipc::win32_window::WindowRect, source_dpi: u32, requested_dpi: u32)
    -> ipc::win32_window::WindowRect
{
    ipc::win32_window::WindowRect {
        left: map_dpi(rect.left, source_dpi, requested_dpi),
        top: map_dpi(rect.top, source_dpi, requested_dpi),
        right: map_dpi(rect.right, source_dpi, requested_dpi),
        bottom: map_dpi(rect.bottom, source_dpi, requested_dpi),
    }
}

fn offset(rect: ipc::win32_window::WindowRect, dx: i32, dy: i32) -> ipc::win32_window::WindowRect {
    ipc::win32_window::WindowRect {
        left: rect.left.saturating_add(dx), right: rect.right.saturating_add(dx),
        top: rect.top.saturating_add(dy), bottom: rect.bottom.saturating_add(dy),
    }
}

/// WM_NCHITTEST carries a screen point even for a child. Use the screen
/// rectangle query so every ancestor contributes its client origin once.
/// # C: O(N_windows)
pub(crate) fn default_proc_state(state: &ipc::win32_window::WindowManager, hwnd: u32,
    message: u32, lparam: i64) -> ipc::win32_window::DefaultWindowResult {
    use ipc::win32_window::{default_window_proc, default_window_proc_for_rect, WindowId};
    let rect = WindowId::from_raw(hwnd).and_then(|window| query_state(state, window, RectKind::Window, 0, 0));
    rect.map_or_else(|| default_window_proc(message), |rect| default_window_proc_for_rect(message, rect, lparam))
}

/// Child rectangles are parent-client-relative, so a screen result adds the
/// parent chain's client origin from the canonical mapping owner. A client
/// result stays local `[0,width]x[0,height]` unless the screen form is asked
/// for. # C: O(N_windows)
pub(crate) fn query_state(
    state: &ipc::win32_window::WindowManager,
    window: ipc::win32_window::WindowId,
    kind: RectKind,
    requested_dpi: u32,
    source_dpi: u32,
) -> Option<ipc::win32_window::WindowRect> {
    let to_screen = |rect| match state.get(window)?.parent {
        Some(parent) => { let (dx, dy) = state.client_origin(parent)?; Some(offset(rect, dx, dy)) }
        None => Some(rect),
    };
    let rect = match kind {
        RectKind::Client => state.client_rect(window)?,
        RectKind::Parent => state.rect(window)?,
        RectKind::ClientScreen => to_screen(state.client_rect_raw(window)?)?,
        RectKind::Window | RectKind::Present => to_screen(state.rect(window)?)?,
    };
    Some(map_rect(rect, source_dpi, if requested_dpi == 0 { source_dpi } else { requested_dpi }))
}

#[cfg(test)]
#[path = "tests/policy.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/dispatch_pointer.rs"]
mod dispatch_pointer_tests;
