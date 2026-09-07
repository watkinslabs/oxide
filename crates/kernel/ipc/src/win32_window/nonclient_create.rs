//! What a window's creation-time nonclient size calculation is handed, and
//! which reply it adopts as the client rectangle.
use super::WindowRect;
pub use super::nonclient_menu::menu_bar_band;

/// A rectangle with no negative extent. # C: O(1)
pub const fn well_formed(rect: WindowRect) -> bool { rect.right >= rect.left && rect.bottom >= rect.top }

/// The rectangle one window's creation-time `WM_NCCALCSIZE` computes into: its
/// own window rectangle, in the coordinates the window rectangle is kept in.
/// A window whose class carries no procedure runs no callback, and its client
/// area stays equal to its window rectangle. # C: O(1)
pub const fn creation_nccalcsize(wndproc: u64, window: WindowRect) -> Option<WindowRect> {
    if wndproc == 0 || !well_formed(window) { return None; }
    Some(window)
}

/// The client rectangle a window adopts from that reply. An ill-formed reply
/// leaves the client area equal to the window rectangle. # C: O(1)
pub const fn creation_client_rect(window: WindowRect, returned: WindowRect) -> WindowRect {
    if well_formed(returned) { returned } else { window }
}

/// A child rectangle is kept relative to its parent's client area; presenting
/// it beside the parent's own surface takes the parent's client origin.
/// # C: O(1)
pub const fn client_origin(window: WindowRect, client: WindowRect) -> (i32, i32) {
    (client.left - window.left, client.top - window.top)
}

/// The four nonclient insets one client rectangle takes off its window
/// rectangle, in that rectangle's own coordinates. # C: O(1)
pub const fn insets(window: WindowRect, client: WindowRect) -> (i32, i32, i32, i32) {
    (client.left - window.left, client.top - window.top, window.right - client.right, window.bottom - client.bottom)
}

/// The client rectangle those insets name inside a new window rectangle: what
/// a nonclient size calculation answers again after a geometry change, so the
/// client area follows its window instead of naming the previous one.
/// # C: O(1)
pub const fn inset_client(window: WindowRect, insets: (i32, i32, i32, i32)) -> Option<WindowRect> {
    let (left, top, right, bottom) = (window.left + insets.0, window.top + insets.1, window.right - insets.2, window.bottom - insets.3);
    let client = WindowRect { left, top, right, bottom };
    if well_formed(client) { Some(client) } else { None }
}

#[cfg(test)]
#[path = "tests/nonclient_create.rs"]
mod tests;
