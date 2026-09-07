//! Resolve, against canonical window state, everything the retrieval-time
//! hardware ladder decides with: the hit-test code, the capture, the active
//! window, the root ancestor and its style, the class double-click style, and
//! the parent chain a button-down notifies.
use alloc::vec::Vec;
use ipc::win32_window::hardware::{self, LadderContext, MouseContext, KeyContext, ProcCall, make_point, split_point};
use ipc::win32_window::{MessageFilter, WinMessage, WindowId, WindowManager, GA_ROOT, GCL_STYLE, HTCLIENT};

/// Extended style of a child that declines to notify its parent.
const WS_EX_NOPARENTNOTIFY: u32 = 0x0000_0004;
/// Class-long width the class style is read at.
const CLASS_LONG_WIDTH: usize = 4;

/// Screen origin of one window's client area, which a client hit's point is
/// reported relative to. A window that ran no nonclient size calculation has
/// a client area at its own origin. # C: O(N_windows)
pub(super) fn client_origin(state: &WindowManager, window: WindowId) -> (i32, i32) {
    state.client_rect_raw(window).map_or((0, 0), |rect| (rect.left, rect.top))
}

/// The hit-test code the window procedure answered, as the reference reads an
/// `LRESULT` that carries one. A window that could not be asked is taken as a
/// client hit, which is what the reference does for every window it declines
/// to send the message to; only an answer can say the point is nowhere.
/// # C: O(1)
pub(super) fn hit_code(result: Result<u64, ()>) -> i32 { result.map_or(HTCLIENT, |value| value as i64 as i32) }

/// # C: O(N_windows + N_classes)
pub(super) fn mouse_context(state: &WindowManager, window: WindowId, hit_test: i32, menu_mode: bool, modal: bool,
    time_ms: u32, double_click_ms: u32, remove: bool, filter: MessageFilter) -> MouseContext {
    MouseContext {
        hit_test,
        client_origin: client_origin(state, window),
        menu_mode,
        captured: state.capture_window().is_some(),
        modal,
        class_dbl_clks: state.class_long(window, GCL_STYLE, CLASS_LONG_WIDTH)
            .is_ok_and(|style| style as u32 & hardware::CS_DBLCLKS != 0),
        double_click_ms,
        double_click_width: metric(hardware::SM_CXDOUBLECLK),
        double_click_height: metric(hardware::SM_CYDOUBLECLK),
        time_ms, remove, filter,
    }
}

/// # C: O(1)
fn metric(index: i32) -> i32 { ipc::win32_gdi::system_metric_default(index).unwrap_or(0) }

/// # C: O(N_windows)
pub(super) fn key_context(state: &WindowManager, window: WindowId, menu_active: bool, remove: bool,
    filter: MessageFilter) -> KeyContext {
    KeyContext { remove, desktop: state.get(window).is_some_and(|record| record.parent.is_none() && !record.visible),
        menu_active, filter }
}

/// # C: O(N_windows)
pub(super) fn ladder_context(state: &WindowManager, prepared: &WinMessage, origin: u32, hit_test: i32,
    queued_lparam: i64) -> Option<LadderContext> {
    let window = prepared.hwnd?;
    let root = state.ancestor(window, GA_ROOT).unwrap_or(window);
    let button_down = hardware::is_button_down(origin);
    Some(LadderContext {
        hwnd: window.raw(), hit_test, origin, button_down,
        active: state.active_window().map(|active| active.raw()),
        root: root.raw(),
        root_style: state.get(root).map_or(0, |record| record.style),
        notify: if button_down { parent_notify(state, window, origin, queued_lparam) } else { Vec::new() },
    })
}

/// The chain a button going down notifies: every ancestor of a child window
/// that has not declined the notification, stopping below the desktop, each
/// told the point in its own client coordinates. The queued point is in
/// screen coordinates, so each parent's own client origin is what it is
/// measured from. # C: O(N_windows)
fn parent_notify(state: &WindowManager, window: WindowId, origin: u32, screen: i64) -> Vec<ProcCall> {
    let mut calls = Vec::new();
    let (x, y) = split_point(screen);
    let mut cursor = window;
    for _ in 0..state.window_count() {
        let Some(record) = state.get(cursor) else { break; };
        if record.style & hardware::WS_CHILD == 0 { break; }
        if record.ex_style & WS_EX_NOPARENTNOTIFY != 0 { break; }
        let Some(parent) = record.parent else { break; };
        if state.get(parent).map_or(true, |parent| parent.parent.is_none() && !parent.visible) { break; }
        cursor = parent;
        if calls.try_reserve(1).is_err() { break; }
        let (left, top) = client_origin(state, cursor);
        calls.push(ProcCall { hwnd: parent.raw(), message: hardware::WM_PARENTNOTIFY,
            wparam: origin as u64, lparam: make_point(x - left, y - top) });
    }
    calls
}
