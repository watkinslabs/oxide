//! Drag detection, drag-and-drop transfer and the process input-idle wait:
//! every decision each ordinal answers, independent of the live owners.

pub(crate) const DRAG_DETECT: u64 = 0x1393;
pub(crate) const DRAG_OBJECT: u64 = 0x1394;
pub(crate) const WAIT_FOR_INPUT_IDLE: u64 = 0x15f8;

/// The wait was satisfied: the process went idle, or ended first.
pub(crate) const WAIT_OBJECT_0: u64 = 0;
/// The wait timed out.
pub(crate) const WAIT_TIMEOUT: u64 = 0x0000_0102;
/// The wait could not be started.
pub(crate) const WAIT_FAILED: u64 = 0xffff_ffff;

/// Left mouse button virtual key.
pub(crate) const VK_LBUTTON: u32 = 0x01;
/// A key state word carries the pressed state in its top bit.
pub(crate) const KEY_PRESSED: u16 = 0x8000;
/// Half-extents of the square a pointer may travel before a press is a drag.
pub(crate) const SM_CXDRAG: i32 = 68;
pub(crate) const SM_CYDRAG: i32 = 69;
/// A timeout that never expires.
pub(crate) const INFINITE: u32 = 0xffff_ffff;
/// The drop-transfer ordinal reports that no object was accepted.
pub(crate) const DRAG_OBJECT_NONE: u64 = 0;

/// A press is only a candidate drag while the button is still down. # C: O(1)
pub(crate) const fn left_button_down(state: u16) -> bool { state & KEY_PRESSED != 0 }

/// The square around the press, in the coordinates the caller supplied, that a
/// pointer must leave before the gesture counts as a drag. Both extents come
/// from the drag metrics, so the square spans twice each of them. # C: O(1)
pub(crate) fn drag_rect(x: i32, y: i32, width: i32, height: i32) -> ipc::win32_window::WindowRect {
    ipc::win32_window::WindowRect {
        left: x.saturating_sub(width), top: y.saturating_sub(height),
        right: x.saturating_add(width), bottom: y.saturating_add(height),
    }
}

/// A rectangle holds its left and top edges and excludes its right and bottom.
/// # C: O(1)
pub(crate) const fn pt_in_rect(rect: ipc::win32_window::WindowRect, x: i32, y: i32) -> bool {
    x >= rect.left && x < rect.right && y >= rect.top && y < rect.bottom
}

/// A mouse message carries its position as two signed sixteen-bit halves of
/// the low `lParam` word. # C: O(1)
pub(crate) const fn mouse_point(lparam: i64) -> (i32, i32) {
    ((lparam as u32 as u16) as i16 as i32, ((lparam as u32 >> 16) as u16) as i16 as i32)
}

/// What one peeked mouse message does to a running drag-detect gesture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DragStep {
    /// The button came up inside the square: the gesture is a click.
    Released,
    /// The pointer left the square while held: the gesture is a drag.
    Escaped,
    /// Neither, so the loop keeps draining the mouse range.
    Continue,
}

/// Classify one mouse message against the drag square. # C: O(1)
pub(crate) fn drag_step(message: u32, lparam: i64, rect: ipc::win32_window::WindowRect) -> DragStep {
    if message == ipc::win32_window::WM_LBUTTONUP { return DragStep::Released; }
    if message != ipc::win32_window::WM_MOUSEMOVE { return DragStep::Continue; }
    let (x, y) = mouse_point(lparam);
    if pt_in_rect(rect, x, y) { DragStep::Continue } else { DragStep::Escaped }
}

/// What one round of the input-idle wait observed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IdleWake {
    /// The waited process ended before it went idle.
    ProcessEnded,
    /// The process reported that it has drained its input.
    Idle,
    /// Neither happened before the caller's timeout.
    TimedOut,
    /// The wait could not be started at all.
    Failed,
}

/// The DWORD one input-idle wait answers. Both an ended process and an idle
/// one report success; only the timeout and the refusal keep their wait codes.
/// # C: O(1)
pub(crate) const fn idle_result(wake: IdleWake) -> u64 {
    match wake {
        IdleWake::ProcessEnded | IdleWake::Idle => WAIT_OBJECT_0,
        IdleWake::TimedOut => WAIT_TIMEOUT,
        IdleWake::Failed => WAIT_FAILED,
    }
}

/// An infinite wait never expires; every other one expires once the elapsed
/// milliseconds pass the requested timeout. # C: O(1)
pub(crate) const fn idle_expired(timeout_ms: u32, elapsed_ms: u64) -> bool {
    timeout_ms != INFINITE && elapsed_ms > timeout_ms as u64
}

#[cfg(test)]
#[path = "tests/drag_raw.rs"]
mod tests;
