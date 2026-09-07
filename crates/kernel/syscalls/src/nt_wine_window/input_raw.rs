//! Cursor position, capture, queue-status and pointer-tracking ordinals: the
//! record layouts and every decision each answers.

pub(crate) const CLIP_CURSOR: u64 = 0x1350;
pub(crate) const GET_CLIP_CURSOR: u64 = 0x13da;
pub(crate) const GET_CURSOR_INFO: u64 = 0x13e9;
pub(crate) const GET_CURSOR_POS: u64 = 0x13ea;
pub(crate) const SET_CURSOR_POS: u64 = 0x154a;
pub(crate) const GET_MOUSE_MOVE_POINTS_EX: u64 = 0x141f;
pub(crate) const TRACK_MOUSE_EVENT: u64 = 0x15d3;
pub(crate) const SET_CAPTURE: u64 = 0x153a;
pub(crate) const RELEASE_CAPTURE: u64 = 0x1508;
pub(crate) const GET_MESSAGE_POS: u64 = 0x141c;
pub(crate) const SET_MESSAGE_EXTRA_INFO: u64 = 0x156d;
pub(crate) const GET_QUEUE_STATUS: u64 = 0x143b;
pub(crate) const GET_THREAD_STATE: u64 = 0x144e;
pub(crate) const GET_CURRENT_INPUT_MESSAGE_SOURCE: u64 = 0x13e6;
pub(crate) const GET_DOUBLE_CLICK_TIME: u64 = 0x13f5;
pub(crate) const REGISTER_HOTKEY: u64 = 0x14f3;
pub(crate) const UNREGISTER_HOTKEY: u64 = 0x15e0;
pub(crate) const ATTACH_THREAD_INPUT: u64 = 0x1322;
pub(crate) const SEND_INPUT: u64 = 0x152e;
pub(crate) const ENABLE_MOUSE_IN_POINTER: u64 = 0x13a9;
pub(crate) const ENABLE_MOUSE_IN_POINTER_FOR_THREAD: u64 = 0x13aa;
pub(crate) const IS_MOUSE_IN_POINTER_ENABLED: u64 = 0x1490;
pub(crate) const REGISTER_TOUCH_PAD_CAPABLE: u64 = 0x1503;

/// `RECT`: four signed edges.
pub(crate) const RECT_BYTES: usize = 16;
/// `POINT`: two signed coordinates.
pub(crate) const POINT_BYTES: usize = 8;
/// `CURSORINFO` on the 64-bit client ABI.
pub(crate) const CURSORINFO_BYTES: usize = 24;
/// `MOUSEMOVEPOINT` on the 64-bit client ABI.
pub(crate) const MOUSEMOVEPOINT_BYTES: usize = 24;
/// `TRACKMOUSEEVENT` on the 64-bit client ABI.
pub(crate) const TRACKMOUSEEVENT_BYTES: usize = 24;
/// `INPUT_MESSAGE_SOURCE`: the device type then the origin.
pub(crate) const INPUT_MESSAGE_SOURCE_BYTES: usize = 8;
/// `INPUT` on the 64-bit client ABI; the size the caller must declare.
pub(crate) const INPUT_BYTES: u64 = 40;
/// The cursor is displayed.
pub(crate) const CURSOR_SHOWING: u32 = 0x0000_0001;
/// Positions the move-point history holds.
pub(crate) const MOVE_POINT_HISTORY: usize = 64;
/// The only resolution the move-point query admits.
pub(crate) const GMMP_USE_DISPLAY_POINTS: u32 = 1;
/// Default double-click interval in milliseconds.
pub(crate) const DEFAULT_DOUBLE_CLICK_MS: u32 = 500;

/// Decode a `RECT`. # C: O(1)
pub(crate) fn decode_rect(bytes: &[u8; RECT_BYTES]) -> ipc::win32_window::WindowRect {
    let word = |index: usize| i32::from_le_bytes([bytes[index * 4], bytes[index * 4 + 1], bytes[index * 4 + 2], bytes[index * 4 + 3]]);
    ipc::win32_window::WindowRect { left: word(0), top: word(1), right: word(2), bottom: word(3) }
}

/// Encode a `RECT`. # C: O(1)
pub(crate) fn encode_rect(rect: ipc::win32_window::WindowRect) -> [u8; RECT_BYTES] {
    let mut bytes = [0u8; RECT_BYTES];
    for (index, value) in [rect.left, rect.top, rect.right, rect.bottom].iter().enumerate() {
        bytes[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes
}

/// Encode a `CURSORINFO`. # C: O(1)
pub(crate) fn encode_cursor_info(cursor: u64, showing: bool, point: (i32, i32)) -> [u8; CURSORINFO_BYTES] {
    let mut bytes = [0u8; CURSORINFO_BYTES];
    bytes[0..4].copy_from_slice(&(CURSORINFO_BYTES as u32).to_le_bytes());
    bytes[4..8].copy_from_slice(&(if showing { CURSOR_SHOWING } else { 0 }).to_le_bytes());
    bytes[8..16].copy_from_slice(&cursor.to_le_bytes());
    bytes[16..20].copy_from_slice(&point.0.to_le_bytes());
    bytes[20..24].copy_from_slice(&point.1.to_le_bytes());
    bytes
}

/// Encode one `MOUSEMOVEPOINT`. # C: O(1)
pub(crate) fn encode_move_point(point: ipc::win32_window::CursorPos) -> [u8; MOUSEMOVEPOINT_BYTES] {
    let mut bytes = [0u8; MOUSEMOVEPOINT_BYTES];
    bytes[0..4].copy_from_slice(&point.x.to_le_bytes());
    bytes[4..8].copy_from_slice(&point.y.to_le_bytes());
    bytes[8..12].copy_from_slice(&point.time.to_le_bytes());
    bytes[16..24].copy_from_slice(&point.info.to_le_bytes());
    bytes
}

/// Why a move-point query was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MovePointError {
    /// The record size, the count, or the resolution is out of range.
    InvalidParameter,
    /// A required buffer pointer is absent.
    NoAccess,
    /// The probe names no recorded position.
    PointNotFound,
}

/// Admit one move-point request before any history is read. # C: O(1)
pub(crate) fn check_move_points(size: u32, probe: u64, out: u64, count: i32, resolution: u32) -> Result<(), MovePointError> {
    if size as usize != MOUSEMOVEPOINT_BYTES { return Err(MovePointError::InvalidParameter); }
    if count < 0 || count as usize > MOVE_POINT_HISTORY { return Err(MovePointError::InvalidParameter); }
    if probe == 0 || (out == 0 && count != 0) { return Err(MovePointError::NoAccess); }
    if resolution != GMMP_USE_DISPLAY_POINTS { return Err(MovePointError::PointNotFound); }
    Ok(())
}

/// Every `SendInput` record must declare the client `INPUT` size, and a zero
/// count or absent array is refused. # C: O(1)
pub(crate) const fn check_send_input(count: u32, inputs: u64, size: u64) -> bool {
    size == INPUT_BYTES && count != 0 && inputs != 0
}

/// `INPUT` record kinds.
pub(crate) const INPUT_MOUSE: u32 = 0;
pub(crate) const INPUT_KEYBOARD: u32 = 1;
pub(crate) const INPUT_HARDWARE: u32 = 2;

/// `MOUSEINPUT` field offsets inside an `INPUT` record.
pub(crate) const MOUSE_DX: u64 = 8;
pub(crate) const MOUSE_DY: u64 = 12;
pub(crate) const MOUSE_DATA: u64 = 16;
pub(crate) const MOUSE_FLAGS: u64 = 20;
/// `KEYBDINPUT` field offsets inside an `INPUT` record.
pub(crate) const KEY_VK: u64 = 8;
#[allow(dead_code)] // KI-0673
pub(crate) const KEY_SCAN: u64 = 10;
pub(crate) const KEY_FLAGS: u64 = 12;

pub(crate) const MOUSEEVENTF_MOVE: u32 = 0x0001;
pub(crate) const MOUSEEVENTF_LEFTDOWN: u32 = 0x0002;
pub(crate) const MOUSEEVENTF_LEFTUP: u32 = 0x0004;
pub(crate) const MOUSEEVENTF_RIGHTDOWN: u32 = 0x0008;
pub(crate) const MOUSEEVENTF_RIGHTUP: u32 = 0x0010;
pub(crate) const MOUSEEVENTF_MIDDLEDOWN: u32 = 0x0020;
pub(crate) const MOUSEEVENTF_MIDDLEUP: u32 = 0x0040;
pub(crate) const MOUSEEVENTF_WHEEL: u32 = 0x0800;
pub(crate) const MOUSEEVENTF_ABSOLUTE: u32 = 0x8000;
pub(crate) const KEYEVENTF_KEYUP: u32 = 0x0002;
/// Absolute coordinates are normalized over this range before mapping onto
/// the screen rectangle.
#[allow(dead_code)] // KI-0673
pub(crate) const ABSOLUTE_RANGE: i64 = 1 << 16;

/// One injected input transition, in the order the caller's record produces it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SendStep {
    /// Screen-absolute cursor destination.
    MoveTo { x: i32, y: i32 },
    /// Cursor displacement.
    MoveBy { dx: i32, dy: i32 },
    /// Linux button code and its new state.
    Button { code: u16, pressed: bool },
    /// Wheel notches, positive away from the user.
    Wheel { notches: i32 },
    /// Virtual key and its new state.
    Key { vkey: u16, pressed: bool },
}

/// Steps this array can hold: a move plus each button transition and a wheel.
pub(crate) const MAX_STEPS: usize = 5;

/// Map an absolute injected coordinate onto the screen rectangle. # C: O(1)
pub(crate) fn absolute_point(dx: i32, dy: i32, screen: ipc::win32_window::WindowRect) -> (i32, i32) {
    let map = |value: i32, low: i32, high: i32| {
        let span = (high - low) as i64;
        (low as i64 + ((value as i64 * span) >> 16)) as i32
    };
    (map(dx, screen.left, screen.right), map(dy, screen.top, screen.bottom))
}

/// Decode one mouse record into its transitions. # C: O(1)
pub(crate) fn mouse_steps(dx: i32, dy: i32, data: u32, flags: u32, screen: ipc::win32_window::WindowRect)
    -> ([SendStep; MAX_STEPS], usize) {
    const BUTTONS: [(u32, u32, u16); 3] = [
        (MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP, ipc::win32_window::BTN_LEFT),
        (MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP, ipc::win32_window::BTN_RIGHT),
        (MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP, ipc::win32_window::BTN_MIDDLE),
    ];
    let mut steps = [SendStep::MoveBy { dx: 0, dy: 0 }; MAX_STEPS];
    let mut count = 0;
    let mut push = |step| { if count < MAX_STEPS { steps[count] = step; count += 1; } };
    if flags & MOUSEEVENTF_MOVE != 0 {
        if flags & MOUSEEVENTF_ABSOLUTE != 0 {
            let (x, y) = absolute_point(dx, dy, screen);
            push(SendStep::MoveTo { x, y });
        } else { push(SendStep::MoveBy { dx, dy }); }
    }
    for (down, up, code) in BUTTONS {
        if flags & down != 0 { push(SendStep::Button { code, pressed: true }); }
        if flags & up != 0 { push(SendStep::Button { code, pressed: false }); }
    }
    // The wheel notch is the signed multiple of the standard detent.
    if flags & MOUSEEVENTF_WHEEL != 0 { push(SendStep::Wheel { notches: (data as i32) / 120 }); }
    (steps, count)
}

/// Decode one keyboard record. # C: O(1)
pub(crate) const fn key_step(vkey: u16, flags: u32) -> SendStep {
    SendStep::Key { vkey, pressed: flags & KEYEVENTF_KEYUP == 0 }
}

#[cfg(target_os = "oxide-kernel")]
#[path = "input_raw/kernel.rs"]
pub(super) mod kernel;

#[cfg(test)]
#[path = "input_raw/tests.rs"]
mod tests;
