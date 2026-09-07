//! The one method-to-request mapping for `NtUserCallHwndParam`.
//!
//! Every family reaching this ordinal decodes through here. A second chain
//! kept beside this one could route a method the other refuses, which is how
//! a client comes to dereference the answer to a call the kernel never made.

use super::method::*;

/// Which of the three rectangles a rectangle query wants. The method decides
/// it; the parameter record carries only the destination and the dpi.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RectKind {
    /// Window rectangle in screen coordinates.
    Window,
    /// Window rectangle in the parent's client coordinates.
    Parent,
    /// Client rectangle at its own origin.
    Client,
    /// The rectangle the window's contents are presented through.
    Present,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Request {
    ClientToScreen { point: u64 },
    ScreenToClient { point: u64 },
    /// A class-long read. The window travels with the call, so only the
    /// slot, its width and its encoding are named here.
    ClassLong { offset: i32, width: usize, ansi: bool },
    GetScrollInfo { params: u64 },
    GetWindowInfo { info: u64 },
    /// The A and W forms differ only in the procedure encoding a wndproc slot
    /// answers with; both read the same slot at the same width.
    GetWindowLong { offset: i32, width: usize, ansi: bool },
    GetRect { kind: RectKind, params: u64 },
    GetWindowRelative { relationship: u32 },
    GetWindowThread { process: u64 },
    GetWindowWord { offset: i32 },
    IsChild { child: u64 },
    MapWindowPoints { params: u64 },
    MirrorRgn { region: u64 },
    MonitorFromWindow { flags: u32 },
    SetDialogInfo { info: u64 },
    SetMdiClientInfo { info: u64 },
    SendHardwareInput { params: u64 },
    ExposeWindowSurface { params: u64 },
    GetWinMonitorDpi { kind: u32 },
    SetRawWindowPos { params: u64 },
    GetPrivateData { params: u64 },
    SetPrivateData { params: u64 },
}

/// Name the request one method and its parameter word make. A method the
/// enumeration does not hold answers nothing. # C: O(1)
pub(crate) const fn decode(method: u32, param: u64) -> Option<Request> {
    Some(match method {
        CLIENT_TO_SCREEN => Request::ClientToScreen { point: param },
        SCREEN_TO_CLIENT => Request::ScreenToClient { point: param },
        GET_CHILD_RECT => Request::GetRect { kind: RectKind::Parent, params: param },
        GET_CLASS_LONG_A => Request::ClassLong { offset: param as u32 as i32, width: 4, ansi: true },
        GET_CLASS_LONG_W => Request::ClassLong { offset: param as u32 as i32, width: 4, ansi: false },
        GET_CLASS_LONG_PTR_A => Request::ClassLong { offset: param as u32 as i32, width: 8, ansi: true },
        GET_CLASS_LONG_PTR_W => Request::ClassLong { offset: param as u32 as i32, width: 8, ansi: false },
        GET_CLASS_WORD => Request::ClassLong { offset: param as u32 as i32, width: 2, ansi: true },
        GET_SCROLL_INFO => Request::GetScrollInfo { params: param },
        GET_WINDOW_INFO => Request::GetWindowInfo { info: param },
        GET_WINDOW_LONG_A => Request::GetWindowLong { offset: param as i32, width: 4, ansi: true },
        GET_WINDOW_LONG_W => Request::GetWindowLong { offset: param as i32, width: 4, ansi: false },
        GET_WINDOW_LONG_PTR_A => Request::GetWindowLong { offset: param as i32, width: 8, ansi: true },
        GET_WINDOW_LONG_PTR_W => Request::GetWindowLong { offset: param as i32, width: 8, ansi: false },
        GET_WINDOW_RECT => Request::GetRect { kind: RectKind::Window, params: param },
        GET_CLIENT_RECT => Request::GetRect { kind: RectKind::Client, params: param },
        GET_PRESENT_RECT => Request::GetRect { kind: RectKind::Present, params: param },
        GET_WINDOW_RELATIVE => Request::GetWindowRelative { relationship: param as u32 },
        GET_WINDOW_THREAD => Request::GetWindowThread { process: param },
        GET_WINDOW_WORD => Request::GetWindowWord { offset: param as i32 },
        IS_CHILD => Request::IsChild { child: param },
        MAP_WINDOW_POINTS => Request::MapWindowPoints { params: param },
        MIRROR_RGN => Request::MirrorRgn { region: param },
        MONITOR_FROM_WINDOW => Request::MonitorFromWindow { flags: param as u32 },
        SET_DIALOG_INFO => Request::SetDialogInfo { info: param },
        SET_MDI_CLIENT_INFO => Request::SetMdiClientInfo { info: param },
        SEND_HARDWARE_INPUT => Request::SendHardwareInput { params: param },
        EXPOSE_WINDOW_SURFACE => Request::ExposeWindowSurface { params: param },
        GET_WIN_MONITOR_DPI => Request::GetWinMonitorDpi { kind: param as u32 },
        SET_RAW_WINDOW_POS => Request::SetRawWindowPos { params: param },
        GET_PRIVATE_DATA => Request::GetPrivateData { params: param },
        SET_PRIVATE_DATA => Request::SetPrivateData { params: param },
        _ => return None,
    })
}

#[cfg(test)]
#[path = "tests/decode.rs"]
mod tests;
