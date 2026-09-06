use ipc::win32_window::WindowRect;
pub(super) const NOSIZE: u32 = 0x0001;
pub(super) const NOMOVE: u32 = 0x0002;
pub(super) const NOZORDER: u32 = 0x0004;
pub(super) const NOREDRAW: u32 = 0x0008;
pub(super) const NOACTIVATE: u32 = 0x0010;
pub(super) const SHOW: u32 = 0x0040;
pub(super) const HIDE: u32 = 0x0080;
pub(super) const WS_CHILD: u32 = 0x4000_0000;
pub(super) const WS_POPUP: u32 = 0x8000_0000;
pub(super) const COORD_MIN: i32 = -32768;
pub(super) const COORD_MAX: i32 = 32767;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Order { Top, Bottom, Topmost, NotTopmost, After(u64) }
#[derive(Clone, Copy, Debug)]
pub(crate) struct Context { pub rect: WindowRect, pub parent: Option<u64>, pub style: u32, pub visible: bool }
/// Transient command, never persistent placement state. Flags retain owner execution semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Request { pub hwnd: u64, pub rect: WindowRect, pub order: Option<Order>, pub visible: Option<bool>, pub flags: u32 }

/// `NtUserMoveWindow(hwnd, x, y, cx, cy, repaint)` is `NtUserSetWindowPos`
/// with no z-order change, no activation, and no redraw unless asked.
/// # C: O(1)
pub(crate) fn move_window_args(args: &[u64; 6]) -> [u64; 7] {
    let mut flags = NOZORDER | NOACTIVATE;
    if args[5] as u32 == 0 { flags |= NOREDRAW; }
    [args[0], 0, args[1], args[2], args[3], args[4], u64::from(flags)]
}
