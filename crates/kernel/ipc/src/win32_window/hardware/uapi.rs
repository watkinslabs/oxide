//! Message numbers, activation codes and virtual keys the retrieval-time
//! hardware stage decides with.

/// Sent to the clicked window before the click is delivered; the answer says
/// whether the window becomes foreground and whether the click survives.
pub const WM_MOUSEACTIVATE: u32 = 0x0021;
/// Sent up the child chain when a pointer button goes down over a child.
pub const WM_PARENTNOTIFY: u32 = 0x0210;
/// Posted to the window a help key was pressed over.
pub const WM_KEYF1: u32 = 0x004d;
/// Posted for the applications key, and sent for the media/browser keys.
pub const WM_CONTEXTMENU: u32 = 0x007b;
pub const WM_APPCOMMAND: u32 = 0x0319;
/// The `WM_APPCOMMAND` device word naming the keyboard as the source.
pub const FAPPCOMMAND_KEY: u32 = 0;

pub const MA_ACTIVATE: u64 = 1;
pub const MA_ACTIVATEANDEAT: u64 = 2;
pub const MA_NOACTIVATE: u64 = 3;
pub const MA_NOACTIVATEANDEAT: u64 = 4;

/// First and last message of the client pointer range.
pub const WM_MOUSEMOVE: u32 = 0x0200;
pub const WM_MOUSELAST: u32 = 0x020e;
pub const WM_LBUTTONDOWN: u32 = 0x0201;
pub const WM_LBUTTONDBLCLK: u32 = 0x0203;
pub const WM_RBUTTONDOWN: u32 = 0x0204;
pub const WM_MBUTTONDOWN: u32 = 0x0207;
pub const WM_XBUTTONDOWN: u32 = 0x020b;
pub const WM_MOUSEWHEEL: u32 = 0x020a;
/// First and last message of the nonclient pointer range, which a client
/// pointer message is renumbered into when the point is not over the client
/// area.
pub const WM_NCMOUSEMOVE: u32 = 0x00a0;
pub const WM_NCMOUSELAST: u32 = 0x00ae;

/// First and last message of the keyboard range, whose last member is the
/// UTF-16 character message.
pub const WM_KEYFIRST: u32 = 0x0100;
pub const WM_UNICHAR: u32 = 0x0109;
pub const WM_KEYLAST: u32 = WM_UNICHAR;
pub const WM_KEYDOWN: u32 = 0x0100;
pub const WM_KEYUP: u32 = 0x0101;
pub const WM_CHAR: u32 = 0x0102;
pub const WM_SYSKEYDOWN: u32 = 0x0104;
pub const WM_SYSKEYUP: u32 = 0x0105;

pub const VK_SHIFT: u64 = 0x10;
pub const VK_CONTROL: u64 = 0x11;
pub const VK_MENU: u64 = 0x12;
pub const VK_APPS: u64 = 0x5d;
pub const VK_F1: u64 = 0x70;
pub const VK_LSHIFT: u64 = 0xa0;
pub const VK_RSHIFT: u64 = 0xa1;
pub const VK_LCONTROL: u64 = 0xa2;
pub const VK_RCONTROL: u64 = 0xa3;
pub const VK_LMENU: u64 = 0xa4;
pub const VK_RMENU: u64 = 0xa5;
/// First and last virtual key that carries an application command.
pub const VK_BROWSER_BACK: u64 = 0xa6;
pub const VK_LAUNCH_APP2: u64 = 0xb7;

pub const WS_CHILD: u32 = 0x4000_0000;
pub const WS_POPUP: u32 = 0x8000_0000;
/// Class style asking for double-click synthesis over the client area.
pub const CS_DBLCLKS: u32 = 0x0000_0008;

/// System metric indexes naming the double-click rectangle.
pub const SM_CXDOUBLECLK: i32 = 36;
pub const SM_CYDOUBLECLK: i32 = 37;

/// Whether a queued message is one the hardware stage owns. # C: O(1)
pub const fn is_hardware_message(message: u32) -> bool {
    is_mouse_message(message) || is_keyboard_message(message)
}

/// # C: O(1)
pub const fn is_keyboard_message(message: u32) -> bool { message >= WM_KEYFIRST && message <= WM_KEYLAST }

/// # C: O(1)
pub const fn is_mouse_message(message: u32) -> bool {
    (message >= WM_NCMOUSEMOVE && message <= WM_NCMOUSELAST) || (message >= WM_MOUSEMOVE && message <= WM_MOUSELAST)
}

/// Whether a pointer message is a button going down, which is the only
/// transition that notifies a parent or decides activation. # C: O(1)
pub const fn is_button_down(message: u32) -> bool {
    matches!(message, WM_LBUTTONDOWN | WM_RBUTTONDOWN | WM_MBUTTONDOWN | WM_XBUTTONDOWN)
}

/// Pack a point into a message parameter. # C: O(1)
pub const fn make_point(x: i32, y: i32) -> i64 { (((y as u32 as u64) << 16) | (x as u32 as u64 & 0xffff)) as i64 }

/// Pack a hit-test code and the message that produced it into the
/// `WM_MOUSEACTIVATE` and `WM_SETCURSOR` parameter. # C: O(1)
pub const fn make_hit_param(hit_test: i32, message: u32) -> i64 { (((message as u64) << 16) | (hit_test as i16 as u16 as u64)) as i64 }

/// Split a message parameter carrying a point. # C: O(1)
pub const fn split_point(lparam: i64) -> (i32, i32) {
    ((lparam as u64 as u16 as i16) as i32, (((lparam as u64) >> 16) as u16 as i16) as i32)
}
