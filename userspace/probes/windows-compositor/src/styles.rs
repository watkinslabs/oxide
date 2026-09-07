//! Window style bits the backend's presentation decisions read.

pub const WS_CHILD: u32 = 0x4000_0000;
pub const WS_POPUP: u32 = 0x8000_0000;
pub const WS_VISIBLE: u32 = 0x1000_0000;
pub const WS_BORDER: u32 = 0x0080_0000;
pub const WS_DLGFRAME: u32 = 0x0040_0000;
/// Both frame bits together: a window has a caption only when it has both.
pub const WS_CAPTION: u32 = WS_BORDER | WS_DLGFRAME;
pub const WS_SYSMENU: u32 = 0x0008_0000;
pub const WS_THICKFRAME: u32 = 0x0004_0000;

pub const WS_EX_APPWINDOW: u32 = 0x0004_0000;
