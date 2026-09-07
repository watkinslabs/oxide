//! Window style and extended-style bits shared by the window-state owner.

pub const WS_POPUP: u32 = 0x8000_0000;
pub const WS_CHILD: u32 = 0x4000_0000;
pub const WS_MINIMIZE: u32 = 0x2000_0000;
pub const WS_VISIBLE: u32 = 0x1000_0000;
pub const WS_DISABLED: u32 = 0x0800_0000;
pub const WS_MAXIMIZE: u32 = 0x0100_0000;
pub const WS_CAPTION: u32 = 0x00c0_0000;
pub const WS_DLGFRAME: u32 = 0x0040_0000;
pub const WS_VSCROLL: u32 = 0x0020_0000;
pub const WS_HSCROLL: u32 = 0x0010_0000;
pub const WS_SYSMENU: u32 = 0x0008_0000;
pub const WS_THICKFRAME: u32 = 0x0004_0000;
pub const WS_MINIMIZEBOX: u32 = 0x0002_0000;
pub const WS_MAXIMIZEBOX: u32 = 0x0001_0000;
pub const WS_TABSTOP: u32 = 0x0001_0000;

pub const WS_EX_TOPMOST: u32 = 0x0000_0008;
pub const WS_EX_TRANSPARENT: u32 = 0x0000_0020;
pub const WS_EX_TOOLWINDOW: u32 = 0x0000_0080;
pub const WS_EX_CONTEXTHELP: u32 = 0x0000_0400;
pub const WS_EX_LAYERED: u32 = 0x0008_0000;

/// Class style bit that removes the system menu's close item.
pub const CS_NOCLOSE: u32 = 0x0200;

/// GetWindow relationships.
pub const GW_HWNDFIRST: u32 = 0;
pub const GW_HWNDLAST: u32 = 1;
pub const GW_HWNDNEXT: u32 = 2;
pub const GW_HWNDPREV: u32 = 3;
pub const GW_OWNER: u32 = 4;
pub const GW_CHILD: u32 = 5;
pub const GW_ENABLEDPOPUP: u32 = 6;
