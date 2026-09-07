//! Menu ordinal numbers, the standard window-menu commands, and the
//! `MENUINFO` record codec.
use ipc::win32_menu::{MenuInfo, MENUINFO_BYTES};

pub(crate) const END_MENU: u64 = 0x13bb;
pub(crate) const GET_SYSTEM_MENU: u64 = 0x144c;
pub(crate) const HILITE_MENU_ITEM: u64 = 0x146f;
pub(crate) const MENU_ITEM_FROM_POINT: u64 = 0x14b3;
pub(crate) const SET_MENU_CONTEXT_HELP_ID: u64 = 0x156a;
pub(crate) const SET_MENU_DEFAULT_ITEM: u64 = 0x156b;
pub(crate) const SET_SYSTEM_MENU: u64 = 0x158a;
pub(crate) const THUNKED_MENU_INFO: u64 = 0x15cf;
pub(crate) const TRACK_POPUP_MENU_EX: u64 = 0x15d4;

pub(crate) const SC_SIZE: u32 = 0xf000;
pub(crate) const SC_MOVE: u32 = 0xf010;
pub(crate) const SC_MINIMIZE: u32 = 0xf020;
pub(crate) const SC_MAXIMIZE: u32 = 0xf030;
pub(crate) const SC_CLOSE: u32 = 0xf060;
pub(crate) const SC_RESTORE: u32 = 0xf120;
/// A separator carries no command.
pub(crate) const SC_SEPARATOR: u32 = 0;

pub(crate) const WS_SYSMENU: u32 = 0x0008_0000;
#[cfg(target_os = "oxide-kernel")]
pub(crate) use ipc::win32_menu::track::WM_CANCELMODE;
pub(crate) const ERROR_POPUP_ALREADY_ACTIVE: u32 = 1446;
pub(crate) const ERROR_INVALID_MENU_HANDLE: u32 = 1401;
pub(crate) const ERROR_NOACCESS: u32 = 998;
pub(crate) const ERROR_INVALID_WINDOW_HANDLE: u32 = 1400;
pub(crate) const ERROR_INVALID_PARAMETER: u32 = 87;

/// The window menu's commands, in the order a fresh system menu carries them.
/// The text is what the caption menu shows for each command.
pub(crate) const SYSTEM_MENU_COMMANDS: [(u32, &[u16]); 7] = [
    (SC_RESTORE, &[b'R' as u16, b'e' as u16, b's' as u16, b't' as u16, b'o' as u16, b'r' as u16, b'e' as u16]),
    (SC_MOVE, &[b'M' as u16, b'o' as u16, b'v' as u16, b'e' as u16]),
    (SC_SIZE, &[b'S' as u16, b'i' as u16, b'z' as u16, b'e' as u16]),
    (SC_MINIMIZE, &[b'M' as u16, b'i' as u16, b'n' as u16, b'i' as u16, b'm' as u16, b'i' as u16, b'z' as u16, b'e' as u16]),
    (SC_MAXIMIZE, &[b'M' as u16, b'a' as u16, b'x' as u16, b'i' as u16, b'm' as u16, b'i' as u16, b'z' as u16, b'e' as u16]),
    (SC_SEPARATOR, &[]),
    (SC_CLOSE, &[b'C' as u16, b'l' as u16, b'o' as u16, b's' as u16, b'e' as u16]),
];

/// Only a window whose style carries a system menu gets one. # C: O(1)
pub(crate) const fn has_system_menu(style: u32) -> bool { style & WS_SYSMENU != 0 }

/// A revert request reports no menu, having discarded the one it replaced.
/// # C: O(1)
pub(crate) const fn system_menu_result(revert: bool, popup: u64) -> u64 { if revert { 0 } else { popup } }

/// Decode a `MENUINFO`. A record of the wrong size names nothing. # C: O(1)
pub(crate) fn decode_menu_info(bytes: [u8; MENUINFO_BYTES as usize]) -> Option<(u32, MenuInfo)> {
    let dword = |offset: usize| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
    let qword = |offset: usize| u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
    if dword(0) != MENUINFO_BYTES { return None; }
    Some((dword(4), MenuInfo { style: dword(8), max_height: dword(12), background: qword(16),
        context_help_id: dword(24), data: qword(32) }))
}

/// Encode a `MENUINFO` over the caller's record, leaving its mask in place.
/// # C: O(1)
pub(crate) fn encode_menu_info(mut bytes: [u8; MENUINFO_BYTES as usize], info: MenuInfo) -> [u8; MENUINFO_BYTES as usize] {
    bytes[8..12].copy_from_slice(&info.style.to_le_bytes());
    bytes[12..16].copy_from_slice(&info.max_height.to_le_bytes());
    bytes[16..24].copy_from_slice(&info.background.to_le_bytes());
    bytes[24..28].copy_from_slice(&info.context_help_id.to_le_bytes());
    bytes[32..40].copy_from_slice(&info.data.to_le_bytes());
    bytes
}

#[cfg(test)]
#[path = "../tests/menu_raw.rs"]
mod tests;
