//! Cursor and icon object ordinals: the layouts their records use and the
//! decisions each answer before any owner state is touched.

use ipc::win32_window::IconInfo;

pub(crate) const SHOW_CURSOR: u64 = 0x15b8;
pub(crate) const DESTROY_CURSOR: u64 = 0x137f;
pub(crate) const SET_CURSOR_ICON_DATA: u64 = 0x1548;
pub(crate) const FIND_EXISTING_CURSOR_ICON: u64 = 0x13c5;
pub(crate) const GET_ICON_INFO: u64 = 0x1403;
pub(crate) const GET_ICON_SIZE: u64 = 0x1404;
pub(crate) const GET_CURSOR_FRAME_INFO: u64 = 0x13e8;
pub(crate) const INTERNAL_GET_WINDOW_ICON: u64 = 0x1488;

/// `struct cursoricon_frame` on the 64-bit client ABI.
pub(crate) const FRAME_WIDTH: u64 = 0;
pub(crate) const FRAME_HEIGHT: u64 = 4;
pub(crate) const FRAME_COLOR: u64 = 8;
pub(crate) const FRAME_ALPHA: u64 = 16;
pub(crate) const FRAME_MASK: u64 = 24;
pub(crate) const FRAME_HOTSPOT_X: u64 = 32;
pub(crate) const FRAME_HOTSPOT_Y: u64 = 36;
pub(crate) const FRAME_BYTES: u64 = 40;

/// `struct cursoricon_desc` on the 64-bit client ABI.
pub(crate) const DESC_FLAGS: u64 = 0;
pub(crate) const DESC_NUM_STEPS: u64 = 4;
pub(crate) const DESC_NUM_FRAMES: u64 = 8;
pub(crate) const DESC_DELAY: u64 = 12;
pub(crate) const DESC_FRAMES: u64 = 16;
pub(crate) const DESC_FRAME_SEQ: u64 = 24;
pub(crate) const DESC_FRAME_RATES: u64 = 32;
pub(crate) const DESC_RSRC: u64 = 40;

/// `UNICODE_STRING` on the 64-bit client ABI.
pub(crate) const STRING_LENGTH: u64 = 0;
pub(crate) const STRING_MAXIMUM: u64 = 2;
pub(crate) const STRING_BUFFER: u64 = 8;

/// `ICONINFO` on the 64-bit client ABI.
pub(crate) const ICONINFO_BYTES: usize = 32;
const ICONINFO_IS_ICON: usize = 0;
const ICONINFO_HOTSPOT_X: usize = 4;
const ICONINFO_HOTSPOT_Y: usize = 8;
const ICONINFO_MASK: usize = 16;
const ICONINFO_COLOR: usize = 24;

/// Frames a fill request may carry, bounding the record read from user space.
pub(crate) const MAX_FRAMES: usize = 256;
/// Characters a resource name may carry.
pub(crate) const MAX_RESOURCE_NAME: usize = 256;

/// A resource name whose buffer is a small integer names an integer resource
/// rather than a string. # C: O(1)
pub(crate) const fn integer_resource(buffer: u64) -> Option<u16> {
    if buffer > u16::MAX as u64 { return None; }
    Some(buffer as u16)
}

/// Encode one `ICONINFO`. # C: O(1)
pub(crate) fn encode_icon_info(info: IconInfo) -> [u8; ICONINFO_BYTES] {
    let mut bytes = [0u8; ICONINFO_BYTES];
    bytes[ICONINFO_IS_ICON..ICONINFO_IS_ICON + 4].copy_from_slice(&(info.is_icon as u32).to_le_bytes());
    bytes[ICONINFO_HOTSPOT_X..ICONINFO_HOTSPOT_X + 4].copy_from_slice(&(info.hotspot_x as u32).to_le_bytes());
    bytes[ICONINFO_HOTSPOT_Y..ICONINFO_HOTSPOT_Y + 4].copy_from_slice(&(info.hotspot_y as u32).to_le_bytes());
    bytes[ICONINFO_MASK..ICONINFO_MASK + 8].copy_from_slice(&info.mask.to_le_bytes());
    bytes[ICONINFO_COLOR..ICONINFO_COLOR + 8].copy_from_slice(&info.color.to_le_bytes());
    bytes
}

#[cfg(target_os = "oxide-kernel")]
#[path = "cursor_icon_raw/kernel.rs"]
pub(super) mod kernel;

#[cfg(test)]
#[path = "cursor_icon_raw/tests.rs"]
mod tests;
