//! Pointer-input ordinals: the pointer type and information-list queries, the
//! pointer device rectangles, and touch injection.
//!
//! Every decision the four answer lives here or in the canonical pointer owner;
//! the kernel binding only reads and writes the client records.

use ipc::win32_window::pointer;

pub(crate) const GET_POINTER_DEVICE_RECTS: u64 = 0x142b;
pub(crate) const GET_POINTER_INFO_LIST: u64 = 0x142e;
pub(crate) const GET_POINTER_TYPE: u64 = 0x1431;
pub(crate) const INITIALIZE_TOUCH_INJECTION: u64 = 0x147f;

/// `RECT`: four signed edges.
pub(crate) const RECT_BYTES: usize = 16;
/// The device-rectangle query names the whole virtual screen with this handle;
/// every other handle names a pointer device, of which none is present.
pub(crate) const INVALID_HANDLE_VALUE: u64 = u64::MAX;

/// One entry, one pointer: the counts an answered information-list reports.
pub(crate) const ONE_ENTRY: u32 = 1;

/// Encode a `RECT`. # C: O(1)
pub(crate) fn encode_rect(rect: ipc::win32_window::WindowRect) -> [u8; RECT_BYTES] {
    let mut bytes = [0u8; RECT_BYTES];
    for (index, value) in [rect.left, rect.top, rect.right, rect.bottom].iter().enumerate() {
        bytes[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes
}

/// The device rectangle of the virtual screen: its extent in hundredths of a
/// millimetre, anchored at the origin. The display rectangle is the virtual
/// screen itself. # C: O(1)
pub(crate) fn device_rect(screen: ipc::win32_window::WindowRect, dpi: i32) -> ipc::win32_window::WindowRect {
    ipc::win32_window::WindowRect { left: 0, top: 0,
        right: pointer::himetric_of(screen.right.saturating_sub(screen.left), dpi),
        bottom: pointer::himetric_of(screen.bottom.saturating_sub(screen.top), dpi) }
}

/// Encode one `POINTER_INFO` on the 64-bit client ABI. The himetric locations
/// are the pixel locations scaled by the system dots per inch, and the raw
/// locations repeat the mapped ones because no pointer device reports a
/// separate raw position. # C: O(1)
pub(crate) fn encode_pointer_info(info: pointer::PointerInfo, dpi: i32) -> [u8; pointer::POINTER_INFO_BYTES] {
    let mut bytes = [0u8; pointer::POINTER_INFO_BYTES];
    let mut put32 = |at: usize, value: u32| bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    put32(0, info.kind);
    put32(4, info.id);
    put32(8, info.frame);
    put32(12, info.flags);
    bytes[16..24].copy_from_slice(&info.source_device.to_le_bytes());
    bytes[24..32].copy_from_slice(&(info.target as u64).to_le_bytes());
    let himetric = (pointer::himetric_of(info.pixel.0, dpi), pointer::himetric_of(info.pixel.1, dpi));
    for (at, point) in [(32, info.pixel), (40, himetric), (48, info.pixel), (56, himetric)] {
        bytes[at..at + 4].copy_from_slice(&point.0.to_le_bytes());
        bytes[at + 4..at + 8].copy_from_slice(&point.1.to_le_bytes());
    }
    bytes[64..68].copy_from_slice(&info.time.to_le_bytes());
    bytes[68..72].copy_from_slice(&info.history.to_le_bytes());
    bytes[72..76].copy_from_slice(&info.input_data.to_le_bytes());
    bytes[76..80].copy_from_slice(&info.key_states.to_le_bytes());
    bytes[80..88].copy_from_slice(&info.performance_count.to_le_bytes());
    bytes[88..92].copy_from_slice(&info.button_change.to_le_bytes());
    bytes
}

/// Why an information-list request was refused, or the record size it is
/// answered in.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InfoList { Refused, Answer(usize) }

/// Admit one information-list request against the type and the declared record
/// size, and demand every output pointer the answer writes through. # C: O(1)
pub(crate) fn check_info_list(kind: u32, size: u64, entry_count: u64, pointer_count: u64, info: u64) -> InfoList {
    if !pointer::info_list_admitted(kind, size) { return InfoList::Refused; }
    if entry_count == 0 || pointer_count == 0 || info == 0 { return InfoList::Refused; }
    InfoList::Answer(size as usize)
}

/// The ordinals this family answers. The kernel router consults this before
/// any argument is read, so an ordinal admitted by the argument table and
/// absent here would fall through the whole chain rather than reach a router.
/// # C: O(1)
pub(crate) const fn claims(ordinal: u64) -> bool {
    matches!(ordinal, GET_POINTER_DEVICE_RECTS | GET_POINTER_INFO_LIST | GET_POINTER_TYPE | INITIALIZE_TOUCH_INJECTION)
}

#[cfg(target_os = "oxide-kernel")]
#[path = "pointer_raw/kernel.rs"]
pub(super) mod kernel;

#[cfg(test)]
#[path = "pointer_raw/tests.rs"]
mod tests;
