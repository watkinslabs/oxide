//! Raw status-part visibility query; no output writes or GDI state mutation.
use ipc::win32_gdi::Rect;
use ipc::win32_window::PaintRegion;
pub(crate) const RECT_VISIBLE: u64 = 0x1258;
const RECT_BYTES: u64 = 16;

/// Validate DC before copying input, then evaluate the canonical clip snapshot. # C: owner snapshot cost
pub(crate) fn route(ordinal: u64, args: &[u64], snapshot: impl FnOnce(u64) -> Option<PaintRegion>,
    read: impl FnOnce(u64) -> Option<[u8; 16]>, visible: impl FnOnce(PaintRegion, Rect) -> bool) -> Option<u64> {
    if ordinal != RECT_VISIBLE { return None; }
    let [dc, pointer, ..] = args else { return Some(0); };
    let Some(clip) = snapshot(*dc) else { return Some(0); };
    if *pointer == 0 || pointer.checked_add(RECT_BYTES).is_none() { return Some(0); }
    let Some(bytes) = read(*pointer) else { return Some(0); };
    let value = |offset| i32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
    let rect = Rect { left: value(0), top: value(4), right: value(8), bottom: value(12) };
    Some(u64::from(visible(clip, rect)))
}

#[cfg(target_os = "oxide-kernel")]
#[path = "visibility_raw/kernel.rs"]
pub(crate) mod kernel;
#[cfg(test)]
#[path = "tests/visibility_raw.rs"]
mod tests;
