//! Retrieval target and coordinate evidence for pointer dispatch.
#[cfg(feature = "debug-winpump")]
mod enabled {
use ipc::win32_window::{MessageFilter, WinMessage, WindowId};
/// # C: O(1)
pub(crate) fn hit(id: u64, raw: WinMessage, target: WindowId, hit: i32, remove: bool) {
    klog::write_raw(b"[WINDOWS-HARDWARE-HIT] id="); klog::write_hex_u64(id);
    klog::write_raw(b" source="); klog::write_hex_u64(raw.hwnd.map_or(0, |window| window.raw() as u64));
    klog::write_raw(b" target="); klog::write_hex_u64(target.raw() as u64);
    klog::write_raw(b" msg="); klog::write_hex_u64(raw.message as u64);
    klog::write_raw(b" screen="); klog::write_hex_u64(raw.lparam as u64);
    klog::write_raw(b" hit="); klog::write_hex_u64(hit as i64 as u64);
    klog::write_raw(b" remove="); klog::write_hex_u64(u64::from(remove)); klog::write_raw(b"\n");
}
/// # C: O(1)
pub(crate) fn prepared(id: u64, message: WinMessage) {
    klog::write_raw(b"[WINDOWS-HARDWARE-VIEW] id="); klog::write_hex_u64(id);
    klog::write_raw(b" target="); klog::write_hex_u64(message.hwnd.map_or(0, |window| window.raw() as u64));
    klog::write_raw(b" msg="); klog::write_hex_u64(message.message as u64);
    klog::write_raw(b" point="); klog::write_hex_u64(message.lparam as u64); klog::write_raw(b"\n");
}
/// # C: O(1)
pub(crate) fn filtered(id: u64, message: WinMessage, filter: MessageFilter) {
    klog::write_raw(b"[WINDOWS-HARDWARE-FILTER] id="); klog::write_hex_u64(id);
    klog::write_raw(b" target="); klog::write_hex_u64(message.hwnd.map_or(0, |window| window.raw() as u64));
    klog::write_raw(b" msg="); klog::write_hex_u64(message.message as u64);
    klog::write_raw(b" filter-hwnd="); klog::write_hex_u64(filter.hwnd.map_or(0, |window| window.raw() as u64));
    klog::write_raw(b" first="); klog::write_hex_u64(filter.first as u64);
    klog::write_raw(b" last="); klog::write_hex_u64(filter.last as u64); klog::write_raw(b"\n");
}
}
pub(super) use enabled::{hit, prepared, filtered};
