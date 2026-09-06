//! Raw caret syscall ABI constants and argument codecs. Main owns wiring.

pub const CREATE_CARET_ORDINAL: u64 = 0x1360;
pub const DESTROY_CARET_ORDINAL: u64 = 0x137e;
pub const HIDE_CARET_ORDINAL: u64 = 0x146c;
pub const SET_CARET_POS_ORDINAL: u64 = 0x153c;
pub const SHOW_CARET_ORDINAL: u64 = 0x15b7;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CaretPos { pub x: i32, pub y: i32 }

impl CaretPos {
    pub fn decode(bytes: [u8; 8]) -> Self { Self { x: i32::from_le_bytes(bytes[0..4].try_into().unwrap()), y: i32::from_le_bytes(bytes[4..8].try_into().unwrap()) } }
    pub fn encode(self) -> [u8; 8] { let mut bytes = [0; 8]; bytes[0..4].copy_from_slice(&self.x.to_le_bytes()); bytes[4..8].copy_from_slice(&self.y.to_le_bytes()); bytes }
}

/// The compositor/raster owner receives concrete erase/paint callbacks.  It
/// owns the actual surface pixels; this adapter never overlays a framebuffer
/// or fabricates a caret bitmap.
pub(crate) trait CaretRenderSink {
    fn erase_caret_pixels(&mut self, owner_tid: u64, hwnd: u64, rect: (i32, i32, i32, i32), generation: u64) -> bool;
    fn paint_caret_pixels(&mut self, owner_tid: u64, hwnd: u64, rect: (i32, i32, i32, i32), generation: u64) -> bool;
}

/// Publish one committed state transition in raster-safe order.  Erasing the
/// old image precedes painting the new image, including a move while visible.
pub(crate) fn publish_transition<S: CaretRenderSink + ?Sized>(
    sink: &mut S, owner_tid: u64, transition: ipc::win32_window::CaretTransition, generation: u64,
) -> bool {
    let hwnd = transition.hwnd.map(|value| value.raw() as u64).unwrap_or(0);
    let old_hwnd = transition.old_hwnd.map(|value| value.raw() as u64).unwrap_or(0);
    if transition.old_visible && !sink.erase_caret_pixels(owner_tid, old_hwnd, transition.old_rect, generation) { return false; }
    if transition.new_visible && !sink.paint_caret_pixels(owner_tid, hwnd, transition.new_rect, generation) { return false; }
    true
}

#[cfg(target_os = "oxide-kernel")]
#[path = "caret/live.rs"]
pub(crate) mod live;
#[cfg(target_os = "oxide-kernel")]
#[path = "caret/publish.rs"]
pub(crate) mod publish;
#[cfg(target_os = "oxide-kernel")]
#[path = "caret/blink.rs"]
pub(crate) mod blink;
#[cfg(target_os = "oxide-kernel")]
#[path = "caret/paint.rs"]
pub(crate) mod paint;
#[cfg(target_os = "oxide-kernel")]
#[path = "caret/query.rs"]
pub(crate) mod query;

#[cfg(test)]
#[path = "tests/caret.rs"]
mod tests;
