//! Which rectangles one window's presentation is built from, so a coordinate
//! space that disagrees with another names itself in the log instead of being
//! inferred from pixels.
use ipc::win32_window::WindowRect;

/// One trace line, bounded so a running system stays quiet. # C: O(1)
#[cfg(all(feature = "debug-wingeom", target_os = "oxide-kernel"))]
pub(crate) fn line(tag: &'static [u8], hwnd: u64, rects: &[(&'static [u8], WindowRect)]) {
    use core::sync::atomic::{AtomicU32, Ordering};
    /// Trace lines one boot writes before the picture has repeated itself.
    const BUDGET: u32 = 256;
    static WRITTEN: AtomicU32 = AtomicU32::new(0);
    if WRITTEN.fetch_add(1, Ordering::Relaxed) >= BUDGET { return; }
    klog::write_raw(b"[WINDOWS-GEOM] "); klog::write_raw(tag);
    klog::write_raw(b" hwnd="); klog::write_hex_u64(hwnd);
    for (name, rect) in rects {
        klog::write_raw(b" "); klog::write_raw(name); klog::write_raw(b"=");
        for value in [rect.left, rect.top, rect.right, rect.bottom] {
            klog::write_hex_u64(value as i64 as u64); klog::write_raw(b",");
        }
    }
    klog::write_raw(b"\n");
}

/// # C: O(1)
#[cfg(not(all(feature = "debug-wingeom", target_os = "oxide-kernel")))]
pub(crate) fn line(_tag: &'static [u8], _hwnd: u64, _rects: &[(&'static [u8], WindowRect)]) {}
