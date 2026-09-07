//! Bounded admission trace for the application text run.
//!
//! A run that draws nothing and a run that was never issued produce the same
//! empty client area, and the raw entry marker does not separate them: the
//! ordinal is claimed either way. One line per admitted run names the device
//! context, the flags, the unit count and the origin; one line per refusal
//! names the step that refused. Both are bounded so a running desktop stays
//! quiet after the first paints.
use core::sync::atomic::{AtomicU32, Ordering};

/// Lines each trace may emit before it goes quiet. A paint issues a handful of
/// runs, so the first paints of a window are covered and a steady-state
/// desktop costs nothing.
const BUDGET: u32 = 64;

static ADMITTED: AtomicU32 = AtomicU32::new(0);
static REFUSED: AtomicU32 = AtomicU32::new(0);

fn spend(cell: &AtomicU32) -> bool { cell.fetch_add(1, Ordering::Relaxed) < BUDGET }

/// One admitted run and the redirect status its issue returned. # C: O(1)
pub(crate) fn admitted(dc: u64, flags: u32, count: u32, x: i32, y: i32, advances: u64, status: u64) {
    if !spend(&ADMITTED) { return; }
    klog::write_raw(b"[WINDOWS-TEXTOUT] dc="); klog::write_hex_u64(dc);
    klog::write_raw(b" flags="); klog::write_hex_u64(flags as u64);
    klog::write_raw(b" count="); klog::write_hex_u64(count as u64);
    klog::write_raw(b" x="); klog::write_hex_u64(x as i64 as u64);
    klog::write_raw(b" y="); klog::write_hex_u64(y as i64 as u64);
    klog::write_raw(b" adv="); klog::write_hex_u64((advances != 0) as u64);
    klog::write_raw(b" status="); klog::write_hex_u64(status);
    klog::write_raw(b"\n");
}

/// The step that refused a run before any glyph could be rasterized. # C: O(1)
pub(crate) fn refused(dc: u64, step: &'static [u8]) {
    if !spend(&REFUSED) { return; }
    klog::write_raw(b"[WINDOWS-TEXTOUT-DROP] dc="); klog::write_hex_u64(dc);
    klog::write_raw(b" step="); klog::write_raw(step); klog::write_raw(b"\n");
}
