//! Bounded admission trace for the native text measurement.
//!
//! A measurement that answers FALSE and one that answers a zero-sized box are
//! invisible everywhere above: the caller keeps its own uninitialized `SIZE`
//! in the first case and computes an empty rectangle in the second, and both
//! end as a control that draws its frame and no caption without issuing a
//! single text run. One line per refusal and one per degenerate answer names
//! which of the two happened; both are bounded so a steady desktop stays quiet.
use core::sync::atomic::{AtomicU32, Ordering};
use syscall::nt_native_gdi as abi;

/// Lines each trace may emit before it goes quiet.
const BUDGET: u32 = 48;

static REFUSED: AtomicU32 = AtomicU32::new(0);
static DEGENERATE: AtomicU32 = AtomicU32::new(0);

fn spend(cell: &AtomicU32) -> bool { cell.fetch_add(1, Ordering::Relaxed) < BUDGET }

/// The step that refused a measurement before any answer reached the caller.
/// # C: O(1)
pub(crate) fn refused(dc: u64, kind: u32, step: &'static [u8]) {
    if !spend(&REFUSED) { return; }
    klog::write_raw(b"[WINDOWS-TEXTMEASURE-DROP] dc="); klog::write_hex_u64(dc);
    klog::write_raw(b" kind="); klog::write_hex_u64(kind as u64);
    klog::write_raw(b" step="); klog::write_raw(step); klog::write_raw(b"\n");
}

/// One answered measurement whose box has no area, which is the shape that
/// silently empties a caller's label rectangle. # C: O(1)
pub(super) fn answered(request: &abi::MeasureRequest, output: &abi::MeasureOutput) {
    if !output.degenerate_extent(request) { return; }
    if !spend(&DEGENERATE) { return; }
    klog::write_raw(b"[WINDOWS-TEXTMEASURE] dc="); klog::write_hex_u64(request.dc);
    klog::write_raw(b" count="); klog::write_hex_u64(request.count as u64);
    klog::write_raw(b" max="); klog::write_hex_u64(request.max_extent as i64 as u64);
    klog::write_raw(b" height="); klog::write_hex_u64(request.height as i64 as u64);
    klog::write_raw(b" w="); klog::write_hex_u64(output.width as i64 as u64);
    klog::write_raw(b" h="); klog::write_hex_u64(output.height as i64 as u64);
    klog::write_raw(b" fit="); klog::write_hex_u64(output.fit as u64);
    klog::write_raw(b"\n");
}
