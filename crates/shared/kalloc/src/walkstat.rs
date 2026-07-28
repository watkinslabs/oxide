// debug-heapwalk: measures the sorted-hole-list walk length that both
// `HoleList::alloc` (first fit) and `HoleList::add_free_region` (ordered
// insert) pay on EVERY kernel allocation and free, with IRQs off.
//
// Both are documented `# C: O(N)` in N = live free-hole count. Whether that is
// a real cost or a theoretical one depends entirely on N at run time, which
// nothing in the tree reports. This counts the steps actually taken and the
// hole count actually present, so "the kernel heap is the boot-slowness floor"
// becomes a measurement instead of an inference.
//
// Diagnostic only — off unless `--features debug-heapwalk` is passed.
#![cfg(feature = "debug-heapwalk")]

use core::sync::atomic::{AtomicU64, Ordering};

/// Dump cadence in recorded ops. Large: this fires on every heap op.
const DUMP_EVERY: u64 = 200_000;

static ALLOC_OPS: AtomicU64 = AtomicU64::new(0);
static ALLOC_STEPS: AtomicU64 = AtomicU64::new(0);
static ALLOC_MAX: AtomicU64 = AtomicU64::new(0);
static FREE_OPS: AtomicU64 = AtomicU64::new(0);
static FREE_STEPS: AtomicU64 = AtomicU64::new(0);
static FREE_MAX: AtomicU64 = AtomicU64::new(0);
static SINCE_DUMP: AtomicU64 = AtomicU64::new(0);

/// Record a first-fit walk. # C: O(1)
#[inline]
pub fn note_alloc(steps: u64) {
    ALLOC_OPS.fetch_add(1, Ordering::Relaxed);
    ALLOC_STEPS.fetch_add(steps, Ordering::Relaxed);
    ALLOC_MAX.fetch_max(steps, Ordering::Relaxed);
}

/// Record an ordered-insert walk. # C: O(1)
#[inline]
pub fn note_free(steps: u64) {
    FREE_OPS.fetch_add(1, Ordering::Relaxed);
    FREE_STEPS.fetch_add(steps, Ordering::Relaxed);
    FREE_MAX.fetch_max(steps, Ordering::Relaxed);
}

/// True once per `DUMP_EVERY` heap ops. Call while the heap lock is held so
/// the hole count read alongside it is consistent. # C: O(1)
#[inline]
pub fn due() -> bool {
    if SINCE_DUMP.fetch_add(1, Ordering::Relaxed) + 1 < DUMP_EVERY { return false; }
    SINCE_DUMP.store(0, Ordering::Relaxed);
    true
}

/// Emit cumulative walk cost plus the current hole count. Call with the heap
/// lock RELEASED — klog's console fan-out can allocate. # C: O(1)
pub fn dump(holes: u64) {
    let aops = ALLOC_OPS.load(Ordering::Relaxed);
    let fops = FREE_OPS.load(Ordering::Relaxed);
    klog::write_raw(b"[HEAPWALK] holes=");
    klog::write_dec_u64(holes);
    klog::write_raw(b" alloc_ops=");
    klog::write_dec_u64(aops);
    klog::write_raw(b" alloc_avg_steps=");
    klog::write_dec_u64(if aops > 0 { ALLOC_STEPS.load(Ordering::Relaxed) / aops } else { 0 });
    klog::write_raw(b" alloc_max_steps=");
    klog::write_dec_u64(ALLOC_MAX.load(Ordering::Relaxed));
    klog::write_raw(b" free_ops=");
    klog::write_dec_u64(fops);
    klog::write_raw(b" free_avg_steps=");
    klog::write_dec_u64(if fops > 0 { FREE_STEPS.load(Ordering::Relaxed) / fops } else { 0 });
    klog::write_raw(b" free_max_steps=");
    klog::write_dec_u64(FREE_MAX.load(Ordering::Relaxed));
    klog::write_raw(b"\n");
}
