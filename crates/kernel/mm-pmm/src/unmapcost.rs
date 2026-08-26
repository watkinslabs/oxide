//! Low-distortion `munmap` stage counters for the syscall-cost report.

#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::{AtomicU64, Ordering};

const NS_PER_MS: u64 = 1_000_000;

static WALK_NS: AtomicU64 = AtomicU64::new(0);
static WALK_CALLS: AtomicU64 = AtomicU64::new(0);
static WALK_HITS: AtomicU64 = AtomicU64::new(0);
static ACCOUNT_NS: AtomicU64 = AtomicU64::new(0);
static ACCOUNT_CALLS: AtomicU64 = AtomicU64::new(0);
static VMA_NS: AtomicU64 = AtomicU64::new(0);
static VMA_CALLS: AtomicU64 = AtomicU64::new(0);

/// Record one page-table lookup, including whether it found a leaf. # C: O(1)
pub fn walk(start: u64, hit: bool) {
    WALK_NS.fetch_add(now_ns().saturating_sub(start), Ordering::Relaxed);
    WALK_CALLS.fetch_add(1, Ordering::Relaxed);
    if hit { WALK_HITS.fetch_add(1, Ordering::Relaxed); }
}

/// Record one resident-accounting lookup. # C: O(1)
pub fn account(start: u64) {
    ACCOUNT_NS.fetch_add(now_ns().saturating_sub(start), Ordering::Relaxed);
    ACCOUNT_CALLS.fetch_add(1, Ordering::Relaxed);
}

/// Record the VMA-tree side of one unmap. # C: O(1)
pub fn vma(start: u64) {
    VMA_NS.fetch_add(now_ns().saturating_sub(start), Ordering::Relaxed);
    VMA_CALLS.fetch_add(1, Ordering::Relaxed);
}

/// Read the architecture monotonic clock used by the syscall profiler. # C: O(1)
#[inline]
pub fn now_ns() -> u64 {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
}

/// Emit the `munmap` stage table beside `[SYSCOST]`. # C: O(1)
pub fn dump() {
    let wc = WALK_CALLS.load(Ordering::Relaxed);
    let ac = ACCOUNT_CALLS.load(Ordering::Relaxed);
    let vc = VMA_CALLS.load(Ordering::Relaxed);
    klog::write_raw(b"  unmap walk_calls="); klog::write_dec_u64(wc);
    klog::write_raw(b" hits="); klog::write_dec_u64(WALK_HITS.load(Ordering::Relaxed));
    klog::write_raw(b" ms="); klog::write_dec_u64(WALK_NS.load(Ordering::Relaxed) / NS_PER_MS);
    klog::write_raw(b" account_calls="); klog::write_dec_u64(ac);
    klog::write_raw(b" account_ms="); klog::write_dec_u64(ACCOUNT_NS.load(Ordering::Relaxed) / NS_PER_MS);
    klog::write_raw(b" vma_calls="); klog::write_dec_u64(vc);
    klog::write_raw(b" vma_ms="); klog::write_dec_u64(VMA_NS.load(Ordering::Relaxed) / NS_PER_MS);
    klog::write_raw(b"\n");
}
