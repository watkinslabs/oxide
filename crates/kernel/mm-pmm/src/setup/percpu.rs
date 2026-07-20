//! Permanent per-CPU page ownership.

use core::sync::atomic::{AtomicU64, Ordering};

use cgroup::MemoryKind;

use super::{alloc_object_frame, frame_ptr, release_object_frame};

const PAGE_BYTES: u64 = hal::PAGE_SIZE_BYTES;
static LIVE_PAGES: AtomicU64 = AtomicU64::new(0);

/// Exact permanent per-CPU backing snapshot. AP startup intentionally retains
/// these pages until CPU teardown exists, so there is no fictional free path.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PerCpuSnapshot { pub pages: u64, pub bytes: u64 }

#[cfg(target_os = "oxide-kernel")]
fn current_memcg() -> u64 {
    let pid = sched::live::current().map(|task| task.tgid.load(Ordering::Acquire) as u64).unwrap_or(0);
    cgroup::cgroup_of(pid)
}
#[cfg(not(target_os = "oxide-kernel"))]
fn current_memcg() -> u64 { cgroup::cgroup_of(0) }

/// Allocate one base page for an AP's permanent per-CPU area. The PMM object
/// reference, matching root-memcg `PerCpu` charge, and snapshot transition are
/// committed together; failure leaves no partial owner. # C: O(1)
pub fn alloc_percpu_page() -> Option<*mut u8> {
    let cgid = current_memcg();
    if !cgroup::try_charge_memory(cgid, MemoryKind::PerCpu, PAGE_BYTES) { return None; }
    let Some(pa) = alloc_object_frame() else {
        cgroup::uncharge_memory(cgid, MemoryKind::PerCpu, PAGE_BYTES);
        return None;
    };
    let Some(ptr) = frame_ptr(pa) else {
        release_object_frame(pa);
        cgroup::uncharge_memory(cgid, MemoryKind::PerCpu, PAGE_BYTES);
        return None;
    };
    // AP bootstrap reads a clean cpu-id/scratch page before publishing it.
    // SAFETY: ptr is the caller's newly allocated, exclusively owned PMM page.
    unsafe { core::ptr::write_bytes(ptr, 0, PAGE_BYTES as usize); }
    LIVE_PAGES.fetch_add(1, Ordering::AcqRel);
    Some(ptr)
}

/// Snapshot real PMM per-CPU backing, never a CPU-count estimate. # C: O(1)
pub fn percpu_snapshot() -> PerCpuSnapshot {
    let pages = LIVE_PAGES.load(Ordering::Acquire);
    PerCpuSnapshot { pages, bytes: pages.saturating_mul(PAGE_BYTES) }
}
