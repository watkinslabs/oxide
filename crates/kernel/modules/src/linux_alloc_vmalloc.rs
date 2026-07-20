//! Canonical Linux `vmalloc` backing and lifetime registry.
//!
//! Unlike `kmalloc`, every live allocation here owns individually allocated
//! PMM pages and a distinct kernel virtual range.  The registry is therefore
//! the allocation owner for both the virtual address and the matching memcg
//! `Vmalloc` charge; snapshots never reconstruct either fact from heap use.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use cgroup::MemoryKind;
use hal::{MmuOps, Pa, PageFlags, PageSize, Va};
use sync::Spinlock;

#[cfg(target_arch = "aarch64")]
use hal_aarch64::mmu_ops::ArmMmu;
#[cfg(target_arch = "x86_64")]
use hal_x86_64::mmu_ops::X86Mmu;

const PAGE_BYTES: usize = hal::PAGE_SIZE_BYTES as usize;
/// Dedicated kernel VA arena, below the device BAR arena (`mmio-map`).
const VMALLOC_VA_BASE: u64 = 0xffff_fc00_0000_0000;
const VMALLOC_VA_BYTES: u64 = 1u64 << 40;
const VMALLOC_VA_END: u64 = VMALLOC_VA_BASE + VMALLOC_VA_BYTES;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Snapshot { pub total: u64, pub used: u64, pub largest_free: u64, pub allocations: u64 }

struct Allocation { pages: Vec<u64>, bytes: u64, cgid: u64 }
struct State { initialized: bool, free: BTreeMap<u64, u64>, live: BTreeMap<u64, Allocation>, used: u64 }
impl State {
    const fn new() -> Self { Self { initialized: false, free: BTreeMap::new(), live: BTreeMap::new(), used: 0 } }
    fn init(&mut self) { if !self.initialized { self.free.insert(VMALLOC_VA_BASE, VMALLOC_VA_BYTES); self.initialized = true; } }
    fn reserve(&mut self, bytes: u64) -> Option<u64> {
        self.init();
        let (base, span) = self.free.iter().find(|(_, span)| **span >= bytes).map(|(base, span)| (*base, *span))?;
        self.free.remove(&base);
        if span > bytes { self.free.insert(base + bytes, span - bytes); }
        self.used = self.used.checked_add(bytes)?;
        Some(base)
    }
    fn release(&mut self, base: u64, bytes: u64) {
        self.used = self.used.saturating_sub(bytes);
        let mut start = base;
        let mut span = bytes;
        if let Some((&prev, &prev_len)) = self.free.range(..base).next_back() {
            if prev.checked_add(prev_len) == Some(base) { self.free.remove(&prev); start = prev; span = span.saturating_add(prev_len); }
        }
        if let Some((&next, &next_len)) = self.free.range(base..).next() {
            if base.checked_add(bytes) == Some(next) { self.free.remove(&next); span = span.saturating_add(next_len); }
        }
        self.free.insert(start, span);
    }
}
static STATE: Spinlock<State, sync::KMalloc> = Spinlock::new(State::new());

#[cfg(target_os = "oxide-kernel")]
fn current_memcg() -> u64 {
    let pid = sched::live::current().map(|task| task.tgid.load(Ordering::Acquire) as u64).unwrap_or(0);
    cgroup::cgroup_of(pid)
}

fn pages_for(size: usize) -> Option<usize> { size.checked_add(PAGE_BYTES - 1).map(|v| v / PAGE_BYTES).filter(|n| *n != 0) }

#[cfg(target_os = "oxide-kernel")]
unsafe fn map(base: u64, pages: &[u64]) -> bool {
    for (i, pa) in pages.iter().copied().enumerate() {
        let va = base + i as u64 * PAGE_BYTES as u64;
        // SAFETY: base is exclusively reserved by STATE and pa is a newly-owned PMM page.
        let old = unsafe {
            #[cfg(target_arch = "x86_64")]
            { <X86Mmu as MmuOps>::map(Va(va), Pa(pa), PageFlags::READ | PageFlags::WRITE, PageSize::P4K) }
            #[cfg(target_arch = "aarch64")]
            { <ArmMmu as MmuOps>::map(Va(va), Pa(pa), PageFlags::READ | PageFlags::WRITE, PageSize::P4K) }
        };
        if old.is_some() { return false; }
    }
    #[cfg(target_arch = "x86_64")]
    // SAFETY: propagates the fresh kernel-half mappings to AP master tables.
    unsafe { hal_x86_64::mmu_ops::resync_kernel_master(); }
    true
}

#[cfg(target_os = "oxide-kernel")]
unsafe fn unmap(base: u64, pages: usize) {
    for i in 0..pages {
        // SAFETY: caller removed the exact live allocation from STATE and quiesced users.
        unsafe {
            #[cfg(target_arch = "x86_64")]
            { <X86Mmu as MmuOps>::unmap(Va(base + i as u64 * PAGE_BYTES as u64), PageSize::P4K); }
            #[cfg(target_arch = "aarch64")]
            { <ArmMmu as MmuOps>::unmap(Va(base + i as u64 * PAGE_BYTES as u64), PageSize::P4K); }
        }
    }
    #[cfg(target_arch = "x86_64")]
    // SAFETY: propagates kernel-half teardown to AP master tables.
    unsafe { hal_x86_64::mmu_ops::resync_kernel_master(); }
}

/// Allocate a zeroed or uninitialized Linux vmalloc area. # C: O(pages)
#[cfg(target_os = "oxide-kernel")]
pub fn alloc(size: usize, zero: bool) -> *mut u8 {
    let Some(count) = pages_for(size) else { return core::ptr::null_mut(); };
    let bytes = match (count as u64).checked_mul(PAGE_BYTES as u64) { Some(v) => v, None => return core::ptr::null_mut() };
    let cgid = current_memcg();
    if !cgroup::try_charge_memory(cgid, MemoryKind::Vmalloc, bytes) { return core::ptr::null_mut(); }
    let mut pages = Vec::new();
    if pages.try_reserve_exact(count).is_err() { cgroup::uncharge_memory(cgid, MemoryKind::Vmalloc, bytes); return core::ptr::null_mut(); }
    for _ in 0..count {
        let Some(pa) = pmm::setup::alloc_object_frame() else {
            for pa in pages { pmm::setup::release_object_frame(pa); }
            cgroup::uncharge_memory(cgid, MemoryKind::Vmalloc, bytes);
            return core::ptr::null_mut();
        };
        pages.push(pa);
    }
    let base = { STATE.lock().reserve(bytes) };
    let Some(base) = base else {
        for pa in pages { pmm::setup::release_object_frame(pa); }
        cgroup::uncharge_memory(cgid, MemoryKind::Vmalloc, bytes);
        return core::ptr::null_mut();
    };
    // SAFETY: pages and VA range are private until the successful registry insertion below.
    if !unsafe { map(base, &pages) } {
        STATE.lock().release(base, bytes);
        for pa in pages { pmm::setup::release_object_frame(pa); }
        cgroup::uncharge_memory(cgid, MemoryKind::Vmalloc, bytes);
        return core::ptr::null_mut();
    }
    if zero {
        // SAFETY: all mapped pages are private and cover exactly bytes.
        unsafe { core::ptr::write_bytes(base as *mut u8, 0, bytes as usize); }
    }
    STATE.lock().live.insert(base, Allocation { pages, bytes, cgid });
    base as *mut u8
}

/// Release an area only if `base` is its exact vmalloc base. # C: O(pages)
#[cfg(target_os = "oxide-kernel")]
pub fn free(base: *mut u8) -> bool {
    if base.is_null() { return true; }
    let base = base as u64;
    let allocation = STATE.lock().live.remove(&base);
    let Some(allocation) = allocation else { return false; };
    // SAFETY: removal makes this the sole teardown owner of the exact mapped range.
    unsafe { unmap(base, allocation.pages.len()); }
    for pa in allocation.pages { pmm::setup::release_object_frame(pa); }
    cgroup::uncharge_memory(allocation.cgid, MemoryKind::Vmalloc, allocation.bytes);
    STATE.lock().release(base, allocation.bytes);
    true
}

#[cfg(not(target_os = "oxide-kernel"))]
pub fn alloc(size: usize, zero: bool) -> *mut u8 { super::alloc_bytes(size, PAGE_BYTES, zero) }
#[cfg(not(target_os = "oxide-kernel"))]
pub fn free(base: *mut u8) -> bool { if base.is_null() { true } else { super::free_bytes(base); true } }

/// Snapshot exact live virtual allocator state. # C: O(live ranges)
pub fn snapshot() -> Snapshot {
    #[cfg(target_os = "oxide-kernel")]
    { let s = STATE.lock(); Snapshot { total: VMALLOC_VA_BYTES, used: s.used, largest_free: s.free.values().copied().max().unwrap_or(0), allocations: s.live.len() as u64 } }
    #[cfg(not(target_os = "oxide-kernel"))]
    { Snapshot::default() }
}
