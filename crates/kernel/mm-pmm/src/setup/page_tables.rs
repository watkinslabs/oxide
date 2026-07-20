// Canonical page-table-frame ownership and memcg accounting.
//
// The architecture walker asks this PMM entry point for every root and
// intermediate table frame.  The PageMeta record is the one source of truth:
// `PAGETABLE` selects the type, `memcg` is the allocating cgroup, and the
// otherwise-mutually-exclusive `mapping` slot holds the owning root PA.
// `free_one_frame` performs
// the only matching release before returning the frame to the buddy.

use core::sync::atomic::{AtomicU64, Ordering};

use cgroup::MemoryKind;

use super::{alloc_raw_frame, page_meta};

const PAGE_BYTES: u64 = hal::PAGE_SIZE_BYTES;

/// Authoritative lifecycle snapshot for all PMM-owned page-table frames.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PageTableSnapshot {
    pub frames: u64,
    pub bytes: u64,
}

static LIVE_FRAMES: AtomicU64 = AtomicU64::new(0);

/// Resolve the allocating task's memcg.  Kernel threads and early boot have
/// no task and correctly charge root, matching Linux's root-memcg fallback.
/// # C: O(log n)
#[cfg(target_os = "oxide-kernel")]
fn current_memcg() -> u64 {
    let pid = sched::live::current()
        .map(|task| task.tgid.load(Ordering::Acquire) as u64)
        .unwrap_or(0);
    cgroup::cgroup_of(pid)
}

#[cfg(not(target_os = "oxide-kernel"))]
fn current_memcg() -> u64 { cgroup::cgroup_of(0) }

/// Allocate one page-table frame for `root_pa`.  A zero root denotes creation
/// of the root itself; the new PA becomes its own context identity.  The
/// memcg reservation precedes allocation so `memory.max` failure cannot leave
/// a partially published page-table page.
/// # C: O(1) amortised
pub fn alloc_page_table_frame(root_pa: u64) -> Option<u64> {
    let cgid = current_memcg();
    if !cgroup::try_charge_memory(cgid, MemoryKind::PageTables, PAGE_BYTES) {
        return None;
    }
    let Some(pa) = alloc_raw_frame() else {
        cgroup::uncharge_memory(cgid, MemoryKind::PageTables, PAGE_BYTES);
        return None;
    };
    let Some(meta) = page_meta() else {
        // The installed architecture allocator is not permitted to create
        // user page tables before PageMeta exists: without it there is no
        // canonical owner to release at free time.
        // SAFETY: `pa` is this function's fresh raw allocation and has never
        // been published into a walker.
        unsafe { super::free_one_frame(pa); }
        cgroup::uncharge_memory(cgid, MemoryKind::PageTables, PAGE_BYTES);
        return None;
    };
    let pfn = hal::Pfn(pa / PAGE_BYTES);
    let Some(m) = meta.get(pfn) else {
        // SAFETY: identical unpublished-allocation contract as above.
        unsafe { super::free_one_frame(pa); }
        cgroup::uncharge_memory(cgid, MemoryKind::PageTables, PAGE_BYTES);
        return None;
    };
    let context = if root_pa == 0 { pa } else { root_pa };
    m.memcg.store(cgid, Ordering::Release);
    m.mapping.store(context as usize as *mut (), Ordering::Release);
    m.flags.fetch_or(crate::PageFlags::PAGETABLE.bits(), Ordering::Release);
    LIVE_FRAMES.fetch_add(1, Ordering::AcqRel);
    // Roots are allocated before AddressSpace registration; its accounting
    // starts at one. Every later intermediate table has a registered root.
    if root_pa != 0 { vmm::page_table_frame_allocated(root_pa); }
    Some(pa)
}

/// Consume page-table ownership immediately before the frame enters the
/// buddy.  Returns true iff `pa` was a page-table frame; duplicate cleanup is
/// impossible because the type bit is cleared in this exact transition.
/// # C: O(1)
pub(super) fn release_page_table_frame(pa: u64) -> bool {
    let Some(meta) = page_meta() else { return false; };
    let pfn = hal::Pfn(pa / PAGE_BYTES);
    let Some(m) = meta.get(pfn) else { return false; };
    let flags = crate::PageFlags::from_bits_retain(m.flags.load(Ordering::Acquire));
    if !flags.contains(crate::PageFlags::PAGETABLE) { return false; }
    let cgid = m.memcg.load(Ordering::Acquire);
    let root_pa = m.mapping.load(Ordering::Acquire) as usize as u64;
    m.flags.fetch_and(!crate::PageFlags::PAGETABLE.bits(), Ordering::AcqRel);
    m.mapping.store(core::ptr::null_mut(), Ordering::Release);
    m.memcg.store(cgroup::NO_MEMCG, Ordering::Release);
    LIVE_FRAMES.fetch_sub(1, Ordering::AcqRel);
    if root_pa != 0 { vmm::page_table_frame_released(root_pa); }
    if cgid != cgroup::NO_MEMCG {
        cgroup::uncharge_memory(cgid, MemoryKind::PageTables, PAGE_BYTES);
    }
    true
}

/// Snapshot only concrete PMM page-table allocations, never inferred PTE
/// counts or formatter guesses.
/// # C: O(1)
pub fn page_table_snapshot() -> PageTableSnapshot {
    let frames = LIVE_FRAMES.load(Ordering::Acquire);
    PageTableSnapshot { frames, bytes: frames.saturating_mul(PAGE_BYTES) }
}

#[cfg(test)]
pub(super) fn reset_page_table_snapshot_for_test() {
    LIVE_FRAMES.store(0, Ordering::Release);
}
