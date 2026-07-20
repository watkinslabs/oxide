//! PTE-derived per-range resident and swap accounting for procfs.

use super::*;
use sched::oom::{OomMemory, PSS_UNITS_PER_PAGE};

const PAGE_BYTES: u64 = hal::PAGE_SIZE_BYTES;

/// Snapshot of one page-aligned user range. A page is counted in exactly one
/// of resident, swapped, or neither (unfaulted/hole) according to its current
/// leaf PTE. # C: O(pages × page-table walk depth)
#[derive(Copy, Clone, Default)]
pub struct RangeMemoryStats {
    pub resident_pages: u64,
    pub swapped_pages: u64,
}

/// Count present and swap PTEs in `[start,end)` while its owning page table is
/// stable. This is observation only: procfs never synthesizes residency from
/// VMA length. # C: O(pages × page-table walk depth)
pub fn range_memory_stats(as_: &AddressSpace, start: UserVirtAddr, end: UserVirtAddr) -> RangeMemoryStats {
    let _pt = as_.lock_page_table();
    let hhdm = hhdm_offset();
    let mut out = RangeMemoryStats::default();
    let mut va = start.as_u64();
    while va < end.as_u64() {
        // SAFETY: the owning AS page-table lock is held and `hhdm` maps all
        // page-table frames; this is a read-only leaf translation walk.
        let present = unsafe { super::foreign::read_foreign_leaf_pa(as_.root_pa(), va, hhdm) }.is_some();
        if present {
            out.resident_pages += 1;
        } else {
            // SAFETY: the same locked live page-table root is inspected for
            // one architecture-encoded non-present swap PTE at this VA.
            let swapped = unsafe {
                #[cfg(target_arch = "x86_64")]
                { hal::pt_walker::swap_entry_4k_at_root::<hal_x86_64::vmm::PtWalkerX86>(as_.root_pa(), va, hhdm).is_some() }
                #[cfg(target_arch = "aarch64")]
                { hal::pt_walker::swap_entry_4k_at_root::<hal_aarch64::vmm::PtWalkerArm>(as_.root_pa(), va, hhdm).is_some() }
                #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
                { false }
            };
            if swapped { out.swapped_pages += 1; }
        }
        va = match va.checked_add(PAGE_BYTES) { Some(next) => next, None => break };
    }
    out
}

/// PMM's single OOM accounting observer.  It walks the live present leaves
/// while holding the owning page-table lock and apportions each managed frame
/// by its canonical PMM mapcount.  A zero mapcount for a present managed user
/// PTE is an invariant failure, not a reason to silently charge the mapping
/// in full or ignore it. # C: O(mapped user pages × page-table walk depth)
pub fn oom_memory(as_: &AddressSpace) -> Option<OomMemory> {
    let _pt = as_.lock_page_table();
    // Lock order is PageTable → AddressSpace; keeping the page-table lock
    // while taking this VMA snapshot binds backing classification to the leaf
    // set being observed.
    let vmas = as_.snapshot_vmas();
    let hhdm = hhdm_offset();
    let mut out = OomMemory {
        page_table_pages: as_.accounting_snapshot().page_table_frames,
        ..OomMemory::default()
    };
    for vma in vmas {
        let charge = matches!(vma.backing, VmaBacking::Anonymous | VmaBacking::File { .. } | VmaBacking::KernelBytes { .. });
        let mut va = vma.start.as_u64();
        while va < vma.end.as_u64() {
            // SAFETY: the live mm and its page-table lock are held; this is a
            // read-only translation through its root under the direct map.
            if let Some(pa) = unsafe { super::foreign::read_foreign_leaf_pa(as_.root_pa(), va, hhdm) } {
                if !charge {
                    va = va.checked_add(PAGE_BYTES)?;
                    continue;
                }
                let mapcount = crate::setup::frame_mapcount(pa);
                if mapcount == 0 { return None; }
                out.proportional_resident_units = out.proportional_resident_units
                    .saturating_add(PSS_UNITS_PER_PAGE / u64::from(mapcount));
            } else {
                // Swap identity is independent of the VMA's backing type:
                // tmpfs/shmem can lawfully acquire swap leaves too. Any live
                // user swap PTE is apportioned through its canonical slot
                // mapcount rather than being restricted to anonymous VMAs.
                let entry = unsafe {
                    #[cfg(target_arch = "x86_64")]
                    { hal::pt_walker::swap_entry_4k_at_root::<hal_x86_64::vmm::PtWalkerX86>(as_.root_pa(), va, hhdm) }
                    #[cfg(target_arch = "aarch64")]
                    { hal::pt_walker::swap_entry_4k_at_root::<hal_aarch64::vmm::PtWalkerArm>(as_.root_pa(), va, hhdm) }
                    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
                    { None }
                };
                if let Some(entry) = entry {
                    let mapcount = crate::swap::pte_mapcount(entry).ok()?;
                    if mapcount == 0 { return None; }
                    out.proportional_swap_units = out.proportional_swap_units
                        .saturating_add(PSS_UNITS_PER_PAGE / u64::from(mapcount));
                }
            }
            va = va.checked_add(PAGE_BYTES)?;
        }
    }
    Some(out)
}
