// UFFDIO_WRITEPROTECT: arm or resolve the per-page write-protect state.
//
// For a page that is there, the state and the write permission are changed
// together in one leaf rewrite, so the two can never be observed apart.
// Resolving clears the state and stops there: write permission comes back
// through an ordinary write fault, which is where the decision (copy-on-write,
// shared page, exclusive page) belongs. Handing write permission back here
// would skip that decision.
//
// For an address with NO page there are no permissions to change, so the state
// becomes an entry of its own — a marker leaf, which the fault path recognises
// and which every zap removes. `markers` is the caller's per-VMA answer to
// whether this range gets that treatment.

use super::arch::{hhdm, Walker};

/// Apply the transition to every page in `[start, end)` and invalidate the
/// range on this CPU and every peer.
/// # C: O((end - start) / 4096 * walk depth)
pub fn wp_range(mm: &vmm::AddressSpace, start: u64, end: u64, protect: bool, markers: bool) {
    {
        let _pt = mm.lock_page_table();
        // SAFETY: the page-table lock is held across the whole walk, so no table along it can be freed and no peer resolve can interleave; HHDM covers page-table memory; every leaf rewritten belongs to this address space's own tree, and the frames the walk may take are used only for intermediate tables under a non-present leaf.
        unsafe {
            hal::pt_walker::uffd_wp_range_at_root::<Walker, _>(
                mm.root_pa(), start, end, protect, markers, hhdm(),
                &mut (|| pmm::setup::alloc_one_frame()));
        }
    }
    let mut va = start;
    while va < end {
        super::arch::flush(mm, va);
        va += hal::PAGE_SIZE_BYTES;
    }
}
