// UFFDIO_WRITEPROTECT: arm or resolve the per-page write-protect marker.
//
// The marker and the write permission are changed together in one leaf
// rewrite, so the two can never be observed apart. Resolving clears the marker
// and stops there: write permission comes back through an ordinary write
// fault, which is where the decision (copy-on-write, shared page, exclusive
// page) belongs. Handing write permission back here would skip that decision.

use super::arch::{hhdm, Walker};

/// Apply the transition to every present leaf in `[start, end)` and invalidate
/// the range on this CPU and every peer.
/// # C: O((end - start) / 4096 * walk depth)
pub fn wp_range(mm: &vmm::AddressSpace, start: u64, end: u64, protect: bool) {
    {
        let _pt = mm.lock_page_table();
        // SAFETY: the page-table lock is held across the whole walk, so no table along it can be freed and no peer resolve can interleave; HHDM covers page-table memory; every leaf rewritten belongs to this address space's own tree.
        unsafe {
            hal::pt_walker::uffd_wp_range_at_root::<Walker>(mm.root_pa(), start, end, protect, hhdm());
        }
    }
    let mut va = start;
    while va < end {
        super::arch::flush(mm, va);
        va += hal::PAGE_SIZE_BYTES;
    }
}
