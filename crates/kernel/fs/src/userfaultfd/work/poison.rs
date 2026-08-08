// UFFDIO_POISON: mark pages whose contents are unrecoverable.
//
// The marker is a non-present leaf, so the next access faults and the fault
// path reports a memory error instead of materialising a page. That is the
// whole point: a poisoned address must never quietly become fresh zeroes, and
// the marker must survive in the one place every access consults.

use hal::pt_walker::PtWalker;
use syscall::errno::Errno;

use super::arch::{hhdm, leaf, Walker};
use super::Progress;

/// Install the marker across `[start, end)`, stopping at the first page that
/// already holds something. Refusing to overwrite ANY existing entry — a
/// present page, a swap entry, or another marker — is what keeps poisoning
/// from destroying state the process still owns.
/// # C: O((end - start) / 4096 * walk depth)
pub fn poison_range(mm: &vmm::AddressSpace, start: u64, end: u64) -> Progress {
    let mut done = 0u64;
    while start + done < end {
        let va = start + done;
        let _pt = mm.lock_page_table();
        if let Err(e) = super::leaf::dst_must_be_empty(leaf(mm, va)) { return (done, Some(e)); }
        let marker = <Walker as PtWalker>::pack_poison_marker();
        // SAFETY: the page-table lock is held; `va` lies in a VMA of this address space that the caller has already validated, and the marker is a non-present leaf, so no mapping reference is created or destroyed by installing it. Intermediate tables are allocated from the PMM.
        let placed = unsafe {
            hal::pt_walker::map_at_level_with_root::<Walker, _>(
                mm.root_pa(), va, 3, marker, hhdm(),
                &mut (|| pmm::setup::alloc_one_frame()))
        };
        if placed.is_err() { return (done, Some(Errno::Enomem)); }
        done += hal::PAGE_SIZE_BYTES;
    }
    (done, None)
}
