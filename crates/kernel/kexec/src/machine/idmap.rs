// The identity page tables the trampoline runs under.
//
// Built at LOAD time out of image-owned control pages, which is the reference's
// arrangement and the reason for it: control pages are the one supply
// guaranteed to sit outside every destination range, so the relocation cannot
// overwrite the tables that are describing it. Ordinary pages would be
// overwritten by the very copy they are translating.
//
// The walker is the kernel's own (`hal::pt_walker`) rather than a second one
// written here. A private page-table builder beside the real one is the split
// source of truth this project forbids, and it would encode the leaf bits
// twice — with only one of the two ever exercised by a running kernel.

use hal::pt_walker::{map_at_level_with_root, PtWalker, WalkErr};
use hal::PageFlags;

use crate::machine::plan::{BLOCK_LEVEL, BLOCK_SIZE};

/// Protection every identity leaf carries: readable, writable and executable.
///
/// Executable because the trampoline itself runs out of one of these leaves
/// once the tables take effect; writable because every destination page is
/// written through them. Narrowing either would fault the trampoline at a
/// point where nothing is left able to report it.
pub fn leaf_flags() -> PageFlags { PageFlags::READ | PageFlags::WRITE | PageFlags::EXEC }

/// Install `phys → phys` block leaves over every byte of `ranges`.
///
/// `ranges` must already be block-aligned and merged (`plan::normalize`);
/// overlapping input would ask the walker to install two different leaves at
/// one address and be refused as `AlreadyMapped`.
/// # SAFETY: `root_pa` is a page-table root this image owns exclusively,
/// `hhdm` maps every table page written here, and `alloc` yields fresh
/// zeroed 4 KiB frames the image owns.
/// # C: O(total bytes / block size)
pub unsafe fn build<W: PtWalker, F: FnMut() -> Option<u64>>(
    root_pa: u64, ranges: &[(u64, u64)], hhdm: u64, mut alloc: F,
) -> Result<(), WalkErr> {
    for &(start, end) in ranges {
        let mut pa = start;
        while pa < end {
            let leaf = W::pack_block_leaf(pa, leaf_flags());
            // SAFETY: forwarded — image-owned root, HHDM-reachable tables, fresh frames.
            unsafe { map_at_level_with_root::<W, _>(root_pa, pa, BLOCK_LEVEL, leaf, hhdm, &mut alloc)? };
            pa += BLOCK_SIZE;
        }
    }
    Ok(())
}

/// Map `va → pa` as a single executable 4 KiB leaf.
///
/// This is the reference's transition mapping. The trampoline is entered at
/// the control page's KERNEL address and switches page tables from inside
/// itself; without this leaf the instruction after `mov cr3` is unmapped and
/// the machine triple-faults with the old kernel already dismantled.
/// # SAFETY: as [`build`].
/// # C: O(walk depth)
pub unsafe fn map_transition<W: PtWalker, F: FnMut() -> Option<u64>>(
    root_pa: u64, va: u64, pa: u64, hhdm: u64, mut alloc: F,
) -> Result<(), WalkErr> {
    let leaf = W::pack_4k_leaf(pa, leaf_flags());
    // SAFETY: forwarded — image-owned root, HHDM-reachable tables, fresh frames.
    unsafe { map_at_level_with_root::<W, _>(root_pa, va, 3, leaf, hhdm, &mut alloc) }
}
