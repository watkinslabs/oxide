use core::ptr;

use super::{PtWalker, SwapEntry, WalkErr, ENTRIES_PER_TABLE, L0_SHIFT, L1_SHIFT, L2_SHIFT, L3_SHIFT, TABLE_IDX_MASK};

/// Zero is the sole architecturally absent page-table leaf on both walkers.
const EMPTY_PTE: u64 = 0;
/// L3 is the 4 KiB leaf level in the shared four-level walker.
const SWAP_LEAF_LEVEL: usize = 3;

/// Install one non-present swap leaf into `root_pa` without replacing any
/// existing leaf.  Fork uses this to give the child its own PTE reference to
/// the same canonical swap slot; accepting an occupied slot would silently
/// lose that ownership.
///
/// # SAFETY: caller owns `root_pa`, holds its page-table lock, and supplies a
/// fresh table-frame allocator through the architecture wrapper.
/// # C: O(walk depth)
pub unsafe fn install_swap_4k_at_root<W: PtWalker, F: FnMut() -> Option<u64>>(
    root_pa: u64, va: u64, entry: SwapEntry, hhdm_offset: u64, mut alloc_pa: F,
) -> Result<(), WalkErr> {
    let mut current_pa = root_pa;
    let shifts = [L0_SHIFT, L1_SHIFT, L2_SHIFT, L3_SHIFT];
    for level in 0..SWAP_LEAF_LEVEL {
        let idx = ((va >> shifts[level]) & TABLE_IDX_MASK) as usize;
        // SAFETY: caller provides a live root and serialized table access.
        current_pa = unsafe { walk_or_alloc::<W, _>(current_pa, idx, hhdm_offset, &mut alloc_pa)? };
    }
    let leaf_idx = ((va >> L3_SHIFT) & TABLE_IDX_MASK) as usize;
    // SAFETY: the final table is live through HHDM and exclusively owned here.
    unsafe {
        let table = (hhdm_offset.wrapping_add(current_pa)) as *mut u64;
        let slot = table.add(leaf_idx);
        if ptr::read_volatile(slot) != EMPTY_PTE { return Err(WalkErr::AlreadyMapped); }
        ptr::write_volatile(slot, W::pack_swap_entry(entry));
    }
    Ok(())
}

/// Install a Device-attr 4 KiB leaf `va → pa` in the active 4-level
/// page-table tree. Walks via HHDM, allocating intermediate tables
/// from `alloc_pa` as needed; zero-initializes new tables before
/// linking so partial walks behave as "not present".
///
/// `alloc_pa()` returns the physical address of a fresh, page-
/// aligned, kernel-owned 4 KiB frame. Caller (kernel) typically
/// wraps PMM: `|| pmm.alloc(Order(0)).ok().map(|pfn| pfn.0 * 4096)`.
///
/// # SAFETY: caller asserts (a) `va` is canonical and not currently
/// owned by another subsystem, (b) `pa` is a real device MMIO base,
/// (c) `hhdm_offset` covers RAM holding page-table memory, (d)
/// `alloc_pa` returns frames the kernel exclusively owns. Single-
/// CPU, IRQ-off context (no concurrent walkers).
/// # C: O(walk depth) = O(4)
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn map_device_4k<W: PtWalker, F: FnMut() -> Option<u64>>(
    va: u64,
    pa: u64,
    hhdm_offset: u64,
    mut alloc_pa: F,
) -> Result<(), WalkErr> {
    // SAFETY: per fn contract — privileged register read, legal in
    // kernel mode; result is the live root-table PA.
    let l0_pa = unsafe { W::read_pt_base(va) };

    let i_l0 = ((va >> L0_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l1 = ((va >> L1_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l2 = ((va >> L2_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l3 = ((va >> L3_SHIFT) & TABLE_IDX_MASK) as usize;

    // SAFETY: per fn contract — HHDM covers page-table memory; alloc_pa returns kernel-owned frames; single-CPU + IRQs off prevents concurrent walkers; the leaf write at the bottom runs only after every intermediate is in place.
    unsafe {
        let l1_pa = walk_or_alloc::<W, _>(l0_pa, i_l0, hhdm_offset, &mut alloc_pa)?;
        let l2_pa = walk_or_alloc::<W, _>(l1_pa, i_l1, hhdm_offset, &mut alloc_pa)?;
        let l3_pa = walk_or_alloc::<W, _>(l2_pa, i_l2, hhdm_offset, &mut alloc_pa)?;
        let l3_va = (hhdm_offset.wrapping_add(l3_pa)) as *mut u64;
        let slot = l3_va.add(i_l3);
        let cur = ptr::read_volatile(slot);
        if W::is_valid(cur) && (cur & W::PHYS_MASK) != (pa & W::PHYS_MASK) {
            return Err(WalkErr::AlreadyMapped);
        }
        ptr::write_volatile(slot, W::pack_device_leaf(pa));
        W::flush_va(va);
    }
    Ok(())
}

/// Install a 4 KiB leaf with arch-neutral flags `va → pa`. Mirrors
/// `map_device_4k`'s walk discipline; the only difference is the
/// leaf bit pattern comes from `W::pack_4k_leaf(pa, flags)` rather
/// than the hardcoded device-attr packer. Used by `MmuOps::map`
/// per `20§5`/`21§5`.
///
/// # SAFETY: same contract as `map_device_4k`.
/// # C: O(walk depth) = O(4)
/// # Ctx: pre-init or under PT lock; single-CPU walker.
pub unsafe fn map_4k<W: PtWalker, F: FnMut() -> Option<u64>>(
    va: u64,
    pa: u64,
    flags: crate::PageFlags,
    hhdm_offset: u64,
    mut alloc_pa: F,
) -> Result<(), WalkErr> {
    // SAFETY: privileged read; legal in kernel mode.
    let l0_pa = unsafe { W::read_pt_base(va) };

    let i_l0 = ((va >> L0_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l1 = ((va >> L1_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l2 = ((va >> L2_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l3 = ((va >> L3_SHIFT) & TABLE_IDX_MASK) as usize;

    // SAFETY: per fn contract; mirrors `map_device_4k`'s body.
    unsafe {
        let l1_pa = walk_or_alloc::<W, _>(l0_pa, i_l0, hhdm_offset, &mut alloc_pa)?;
        let l2_pa = walk_or_alloc::<W, _>(l1_pa, i_l1, hhdm_offset, &mut alloc_pa)?;
        let l3_pa = walk_or_alloc::<W, _>(l2_pa, i_l2, hhdm_offset, &mut alloc_pa)?;
        let l3_va = (hhdm_offset.wrapping_add(l3_pa)) as *mut u64;
        let slot = l3_va.add(i_l3);
        let cur = ptr::read_volatile(slot);
        if W::is_valid(cur) && (cur & W::PHYS_MASK) != (pa & W::PHYS_MASK) {
            return Err(WalkErr::AlreadyMapped);
        }
        ptr::write_volatile(slot, W::pack_4k_leaf(pa, flags));
        W::flush_va(va);
    }
    Ok(())
}

/// Install a leaf at the requested level — `1` = 1 GiB block (L1),
/// `2` = 2 MiB block (L2), `3` = 4 KiB page (L3). The walker
/// descends to the parent of `leaf_level`, allocating intermediate
/// tables as it goes, then writes `leaf` at the parent table's
/// index for `va`.
///
/// `va` and the embedded `pa` in `leaf` must be aligned to the
/// page size implied by `leaf_level` (caller satisfies; checked by
/// the `MmuOps::map` wrapper via `kassert!`).
///
/// # SAFETY: same contract as `map_4k`.
/// # C: O(leaf_level) — at most 4
/// # Ctx: pre-init or under PT lock; single-CPU walker.
pub unsafe fn map_at_level<W: PtWalker, F: FnMut() -> Option<u64>>(
    va: u64,
    leaf_level: u8,
    leaf: u64,
    hhdm_offset: u64,
    mut alloc_pa: F,
) -> Result<(), WalkErr> {
    // SAFETY: privileged read; legal in kernel mode.
    let root_pa = unsafe { W::read_pt_base(va) };
    // SAFETY: delegated; root_pa is the active root.
    unsafe { map_at_level_with_root::<W, _>(root_pa, va, leaf_level, leaf, hhdm_offset, &mut alloc_pa) }
}

/// Like `map_at_level` but installs into the tree rooted at
/// `root_pa` instead of reading from the active CR3 / TTBR0.
/// Used by `AddressSpace::fork` per docs/11§7 to populate child
/// page tables without temporarily activating them.
///
/// # SAFETY: caller asserts (a) `root_pa` is a valid kernel-owned
/// PT root, (b) other map_at_level preconditions per the
/// active-root form. Single-CPU walker; per-AS PT lock held.
/// # C: O(leaf_level)
pub unsafe fn map_at_level_with_root<W: PtWalker, F: FnMut() -> Option<u64>>(
    root_pa: u64,
    va: u64,
    leaf_level: u8,
    leaf: u64,
    hhdm_offset: u64,
    mut alloc_pa: &mut F,
) -> Result<(), WalkErr> {
    let mut current_pa = root_pa;
    let shifts = [L0_SHIFT, L1_SHIFT, L2_SHIFT, L3_SHIFT];
    // Walk levels 0..(leaf_level - 1), descending into table entries.
    for level in 0..leaf_level {
        let idx = ((va >> shifts[level as usize]) & TABLE_IDX_MASK) as usize;
        // SAFETY: per fn contract; descend through one level of tables.
        current_pa = unsafe { walk_or_alloc::<W, _>(current_pa, idx, hhdm_offset, &mut alloc_pa)? };
    }
    // `current_pa` is the parent of the leaf level. Write the leaf
    // at the appropriate index.
    let leaf_idx = ((va >> shifts[leaf_level as usize]) & TABLE_IDX_MASK) as usize;
    // SAFETY: HHDM covers page-table memory per fn contract; we own
    // the slot for the duration of the write per single-CPU walker.
    unsafe {
        let table_va = (hhdm_offset.wrapping_add(current_pa)) as *mut u64;
        let slot = table_va.add(leaf_idx);
        let cur = ptr::read_volatile(slot);
        if W::is_valid(cur) && (cur & W::PHYS_MASK) != (leaf & W::PHYS_MASK) {
            return Err(WalkErr::AlreadyMapped);
        }
        ptr::write_volatile(slot, leaf);
        W::flush_va(va);
    }
    Ok(())
}


/// Read entry `[idx]` in the table at PA `parent_pa` (via HHDM).
/// If empty, allocate + zero-init + link a fresh child table and
/// return its PA. If present and a non-bottom-level leaf, error.
///
/// # SAFETY: see `map_device_4k`.
unsafe fn walk_or_alloc<W: PtWalker, F: FnMut() -> Option<u64>>(
    parent_pa: u64,
    idx: usize,
    hhdm_offset: u64,
    alloc_pa: &mut F,
) -> Result<u64, WalkErr> {
    // SAFETY: parent_pa references a 4 KiB-aligned table page; HHDM maps it into kernel VA; single-CPU/IRQs-off per `map_device_4k`'s contract.
    unsafe {
        let parent_va = (hhdm_offset.wrapping_add(parent_pa)) as *mut u64;
        let slot = parent_va.add(idx);
        let entry = ptr::read_volatile(slot);
        if !W::is_valid(entry) {
            let child_pa = alloc_pa().ok_or(WalkErr::AllocFailed)?;
            // Fresh kernel-owned frame; zero every entry through HHDM
            // so a missing leaf below acts as "not present".
            let child_va = (hhdm_offset.wrapping_add(child_pa)) as *mut u64;
            for k in 0..ENTRIES_PER_TABLE {
                ptr::write_volatile(child_va.add(k), 0);
            }
            ptr::write_volatile(slot, W::pack_table(child_pa));
            return Ok(child_pa);
        }
        if W::is_huge_or_block(entry) {
            return Err(WalkErr::HitHugeOrBlock);
        }
        Ok(entry & W::PHYS_MASK)
    }
}
