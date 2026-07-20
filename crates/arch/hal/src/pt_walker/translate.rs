use core::ptr;

use super::{MigrationEntry, PtWalker, SwapEntry, L0_SHIFT, L1_SHIFT, L2_SHIFT, L3_SHIFT, TABLE_IDX_MASK};

/// Translate `va` to (`pa`, raw_leaf_entry) by walking the live
/// tables. Returns `None` if the leaf is missing or sits at a
/// non-bottom level (huge/block — caller decides). Reads only;
/// safe to call without holding a PT-write lock if the caller
/// accepts a torn-walk view (some entries from before, some from
/// after a concurrent write).
///
/// # SAFETY: caller asserts (a) HHDM covers page-table memory,
/// (b) the active root is stable for the walk duration. Single-
/// CPU + IRQ-off makes (b) trivially hold.
/// # C: O(walk depth) = O(4)
/// # Ctx: read-only walk
pub unsafe fn translate_4k<W: PtWalker>(va: u64, hhdm_offset: u64) -> Option<(u64, u64)> {
    // SAFETY: privileged read; legal in kernel mode.
    let l0_pa = unsafe { W::read_pt_base(va) };
    let i_l0 = ((va >> L0_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l1 = ((va >> L1_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l2 = ((va >> L2_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l3 = ((va >> L3_SHIFT) & TABLE_IDX_MASK) as usize;

    // SAFETY: HHDM covers page-table memory per fn contract; reads only.
    unsafe {
        let l0 = (hhdm_offset.wrapping_add(l0_pa)) as *const u64;
        let e0 = ptr::read_volatile(l0.add(i_l0));
        if !W::is_valid(e0) || W::is_huge_or_block(e0) { return None; }
        let l1_pa = e0 & W::PHYS_MASK;
        let l1 = (hhdm_offset.wrapping_add(l1_pa)) as *const u64;
        let e1 = ptr::read_volatile(l1.add(i_l1));
        if !W::is_valid(e1) || W::is_huge_or_block(e1) { return None; }
        let l2_pa = e1 & W::PHYS_MASK;
        let l2 = (hhdm_offset.wrapping_add(l2_pa)) as *const u64;
        let e2 = ptr::read_volatile(l2.add(i_l2));
        if !W::is_valid(e2) || W::is_huge_or_block(e2) { return None; }
        let l3_pa = e2 & W::PHYS_MASK;
        let l3 = (hhdm_offset.wrapping_add(l3_pa)) as *const u64;
        let leaf = ptr::read_volatile(l3.add(i_l3));
        if !W::is_valid(leaf) { return None; }
        Some((leaf & W::PHYS_MASK, leaf))
    }
}

/// Same as `translate_4k` but walks tables rooted at the
/// caller-supplied `root_pa` instead of the active CR3 / TTBR.
/// Used for foreign-mm reads (e.g. ptrace PEEK reading another
/// task's user memory) where we have the AddressSpace's
/// `root_pa()` but the target is not the running task.
///
/// # SAFETY: same as `translate_4k`, plus caller asserts
/// `root_pa` is a valid 4 KiB-aligned page-table root frame
/// owned by a live AddressSpace; the AS must outlive the walk
/// (caller holds an Arc keeping it alive).
/// # C: O(walk depth) = O(4)
/// # Ctx: read-only walk
pub unsafe fn translate_4k_at_root<W: PtWalker>(
    root_pa: u64, va: u64, hhdm_offset: u64,
) -> Option<(u64, u64)> {
    let i_l0 = ((va >> L0_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l1 = ((va >> L1_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l2 = ((va >> L2_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l3 = ((va >> L3_SHIFT) & TABLE_IDX_MASK) as usize;
    // SAFETY: HHDM covers page-table memory per fn contract; reads only.
    unsafe {
        let l0 = (hhdm_offset.wrapping_add(root_pa)) as *const u64;
        let e0 = ptr::read_volatile(l0.add(i_l0));
        if !W::is_valid(e0) || W::is_huge_or_block(e0) { return None; }
        let l1_pa = e0 & W::PHYS_MASK;
        let l1 = (hhdm_offset.wrapping_add(l1_pa)) as *const u64;
        let e1 = ptr::read_volatile(l1.add(i_l1));
        if !W::is_valid(e1) || W::is_huge_or_block(e1) { return None; }
        let l2_pa = e1 & W::PHYS_MASK;
        let l2 = (hhdm_offset.wrapping_add(l2_pa)) as *const u64;
        let e2 = ptr::read_volatile(l2.add(i_l2));
        if !W::is_valid(e2) || W::is_huge_or_block(e2) { return None; }
        let l3_pa = e2 & W::PHYS_MASK;
        let l3 = (hhdm_offset.wrapping_add(l3_pa)) as *const u64;
        let leaf = ptr::read_volatile(l3.add(i_l3));
        if !W::is_valid(leaf) { return None; }
        Some((leaf & W::PHYS_MASK, leaf))
    }
}

/// Decode a non-present swap entry at a 4 KiB leaf in a supplied AS root.
/// `None` means either a missing walk, a present leaf, or another non-present
/// state such as userfaultfd. The caller owns synchronization with PTE writes.
///
/// # SAFETY: `root_pa` references a live AS root and HHDM covers its tables.
/// # C: O(walk depth)
pub unsafe fn swap_entry_4k_at_root<W: PtWalker>(
    root_pa: u64, va: u64, hhdm_offset: u64,
) -> Option<SwapEntry> {
    let i_l0 = ((va >> L0_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l1 = ((va >> L1_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l2 = ((va >> L2_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l3 = ((va >> L3_SHIFT) & TABLE_IDX_MASK) as usize;
    // SAFETY: caller keeps the root live; this reads only HHDM-mapped tables.
    unsafe {
        let l0 = (hhdm_offset.wrapping_add(root_pa)) as *const u64;
        let e0 = ptr::read_volatile(l0.add(i_l0));
        if !W::is_valid(e0) || W::is_huge_or_block(e0) { return None; }
        let l1 = (hhdm_offset.wrapping_add(e0 & W::PHYS_MASK)) as *const u64;
        let e1 = ptr::read_volatile(l1.add(i_l1));
        if !W::is_valid(e1) || W::is_huge_or_block(e1) { return None; }
        let l2 = (hhdm_offset.wrapping_add(e1 & W::PHYS_MASK)) as *const u64;
        let e2 = ptr::read_volatile(l2.add(i_l2));
        if !W::is_valid(e2) || W::is_huge_or_block(e2) { return None; }
        let l3 = (hhdm_offset.wrapping_add(e2 & W::PHYS_MASK)) as *const u64;
        W::unpack_swap_entry(ptr::read_volatile(l3.add(i_l3)))
    }
}

/// Decode one transient migration marker at a supplied root. # C: O(walk depth)
pub unsafe fn migration_entry_4k_at_root<W: PtWalker>(root_pa: u64, va: u64, hhdm_offset: u64) -> Option<MigrationEntry> {
    let i0 = ((va >> L0_SHIFT) & TABLE_IDX_MASK) as usize;
    let i1 = ((va >> L1_SHIFT) & TABLE_IDX_MASK) as usize;
    let i2 = ((va >> L2_SHIFT) & TABLE_IDX_MASK) as usize;
    let i3 = ((va >> L3_SHIFT) & TABLE_IDX_MASK) as usize;
    // SAFETY: caller keeps root/table pages alive and serializes PTE mutation.
    unsafe {
        let l0 = (hhdm_offset + root_pa) as *const u64;
        let e0 = ptr::read_volatile(l0.add(i0)); if !W::is_valid(e0) || W::is_huge_or_block(e0) { return None; }
        let l1 = (hhdm_offset + (e0 & W::PHYS_MASK)) as *const u64;
        let e1 = ptr::read_volatile(l1.add(i1)); if !W::is_valid(e1) || W::is_huge_or_block(e1) { return None; }
        let l2 = (hhdm_offset + (e1 & W::PHYS_MASK)) as *const u64;
        let e2 = ptr::read_volatile(l2.add(i2)); if !W::is_valid(e2) || W::is_huge_or_block(e2) { return None; }
        let l3 = (hhdm_offset + (e2 & W::PHYS_MASK)) as *const u64;
        W::unpack_migration_entry(ptr::read_volatile(l3.add(i3)))
    }
}

/// Walk `[va_start, va_end)` in 4 KiB steps and rewrite each
/// present 4 KiB leaf with `W::pack_4k_leaf(pa, new_flags)`,
/// preserving the leaf's PA. Skips not-present and huge/block
/// leaves (per-page mprotect on a huge mapping needs split-down
/// first; rare in v1 — most user mappings are 4 KiB). Returns
/// the count of leaves actually rewritten.
///
/// Caller is responsible for TLB invalidation of every va in
/// the range AFTER this returns; this fn writes the PTE entries
/// only.
///
/// # SAFETY: same contract as `translate_4k_at_root` plus
/// caller asserts no concurrent walker / fault path is racing
/// with the rewrite (single-CPU + IRQ-off or per-AS PT lock).
/// # C: O((va_end - va_start) / 4096 * walk_depth)
/// # Ctx: under PT lock or pre-init single-CPU.
pub unsafe fn protect_4k_at_root<W: PtWalker>(
    root_pa: u64, va_start: u64, va_end: u64, new_flags: crate::PageFlags,
    hhdm_offset: u64,
) -> usize {
    let mut updated = 0usize;
    let mut va = va_start & !((1u64 << L3_SHIFT) - 1);
    while va < va_end {
        let i_l0 = ((va >> L0_SHIFT) & TABLE_IDX_MASK) as usize;
        let i_l1 = ((va >> L1_SHIFT) & TABLE_IDX_MASK) as usize;
        let i_l2 = ((va >> L2_SHIFT) & TABLE_IDX_MASK) as usize;
        let i_l3 = ((va >> L3_SHIFT) & TABLE_IDX_MASK) as usize;
        // SAFETY: HHDM covers PT memory per fn contract; reads/writes only the L3 leaf slot which is exclusive under the PT lock.
        unsafe {
            let l0 = (hhdm_offset.wrapping_add(root_pa)) as *const u64;
            let e0 = ptr::read_volatile(l0.add(i_l0));
            if W::is_valid(e0) && !W::is_huge_or_block(e0) {
                let l1_pa = e0 & W::PHYS_MASK;
                let l1 = (hhdm_offset.wrapping_add(l1_pa)) as *const u64;
                let e1 = ptr::read_volatile(l1.add(i_l1));
                if W::is_valid(e1) && !W::is_huge_or_block(e1) {
                    let l2_pa = e1 & W::PHYS_MASK;
                    let l2 = (hhdm_offset.wrapping_add(l2_pa)) as *const u64;
                    let e2 = ptr::read_volatile(l2.add(i_l2));
                    if W::is_valid(e2) && !W::is_huge_or_block(e2) {
                        let l3_pa = e2 & W::PHYS_MASK;
                        let l3 = (hhdm_offset.wrapping_add(l3_pa)) as *mut u64;
                        let leaf = ptr::read_volatile(l3.add(i_l3));
                        if W::is_valid(leaf) {
                            let pa = leaf & W::PHYS_MASK;
                            let new_leaf = W::pack_4k_leaf(pa, new_flags);
                            ptr::write_volatile(l3.add(i_l3), new_leaf);
                            updated += 1;
                        }
                    }
                }
            }
        }
        va = va.wrapping_add(1u64 << L3_SHIFT);
    }
    updated
}


/// Translate `va` walking the live tables, recognising huge/block
/// leaves at intermediate levels. Returns
/// `Some((pa_for_va, raw_leaf, leaf_level))` where:
/// - `pa_for_va` includes the in-leaf offset (so `va`'s low bits
///   appear in the result).
/// - `raw_leaf` is the unmodified leaf entry (caller decodes flags).
/// - `leaf_level` ∈ {1 (1 GiB block), 2 (2 MiB block), 3 (4 KiB page)}.
///
/// Returns `None` if no leaf is present along the walk.
///
/// # SAFETY: caller asserts (a) HHDM covers page-table memory,
/// (b) the active root is stable for the walk duration. Reads only.
/// # C: O(walk depth) = O(4)
/// # Ctx: read-only walk
pub unsafe fn translate_at_va<W: PtWalker>(va: u64, hhdm_offset: u64) -> Option<(u64, u64, u8)> {
    // SAFETY: privileged read; legal in kernel mode.
    let mut current_pa = unsafe { W::read_pt_base(va) };
    let shifts = [L0_SHIFT, L1_SHIFT, L2_SHIFT, L3_SHIFT];
    for level in 0..4u8 {
        let idx = ((va >> shifts[level as usize]) & TABLE_IDX_MASK) as usize;
        // SAFETY: HHDM covers page-table memory per fn contract; reads only.
        let entry = unsafe {
            let table = (hhdm_offset.wrapping_add(current_pa)) as *const u64;
            ptr::read_volatile(table.add(idx))
        };
        if !W::is_valid(entry) { return None; }
        if level == 3 {
            // L3 page leaf — final descent.
            let page_pa = entry & W::PHYS_MASK;
            let offset = va & ((1u64 << L3_SHIFT) - 1);
            return Some((page_pa | offset, entry, 3));
        }
        if W::is_huge_or_block(entry) {
            // Block leaf at L1 (1 GiB) or L2 (2 MiB). L0 huge isn't
            // legal on either arch in v1 — bail to avoid a 512 GiB
            // misread.
            if level == 0 { return None; }
            let block_pa = entry & W::PHYS_MASK;
            let offset = va & ((1u64 << shifts[level as usize]) - 1);
            return Some((block_pa | offset, entry, level));
        }
        current_pa = entry & W::PHYS_MASK;
    }
    None
}
