use core::ptr;

use super::{PtWalker, ENTRIES_PER_TABLE, L0_SHIFT, L1_SHIFT, L2_SHIFT, L3_SHIFT, TABLE_IDX_MASK};

/// Tear down the user half of a page-table tree rooted at
/// `root_pa`: walk every present leaf in L0[0..256] (canonical
/// "low-half user" on both x86 PML4 and aarch64 TTBR0) and hand
/// each leaf physical address plus each intermediate-table page
/// to `free_pa`. The L0 table itself (`root_pa`) is NOT freed by
/// this fn — the caller decides whether the root is owned by the
/// AS or shared.
///
/// Skips huge/block leaves (`is_huge_or_block`); v1 user mappings
/// are uniform 4 KiB. Skips not-present entries.
///
/// # SAFETY: caller asserts (a) HHDM covers the table memory,
/// (b) the root is no longer active on any CPU (else freeing the
/// frames would race with hardware walks), (c) `free_pa` matches
/// the allocator that handed out the pages.
/// # C: O(N_present_leaves + N_present_tables)
/// # Ctx: AS drop, single-CPU UP.
pub unsafe fn free_user_tree<W: PtWalker, F: FnMut(u64)>(
    root_pa: u64,
    hhdm_offset: u64,
    mut free_pa: F,
) {
    // SAFETY: per-fn contract — HHDM maps the root + child tables read/write.
    unsafe {
        let l0 = (hhdm_offset.wrapping_add(root_pa)) as *const u64;
        for i_l0 in 0..(ENTRIES_PER_TABLE / 2) {
            let e0 = ptr::read_volatile(l0.add(i_l0));
            if !W::is_valid(e0) || W::is_huge_or_block(e0) { continue; }
            let l1_pa = e0 & W::PHYS_MASK;
            let l1 = (hhdm_offset.wrapping_add(l1_pa)) as *const u64;
            for i_l1 in 0..ENTRIES_PER_TABLE {
                let e1 = ptr::read_volatile(l1.add(i_l1));
                if !W::is_valid(e1) || W::is_huge_or_block(e1) { continue; }
                let l2_pa = e1 & W::PHYS_MASK;
                let l2 = (hhdm_offset.wrapping_add(l2_pa)) as *const u64;
                for i_l2 in 0..ENTRIES_PER_TABLE {
                    let e2 = ptr::read_volatile(l2.add(i_l2));
                    if !W::is_valid(e2) || W::is_huge_or_block(e2) { continue; }
                    let l3_pa = e2 & W::PHYS_MASK;
                    let l3 = (hhdm_offset.wrapping_add(l3_pa)) as *const u64;
                    for i_l3 in 0..ENTRIES_PER_TABLE {
                        let leaf = ptr::read_volatile(l3.add(i_l3));
                        if !W::is_valid(leaf) { continue; }
                        free_pa(leaf & W::PHYS_MASK);
                    }
                    free_pa(l3_pa);
                }
                free_pa(l2_pa);
            }
            free_pa(l1_pa);
        }
    }
}

/// Like `free_user_tree` but with separate callbacks for **leaves**
/// (4 KiB pages mapped to user) and **tables** (intermediate PT
/// frames). F157: lets the kernel call `dec_and_maybe_free_frame`
/// for leaves (COW-aware refcount) while always-freeing the
/// intermediate tables (always private to one AS).
/// # SAFETY: same as `free_user_tree`.
/// # C: same as `free_user_tree`.
pub unsafe fn free_user_tree_leafmap<W, FL, FT>(
    root_pa: u64,
    hhdm_offset: u64,
    free_leaf: &mut FL,
    free_table: &mut FT,
)
where
    W: PtWalker,
    FL: FnMut(u64, u64),
    FT: FnMut(u64),
{
    // SAFETY: per-fn contract — HHDM maps the root + child tables read/write.
    unsafe {
        let l0 = (hhdm_offset.wrapping_add(root_pa)) as *const u64;
        // Only iterate the user half: L0 indices 0..256. The kernel
        // half (256..512) is shared from the master template and
        // must not be freed.
        for i_l0 in 0..(ENTRIES_PER_TABLE / 2) {
            let e0 = ptr::read_volatile(l0.add(i_l0));
            if !W::is_valid(e0) || W::is_huge_or_block(e0) { continue; }
            let l1_pa = e0 & W::PHYS_MASK;
            let l1 = (hhdm_offset.wrapping_add(l1_pa)) as *const u64;
            for i_l1 in 0..ENTRIES_PER_TABLE {
                let e1 = ptr::read_volatile(l1.add(i_l1));
                if !W::is_valid(e1) || W::is_huge_or_block(e1) { continue; }
                let l2_pa = e1 & W::PHYS_MASK;
                let l2 = (hhdm_offset.wrapping_add(l2_pa)) as *const u64;
                for i_l2 in 0..ENTRIES_PER_TABLE {
                    let e2 = ptr::read_volatile(l2.add(i_l2));
                    if !W::is_valid(e2) || W::is_huge_or_block(e2) { continue; }
                    let l3_pa = e2 & W::PHYS_MASK;
                    let l3 = (hhdm_offset.wrapping_add(l3_pa)) as *const u64;
                    for i_l3 in 0..ENTRIES_PER_TABLE {
                        let leaf = ptr::read_volatile(l3.add(i_l3));
                        if !W::is_valid(leaf) { continue; }
                        // Reconstruct the user VA from the 4-level indices so
                        // the leaf callback can identify the mapping (free-
                        // while-mapped detection). User half ⇒ no sign-extend.
                        let va = ((i_l0 as u64) << L0_SHIFT)
                               | ((i_l1 as u64) << L1_SHIFT)
                               | ((i_l2 as u64) << L2_SHIFT)
                               | ((i_l3 as u64) << L3_SHIFT);
                        free_leaf(va, leaf & W::PHYS_MASK);
                    }
                    free_table(l3_pa);
                }
                free_table(l2_pa);
            }
            free_table(l1_pa);
        }
    }
}


/// Tear down a leaf at `va` regardless of size. Walks live tables,
/// stops at the first leaf encountered (4 KiB page or huge block),
/// zeroes its slot, and locally flushes the TLB. Returns the
/// `(torn_leaf, leaf_level)` on success or `None` if no leaf is
/// present.
///
/// # SAFETY: caller asserts (a) HHDM covers page-table memory,
/// (b) `va` exclusively owned (no concurrent walker/use), (c)
/// caller will perform any cross-CPU TLB shootdown beyond the
/// local invalidate this function does.
/// # C: O(walk depth) = O(4)
/// # Ctx: pre-init or under PT-write lock.
pub unsafe fn unmap_at_va<W: PtWalker>(va: u64, hhdm_offset: u64) -> Option<(u64, u8)> {
    // SAFETY: privileged read; legal in kernel mode.
    let mut current_pa = unsafe { W::read_pt_base(va) };
    let shifts = [L0_SHIFT, L1_SHIFT, L2_SHIFT, L3_SHIFT];
    for level in 0..4u8 {
        let idx = ((va >> shifts[level as usize]) & TABLE_IDX_MASK) as usize;
        // SAFETY: HHDM covers page-table memory; va exclusively owned per fn contract.
        unsafe {
            let table = (hhdm_offset.wrapping_add(current_pa)) as *mut u64;
            let slot = table.add(idx);
            let entry = ptr::read_volatile(slot);
            if !W::is_valid(entry) { return None; }
            let is_leaf = level == 3 || (W::is_huge_or_block(entry) && level != 0);
            if is_leaf {
                ptr::write_volatile(slot, 0);
                W::flush_va(va);
                return Some((entry, level));
            }
            // L0 with huge bit set is malformed; bail.
            if W::is_huge_or_block(entry) { return None; }
            current_pa = entry & W::PHYS_MASK;
        }
    }
    None
}

/// Tear down a 4 KiB leaf at `va` if present. No-op if not mapped
/// or if a non-bottom-level entry blocks the walk. Returns the
/// torn-down leaf entry on success.
///
/// # SAFETY: caller asserts (a) HHDM covers page-table memory,
/// (b) `va` exclusively owned (no concurrent walker/use), (c)
/// caller will perform any cross-CPU TLB shootdown beyond the
/// local invalidate this function does.
/// # C: O(walk depth) = O(4)
/// # Ctx: pre-init or under PT-write lock.
pub unsafe fn unmap_4k<W: PtWalker>(va: u64, hhdm_offset: u64) -> Option<u64> {
    // SAFETY: privileged read; legal in kernel mode.
    let l0_pa = unsafe { W::read_pt_base(va) };
    let i_l0 = ((va >> L0_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l1 = ((va >> L1_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l2 = ((va >> L2_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l3 = ((va >> L3_SHIFT) & TABLE_IDX_MASK) as usize;

    // SAFETY: HHDM covers page-table memory; va owned by caller;
    // single writer per fn contract.
    unsafe {
        let l0 = (hhdm_offset.wrapping_add(l0_pa)) as *const u64;
        let e0 = ptr::read_volatile(l0.add(i_l0));
        if !W::is_valid(e0) || W::is_huge_or_block(e0) { return None; }
        let l1 = (hhdm_offset.wrapping_add(e0 & W::PHYS_MASK)) as *const u64;
        let e1 = ptr::read_volatile(l1.add(i_l1));
        if !W::is_valid(e1) || W::is_huge_or_block(e1) { return None; }
        let l2 = (hhdm_offset.wrapping_add(e1 & W::PHYS_MASK)) as *const u64;
        let e2 = ptr::read_volatile(l2.add(i_l2));
        if !W::is_valid(e2) || W::is_huge_or_block(e2) { return None; }
        let l3 = (hhdm_offset.wrapping_add(e2 & W::PHYS_MASK)) as *mut u64;
        let slot = l3.add(i_l3);
        let leaf = ptr::read_volatile(slot);
        if !W::is_valid(leaf) { return None; }
        ptr::write_volatile(slot, 0);
        W::flush_va(va);
        Some(leaf)
    }
}

