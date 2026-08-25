use core::ptr;

use super::super::{MigrationEntry, PtWalker, SwapEntry, ENTRIES_PER_TABLE,
    L0_SHIFT, L1_SHIFT, L2_SHIFT, L3_SHIFT};

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

/// Like `free_user_tree` but with separate callbacks for **present leaves**,
/// **swap leaves**, **migration-marker leaves**, and **tables**.
/// (4 KiB pages mapped to user) and **tables** (intermediate PT
/// frames). F157: lets the kernel call `dec_and_maybe_free_frame`
/// for leaves (COW-aware refcount) while always-freeing the
/// intermediate tables (always private to one AS).
/// # SAFETY: same as `free_user_tree`.
/// # C: same as `free_user_tree`.
pub unsafe fn free_user_tree_leafmap<W, FL, FS, FM, FT>(
    root_pa: u64,
    hhdm_offset: u64,
    free_leaf: &mut FL,
    free_swap: &mut FS,
    free_migration: &mut FM,
    free_table: &mut FT,
)
where
    W: PtWalker,
    FL: FnMut(u64, u64, crate::PageSize),
    FS: FnMut(u64, SwapEntry),
    FM: FnMut(u64, MigrationEntry),
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
                if !W::is_valid(e1) { continue; }
                if W::is_huge_or_block(e1) {
                    // A 1 GiB block leaf. Skipping it would leak the mapping
                    // reference it holds on the huge page behind it, so that
                    // page would never return to the pool that owns it.
                    let va = ((i_l0 as u64) << L0_SHIFT) | ((i_l1 as u64) << L1_SHIFT);
                    free_leaf(va, e1 & W::PHYS_MASK, crate::PageSize::P1G);
                    continue;
                }
                let l2_pa = e1 & W::PHYS_MASK;
                let l2 = (hhdm_offset.wrapping_add(l2_pa)) as *const u64;
                for i_l2 in 0..ENTRIES_PER_TABLE {
                    let e2 = ptr::read_volatile(l2.add(i_l2));
                    if !W::is_valid(e2) { continue; }
                    if W::is_huge_or_block(e2) {
                        // A 2 MiB block leaf — the granule a hugetlbfs mapping
                        // installs. Same reasoning as the 1 GiB case above.
                        let va = ((i_l0 as u64) << L0_SHIFT)
                               | ((i_l1 as u64) << L1_SHIFT)
                               | ((i_l2 as u64) << L2_SHIFT);
                        free_leaf(va, e2 & W::PHYS_MASK, crate::PageSize::P2M);
                        continue;
                    }
                    let l3_pa = e2 & W::PHYS_MASK;
                    let l3 = (hhdm_offset.wrapping_add(l3_pa)) as *const u64;
                    for i_l3 in 0..ENTRIES_PER_TABLE {
                        let leaf = ptr::read_volatile(l3.add(i_l3));
                        // Reconstruct the user VA from the 4-level indices so
                        // the leaf callback can identify the mapping (free-
                        // while-mapped detection). User half ⇒ no sign-extend.
                        let va = ((i_l0 as u64) << L0_SHIFT)
                               | ((i_l1 as u64) << L1_SHIFT)
                               | ((i_l2 as u64) << L2_SHIFT)
                               | ((i_l3 as u64) << L3_SHIFT);
                        if W::is_valid(leaf) {
                            free_leaf(va, leaf & W::PHYS_MASK, crate::PageSize::P4K);
                        } else if let Some(entry) = W::unpack_swap_entry(leaf) {
                            free_swap(va, entry);
                        } else if let Some(entry) = W::unpack_migration_entry(leaf) {
                            free_migration(va, entry);
                        }
                    }
                    free_table(l3_pa);
                }
                free_table(l2_pa);
            }
            free_table(l1_pa);
        }
    }
}

/// Visit every architecture-encoded swap PTE in the user half of `root_pa`.
/// The visitor runs synchronously while the caller holds the address space's
/// PTE lock; it must not block or mutate page tables. Swapoff uses this pass
/// to collect migration work before performing I/O outside that lock.
///
/// # SAFETY: `root_pa` is live, HHDM covers its tables, and its PTE lock is
/// held for the duration of the walk.
/// # C: O(user page-table entries)
pub unsafe fn walk_user_swap_entries_at_root<W, F>(
    root_pa: u64, hhdm_offset: u64, mut visit: F,
)
where
    W: PtWalker,
    F: FnMut(u64, SwapEntry),
{
    // SAFETY: caller pins the root and serializes leaf mutation with its PTE lock.
    unsafe {
        let l0 = (hhdm_offset.wrapping_add(root_pa)) as *const u64;
        for i_l0 in 0..(ENTRIES_PER_TABLE / 2) {
            let e0 = ptr::read_volatile(l0.add(i_l0));
            if !W::is_valid(e0) || W::is_huge_or_block(e0) { continue; }
            let l1 = (hhdm_offset.wrapping_add(e0 & W::PHYS_MASK)) as *const u64;
            for i_l1 in 0..ENTRIES_PER_TABLE {
                let e1 = ptr::read_volatile(l1.add(i_l1));
                if !W::is_valid(e1) || W::is_huge_or_block(e1) { continue; }
                let l2 = (hhdm_offset.wrapping_add(e1 & W::PHYS_MASK)) as *const u64;
                for i_l2 in 0..ENTRIES_PER_TABLE {
                    let e2 = ptr::read_volatile(l2.add(i_l2));
                    if !W::is_valid(e2) || W::is_huge_or_block(e2) { continue; }
                    let l3 = (hhdm_offset.wrapping_add(e2 & W::PHYS_MASK)) as *const u64;
                    for i_l3 in 0..ENTRIES_PER_TABLE {
                        let leaf = ptr::read_volatile(l3.add(i_l3));
                        let Some(entry) = W::unpack_swap_entry(leaf) else { continue; };
                        let va = ((i_l0 as u64) << L0_SHIFT)
                            | ((i_l1 as u64) << L1_SHIFT)
                            | ((i_l2 as u64) << L2_SHIFT)
                            | ((i_l3 as u64) << L3_SHIFT);
                        visit(va, entry);
                    }
                }
            }
        }
    }
}
