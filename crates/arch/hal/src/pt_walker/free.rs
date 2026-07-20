use core::ptr;

use super::{MigrationEntry, PtWalker, SwapEntry, ENTRIES_PER_TABLE, L0_SHIFT, L1_SHIFT, L2_SHIFT, L3_SHIFT, TABLE_IDX_MASK};

/// A zero leaf slot is architecturally absent on both supported walkers.
const EMPTY_PTE: u64 = 0;

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
    FL: FnMut(u64, u64),
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
                        // Reconstruct the user VA from the 4-level indices so
                        // the leaf callback can identify the mapping (free-
                        // while-mapped detection). User half ⇒ no sign-extend.
                        let va = ((i_l0 as u64) << L0_SHIFT)
                               | ((i_l1 as u64) << L1_SHIFT)
                               | ((i_l2 as u64) << L2_SHIFT)
                               | ((i_l3 as u64) << L3_SHIFT);
                        if W::is_valid(leaf) {
                            free_leaf(va, leaf & W::PHYS_MASK);
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

/// Clear `expected` only when it remains the swap PTE at `va`.  The checked
/// transition makes zapping race-safe against swap-in and preserves the slot
/// reference until no page table can reach it.
///
/// # SAFETY: caller holds the owning address space PTE lock; `root_pa` is live
/// and HHDM covers every traversed table page.
/// # C: O(walk depth)
pub unsafe fn clear_swap_4k_at_root<W: PtWalker>(
    root_pa: u64, va: u64, expected: SwapEntry, hhdm_offset: u64,
) -> bool {
    let i_l0 = ((va >> L0_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l1 = ((va >> L1_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l2 = ((va >> L2_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l3 = ((va >> L3_SHIFT) & TABLE_IDX_MASK) as usize;
    // SAFETY: caller serializes the leaf slot and HHDM maps the page tables.
    unsafe {
        let l0 = (hhdm_offset.wrapping_add(root_pa)) as *const u64;
        let e0 = ptr::read_volatile(l0.add(i_l0));
        if !W::is_valid(e0) || W::is_huge_or_block(e0) { return false; }
        let l1 = (hhdm_offset.wrapping_add(e0 & W::PHYS_MASK)) as *const u64;
        let e1 = ptr::read_volatile(l1.add(i_l1));
        if !W::is_valid(e1) || W::is_huge_or_block(e1) { return false; }
        let l2 = (hhdm_offset.wrapping_add(e1 & W::PHYS_MASK)) as *const u64;
        let e2 = ptr::read_volatile(l2.add(i_l2));
        if !W::is_valid(e2) || W::is_huge_or_block(e2) { return false; }
        let l3 = (hhdm_offset.wrapping_add(e2 & W::PHYS_MASK)) as *mut u64;
        let slot = l3.add(i_l3);
        if ptr::read_volatile(slot) != W::pack_swap_entry(expected) { return false; }
        ptr::write_volatile(slot, EMPTY_PTE);
        true
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

/// Tear down a 4 KiB leaf at `va` in the tree rooted at the
/// caller-supplied `root_pa` (not the active CR3/TTBR). Mirror of
/// `unmap_4k` for a FOREIGN address space (process_madvise
/// MADV_DONTNEED/FREE targeting another task). Zeroes the leaf slot
/// and returns the leaf's PHYSICAL address (`leaf & PHYS_MASK`, flag
/// bits stripped); `None` if not present or a non-bottom-level entry
/// blocks the walk. Does NOT flush any TLB —
/// `root_pa` is a non-active root; the target's TLB is flushed on its
/// next CR3/TTBR reload (UP: the foreign task is not concurrently
/// executing).
///
/// # SAFETY: caller asserts (a) HHDM covers page-table memory, (b)
/// `root_pa` is a valid 4 KiB-aligned root of a live AS the caller
/// keeps alive (Arc) and that is NOT active on this CPU, (c) `va` in
/// that AS is exclusively owned for the duration (UP + preempt-off,
/// target not running).
/// # C: O(walk depth) = O(4)
/// # Ctx: UP single-CPU, target not scheduled.
pub unsafe fn unmap_4k_at_root<W: PtWalker>(root_pa: u64, va: u64, hhdm_offset: u64) -> Option<u64> {
    let i_l0 = ((va >> L0_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l1 = ((va >> L1_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l2 = ((va >> L2_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l3 = ((va >> L3_SHIFT) & TABLE_IDX_MASK) as usize;
    // SAFETY: HHDM covers page-table memory; `root_pa` is a live
    // non-active root exclusively owned per fn contract; only the L3
    // leaf slot is written.
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
        let l3 = (hhdm_offset.wrapping_add(e2 & W::PHYS_MASK)) as *mut u64;
        let slot = l3.add(i_l3);
        let leaf = ptr::read_volatile(slot);
        if !W::is_valid(leaf) { return None; }
        ptr::write_volatile(slot, 0);
        Some(leaf & W::PHYS_MASK)
    }
}

/// Replace a present 4 KiB leaf with an architecture-encoded non-present swap
/// entry. Returns the displaced raw leaf so the caller can account its frame;
/// does not invalidate a TLB because `root_pa` is foreign to the caller.
///
/// # SAFETY: `root_pa` is a live, non-active AS root; its PTE lock is held;
/// HHDM covers its tables; the target VA is a 4 KiB present leaf.
/// # C: O(walk depth)
pub unsafe fn replace_present_4k_with_swap_at_root<W: PtWalker>(
    root_pa: u64, va: u64, entry: SwapEntry, hhdm_offset: u64,
) -> Option<u64> {
    let i_l0 = ((va >> L0_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l1 = ((va >> L1_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l2 = ((va >> L2_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l3 = ((va >> L3_SHIFT) & TABLE_IDX_MASK) as usize;
    // SAFETY: caller supplies an exclusive live root and an HHDM mapping of every table.
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
        let l3 = (hhdm_offset.wrapping_add(e2 & W::PHYS_MASK)) as *mut u64;
        let slot = l3.add(i_l3);
        let leaf = ptr::read_volatile(slot);
        if !W::is_valid(leaf) { return None; }
        ptr::write_volatile(slot, W::pack_swap_entry(entry));
        Some(leaf)
    }
}

/// Replace a present 4 KiB leaf only if it still maps `expected_pa`. The
/// physical-address comparison closes the rmap-walk-to-PTE-rewrite race: a
/// stale page-out visit cannot replace a subsequently remapped leaf.
/// Does not invalidate a TLB; the caller owns the address-space shootdown.
///
/// # SAFETY: `root_pa` is live; its PTE lock is held; HHDM covers its tables;
/// and `expected_pa` is page-aligned.
/// # C: O(walk depth)
pub unsafe fn replace_present_4k_with_swap_if_pa_at_root<W: PtWalker>(
    root_pa: u64, va: u64, expected_pa: u64, entry: SwapEntry, hhdm_offset: u64,
) -> Option<u64> {
    let i_l0 = ((va >> L0_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l1 = ((va >> L1_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l2 = ((va >> L2_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l3 = ((va >> L3_SHIFT) & TABLE_IDX_MASK) as usize;
    // SAFETY: caller supplies an exclusive live root and an HHDM mapping of every table.
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
        let l3 = (hhdm_offset.wrapping_add(e2 & W::PHYS_MASK)) as *mut u64;
        let slot = l3.add(i_l3);
        let leaf = ptr::read_volatile(slot);
        if !W::is_valid(leaf) || leaf & W::PHYS_MASK != expected_pa & W::PHYS_MASK { return None; }
        ptr::write_volatile(slot, W::pack_swap_entry(entry));
        Some(leaf)
    }
}

/// Rewrite the flags of a present 4 KiB leaf only if it still maps
/// `expected_pa`. Page-out uses this to write-protect exactly the rmap-verified
/// source before copying it to swap; a stale visit cannot downgrade a remap.
/// Does not invalidate a TLB; the caller owns the address-space shootdown.
///
/// # SAFETY: `root_pa` is live, its PTE lock is held, HHDM covers tables, and
/// `expected_pa` is page-aligned.
/// # C: O(walk depth)
pub unsafe fn replace_present_4k_flags_if_pa_at_root<W: PtWalker>(
    root_pa: u64, va: u64, expected_pa: u64, flags: crate::PageFlags, hhdm_offset: u64,
) -> bool {
    let i_l0 = ((va >> L0_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l1 = ((va >> L1_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l2 = ((va >> L2_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l3 = ((va >> L3_SHIFT) & TABLE_IDX_MASK) as usize;
    // SAFETY: caller pins the root and serializes its leaf mutation with the PTE lock.
    unsafe {
        let l0 = (hhdm_offset.wrapping_add(root_pa)) as *const u64;
        let e0 = ptr::read_volatile(l0.add(i_l0));
        if !W::is_valid(e0) || W::is_huge_or_block(e0) { return false; }
        let l1 = (hhdm_offset.wrapping_add(e0 & W::PHYS_MASK)) as *const u64;
        let e1 = ptr::read_volatile(l1.add(i_l1));
        if !W::is_valid(e1) || W::is_huge_or_block(e1) { return false; }
        let l2 = (hhdm_offset.wrapping_add(e1 & W::PHYS_MASK)) as *const u64;
        let e2 = ptr::read_volatile(l2.add(i_l2));
        if !W::is_valid(e2) || W::is_huge_or_block(e2) { return false; }
        let l3 = (hhdm_offset.wrapping_add(e2 & W::PHYS_MASK)) as *mut u64;
        let slot = l3.add(i_l3);
        let leaf = ptr::read_volatile(slot);
        if !W::is_valid(leaf) || leaf & W::PHYS_MASK != expected_pa & W::PHYS_MASK { return false; }
        ptr::write_volatile(slot, W::pack_4k_leaf(expected_pa, flags));
        true
    }
}

/// Replace exactly `expected` non-present swap leaf at `va` with a present
/// 4 KiB leaf. Returns `true` only when the leaf still encoded `expected`.
/// The checked compare prevents a delayed swap fault from replacing a mapping
/// installed by a concurrent fault, unmap, or remap operation.
///
/// # SAFETY: `root_pa` is the active, live AS root; its PTE lock is held;
/// HHDM covers its tables; and the caller performs any required cross-CPU TLB
/// shootdown after this local invalidation.
/// # C: O(walk depth)
pub unsafe fn replace_swap_4k_with_present_at_root<W: PtWalker>(
    root_pa: u64, va: u64, expected: SwapEntry, pa: u64,
    flags: crate::PageFlags, hhdm_offset: u64,
) -> bool {
    let i_l0 = ((va >> L0_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l1 = ((va >> L1_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l2 = ((va >> L2_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l3 = ((va >> L3_SHIFT) & TABLE_IDX_MASK) as usize;
    // SAFETY: caller supplies an exclusive active root and an HHDM mapping of every table.
    unsafe {
        let l0 = (hhdm_offset.wrapping_add(root_pa)) as *const u64;
        let e0 = ptr::read_volatile(l0.add(i_l0));
        if !W::is_valid(e0) || W::is_huge_or_block(e0) { return false; }
        let l1 = (hhdm_offset.wrapping_add(e0 & W::PHYS_MASK)) as *const u64;
        let e1 = ptr::read_volatile(l1.add(i_l1));
        if !W::is_valid(e1) || W::is_huge_or_block(e1) { return false; }
        let l2 = (hhdm_offset.wrapping_add(e1 & W::PHYS_MASK)) as *const u64;
        let e2 = ptr::read_volatile(l2.add(i_l2));
        if !W::is_valid(e2) || W::is_huge_or_block(e2) { return false; }
        let l3 = (hhdm_offset.wrapping_add(e2 & W::PHYS_MASK)) as *mut u64;
        let slot = l3.add(i_l3);
        if W::unpack_swap_entry(ptr::read_volatile(slot)) != Some(expected) { return false; }
        ptr::write_volatile(slot, W::pack_4k_leaf(pa, flags));
        W::flush_va(va);
        true
    }
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
