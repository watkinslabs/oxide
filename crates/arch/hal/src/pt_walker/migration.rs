//! Non-present migration-marker leaf mutations.

use core::ptr;
use super::{MigrationEntry, PtWalker, SwapEntry, L0_SHIFT, L1_SHIFT, L2_SHIFT, L3_SHIFT, TABLE_IDX_MASK};

unsafe fn leaf_slot<W: PtWalker>(root: u64, va: u64, hhdm: u64) -> Option<*mut u64> {
    let ix = [((va >> L0_SHIFT) & TABLE_IDX_MASK) as usize, ((va >> L1_SHIFT) & TABLE_IDX_MASK) as usize,
        ((va >> L2_SHIFT) & TABLE_IDX_MASK) as usize, ((va >> L3_SHIFT) & TABLE_IDX_MASK) as usize];
    // SAFETY: caller guarantees root/table lifetime and serializes leaf writes.
    unsafe {
        let l0 = (hhdm + root) as *const u64;
        let e0 = ptr::read_volatile(l0.add(ix[0])); if !W::is_valid(e0) || W::is_huge_or_block(e0) { return None; }
        let l1 = (hhdm + (e0 & W::PHYS_MASK)) as *const u64;
        let e1 = ptr::read_volatile(l1.add(ix[1])); if !W::is_valid(e1) || W::is_huge_or_block(e1) { return None; }
        let l2 = (hhdm + (e1 & W::PHYS_MASK)) as *const u64;
        let e2 = ptr::read_volatile(l2.add(ix[2])); if !W::is_valid(e2) || W::is_huge_or_block(e2) { return None; }
        let l3 = (hhdm + (e2 & W::PHYS_MASK)) as *mut u64;
        Some(l3.add(ix[3]))
    }
}

/// Atomically replace an exact present frame with a migration marker. # C: O(walk depth)
pub unsafe fn replace_present_4k_with_migration_if_pa_at_root<W: PtWalker>(root: u64, va: u64, pa: u64, entry: MigrationEntry, hhdm: u64) -> bool {
    // SAFETY: caller holds the target mm PTE lock and root remains live.
    let Some(slot) = (unsafe { leaf_slot::<W>(root, va, hhdm) }) else { return false; };
    // SAFETY: leaf_slot returned the protected L3 slot.
    unsafe { let old = ptr::read_volatile(slot); if !W::is_valid(old) || old & W::PHYS_MASK != pa & W::PHYS_MASK { return false; } ptr::write_volatile(slot, W::pack_migration_entry(entry)); }
    true
}

/// Commit an exact marker to a canonical swap PTE. # C: O(walk depth)
pub unsafe fn replace_migration_4k_with_swap_at_root<W: PtWalker>(root: u64, va: u64, expected: MigrationEntry, entry: SwapEntry, hhdm: u64) -> bool {
    // SAFETY: caller owns PTE serialization and marker lifetime.
    let Some(slot) = (unsafe { leaf_slot::<W>(root, va, hhdm) }) else { return false; };
    // SAFETY: leaf_slot returned the protected L3 slot.
    unsafe { if W::unpack_migration_entry(ptr::read_volatile(slot)) != Some(expected) { return false; } ptr::write_volatile(slot, W::pack_swap_entry(entry)); }
    true
}

/// Roll an exact marker back to its original resident frame. # C: O(walk depth)
pub unsafe fn replace_migration_4k_with_present_at_root<W: PtWalker>(root: u64, va: u64, expected: MigrationEntry, pa: u64, flags: crate::PageFlags, hhdm: u64) -> bool {
    // SAFETY: caller owns PTE serialization and original frame lifetime.
    let Some(slot) = (unsafe { leaf_slot::<W>(root, va, hhdm) }) else { return false; };
    // SAFETY: leaf_slot returned the protected L3 slot.
    unsafe { if W::unpack_migration_entry(ptr::read_volatile(slot)) != Some(expected) { return false; } ptr::write_volatile(slot, W::pack_4k_leaf(pa, flags)); W::flush_va(va); }
    true
}

/// Clear an exact marker when its VMA is torn down. # C: O(walk depth)
pub unsafe fn clear_migration_4k_at_root<W: PtWalker>(root: u64, va: u64, expected: MigrationEntry, hhdm: u64) -> bool {
    // SAFETY: caller owns PTE serialization and migration mapping participation.
    let Some(slot) = (unsafe { leaf_slot::<W>(root, va, hhdm) }) else { return false; };
    // SAFETY: leaf_slot returned the protected L3 slot.
    unsafe { if W::unpack_migration_entry(ptr::read_volatile(slot)) != Some(expected) { return false; } ptr::write_volatile(slot, 0); W::flush_va(va); }
    true
}
