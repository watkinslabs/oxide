// Page-table primitives the userfaultfd modes are built on: raw leaf
// read/exchange, the write-protect range walk, and the poison marker.
//
// These deliberately expose the RAW leaf rather than decoded `PageFlags`.
// Write-protect state, poison state and a moved page's permissions are
// per-page facts that must live in the leaf the CPU actually walks; decoding
// to flags and re-packing would lose whatever the leaf carries that the
// arch-neutral flag set does not model, and would create a second place where
// "is this page write-protected" could be answered differently.

use core::ptr;

use super::{PtWalker, L0_SHIFT, L1_SHIFT, L2_SHIFT, L3_SHIFT, TABLE_IDX_MASK};

/// Address of the L3 leaf slot for `va` in the tree rooted at `root_pa`, or
/// `None` when any level of the walk is absent or a huge/block leaf.
///
/// # SAFETY: caller asserts the HHDM window covers page-table memory, `root_pa`
/// is a live root it owns, and the returned slot is used only while the
/// page-table lock is held.
/// # C: O(walk depth)
unsafe fn leaf_slot<W: PtWalker>(root_pa: u64, va: u64, hhdm: u64) -> Option<*mut u64> {
    let idx = [
        ((va >> L0_SHIFT) & TABLE_IDX_MASK) as usize,
        ((va >> L1_SHIFT) & TABLE_IDX_MASK) as usize,
        ((va >> L2_SHIFT) & TABLE_IDX_MASK) as usize,
        ((va >> L3_SHIFT) & TABLE_IDX_MASK) as usize,
    ];
    // SAFETY: per fn contract — every table page read here is reachable through
    // the HHDM window and stable for the walk under the caller's lock.
    unsafe {
        let mut table_pa = root_pa;
        for level in 0..3 {
            let table = (hhdm.wrapping_add(table_pa)) as *const u64;
            let e = ptr::read_volatile(table.add(idx[level]));
            if !W::is_valid(e) || W::is_huge_or_block(e) { return None; }
            table_pa = e & W::PHYS_MASK;
        }
        Some(((hhdm.wrapping_add(table_pa)) as *mut u64).add(idx[3]))
    }
}

/// The raw L3 leaf for `va` (including the all-zero absent value), or `None`
/// when no L3 table covers `va`.
///
/// # SAFETY: as [`leaf_slot`]; reads only.
/// # C: O(walk depth)
pub unsafe fn read_leaf_4k_at_root<W: PtWalker>(root_pa: u64, va: u64, hhdm: u64) -> Option<u64> {
    // SAFETY: delegated to `leaf_slot`; the read is a plain volatile load of a live table slot.
    unsafe { leaf_slot::<W>(root_pa, va, hhdm).map(|s| ptr::read_volatile(s)) }
}

/// Store `raw` into the existing L3 leaf slot for `va`, returning the previous
/// value. `None` when no L3 table covers `va` — this never allocates, so a
/// caller that must materialise the table walks the mapping path instead.
///
/// # SAFETY: as [`leaf_slot`], plus the caller owns the mapping the leaf
/// describes and is responsible for TLB invalidation.
/// # C: O(walk depth)
pub unsafe fn write_leaf_4k_at_root<W: PtWalker>(root_pa: u64, va: u64, raw: u64, hhdm: u64)
    -> Option<u64> {
    // SAFETY: per fn contract — exclusive access to the leaf slot under the page-table lock.
    unsafe {
        let slot = leaf_slot::<W>(root_pa, va, hhdm)?;
        let old = ptr::read_volatile(slot);
        ptr::write_volatile(slot, raw);
        Some(old)
    }
}

/// Exchange the L3 leaf for `va` only if it still holds `expected`, returning
/// whether the exchange happened. Used where losing a race must be observable
/// (a page moving out from under a monitor) rather than silently overwritten.
///
/// # SAFETY: as [`write_leaf_4k_at_root`].
/// # C: O(walk depth)
pub unsafe fn swap_leaf_if_4k_at_root<W: PtWalker>(
    root_pa: u64, va: u64, expected: u64, raw: u64, hhdm: u64,
) -> bool {
    // SAFETY: per fn contract; the compare and the store both run under the caller's page-table lock, so no third party can interleave.
    unsafe {
        let Some(slot) = leaf_slot::<W>(root_pa, va, hhdm) else { return false };
        if ptr::read_volatile(slot) != expected { return false; }
        ptr::write_volatile(slot, raw);
        true
    }
}

/// Walk `[start, end)` in 4 KiB steps applying the userfaultfd write-protect
/// transition to every PRESENT leaf: `protect` sets the marker and drops write
/// permission, `!protect` clears the marker and leaves the leaf read-only so
/// the next write takes an ordinary protection fault.
///
/// Absent leaves and non-present encodings (swap, migration, poison) are
/// skipped: they carry no write permission to remove, and the fault that
/// materialises them consults the VMA registration.
///
/// Returns the number of leaves rewritten. The caller invalidates the range.
///
/// # SAFETY: as [`write_leaf_4k_at_root`], for every page of the range.
/// # C: O((end - start) / 4096 * walk depth)
pub unsafe fn uffd_wp_range_at_root<W: PtWalker>(
    root_pa: u64, start: u64, end: u64, protect: bool, hhdm: u64,
) -> usize {
    let mut changed = 0usize;
    let mut va = start;
    while va < end {
        // SAFETY: per fn contract — one leaf slot at a time under the caller's page-table lock.
        unsafe {
            if let Some(slot) = leaf_slot::<W>(root_pa, va, hhdm) {
                let old = ptr::read_volatile(slot);
                if W::is_valid(old) {
                    let new = if protect { W::leaf_set_uffd_wp(W::leaf_wrprotect(old)) }
                              else       { W::leaf_clear_uffd_wp(old) };
                    if new != old { ptr::write_volatile(slot, new); changed += 1; }
                }
            }
        }
        va = va.wrapping_add(1u64 << L3_SHIFT);
    }
    changed
}

/// Whether the leaf for `va` is present and carries the userfaultfd
/// write-protect marker.
///
/// # SAFETY: as [`read_leaf_4k_at_root`].
/// # C: O(walk depth)
pub unsafe fn is_uffd_wp_4k_at_root<W: PtWalker>(root_pa: u64, va: u64, hhdm: u64) -> bool {
    // SAFETY: delegated to `read_leaf_4k_at_root` under the caller's page-table lock; reads only.
    unsafe { read_leaf_4k_at_root::<W>(root_pa, va, hhdm).is_some_and(W::leaf_is_uffd_wp) }
}

/// Whether the leaf for `va` is a poison marker.
///
/// # SAFETY: as [`read_leaf_4k_at_root`].
/// # C: O(walk depth)
pub unsafe fn is_poisoned_4k_at_root<W: PtWalker>(root_pa: u64, va: u64, hhdm: u64) -> bool {
    // SAFETY: delegated to `read_leaf_4k_at_root` under the caller's page-table lock; reads only.
    unsafe { read_leaf_4k_at_root::<W>(root_pa, va, hhdm).is_some_and(W::is_poison_marker) }
}
