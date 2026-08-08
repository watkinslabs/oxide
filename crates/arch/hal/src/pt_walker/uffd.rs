// Page-table primitives the userfaultfd modes are built on: raw leaf
// read/exchange, the write-protect range walk, and the marker leaves the walk
// plants where there is no page to carry the state.
//
// These deliberately expose the RAW leaf rather than decoded `PageFlags`.
// Write-protect state, poison state and a moved page's permissions are
// per-page facts that must live in the leaf the CPU actually walks; decoding
// to flags and re-packing would lose whatever the leaf carries that the
// arch-neutral flag set does not model, and would create a second place where
// "is this page write-protected" could be answered differently.

use core::ptr;

use super::{PteMarker, PtWalker, L0_SHIFT, L1_SHIFT, L2_SHIFT, L3_SHIFT, TABLE_IDX_MASK};

/// Bottom (4 KiB) level of the shared four-level walk.
const LEAF_LEVEL_4K: u8 = 3;

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

/// The leaf one page of a userfaultfd write-protect transition must end up
/// holding, or `None` to leave it exactly as it is.
///
/// `protect` arms the barrier, `!protect` resolves it. `markers` is whether
/// this mapping carries the protection over addresses with NO resident page —
/// without it an absent leaf is left alone, and the barrier applies only to
/// pages that already exist.
///
/// The cases, and why each is what it is:
///
/// - A present leaf carries the state in its own permissions: arming removes
///   write permission AND sets the marker bit; resolving clears the marker bit
///   and stops there, so the next write takes an ordinary protection fault,
///   which is where write access is decided.
/// - An address with no page has no permissions to remove, so the state has to
///   become an entry of its own: a marker leaf. Resolving one removes it, and
///   the address goes back to being a hole that faults in normally.
/// - A marker declaring the contents unrecoverable is left alone in BOTH
///   directions. Contents that are gone outrank a barrier over writes to them,
///   and dropping the marker to resolve a barrier would turn a permanent memory
///   error into a page of fresh zeroes.
/// - A swapped-out page and a page in transit take the state INTO the entry
///   that names them. Neither carries write permission right now, so leaving
///   them alone looks harmless — but the fault that brings either back builds a
///   fresh leaf from the mapping's permissions, which is writable. The barrier
///   has to survive in the only thing that survives the round trip: the entry.
/// # C: O(1)
pub fn uffd_wp_step<W: PtWalker>(raw: Option<u64>, protect: bool, markers: bool) -> Option<u64> {
    let raw = raw.unwrap_or(0);
    if raw == 0 {
        return if protect && markers { Some(W::pack_uffd_wp_marker()) } else { None };
    }
    if W::is_valid(raw) {
        let new = if protect { W::leaf_set_uffd_wp(W::leaf_wrprotect(raw)) }
                  else       { W::leaf_clear_uffd_wp(raw) };
        return if new != raw { Some(new) } else { None };
    }
    if let Some(m) = W::unpack_pte_marker(raw) {
        return match m {
            m if m.contains(PteMarker::UFFD_WP) && !protect =>
                Some(match m.without(PteMarker::UFFD_WP) {
                    Some(rest) => W::pack_pte_marker(rest),
                    None => 0,
                }),
            _ => None,
        };
    }
    let new = if protect { W::nonpresent_set_uffd_wp(raw) } else { W::nonpresent_clear_uffd_wp(raw) };
    if new != raw { Some(new) } else { None }
}

/// Apply [`uffd_wp_step`] to every page of `[start, end)`, returning the number
/// of leaves rewritten. `alloc` supplies the intermediate tables an address
/// that has never been touched needs before it can hold a marker; a page whose
/// step needs no table is never charged one.
///
/// The caller invalidates the range.
///
/// # SAFETY: as [`write_leaf_4k_at_root`], for every page of the range, plus
/// `alloc` returns kernel-owned zeroed frames.
/// # C: O((end - start) / 4096 * walk depth)
pub unsafe fn uffd_wp_range_at_root<W: PtWalker, F: FnMut() -> Option<u64>>(
    root_pa: u64, start: u64, end: u64, protect: bool, markers: bool, hhdm: u64, alloc: &mut F,
) -> usize {
    let mut changed = 0usize;
    let mut va = start;
    while va < end {
        // SAFETY: per fn contract — one leaf slot at a time under the caller's page-table lock; the map path allocates only intermediate tables and publishes a non-present leaf, so it creates no mapping reference.
        unsafe {
            let slot = leaf_slot::<W>(root_pa, va, hhdm);
            let old = slot.map(|s| ptr::read_volatile(s));
            if let Some(new) = uffd_wp_step::<W>(old, protect, markers) {
                match slot {
                    Some(s) => { ptr::write_volatile(s, new); changed += 1; }
                    None => {
                        let placed = super::map_at_level_with_root::<W, _>(
                            root_pa, va, LEAF_LEVEL_4K, new, hhdm, alloc);
                        if placed.is_ok() { changed += 1; }
                    }
                }
            }
        }
        va = va.wrapping_add(1u64 << L3_SHIFT);
    }
    changed
}
