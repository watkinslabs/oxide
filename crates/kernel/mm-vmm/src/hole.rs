// Hole search + clear-check helpers for `AddressSpace::mmap`.
// Split out of `address_space.rs` per `docs/08§7` (file-length cap).

use hal::UserVirtAddr;

use crate::address_space::{MIN_USER_VA, MMAP_TOP};
use crate::tree::VmaTree;

/// True iff `[start, end)` overlaps no existing VMA.
/// # C: O(N)
pub(crate) fn hole_clear(tree: &VmaTree, start: UserVirtAddr, end: UserVirtAddr) -> bool {
    let s = start.as_u64();
    let e = end.as_u64();
    for v in tree.iter() {
        if v.start.as_u64() >= e { break; }
        if v.end.as_u64()   >  s { return false; }
    }
    true
}

/// Top-down hole search starting at `mmap_top` (per-AS mmap_base
/// or fallback `MMAP_TOP`), descending toward `MIN_USER_VA`.
/// Mirrors Linux `arch_get_unmapped_area_topdown`.
/// # C: O(N) over VMAs
pub(crate) fn find_hole(tree: &VmaTree, len: u64, mmap_top: u64) -> Option<UserVirtAddr> {
    if len == 0 || len > mmap_top.saturating_sub(MIN_USER_VA) { return None; }
    let mut vmas: alloc::vec::Vec<(u64, u64)> = alloc::vec::Vec::new();
    for v in tree.iter() {
        let s = v.start.as_u64().max(MIN_USER_VA);
        let e = v.end.as_u64().min(mmap_top);
        if e > s { vmas.push((s, e)); }
    }
    let mut top = mmap_top;
    for &(s, e) in vmas.iter().rev() {
        if top.saturating_sub(e) >= len {
            return UserVirtAddr::new(top - len);
        }
        top = s;
    }
    if top.saturating_sub(MIN_USER_VA) >= len {
        UserVirtAddr::new(top - len)
    } else {
        None
    }
}

/// Bottom-up hole search starting at `mmap_floor` (the per-AS legacy
/// `mmap_base`), ascending toward [`MMAP_TOP`]. Linux
/// `arch_get_unmapped_area`, the LEGACY layout `mmap_is_legacy` selects —
/// `personality(ADDR_COMPAT_LAYOUT)`, an unlimited `RLIMIT_STACK` on arm64, or
/// `vm.legacy_va_layout`.
///
/// First fit, exactly as Linux's forward `vma_find_unmapped_area` is: the
/// lowest gap at or above the floor that holds `len`. The ceiling is the same
/// user bound the top-down search descends from, so neither direction can
/// place a mapping the other could not.
/// # C: O(N) over VMAs
pub(crate) fn find_hole_bottom_up(tree: &VmaTree, len: u64, mmap_floor: u64)
    -> Option<UserVirtAddr> {
    let floor = mmap_floor.max(MIN_USER_VA);
    if len == 0 || len > MMAP_TOP.saturating_sub(floor) { return None; }
    let mut low = floor;
    for v in tree.iter() {
        let s = v.start.as_u64();
        let e = v.end.as_u64();
        if e <= low { continue; }
        if s.saturating_sub(low) >= len { return UserVirtAddr::new(low); }
        low = e;
        if low > MMAP_TOP.saturating_sub(len) { return None; }
    }
    if MMAP_TOP.saturating_sub(low) >= len { UserVirtAddr::new(low) } else { None }
}
