// Hole search + clear-check helpers for `AddressSpace::mmap`.
// Split out of `address_space.rs` per `docs/08§7` (file-length cap).

use hal::UserVirtAddr;

use crate::address_space::MIN_USER_VA;
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
