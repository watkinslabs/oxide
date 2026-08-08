// The range scan `mbind(2)` runs before it rewrites VMA policies. Two
// observable outputs: a hole in the range is `EFAULT`, and misplaced pages
// under `MPOL_MF_STRICT` (without a MOVE bit) are `EIO`.
//
// On a single-node PMM every resident page is on `NODE_ID_LOCAL`, so
// "misplaced" reduces to "the caller's raw nodemask does not contain node 0"
// — which is reachable: `MPOL_LOCAL` and `MPOL_PREFERRED` with an empty mask
// both pass an empty nodemask down here, and `mbind(MPOL_LOCAL, MPOL_MF_STRICT)`
// over resident pages is `-EIO` on real Linux too.

use super::nodemask::NodeMask;
use super::uapi::*;
use crate::vma::{Vma, VmaBacking};
use crate::Error;

/// Internal-only scan flag — set when the new policy is NULL (MPOL_DEFAULT),
/// which makes holes in the range legal.
pub const MPOL_MF_DISCONTIG_OK: u64 = 1 << 5;
/// Internal-only scan flag — always set by mbind's scan, so
/// "required" means "NOT in the caller's nodemask".
pub const MPOL_MF_INVERT: u64 = 1 << 6;

/// STRICT with neither MOVE bit makes the first misplaced page fatal.
/// # C: O(1)
pub fn strictly_unmovable(flags: u64) -> bool {
    flags & (MPOL_MF_STRICT | MPOL_MF_MOVE | MPOL_MF_MOVE_ALL) == MPOL_MF_STRICT
}

/// Device/IO-backed mappings are never migration candidates. oxide's
/// `PhysRange` is unrefcounted device scanout memory, `KernelFrame` is the
/// vvar-style shared kernel page and `Special` is vDSO/vvar — all three are
/// non-migratable, matching Linux's `VM_PFNMAP`/`VM_IO` exclusion.
/// # C: O(1)
pub fn vma_migratable(vma: &Vma) -> bool {
    matches!(vma.backing,
        VmaBacking::Anonymous | VmaBacking::File { .. } | VmaBacking::KernelBytes { .. })
}

/// With `MPOL_MF_INVERT` set (always, for a caller-facing scan): a page is
/// "required" (i.e. misplaced) when its node is NOT in `nmask`.
/// # C: O(1)
fn folio_required(node: u16, nmask: NodeMask, flags: u64) -> bool {
    nmask.is_set(node) == (flags & MPOL_MF_INVERT == 0)
}

/// The mbind(2)/move_pages(2) range scan. `vmas` is an ordered,
/// non-overlapping snapshot; `present(va)` is the PTE-present query.
///
/// `Err(Error::Fault)` = a hole at the head, middle or tail of the range
/// without `MPOL_MF_DISCONTIG_OK`, or the whole range unmapped.
/// `Ok(n)` = misplaced pages that could not be queued for movement.
/// # C: O(N_pages + N_vmas)
pub fn queue_pages_range<F>(vmas: &[Vma], start: u64, end: u64, nmask: NodeMask,
                            flags: u64, mut present: F) -> Result<u64, Error>
where F: FnMut(u64) -> bool
{
    let discontig_ok = flags & MPOL_MF_DISCONTIG_OK != 0;
    let mut nr_failed: u64 = 0;
    let mut cursor = start;
    let mut saw_any = false;
    for v in vmas.iter() {
        let (vs, ve) = (v.start.as_u64(), v.end.as_u64());
        if ve <= start { continue; }
        if vs >= end { break; }
        if !discontig_ok && vs > cursor { return Err(Error::Fault); }
        saw_any = true;
        cursor = ve;
        // test_walk: a non-migratable VMA is skipped entirely unless STRICT
        // wants to report it.
        if !vma_migratable(v) && flags & MPOL_MF_STRICT == 0 { continue; }
        // test_walk: with neither STRICT nor a MOVE bit the scan is pure
        // range checking.
        if flags & (MPOL_MF_STRICT | MPOL_MF_MOVE | MPOL_MF_MOVE_ALL) == 0 { continue; }
        // Every page in a single-node PMM sits on NODE_ID_LOCAL, so
        // `queue_folio_required` is constant across the whole walk. When it is
        // false nothing can be misplaced and the per-page PTE probe would only
        // burn a page-table walk per page of the range.
        if !folio_required(NODE_ID_LOCAL, nmask, flags) { continue; }
        let (ps, pe) = (core::cmp::max(vs, start), core::cmp::min(ve, end));
        let mut va = ps;
        while va < pe {
            if present(va) {
                // migrate_folio_add succeeds for a migratable VMA with a MOVE
                // bit, and migrating to the node the page already occupies
                // cannot fail — so only these two cases count.
                if flags & (MPOL_MF_MOVE | MPOL_MF_MOVE_ALL) == 0 || !vma_migratable(v) {
                    nr_failed += 1;
                    if strictly_unmovable(flags) { return Ok(nr_failed); }
                }
            }
            va += hal::PAGE_SIZE_BYTES;
        }
    }
    if !saw_any { return Err(Error::Fault); }
    if !discontig_ok && cursor < end { return Err(Error::Fault); }
    Ok(nr_failed)
}
