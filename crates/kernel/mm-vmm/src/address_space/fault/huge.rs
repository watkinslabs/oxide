// Huge-page fault fill for a mapping of a hugetlbfs file.
//
// The page-table layer already speaks block leaves on both arches, so this
// arm reuses `MmuOps::map` with a larger granule rather than adding a second
// page-table path: the only new decisions are which leaf covers the faulting
// address and which offset of the file it names, and both live in
// `huge_fault_target` where a hosted test drives them.

use hal::{MmuOps, Pa, PageSize, UserVirtAddr, Va};

use crate::vma::{FileBackingError, Vma};
use crate::{Error, KResult};

use super::super::super::AddressSpace;

/// The single huge leaf a fault resolves to.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct HugeFaultTarget {
    /// Base address of the leaf — aligned to the huge-page size, NOT to the
    /// base page the CPU reported.
    pub va: u64,
    /// File offset the leaf covers, aligned to the huge-page size.
    pub file_off: u64,
    /// Granule the leaf uses.
    pub size: PageSize,
}

/// Resolve a faulting address inside a huge-page mapping to the leaf that must
/// be installed for it.
///
/// `None` means the mapping cannot be served by huge leaves at all: the size is
/// not one the page tables express, or the mapping's base address or file
/// offset is not aligned to it. Installing a huge leaf for such a mapping would
/// cover addresses outside the VMA, so the caller must refuse the fault rather
/// than approximate it — which is why this returns an option instead of
/// rounding to something plausible.
/// # C: O(1)
pub fn huge_fault_target(va: u64, vma_start: u64, backing_off: u64, huge_bytes: u64)
    -> Option<HugeFaultTarget>
{
    let size = PageSize::from_bytes(huge_bytes)?;
    if size == PageSize::P4K { return None; }
    let mask = huge_bytes - 1;
    if (vma_start & mask) != 0 { return None; }
    if (backing_off & mask) != 0 { return None; }
    if va < vma_start { return None; }
    let base = va & !mask;
    let file_off = backing_off.checked_add(base - vma_start)?;
    Some(HugeFaultTarget { va: base, file_off, size })
}

#[cfg(test)]
mod tests {
    use super::*;

    const M2: u64 = 2 * 1024 * 1024;
    const G1: u64 = 1024 * 1024 * 1024;

    #[test]
    fn a_fault_anywhere_in_a_huge_page_resolves_to_that_pages_leaf() {
        for off in [0u64, 1, 4096, M2 - 1] {
            let t = huge_fault_target(0x4000_0000 + off, 0x4000_0000, 0, M2).unwrap();
            assert_eq!(t.va, 0x4000_0000);
            assert_eq!(t.file_off, 0);
            assert_eq!(t.size, PageSize::P2M);
        }
    }

    #[test]
    fn the_second_huge_page_names_the_second_huge_file_offset() {
        let t = huge_fault_target(0x4000_0000 + M2 + 4096, 0x4000_0000, 0, M2).unwrap();
        assert_eq!(t.va, 0x4000_0000 + M2);
        assert_eq!(t.file_off, M2);
    }

    #[test]
    fn a_mapping_that_starts_partway_into_the_file_carries_the_offset_through() {
        let t = huge_fault_target(0x4000_0000 + 8, 0x4000_0000, 4 * M2, M2).unwrap();
        assert_eq!(t.file_off, 4 * M2);
    }

    #[test]
    fn a_gigantic_mapping_resolves_to_the_gigantic_leaf() {
        let t = huge_fault_target(G1 + 12345, G1, 0, G1).unwrap();
        assert_eq!((t.va, t.size), (G1, PageSize::P1G));
    }

    #[test]
    fn a_size_no_leaf_expresses_is_refused_rather_than_approximated() {
        for bytes in [0u64, 4096, 8192, 3 * 1024 * 1024, M2 + 1] {
            assert!(huge_fault_target(0x4000_0000, 0x4000_0000, 0, bytes).is_none(),
                    "size {bytes} must not resolve to a leaf");
        }
    }

    #[test]
    fn a_misaligned_mapping_base_is_refused() {
        // A leaf installed for this VMA would cover addresses below its start.
        assert!(huge_fault_target(0x4000_1000, 0x4000_1000, 0, M2).is_none());
    }

    #[test]
    fn a_misaligned_file_offset_is_refused() {
        assert!(huge_fault_target(0x4000_0000, 0x4000_0000, 4096, M2).is_none());
    }

    #[test]
    fn a_fault_below_the_mapping_is_refused() {
        assert!(huge_fault_target(0x3fff_f000, 0x4000_0000, 0, M2).is_none());
    }
}

impl AddressSpace {
    /// Re-install the huge leaf covering `va` with the VMA's own protection.
    ///
    /// A write fault on a hugetlbfs mapping is never resolved by copying: the
    /// page IS the file, so the write must land on it and be visible to every
    /// other mapper. The leaf is RO here only because something stripped the
    /// write bit from it, and the fix is to put it back on the SAME page — at
    /// the SAME granule, since re-installing at the base granule would replace
    /// a whole huge page's leaf with one covering a 4 KiB slice of it.
    /// # SAFETY: caller supplies the live MMU and holds no page-table lock.
    /// # C: O(walk depth)
    pub(super) unsafe fn rewrite_huge_leaf<M: MmuOps>(
        &self,
        va: UserVirtAddr,
        vma: &Vma,
        backing: &alloc::sync::Arc<dyn crate::vma::FileBacking>,
        backing_off: u64,
        huge_bytes: u64,
    ) -> KResult<()> {
        let Some(t) = huge_fault_target(va.as_u64(), vma.start.as_u64(), backing_off, huge_bytes)
            else { return Err(Error::Inval) };
        let frame = match backing.shared_frame(t.file_off) {
            Ok(Some(f))                  => f,
            Ok(None)                     => return Err(Error::NoMem),
            Err(FileBackingError::NoMem) => return Err(Error::NoMem),
            Err(_)                       => return Err(Error::Io),
        };
        // A huge backing hands back its page WITHOUT a transient reference —
        // the install path takes the mapping's reference itself. One that did
        // hold a reference would leak it here, since this is a lookup that
        // keeps the existing mapping rather than an install that can pair with
        // a release, so refuse rather than leak.
        if frame.map_ref_held { return Err(Error::Inval); }
        // SAFETY: the granule and both alignments were proved above; the frame
        // is the one this mapping already owns, so no reference changes hands.
        unsafe {
            M::map(Va(t.va), Pa(frame.pa), vma.page_flags(), t.size);
            M::flush_va(Va(t.va));
        }
        Ok(())
    }

    /// Install the huge leaf covering `va` from a hugetlbfs-style backing.
    ///
    /// The backing owns the page and keeps its own reference, so the install
    /// takes one more for this mapping; teardown drops exactly that one.
    /// # SAFETY: caller supplies the live MMU and the PMM refcount callbacks,
    /// and holds no page-table lock across this call.
    /// # C: O(walk depth)
    pub(super) unsafe fn fill_huge_not_present<M, IR>(
        &self,
        va: UserVirtAddr,
        vma: &Vma,
        backing: &alloc::sync::Arc<dyn crate::vma::FileBacking>,
        backing_off: u64,
        huge_bytes: u64,
        wp: hal::PageFlags,
        inc_ref: &mut IR,
    ) -> KResult<()>
    where M: MmuOps, IR: FnMut(u64)
    {
        let Some(t) = huge_fault_target(va.as_u64(), vma.start.as_u64(), backing_off, huge_bytes)
            else { return Err(Error::Inval) };
        // A huge leaf covers `huge_bytes`; a VMA that ends inside one would
        // have the leaf expose addresses it never mapped.
        if vma.end.as_u64() < t.va.saturating_add(huge_bytes) { return Err(Error::Inval); }
        let frame = match backing.shared_frame(t.file_off) {
            Ok(Some(f))                     => f,
            Ok(None)                        => return Err(Error::NoMem),
            Err(FileBackingError::NoMem)    => return Err(Error::NoMem),
            Err(_)                          => return Err(Error::Io),
        };
        if (frame.pa & (huge_bytes - 1)) != 0 { return Err(Error::Inval); }
        if !frame.map_ref_held { inc_ref(frame.pa); }
        let pte_flags = vma.page_flags() | wp;
        // SAFETY: `t.va` and `frame.pa` are both aligned to the granule the
        // backing reports, which `huge_fault_target` proved the page tables
        // express as one leaf; flags carry USER per `11§5`.
        let replaced = unsafe { M::map(Va(t.va), Pa(frame.pa), pte_flags, t.size) };
        if replaced.is_none() { self.accounting.install_pte(vma); }
        Ok(())
    }
}
