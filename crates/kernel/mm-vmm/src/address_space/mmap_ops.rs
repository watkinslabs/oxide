// Address-space-owned mmap placement and insertion.

use hal::UserVirtAddr;

use crate::hole::{find_hole, find_hole_bottom_up, hole_clear};
use crate::vma::{Vma, VmaBacking, VmaFlags, VmaProt};
use crate::{Error, KResult, MdweAdmission, MmapError, MmapPlacement};

use super::layout::{end_of, is_aligned, validate_aligned, validate_len};
use super::limits::MMAP_TOP;
use super::AddressSpace;

enum MdweMode {
    Check,
    Admitted(MdweAdmission),
    Preserve,
}

impl AddressSpace {
    /// Place a new VMA per `11§3` `mmap`.
    ///
    /// - `hint`: candidate placement; with `fixed = true` the request
    ///   is honored exactly (any overlap is cleared first per `11§6`
    ///   `MAP_FIXED`); with `fixed = false` the hint is advisory and a
    ///   first-fit hole search runs if the hint doesn't fit.
    /// - `len`: must be a non-zero multiple of `PAGE_SIZE_BYTES`.
    /// - returns the VMA's start VA on success.
    ///
    /// Returns `Err(Inval)` for misaligned / zero-length requests or
    /// if the hint is `None` while `fixed = true`. `Err(NoMem)` if no
    /// hole large enough exists in the user range.
    /// # C: O(log N) hint path; O(N) hole search fallback
    pub fn mmap(
        &self,
        hint: Option<UserVirtAddr>,
        len: usize,
        prot: VmaProt,
        flags: VmaFlags,
        backing: VmaBacking,
        fixed: bool,
    ) -> KResult<UserVirtAddr> {
        self.mmap_with_may(hint, len, prot, VmaProt::READ | VmaProt::WRITE | VmaProt::EXEC,
            flags, backing, fixed)
    }

    /// Linux `get_unmapped_area(NULL, 0, len, 0, 0)`: the address the top-down
    /// arena search would hand out for `len` bytes, WITHOUT mapping anything.
    ///
    /// The ELF loader needs this for the two images Linux places by hint-0
    /// mmap rather than by an explicit bias — the PT_INTERP dynamic linker
    /// and a PIE with no interpreter — so both inherit `mmap_base`'s
    /// randomisation.
    /// Reserving-then-unmapping to learn the same address would open a window
    /// where another mapping lands in the hole.
    /// # C: O(N) over VMAs
    pub fn get_unmapped_area(&self, len: usize) -> KResult<UserVirtAddr> {
        validate_len(len)?;
        let tree = self.vmas.read();
        self.unmapped_area(&tree, len as u64).ok_or(Error::NoMem)
    }

    /// One entry point that
    /// dispatches on `MMF_TOPDOWN` to `arch_get_unmapped_area_topdown` or, for
    /// the legacy layout, to `arch_get_unmapped_area`. Every hole search goes
    /// through here so the two directions cannot disagree about which anchor
    /// this mm is using.
    /// # C: O(N) over VMAs
    fn unmapped_area(&self, tree: &crate::tree::VmaTree, len: u64) -> Option<UserVirtAddr> {
        let anchor = self.mmap_base.load(core::sync::atomic::Ordering::Acquire);
        if self.mmap_topdown() {
            find_hole(tree, len, if anchor == 0 { MMAP_TOP } else { anchor })
        } else {
            find_hole_bottom_up(tree, len, anchor)
        }
    }

    /// Place a new VMA with Linux `VM_MAY*` permissions.
    /// # C: O(log N) hint path; O(N) hole search fallback
    pub fn mmap_with_may(
        &self,
        hint: Option<UserVirtAddr>,
        len: usize,
        prot: VmaProt,
        may_prot: VmaProt,
        flags: VmaFlags,
        backing: VmaBacking,
        fixed: bool,
    ) -> KResult<UserVirtAddr> {
        let placement = match (fixed, hint) {
            (true, Some(address)) => MmapPlacement::Fixed(address),
            (true, None) => return Err(Error::Inval),
            (false, hint) => MmapPlacement::Advisory(hint),
        };
        self.mmap_with_may_at(placement, len, prot, may_prot, flags, backing)
            .map_err(|error| match error {
                MmapError::Vmm(error) => error,
                MmapError::Exists => Error::Inval,
            })
    }

    /// Place one VMA using the canonical advisory/fixed/no-replace policy.
    /// `FixedNoReplace` tests and inserts under the same VMA write lock.
    /// # C: O(log N) exact path; O(N) advisory fallback
    pub fn mmap_with_may_at(
        &self,
        placement: MmapPlacement,
        len: usize,
        prot: VmaProt,
        may_prot: VmaProt,
        flags: VmaFlags,
        backing: VmaBacking,
    ) -> Result<UserVirtAddr, MmapError> {
        self.mmap_with_may_at_inner(
            placement, len, prot, may_prot, flags, backing, MdweMode::Check,
        )
    }

    /// Consume an owner-issued MDWE proof after MAP_FIXED page-table teardown.
    /// # C: O(log N) exact path
    pub fn mmap_with_may_at_admitted(
        &self,
        placement: MmapPlacement,
        len: usize,
        prot: VmaProt,
        may_prot: VmaProt,
        flags: VmaFlags,
        backing: VmaBacking,
        admission: MdweAdmission,
    ) -> Result<UserVirtAddr, MmapError> {
        self.mmap_with_may_at_inner(
            placement, len, prot, may_prot, flags, backing,
            MdweMode::Admitted(admission),
        )
    }

    /// Move an existing VMA without treating its unchanged permissions as a
    /// new executable gain. Linux mremap preserves both VM_* and VM_MAY*.
    /// # C: O(log N)
    pub(crate) fn mmap_preserving_prot(
        &self,
        hint: Option<UserVirtAddr>,
        len: usize,
        prot: VmaProt,
        may_prot: VmaProt,
        flags: VmaFlags,
        backing: VmaBacking,
        fixed: bool,
    ) -> KResult<UserVirtAddr> {
        let placement = match (fixed, hint) {
            (true, Some(address)) => MmapPlacement::Fixed(address),
            (true, None) => return Err(Error::Inval),
            (false, hint) => MmapPlacement::Advisory(hint),
        };
        self.mmap_with_may_at_inner(
            placement, len, prot, may_prot, flags, backing, MdweMode::Preserve,
        ).map_err(|error| match error {
            MmapError::Vmm(error) => error,
            MmapError::Exists => Error::Inval,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn mmap_with_may_at_inner(
        &self,
        placement: MmapPlacement,
        len: usize,
        prot: VmaProt,
        may_prot: VmaProt,
        flags: VmaFlags,
        backing: VmaBacking,
        mdwe: MdweMode,
    ) -> Result<UserVirtAddr, MmapError> {
        validate_len(len)?;
        // Linux `mmap_region`: `vm_flags |= mm->def_flags`, so an
        // `mlockall(MCL_FUTURE)` policy — including its `MCL_ONFAULT` half —
        // lands on every subsequently created VMA.
        let (future_locked, future_onfault) = self.mlock_future_policy();
        let flags = match (future_locked, future_onfault) {
            (false, _)    => flags,
            (true, false) => flags | VmaFlags::LOCKED,
            (true, true)  => flags | VmaFlags::LOCKED_MASK,
        };
        let len_u64 = len as u64;

        let mut tree = self.vmas.write();
        let (start_va, replace_end) = match placement {
            MmapPlacement::Fixed(h) => {
                validate_aligned(h)?;
                let end = end_of(h, len_u64)?;
                (h, Some(end))
            }
            MmapPlacement::FixedNoReplace(h) => {
                validate_aligned(h)?;
                let end = end_of(h, len_u64)?;
                if !hole_clear(&tree, h, end) { return Err(MmapError::Exists); }
                (h, None)
            }
            MmapPlacement::Advisory(hint) => {
                let from_hint = match hint {
                    Some(h) if is_aligned(h) => {
                        end_of(h, len_u64).ok().and_then(|end| {
                            if hole_clear(&tree, h, end) { Some(h) } else { None }
                        })
                    }
                    _ => None,
                };
                let start = match from_hint {
                    Some(h) => h,
                    None => self.unmapped_area(&tree, len_u64).ok_or(Error::NoMem)?,
                };
                (start, None)
            }
        };

        match mdwe {
            MdweMode::Check => { self.mdwe_admit_new_mapping(prot)?; }
            MdweMode::Admitted(admission) => admission.validate(self, prot)?,
            MdweMode::Preserve => {}
        }
        // Linux `mmap_region`: MDWE precedes `mapping_map_writable`, and both
        // precede MAP_FIXED teardown. Hold the reservation until the rmap edge
        // is attached, excluding a concurrent `F_SEAL_WRITE` transaction.
        let _writable_reservation = match &backing {
            VmaBacking::File { backing, .. }
                if flags.contains(VmaFlags::SHARED)
                    && may_prot.contains(VmaProt::WRITE) =>
            {
                backing.file_rmap().map(|rmap| rmap.reserve_writable()).transpose()?
            }
            _ => None,
        };
        if let Some(end) = replace_end {
            // Linux checks MDWE before `__mmap_region` removes MAP_FIXED
            // overlaps. A denied W+X request must leave the old mapping intact.
            if tree.any_sealed(start_va, end) { return Err(Error::Perm.into()); }
            let removed = tree.remove_range(start_va, end);
            for vma in &removed { self.accounting.remove_vma(vma); }
        }
        let end_va = end_of(start_va, len_u64)?;
        let added = Vma::new_with_may(start_va, end_va, prot, may_prot, flags, backing);
        tree.insert(added.clone()).map_err(|_| Error::Inval)?;
        self.accounting.add_vma(&added);
        // Attach the originating anon/file rmap edge. A merge may have
        // absorbed the new range, so bind through its containing VMA.
        if let Some(vma) = tree.find_containing(start_va) {
            if let Some(av) = vma.anon_vma.as_ref() {
                av.attach(self.self_weak.clone(), start_va.as_u64(), end_va.as_u64());
            }
            if let (Some(rmap), VmaBacking::File { off, .. }) =
                (vma.file_rmap.as_ref(), &vma.backing)
            {
                rmap.attach(
                    self.self_weak.clone(), start_va.as_u64(), end_va.as_u64(),
                    off / hal::PAGE_SIZE_BYTES, vma.may_prot.contains(VmaProt::WRITE),
                );
            }
        }
        Ok(start_va)
    }
}
