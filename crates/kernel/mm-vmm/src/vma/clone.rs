use super::{Vma, VmaBacking, VmaFlags};
use hal::UserVirtAddr;
use core::sync::atomic::{AtomicU64, Ordering};
use alloc::sync::Arc;

impl Clone for Vma {
    fn clone(&self) -> Self {
        Vma {
            start: self.start, end: self.end, prot: self.prot, may_prot: self.may_prot,
            // The child does NOT inherit the uffd registration: we advertise
            // no UFFD_FEATURE_EVENT_FORK, so Linux `dup_userfaultfd` clears
            // `vm_userfaultfd_ctx` + the `__VM_UFFD_FLAGS` on the child (the
            // parent's monitor owns the fd and would `UFFDIO_COPY` into the
            // WRONG mm). Strip the MISSING flag here; `uffd` is dropped below.
            // (`Vma::clone` is the fork-dup path exclusively; splits use
            // `clone_subrange`.)
            flags: self.flags.difference(VmaFlags::UFFD_MISSING),
            backing: self.backing.clone(),
            rss: AtomicU64::new(self.rss.load(Ordering::Relaxed)),
            // VmaTree::insert clones VMAs into the destination tree at fork;
            // we keep the SAME anon_vma so all forked descendants share the
            // chain. The file_rmap owner is shared for the same reason.
            anon_vma: self.anon_vma.as_ref().map(Arc::clone),
            file_rmap: self.file_rmap.as_ref().map(Arc::clone),
            // Linux dup_mmap preserves the VMA's anon-name across fork.
            anon_name: self.anon_name.as_ref().map(Arc::clone),
            uffd: None,
            // Linux `vma_dup_policy` → `mpol_dup`: the child VMA keeps the
            // parent's mbind(2) policy across fork.
            mempolicy: self.mempolicy,
        }
    }
}

impl Vma {
    /// Clone metadata into a sub-range `[new_start, new_end)`. Used by
    /// `VmaTree::remove_range` and `mprotect_range` when splitting at
    /// boundaries. File-backed offset is adjusted to maintain contiguity
    /// (`11§4`: "contig-offset"). `rss` is reset to zero; accurate
    /// resident-count tracking lands with the page-fault handler in a
    /// later P1-N.
    /// # C: O(1)
    pub fn clone_subrange(&self, new_start: UserVirtAddr, new_end: UserVirtAddr) -> Vma {
        let off_delta = new_start.as_u64() - self.start.as_u64();
        let backing = match &self.backing {
            VmaBacking::File { backing, off } => VmaBacking::File {
                backing: alloc::sync::Arc::clone(backing),
                off: off + off_delta,
            },
            VmaBacking::KernelBytes { data, off } => {
                // Sub-range starts `off_delta` bytes into the parent
                // VMA → bump the byte offset into the shared Arc.
                VmaBacking::KernelBytes {
                    data: alloc::sync::Arc::clone(data),
                    off: off + off_delta as usize,
                }
            }
            other => other.clone(),
        };
        Vma {
            start: new_start,
            end:   new_end,
            prot:  self.prot,
            may_prot: self.may_prot,
            flags: self.flags,
            backing,
            rss: AtomicU64::new(0),
            // Sub-range stays in the same anon_vma family — Linux
            // `__split_vma` keeps both halves on the parent's anon_vma
            // (and adds a chain entry for the new half).
            anon_vma: self.anon_vma.as_ref().map(Arc::clone),
            file_rmap: self.file_rmap.as_ref().map(Arc::clone),
            anon_name: self.anon_name.as_ref().map(Arc::clone),
            // Split VMA fragments inherit the uffd registration (Linux
            // `__split_vma` copies `vm_userfaultfd_ctx`).
            uffd: self.uffd.clone(),
            // `__split_vma` → `vma_dup_policy`: both halves keep the policy.
            mempolicy: self.mempolicy,
        }
    }
}
