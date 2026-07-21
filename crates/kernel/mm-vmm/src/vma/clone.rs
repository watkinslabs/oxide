use super::{Vma, VmaFlags};
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
        }
    }
}
