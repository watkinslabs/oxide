use super::{Vma, VmaFlags};
use core::sync::atomic::{AtomicU64, Ordering};
use alloc::sync::Arc;

impl Clone for Vma {
    fn clone(&self) -> Self {
        Vma {
            start: self.start, end: self.end, prot: self.prot, may_prot: self.may_prot,
            // The child does not inherit the uffd registration because this
            // kernel does not advertise UFFD_FEATURE_EVENT_FORK.
            flags: self.flags.difference(VmaFlags::UFFD_MISSING),
            backing: self.backing.clone(),
            rss: AtomicU64::new(self.rss.load(Ordering::Relaxed)),
            anon_vma: self.anon_vma.as_ref().map(Arc::clone),
            // Linux dup_mmap preserves the VMA's anon-name across fork.
            anon_name: self.anon_name.as_ref().map(Arc::clone),
            uffd: None,
        }
    }
}
