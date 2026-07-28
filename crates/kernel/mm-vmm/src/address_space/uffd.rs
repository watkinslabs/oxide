// userfaultfd(2) view of the VMA tree — Linux `vm_userfaultfd_ctx` set/clear
// plus the read-only lookups the fault path and the UFFDIO_* handlers need.
//
// These lookups exist instead of `find_vma`/`snapshot_vmas` because
// `Vma::clone` IS the fork-dup path: it deliberately drops `uffd` and clears
// `UFFD_MISSING` (no `UFFD_FEATURE_EVENT_FORK`, so Linux `dup_userfaultfd`
// clears the child's context). Any caller that clones a VMA out of the tree
// therefore sees `uffd == None` no matter what is registered, which would make
// "is this destination uffd-registered?" answer "no" for every address —
// exactly the kind of silently-wrong authorization fact `docs/02` rule 3 calls
// a split source of truth. Everything here reads the live VMA under the tree
// lock and copies out only scalars plus the ctx `Arc`.

use alloc::sync::Arc;
use alloc::vec::Vec;

use hal::UserVirtAddr;

use crate::uffd::UffdContext;
use crate::vma::{VmaBacking, VmaFlags, VmaProt};

use super::AddressSpace;

/// The uffd-relevant facts about one VMA (`mm/userfaultfd.c` reads
/// `vm_end`, `vm_page_prot`, `VM_MAYWRITE`, `vm_uffd_ops` and
/// `vm_userfaultfd_ctx.ctx` off `dst_vma`).
pub struct UffdVma {
    pub start: u64,
    pub end:   u64,
    /// `vma->vm_page_prot` — the protection an installed page inherits.
    pub prot:  VmaProt,
    /// `vma->vm_flags & VM_MAYWRITE`.
    pub may_write: bool,
    /// Linux `vma_can_userfault`: oxide implements the anonymous
    /// `vm_uffd_ops` only, so this is `VmaBacking::Anonymous`.
    pub anonymous: bool,
    /// `vma->vm_userfaultfd_ctx.ctx`.
    pub ctx: Option<Arc<dyn UffdContext>>,
}

impl AddressSpace {
    /// userfaultfd(2) `UFFDIO_REGISTER(MODE_MISSING)`: bind `ctx` to every
    /// VMA fragment overlapping `[start, end)` and set `UFFD_MISSING`, so a
    /// NotPresent fault there routes to the fd instead of zero-filling.
    /// # C: O(K log N)
    pub fn set_uffd_missing(&self, start: u64, end: u64, ctx: Arc<dyn UffdContext>) {
        let (Some(s), Some(e)) = (UserVirtAddr::new(start), UserVirtAddr::new(end)) else { return };
        self.has_uffd.store(true, core::sync::atomic::Ordering::Release);
        self.vmas.write().set_uffd_range(s, e, Some(ctx));
    }

    /// Fast-path guard: `true` iff any uffd range was ever registered on
    /// this AS. The fault handler checks this before `uffd_for` so
    /// no-uffd processes skip the extra vmas read-lock per fault.
    /// # C: O(1)
    pub fn maybe_uffd(&self) -> bool {
        self.has_uffd.load(core::sync::atomic::Ordering::Acquire)
    }

    /// userfaultfd(2) `UFFDIO_UNREGISTER`: clear the uffd registration +
    /// `UFFD_MISSING` over `[start, end)`.
    /// # C: O(K log N)
    pub fn clear_uffd(&self, start: u64, end: u64) {
        let (Some(s), Some(e)) = (UserVirtAddr::new(start), UserVirtAddr::new(end)) else { return };
        self.vmas.write().set_uffd_range(s, e, None);
    }

    /// Fault-path lookup: the uffd context registered on the VMA
    /// containing `va` plus whether MISSING mode is set. Clones the Arc
    /// out and RELEASES the read lock before returning — the caller
    /// (`missing_fault`) blocks, and must never hold the vmas lock across
    /// a park. `None` when the VMA has no uffd registration.
    /// # C: O(log N)
    pub fn uffd_for(&self, va: UserVirtAddr) -> Option<(Arc<dyn UffdContext>, bool)> {
        let g = self.vmas.read();
        let v = g.find_containing(va)?;
        let ctx = v.uffd.clone()?;
        let missing = v.flags.contains(VmaFlags::UFFD_MISSING);
        Some((ctx, missing))
    }

    /// Linux `vma_lookup(mm, addr)` for `UFFDIO_COPY`/`UFFDIO_ZEROPAGE`'s
    /// destination check, reporting the registration `find_vma` cannot.
    /// # C: O(log N)
    pub fn uffd_vma_at(&self, va: UserVirtAddr) -> Option<UffdVma> {
        let g = self.vmas.read();
        g.find_containing(va).map(project)
    }

    /// Every VMA overlapping `[start, end)`, for `UFFDIO_REGISTER`'s
    /// `for_each_vma_range` scan. Holes are simply absent, matching Linux.
    /// # C: O(N)
    pub fn uffd_vmas_in(&self, start: u64, end: u64) -> Vec<UffdVma> {
        let g = self.vmas.read();
        g.iter()
            .filter(|v| v.end.as_u64() > start && v.start.as_u64() < end)
            .map(project)
            .collect()
    }
}

/// # C: O(1)
fn project(v: &crate::vma::Vma) -> UffdVma {
    UffdVma {
        start: v.start.as_u64(),
        end:   v.end.as_u64(),
        prot:  v.prot,
        may_write: v.may_prot.contains(VmaProt::WRITE),
        anonymous: matches!(v.backing, VmaBacking::Anonymous),
        ctx: v.uffd.clone(),
    }
}
