// userfaultfd(2) view of the VMA tree — the per-VMA context set/clear plus the
// read-only lookups the fault path and every UFFDIO_* handler need.
//
// These lookups exist instead of `find_vma`/`snapshot_vmas` because
// `Vma::clone` IS the fork-dup path: it deliberately drops `uffd` and clears
// the whole mode mask (no fork event feature, so a child inherits no
// registration). Any caller that clones a VMA out of the tree therefore sees
// `uffd == None` no matter what is registered, which would make "is this
// destination uffd-registered?" answer "no" for every address — exactly the
// kind of silently-wrong authorization fact `docs/02` rule 3 calls a split
// source of truth. Everything here reads the live VMA under the tree lock and
// copies out only scalars plus the ctx `Arc`.
//
// The registration is the ONE owner of "which modes are armed on this range":
// the mode flags and the context pointer are written together by
// [`AddressSpace::set_uffd`] and dropped together by
// [`AddressSpace::clear_uffd`]. Per-PAGE write-protect state is likewise owned
// by the page-table leaf alone (`hal::pt_walker` uffd walks), never mirrored
// into a range list that could disagree with what the CPU walks.

use alloc::sync::Arc;
use alloc::vec::Vec;

use hal::UserVirtAddr;

use crate::uffd::UffdContext;
use crate::vma::{FileBacking, VmaBacking, VmaFlags, VmaProt};

use super::AddressSpace;

/// The uffd-relevant facts about one VMA, lifted out so every ladder can be
/// decided without holding the tree lock.
pub struct UffdVma {
    pub start: u64,
    pub end:   u64,
    /// The protection an installed page inherits.
    pub prot:  VmaProt,
    /// Whether the mapping may ever become writable.
    pub may_write: bool,
    /// Whether the mapping is writable NOW.
    pub write: bool,
    /// Whether the mapping is private-anonymous.
    pub anonymous: bool,
    /// Whether the backing is memory-backed shared storage whose pages ARE the
    /// file (the only file-backed shape a minor fault is meaningful on: the
    /// page can already be resident in the backing while absent from the page
    /// table).
    pub shmem: bool,
    /// Whether the mapping is shared.
    pub shared: bool,
    /// Whether the mapping is locked.
    pub locked: bool,
    /// The registration mode flags armed on this VMA, always a subset of
    /// [`VmaFlags::UFFD_MASK`].
    pub modes: VmaFlags,
    /// The registered context, or `None`.
    pub ctx: Option<Arc<dyn UffdContext>>,
    /// Backing file object and its offset at `start`, for the minor-fault and
    /// continue paths.
    pub file: Option<(Arc<dyn FileBacking>, u64)>,
    /// The anonymous-page owner, when one has been established.
    pub anon_vma: Option<Arc<crate::anon_vma::AnonVma>>,
}

impl UffdVma {
    /// File offset backing `va`, or `None` for a mapping with no file object.
    /// # C: O(1)
    pub fn file_off(&self, va: u64) -> Option<u64> {
        self.file.as_ref().map(|(_, off)| off + (va - self.start))
    }
}

/// One fault-path registration hit: the context to deliver to and the modes
/// armed on the VMA that owns `va`.
pub struct UffdHit {
    pub ctx: Arc<dyn UffdContext>,
    pub modes: VmaFlags,
}

impl AddressSpace {
    /// `UFFDIO_REGISTER`: bind `ctx` to every VMA fragment overlapping
    /// `[start, end)` and arm exactly `modes` there, so faults in the range
    /// route to the fd. Re-registering a range REPLACES its mode set.
    /// # C: O(K log N)
    pub fn set_uffd(&self, start: u64, end: u64, ctx: Arc<dyn UffdContext>, modes: VmaFlags) {
        let (Some(s), Some(e)) = (UserVirtAddr::new(start), UserVirtAddr::new(end)) else { return };
        self.has_uffd.store(true, core::sync::atomic::Ordering::Release);
        self.vmas.write().set_uffd_range(s, e, Some(ctx), modes);
    }

    /// Fast-path guard: `true` iff any uffd range was ever registered on this
    /// AS. The fault handler checks this before [`Self::uffd_for`] so no-uffd
    /// processes skip the extra vmas read-lock per fault.
    /// # C: O(1)
    pub fn maybe_uffd(&self) -> bool {
        self.has_uffd.load(core::sync::atomic::Ordering::Acquire)
    }

    /// `UFFDIO_UNREGISTER`: drop the context and every mode flag over
    /// `[start, end)`.
    /// # C: O(K log N)
    pub fn clear_uffd(&self, start: u64, end: u64) {
        let (Some(s), Some(e)) = (UserVirtAddr::new(start), UserVirtAddr::new(end)) else { return };
        self.vmas.write().set_uffd_range(s, e, None, VmaFlags::empty());
    }

    /// Fault-path lookup: the context registered on the VMA containing `va`
    /// plus the modes armed there. Clones the Arc out and RELEASES the read
    /// lock before returning — the caller BLOCKS, and must never hold the vmas
    /// lock across a park. `None` when the VMA has no uffd registration.
    /// # C: O(log N)
    pub fn uffd_for(&self, va: UserVirtAddr) -> Option<UffdHit> {
        let g = self.vmas.read();
        let v = g.find_containing(va)?;
        let ctx = v.uffd.clone()?;
        Some(UffdHit { ctx, modes: v.flags & VmaFlags::UFFD_MASK })
    }

    /// Lookup of the VMA containing `va`, reporting the registration
    /// `find_vma` cannot.
    /// # C: O(log N)
    pub fn uffd_vma_at(&self, va: UserVirtAddr) -> Option<UffdVma> {
        let g = self.vmas.read();
        g.find_containing(va).map(project)
    }

    /// Every VMA overlapping `[start, end)`, for the registration scan. Holes
    /// are simply absent.
    /// # C: O(N)
    pub fn uffd_vmas_in(&self, start: u64, end: u64) -> Vec<UffdVma> {
        let g = self.vmas.read();
        g.iter()
            .filter(|v| v.end.as_u64() > start && v.start.as_u64() < end)
            .map(project)
            .collect()
    }

    /// The anonymous-page owner of the VMA containing `va`, establishing it on
    /// first use. A page moved into an anonymous VMA must join THAT VMA's rmap
    /// family, so the move path needs the same owner the fault path would have
    /// created.
    /// # C: O(log N)
    pub fn uffd_anon_vma(&self, va: UserVirtAddr) -> Option<Arc<crate::anon_vma::AnonVma>> {
        let mut tree = self.vmas.write();
        let vma = tree.find_containing_mut(va)?;
        if let Some(anon) = vma.anon_vma.as_ref() { return Some(Arc::clone(anon)); }
        let anon = crate::anon_vma::AnonVma::new();
        anon.attach(self.self_weak.clone(), vma.start.as_u64(), vma.end.as_u64());
        vma.anon_vma = Some(Arc::clone(&anon));
        Some(anon)
    }

    /// Record that a range acquired anonymous data (a moved-in page counts, so
    /// the VMA is not later treated as never-written).
    /// # C: O(log N)
    pub fn uffd_mark_anon(&self, va: UserVirtAddr) {
        let mut tree = self.vmas.write();
        if let Some(vma) = tree.find_containing_mut(va) {
            vma.anon_pages.store(true, core::sync::atomic::Ordering::Release);
        }
    }

    /// Invalidate `[start, end)` on every other CPU running this address
    /// space. The local CPU is flushed by the walk itself; peers must be told
    /// or a stale writable entry outlives a write-protect.
    /// # C: O((end - start) / 4096)
    pub fn uffd_shootdown_range(&self, start: u64, end: u64) {
        let mask = self.cpumask();
        let mut va = start;
        while va < end {
            hal::tlb::shootdown_others_va(va, mask);
            va += hal::PAGE_SIZE_BYTES;
        }
    }
}

/// # C: O(1)
fn project(v: &crate::vma::Vma) -> UffdVma {
    let file = match &v.backing {
        VmaBacking::File { backing, off } => Some((Arc::clone(backing), *off)),
        _ => None,
    };
    UffdVma {
        start: v.start.as_u64(),
        end:   v.end.as_u64(),
        prot:  v.prot,
        may_write: v.may_prot.contains(VmaProt::WRITE),
        write: v.prot.contains(VmaProt::WRITE),
        anonymous: matches!(v.backing, VmaBacking::Anonymous),
        shmem: file.as_ref().is_some_and(|(b, _)| b.is_shmem()),
        shared: v.flags.contains(VmaFlags::SHARED),
        locked: v.flags.contains(VmaFlags::LOCKED),
        modes: v.flags & VmaFlags::UFFD_MASK,
        ctx: v.uffd.clone(),
        file,
        anon_vma: v.anon_vma.as_ref().map(Arc::clone),
    }
}
