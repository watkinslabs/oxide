// VMA types per `11§4`.
//
// `Vma` is the per-region descriptor held by `VmaTree` (`tree.rs`).
// File backing is a placeholder (`VmaBacking::File { off }`) until the
// VFS lands; once `Arc<File>` exists this variant gains the inode ref
// per `11§4`. `rss` is per-VMA resident-page count; updates land with
// the page-fault handler in a later P1-N.

use core::sync::atomic::{AtomicU64, Ordering};

use alloc::sync::Arc;
use hal::UserVirtAddr;

use crate::anon_vma::AnonVma;

bitflags::bitflags! {
    /// VMA protection bits per `11§4`. R/W/X only at the VMA layer;
    /// the COW write-protect bit is a PTE-level concern (`11§7`).
    #[derive(Copy, Clone, Debug, Eq, PartialEq, Default, Hash)]
    pub struct VmaProt: u8 {
        const READ  = 1 << 0;
        const WRITE = 1 << 1;
        const EXEC  = 1 << 2;
    }
}

impl VmaProt {
    /// Translate to `hal::PageFlags` for an installed PTE. The USER
    /// bit is added by the caller (every VMA-backed PTE is U=1 per
    /// `11§4`/§5). NX semantics: PTE.NX = !VMA.X (x86 NX bit; arm UXN).
    /// # C: O(1)
    pub fn to_page_flags(self) -> hal::PageFlags {
        let mut pf = hal::PageFlags::USER;
        if self.contains(Self::READ)  { pf |= hal::PageFlags::READ;  }
        if self.contains(Self::WRITE) { pf |= hal::PageFlags::WRITE; }
        if self.contains(Self::EXEC)  { pf |= hal::PageFlags::EXEC;  }
        pf
    }

    /// True iff this VMA permits the requested access kind. Used
    /// by `handle_page_fault` per `11§5`.
    /// # C: O(1)
    pub fn permits(self, access: FaultAccess) -> bool {
        match access {
            FaultAccess::Read  => self.contains(Self::READ),
            FaultAccess::Write => self.contains(Self::WRITE),
            FaultAccess::Exec  => self.contains(Self::EXEC),
        }
    }
}

/// Access kind that produced a page fault, per `11§5`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FaultAccess {
    Read,
    Write,
    Exec,
}

/// Page-fault classification handed to `AddressSpace::handle_page_fault`
/// per `11§5`. v1 covers `NotPresent` (demand fault); `Write` (COW
/// upgrade) lands with the per-page metadata + refcount path in P3.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FaultKind {
    /// CPU translation walk found no present PTE for this VA.
    NotPresent { access: FaultAccess },
    /// Present PTE rejected the access (write to RO, exec on NX).
    /// COW resolves the writable variant; v1 returns EFAULT for
    /// non-COW protection mismatches → SIGSEGV upstream.
    Protection { access: FaultAccess },
}

bitflags::bitflags! {
    /// VMA flags per `11§4`. `SHARED`/`PRIVATE` are mutually exclusive
    /// at construction; not enforced here (caller per `15§6.2 mmap`).
    #[derive(Copy, Clone, Debug, Eq, PartialEq, Default, Hash)]
    pub struct VmaFlags: u32 {
        const SHARED    = 1 << 0;
        const PRIVATE   = 1 << 1;
        const ANONYMOUS = 1 << 2;
        const GROWSDOWN = 1 << 3;
        const LOCKED    = 1 << 4;
    }
}

/// File-backed mmap surface, per `11§4` + `17§5`. The demand-page
/// handler calls `read_at(off, dst)` to populate a freshly-allocated
/// user frame; impls are expected to route through the page cache so
/// repeated faults at the same file offset hit cached bytes rather
/// than re-reading the block device. `size_hint` lets the handler
/// zero-fill the tail when a VMA extends past the file's end (Linux
/// returns zeroed-page-with-SIGBUS-past-end; v1 chooses the
/// zero-fill leg).
///
/// Trait-object behind `Arc<dyn FileBacking>` so `VmaBacking::File`
/// can be cloned cheaply across fork(2) without per-FS knowledge in
/// `mm-vmm`. Concrete impls live in `kernel/src/dev/...` (inode
/// wrapper) and pull `vfs::Inode::read` through the page cache.
pub trait FileBacking: Send + Sync {
    /// Fill `dst` with bytes starting at file offset `off`. Short
    /// reads are allowed; the handler zero-fills the unread tail.
    /// `Err(())` signals an FS-level read failure — the page-fault
    /// handler then maps a zero frame (matching Linux's
    /// SIGBUS-on-EIO leg's "page is observable" invariant for v1;
    /// real SIGBUS propagation lands with the dirty-writeback path).
    fn read_at(&self, off: u64, dst: &mut [u8]) -> Result<usize, ()>;

    /// File size at last stat — used only to decide tail zero-fill.
    /// Stale values are harmless: the worst case is a non-zero tail
    /// that gets zero-filled anyway because `read_at` returned short.
    fn size_hint(&self) -> u64;
}

/// VMA backing per `11§4`. `File` carries the file/inode ref via
/// `Arc<dyn FileBacking>` (read-side path through page cache;
/// writeback rides the dirty-tracking work).
/// `Special` covers vDSO / vvar / hugetlb regions which never merge.
///
/// `KernelBytes` is a v1-only bridge until VFS lands per `16`:
/// kernel-side data backs the VMA via a refcounted `Arc<[u8]>`.
/// Used by the ELF loader (`31`) to map PT_LOAD segments from a
/// boot-embedded blob; the demand-page handler copies bytes from
/// `data` into the freshly-allocated user page on each fault.
/// `data.len()` may be smaller than the VMA's byte length — bytes
/// past the slice length zero-fill (PT_LOAD's `p_memsz > p_filesz`
/// = BSS tail).
///
/// `Arc<[u8]>` (not `&'static [u8]`): on fork(2) the child VMA tree
/// clones each VMA, bumping the Arc refcount, so child KernelBytes
/// remain valid even when the parent AS drops. The pre-Arc design
/// stashed boxes in the parent AS's `staged_bytes` Vec and handed
/// out `&'static [u8]` views; child VMAs cloned the slice ref and
/// dangled when the parent dropped first (use-after-free latent
/// bug). Arc gives correct refcount-based lifetime.
#[derive(Clone)]
pub enum VmaBacking {
    Anonymous,
    File { backing: alloc::sync::Arc<dyn FileBacking>, off: u64 },
    KernelBytes { data: alloc::sync::Arc<[u8]>, off: usize },
    Special,
}

impl core::fmt::Debug for VmaBacking {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VmaBacking::Anonymous => f.write_str("Anonymous"),
            VmaBacking::File { off, .. } => write!(f, "File {{ off: {} }}", off),
            VmaBacking::KernelBytes { data, off } => {
                write!(f, "KernelBytes {{ len: {}, off: {} }}", data.len(), off)
            }
            VmaBacking::Special => f.write_str("Special"),
        }
    }
}

impl PartialEq for VmaBacking {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (VmaBacking::Anonymous, VmaBacking::Anonymous) => true,
            (VmaBacking::File { backing: ab, off: ao },
             VmaBacking::File { backing: bb, off: bo }) => {
                alloc::sync::Arc::ptr_eq(ab, bb) && ao == bo
            }
            (VmaBacking::Special, VmaBacking::Special) => true,
            (VmaBacking::KernelBytes { data: a, off: ao },
             VmaBacking::KernelBytes { data: b, off: bo }) => {
                alloc::sync::Arc::ptr_eq(a, b) && ao == bo
            }
            _ => false,
        }
    }
}
impl Eq for VmaBacking {}

/// Single virtual memory area. `start` ≤ `va` < `end` covers this VMA.
/// Per `11§4`. `rss` is the per-VMA resident-page count.
///
/// `anon_vma` is the rmap reverse-link for `VmaBacking::Anonymous` —
/// every anonymous VMA in a fork family shares one `Arc<AnonVma>`,
/// which carries the chain of (mm, vma_range) edges so that a page
/// fault handler / migration / KSM pass can enumerate every PTE
/// referencing a frame. `None` for non-anonymous backings; rmap for
/// file-backed lives in the future `address_space::i_mmap` interval
/// tree (see `anon_vma.rs` header).
pub struct Vma {
    pub start: UserVirtAddr,
    pub end:   UserVirtAddr,
    pub prot:  VmaProt,
    pub flags: VmaFlags,
    pub backing: VmaBacking,
    pub rss: AtomicU64,
    pub anon_vma: Option<Arc<AnonVma>>,
}

impl core::fmt::Debug for Vma {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Vma")
            .field("start", &self.start)
            .field("end", &self.end)
            .field("prot", &self.prot)
            .field("flags", &self.flags)
            .field("backing", &self.backing)
            .field("rss", &self.rss.load(Ordering::Relaxed))
            .field("anon_vma_id", &self.anon_vma.as_ref().map(|a| a.id))
            .finish()
    }
}

impl Vma {
    /// Construct a VMA. Caller must ensure `start < end`; `VmaTree::insert`
    /// rejects degenerate ranges with `Inval`.
    /// # C: O(1)
    pub fn new(
        start: UserVirtAddr,
        end:   UserVirtAddr,
        prot:  VmaProt,
        flags: VmaFlags,
        backing: VmaBacking,
    ) -> Self {
        // Anonymous VMAs: allocate a fresh anon_vma family. The
        // chain edge for *this* VMA gets attached by the caller
        // (`AddressSpace::mmap`) once the VMA is in the tree and
        // we have the AS Arc to weak-ref. Non-anonymous backings
        // get None — file rmap lives elsewhere.
        let anon_vma = if matches!(backing, VmaBacking::Anonymous) {
            Some(AnonVma::new())
        } else {
            None
        };
        Self {
            start, end, prot, flags, backing,
            rss: AtomicU64::new(0),
            anon_vma,
        }
    }

    /// # C: O(1)
    pub fn contains(&self, va: UserVirtAddr) -> bool {
        let v = va.as_u64();
        v >= self.start.as_u64() && v < self.end.as_u64()
    }

    /// True iff this VMA permits the access kind that triggered the
    /// fault, per `11§5`. Forwards to `prot.permits`.
    /// # C: O(1)
    pub fn permits(&self, access: FaultAccess) -> bool {
        self.prot.permits(access)
    }

    /// Byte length of the VMA range.
    /// # C: O(1)
    pub fn len_bytes(&self) -> u64 {
        self.end.as_u64() - self.start.as_u64()
    }

    /// True iff `self` and `next` are mergeable per `11§4`: abutting
    /// (`self.end == next.start`), identical prot/flags/backing kind,
    /// and (for file-backed) contiguous file offsets. `Special`
    /// regions never merge.
    /// # C: O(1)
    pub fn mergeable_with_next(&self, next: &Vma) -> bool {
        if self.end != next.start { return false; }
        if self.prot != next.prot { return false; }
        if self.flags != next.flags { return false; }
        match (&self.backing, &next.backing) {
            (VmaBacking::Anonymous, VmaBacking::Anonymous) => true,
            (VmaBacking::File { backing: ab, off: a },
             VmaBacking::File { backing: bb, off: b }) => {
                if !alloc::sync::Arc::ptr_eq(ab, bb) { return false; }
                a.checked_add(self.len_bytes()).map_or(false, |aend| aend == *b)
            }
            // KernelBytes-backed segments don't merge: each PT_LOAD
            // is a distinct slice; merging would require carrying the
            // join in the backing variant. Match Special's behaviour.
            (VmaBacking::KernelBytes { .. }, VmaBacking::KernelBytes { .. }) => false,
            (VmaBacking::KernelBytes { .. }, _) | (_, VmaBacking::KernelBytes { .. }) => false,
            (VmaBacking::Special, _) | (_, VmaBacking::Special) => false,
            _ => false,
        }
    }

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
            flags: self.flags,
            backing,
            rss: AtomicU64::new(0),
            // Sub-range stays in the same anon_vma family — Linux
            // `__split_vma` keeps both halves on the parent's anon_vma
            // (and adds a chain entry for the new half).
            anon_vma: self.anon_vma.as_ref().map(Arc::clone),
        }
    }
}

impl Clone for Vma {
    fn clone(&self) -> Self {
        Vma {
            start: self.start,
            end:   self.end,
            prot:  self.prot,
            flags: self.flags,
            backing: self.backing.clone(),
            rss: AtomicU64::new(self.rss.load(Ordering::Relaxed)),
            // VmaTree::insert clones VMAs into the destination tree
            // at fork; we keep the SAME anon_vma so all forked
            // descendants share the chain.
            anon_vma: self.anon_vma.as_ref().map(Arc::clone),
        }
    }
}
