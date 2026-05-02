// VMA types per `11§4`.
//
// `Vma` is the per-region descriptor held by `VmaTree` (`tree.rs`).
// File backing is a placeholder (`VmaBacking::File { off }`) until the
// VFS lands; once `Arc<File>` exists this variant gains the inode ref
// per `11§4`. `rss` is per-VMA resident-page count; updates land with
// the page-fault handler in a later P1-N.

use core::sync::atomic::{AtomicU64, Ordering};

use hal::UserVirtAddr;

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

/// VMA backing per `11§4`. `File` is a placeholder until `16` (VFS)
/// freezes; once `Arc<File>` exists this carries the inode ref.
/// `Special` covers vDSO / vvar / hugetlb regions which never merge.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum VmaBacking {
    Anonymous,
    File { off: u64 },
    Special,
}

/// Single virtual memory area. `start` ≤ `va` < `end` covers this VMA.
/// Per `11§4`. `rss` is the per-VMA resident-page count.
#[derive(Debug)]
pub struct Vma {
    pub start: UserVirtAddr,
    pub end:   UserVirtAddr,
    pub prot:  VmaProt,
    pub flags: VmaFlags,
    pub backing: VmaBacking,
    pub rss: AtomicU64,
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
        Self { start, end, prot, flags, backing, rss: AtomicU64::new(0) }
    }

    /// # C: O(1)
    pub fn contains(&self, va: UserVirtAddr) -> bool {
        let v = va.as_u64();
        v >= self.start.as_u64() && v < self.end.as_u64()
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
        match (self.backing, next.backing) {
            (VmaBacking::Anonymous, VmaBacking::Anonymous) => true,
            (VmaBacking::File { off: a }, VmaBacking::File { off: b }) => {
                a.checked_add(self.len_bytes()).map_or(false, |aend| aend == b)
            }
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
        let backing = match self.backing {
            VmaBacking::File { off } => VmaBacking::File { off: off + off_delta },
            other => other,
        };
        Vma {
            start: new_start,
            end:   new_end,
            prot:  self.prot,
            flags: self.flags,
            backing,
            rss: AtomicU64::new(0),
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
            backing: self.backing,
            rss: AtomicU64::new(self.rss.load(Ordering::Relaxed)),
        }
    }
}
