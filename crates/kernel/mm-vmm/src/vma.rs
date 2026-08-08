// VMA types per `11§4`.
//
// `Vma` is the per-region descriptor held by `VmaTree` (`tree.rs`).
// File backing is a placeholder (`VmaBacking::File { off }`) until the
// VFS lands; once `Arc<File>` exists this variant gains the inode ref
// per `11§4`. `rss` is per-VMA resident-page count; updates land with
// the page-fault handler in a later P1-N.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use alloc::sync::Arc;
use hal::UserVirtAddr;

use crate::{file_rmap::FileRmap, PhysCacheMode};

mod clone;

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
        /// mseal(2): the mapping is sealed — mprotect/munmap/mremap/
        /// mmap(MAP_FIXED) over it fail with EPERM. Never cleared.
        const SEALED    = 1 << 5;
        /// madvise(MADV_DONTFORK): the child does NOT inherit this VMA
        /// (Linux VM_DONTCOPY). Cleared by MADV_DOFORK.
        const DONTFORK  = 1 << 6;
        /// madvise(MADV_WIPEONFORK): the child inherits the VMA but its
        /// pages read as fresh zeros (Linux VM_WIPEONFORK; anon-private
        /// only). Cleared by MADV_KEEPONFORK. systemd's random-util
        /// depends on this being FUNCTIONAL, not a hint.
        const WIPEONFORK = 1 << 7;
        /// userfaultfd(2) UFFDIO_REGISTER MODE_MISSING (Linux
        /// `VM_UFFD_MISSING`): a NotPresent fault in this VMA is routed
        /// to the registered `uffd` context instead of being zero-filled.
        const UFFD_MISSING = 1 << 8;
        /// madvise(MADV_RANDOM): prefer minimal readahead.
        const RAND_READ = 1 << 9;
        /// madvise(MADV_SEQUENTIAL): prefer sequential readahead.
        const SEQ_READ = 1 << 10;
        /// madvise(MADV_DONTDUMP): exclude from core dump.
        const DONTDUMP = 1 << 11;
        /// madvise(MADV_MERGEABLE): KSM-merge candidate.
        const MERGEABLE = 1 << 12;
        /// madvise(MADV_HUGEPAGE): transparent hugepage preference.
        const HUGEPAGE = 1 << 13;
        /// madvise(MADV_NOHUGEPAGE): transparent hugepage opt-out.
        const NOHUGEPAGE = 1 << 14;
        /// A SysV shared-memory attachment (`shmat`). Linux identifies these
        /// by `vma->vm_ops == &shm_vm_ops`; this kernel has no per-VMA ops
        /// table, so the marker is a flag. It is what makes `shm_nattch`
        /// track VMA lifetime (`crate::vm_ops`) and what `shmdt` matches on.
        const SYSVSHM = 1 << 15;
        /// mlock2(MLOCK_ONFAULT) / mlockall(MCL_ONFAULT) (Linux
        /// `VM_LOCKONFAULT`): the range is locked, but pages are pinned as
        /// they fault in rather than being prefaulted. Only ever set
        /// alongside `LOCKED`; the pair is [`VmaFlags::LOCKED_MASK`].
        const LOCKONFAULT = 1 << 16;
        /// userfaultfd(2) `UFFDIO_REGISTER` MODE_WP: a write to a page in this
        /// VMA carrying the per-page write-protect marker is routed to the
        /// registered `uffd` context instead of resolving as a normal write
        /// fault. The per-PAGE half of that state lives in the page-table leaf;
        /// this flag is only the per-VMA registration.
        const UFFD_WP = 1 << 17;
        /// userfaultfd(2) `UFFDIO_REGISTER` MODE_MINOR: a not-present fault on
        /// a page the VMA's backing already holds resident is routed to the
        /// registered `uffd` context instead of being mapped straight in.
        const UFFD_MINOR = 1 << 18;
        /// A mapping of secret memory: pages that are absent from the
        /// kernel's linear map. The reference identifies these by the VMA's
        /// operations table, which this kernel does not have per VMA, so the
        /// marker is a flag — the same shape [`VmaFlags::SYSVSHM`] uses. It is
        /// what refuses a pin of such a page and what stops the mapping from
        /// being unlocked.
        const SECRETMEM = 1 << 19;
    }
}

impl VmaFlags {
    /// Every userfaultfd registration-mode flag. A VMA carries flags from this
    /// set together with a context, or carries neither; fork drops the whole
    /// mask with the context so no child is left holding a mode flag whose
    /// context it does not have.
    pub const UFFD_MASK: VmaFlags = VmaFlags::UFFD_MISSING
        .union(VmaFlags::UFFD_WP).union(VmaFlags::UFFD_MINOR);

    /// Linux `VM_LOCKED_MASK` — the mlock-family flag pair. Every mlock
    /// transition clears the whole mask before adding the new state, and
    /// fork/mremap drop the mask outright, so a stale `LOCKONFAULT` can never
    /// survive a plain `mlock()` over the same range.
    pub const LOCKED_MASK: VmaFlags = VmaFlags::LOCKED.union(VmaFlags::LOCKONFAULT);
}

/// Flag set for the user-stack VMA installed by `sys_execve` per
/// `docs/31§5` ("Stack: 8 MiB initial, MAP_GROWSDOWN, MAP_STACK").
/// Centralised so the kernel call site and the hosted regression
/// test agree on the contract: `GROWSDOWN` must be present or the
/// page-fault auto-extend path (`try_grow_stack`) refuses to grow
/// the stack and any task overflowing its initial frame SIGSEGV's.
/// B43: dhcpcd-aarch64 hit this exact failure pre-fix.
pub const EXEC_STACK_VMA_FLAGS: VmaFlags = VmaFlags::PRIVATE
    .union(VmaFlags::ANONYMOUS)
    .union(VmaFlags::GROWSDOWN);

#[cfg(test)]
mod exec_stack_flags_tests {
    use super::{EXEC_STACK_VMA_FLAGS, VmaFlags};

    /// B43 regression: execve's stack VMA must carry `GROWSDOWN` so
    /// `try_grow_stack` extends it on a fault below `vma.start`.
    /// Pre-B43 the flag was missing; this test would have caught it.
    #[test]
    fn exec_stack_flags_include_growsdown() {
        assert!(EXEC_STACK_VMA_FLAGS.contains(VmaFlags::GROWSDOWN),
            "execve stack VMA must be GROWSDOWN — see docs/31§5");
        assert!(EXEC_STACK_VMA_FLAGS.contains(VmaFlags::PRIVATE));
        assert!(EXEC_STACK_VMA_FLAGS.contains(VmaFlags::ANONYMOUS));
        assert!(!EXEC_STACK_VMA_FLAGS.contains(VmaFlags::SHARED));
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
    /// Errors retain their allocation or I/O cause so the fault path never
    /// converts an ENOMEM cache admission failure into a cache miss.
    fn read_at(&self, off: u64, dst: &mut [u8]) -> Result<usize, FileBackingError>;

    /// File size at last stat — used only to decide tail zero-fill.
    /// Stale values are harmless: the worst case is a non-zero tail
    /// that gets zero-filled anyway because `read_at` returned short.
    fn size_hint(&self) -> u64;

    /// Backing inode number — diagnostics only (identify which file a
    /// file-backed VMA maps). Default 0 for non-inode backings.
    fn ino(&self) -> u64 { 0 }

    /// Directory-entry count of the mapped object. Zero marks an object with
    /// no name in any directory — an unlinked file, or the anonymous shared
    /// memory a `MAP_SHARED|MAP_ANONYMOUS` mapping is built on — which is what
    /// separates the anonymous-shared core-dump class from the file-backed
    /// shared one. Default 1 for a backing that maps no inode.
    /// # C: O(1)
    fn i_nlink(&self) -> u32 { 1 }

    /// `i_mode` of the mapped object (file type plus permission bits). The
    /// core-dump header-page rule reads its execute bits to tell a program
    /// image from a plain data mapping. Default 0 for a backing that maps no
    /// inode.
    /// # C: O(1)
    fn i_mode(&self) -> u16 { 0 }

    /// Path the mapping was established from, as the mapper named it. `None`
    /// for a backing with no name in any directory — anonymous shared memory,
    /// a device ring, an unlinked file. A core dump's `NT_FILE` table is built
    /// from these, which is how a debugger reopens the objects a crashed
    /// process had mapped and recovers the pages the dump did not carry.
    /// # C: O(1)
    fn map_path(&self) -> Option<&[u8]> { None }

    /// Stable identity of the OBJECT behind this backing, shared by every
    /// mapping of it in every process, or 0 when the backing has no such
    /// identity.
    ///
    /// This is the value a shared-futex key is derived from — Linux keys a
    /// `!FUTEX_PRIVATE_FLAG` futex on `(inode, page index, offset)` rather than
    /// on an address or a physical page, precisely so that two processes
    /// mapping one file at different addresses hash to the same futex, and so
    /// that the key survives the page being evicted and re-read at a different
    /// physical address.
    ///
    /// It is NOT the inode number: that is only unique within a filesystem.
    /// Implementors return a per-inode kernel identity, and MUST return the
    /// same value for every mapping of the same object or cross-process wakes
    /// are lost.
    /// # C: O(1)
    fn object_id(&self) -> u64 { 0 }

    /// MAP_SHARED page-cache frame for page-aligned file offset `off`. Some =
    /// the persistent backing frame a shared mapping installs directly (Linux
    /// shmem); None (default) = no shareable frame → the fault handler copies
    /// via `read_at` (MAP_PRIVATE / non-page-frame backings). tmpfs/memfd
    /// supply a real frame so writes propagate to the file and other mappers.
    /// # C: O(log N_pages)
    fn shared_frame(&self, _off: u64) -> Result<Option<SharedFrame>, FileBackingError> { Ok(None) }

    /// Byte size of the huge page this backing is built on, or 0 when it maps
    /// ordinary base pages.
    ///
    /// A hugetlbfs file's pages ARE huge pages: a mapping of one resolves
    /// through a single page-table leaf covering the whole page, not through
    /// the base-page leaves the rest of this trait deals in. Reporting the size
    /// here is what sends the fault handler down that path, and it is the only
    /// place the fact is recorded — the VMA carries no second copy that could
    /// disagree with the file it maps.
    ///
    /// A non-zero value must be a granule the page tables express as one leaf,
    /// and `shared_frame` must then accept offsets aligned to it and return a
    /// physical base aligned to it.
    /// # C: O(1)
    fn huge_page_size(&self) -> u64 { 0 }

    /// A PRIVATE copy of the huge page at `off`, for a mapping whose writes
    /// must not reach the file.
    ///
    /// The frame comes back carrying the mapping's own reference and no other,
    /// so the mapping owns it outright and [`FileBacking::huge_put_frame`]
    /// returns it to whatever pool it came from. `None` = nothing to copy.
    /// # C: O(huge page)
    fn huge_cow_frame(&self, _off: u64) -> Result<Option<SharedFrame>, FileBackingError> {
        Ok(None)
    }

    /// Release one reference to a huge page this backing handed out. The
    /// backing owns the release because it is the only thing that knows which
    /// pool the page came from.
    /// # C: O(log nr)
    fn huge_put_frame(&self, _pa: u64) {}

    /// Retained cache frame for Linux-style `map_pages` fault-around. This
    /// MUST be a non-faulting lookup: no allocation, swap-in, or backing I/O.
    /// `None` means the page is not currently eligible. # C: O(log N_pages)
    fn fault_around_frame(&self, _off: u64) -> Result<Option<SharedFrame>, FileBackingError> { Ok(None) }

    /// Whether the mapped pages ARE the object's storage (memory-backed shared
    /// memory) rather than a cache of something durable behind it.
    ///
    /// This is the fact a userfaultfd minor-fault registration turns on: a
    /// minor fault means "the backing already holds this page, only the page
    /// table is missing it", which is only a meaningful distinction where the
    /// backing owns real frames. A backing that merely copies bytes on demand
    /// can never report a page as already resident.
    /// # C: O(1)
    fn is_shmem(&self) -> bool { false }

    /// Device-owned frame installed directly for either mapping type. # C: O(1)
    fn direct_frame(&self, _off: u64) -> Option<u64> { None }

    /// The concrete backing object behind this mapping, for a subsystem that
    /// must recognise one of ITS OWN mappings by identity rather than by
    /// address — the equivalent of Linux comparing `vma->vm_ops` against the
    /// subsystem's own operations table. `None` (default) = the backing
    /// publishes no such identity. # C: O(1)
    fn as_object(&self) -> Option<&(dyn core::any::Any + 'static)> { None }

    /// Flush dirty cache pages overlapping `[start,end)` to the backing store.
    /// Default no-op covers shmem/memfd-style backings where mapped pages are
    /// already the store. # C: O(N_dirty in range)
    fn writeback_range(&self, _start: u64, _end: u64) -> Result<(), ()> { Ok(()) }

    /// `msync(MS_SYNC)`: make `[start,end)` DURABLE, not merely written —
    /// Linux's fsync-range call is page-cache writeback FOLLOWED BY the
    /// filesystem's journal commit and a device barrier.
    ///
    /// Distinct from [`Self::writeback_range`], which only hands the bytes to
    /// the filesystem. A backing that stops at `writeback_range` gives
    /// `MS_SYNC` no more durability than `MS_ASYNC`, which is the whole reason
    /// programs call it. Default forwards to `writeback_range` — correct for
    /// shmem/memfd, where the mapped pages ARE the store and there is nothing
    /// behind them to commit. # C: O(N_dirty in range) + O(journal tx)
    fn fsync_range(&self, start: u64, end: u64) -> Result<(), ()> {
        self.writeback_range(start, end)
    }

    /// Non-faulting Linux `mincore(2)` page-cache residency query for a
    /// page-aligned file offset. `true` means a fault would not need backing I/O.
    /// # C: O(log N_pages)
    fn mincore_page(&self, _off: u64) -> bool { false }

    /// Whether the object's page store OWNS this page-aligned offset in ANY
    /// form — resident, mid-migration, or evicted to swap — as opposed to the
    /// offset being a hole the object has never held contents for.
    ///
    /// Distinct from [`Self::fault_around_frame`], which answers the narrower
    /// "can a PTE be installed from this right now" and must therefore report
    /// nothing for an evicted page. This one answers "does the object hold this
    /// page at all", which is the fact a userfaultfd MINOR registration turns
    /// on: a minor fault means "the object already has these contents, only the
    /// page table is missing them", and that stays true across eviction.
    /// Deciding it from the narrower query silently downgrades a minor fault to
    /// a missing one — the monitor is then asked to supply contents that
    /// already exist, and the page it writes replaces them.
    ///
    /// Non-faulting like every other residency query: no allocation, no
    /// swap-in, no backing I/O.
    /// # C: O(log N_pages)
    fn backing_holds_page(&self, _off: u64) -> bool { false }

    /// Linux `can_do_mincore`: reveal exact file page-cache state only when the
    /// caller owns/can-write the mapped file; otherwise mincore reports resident.
    /// # C: O(1) or inode permission check
    fn mincore_can_reveal(&self) -> bool { true }

    /// Linux `MADV_REMOVE`: punch a shared writable file range with
    /// `FALLOC_FL_PUNCH_HOLE|FALLOC_FL_KEEP_SIZE`.
    /// # C: filesystem-dependent
    fn madvise_remove(&self, _off: u64, _len: u64) -> Result<(), FileBackingError> {
        Err(FileBackingError::OpNotSupp)
    }

    fn madvise_pageout(&self, _off: u64, _len: u64) -> Option<Result<usize, FileBackingError>> { None }

    /// Canonical `address_space->i_mmap` owner for shared file pages.  A
    /// backing that exposes persistent shared frames must return the same
    /// owner for every handle to that inode.  Private/file-copy mappings and
    /// device-only backings return None. # C: O(1)
    fn file_rmap(&self) -> Option<Arc<FileRmap>> { None }
}

/// A page-cache frame handed to a MAP_SHARED fault.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SharedFrame { pub pa: u64, pub map_ref_held: bool }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FileBackingError {
    Acces,
    Badf,
    Inval,
    Io,
    NoMem,
    OpNotSupp,
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
    /// Shared kernel-owned physical frame. The page-fault handler
    /// installs `pa` directly into the user PT — no copy, no per-
    /// task frame allocation. Used for the vvar page so a single
    /// kernel write (via HHDM) propagates to every user mapping.
    KernelFrame { pa: u64 },
    /// Contiguous device physical range (Linux `remap_pfn_range` / VM_PFNMAP).
    /// The page-fault handler maps page at VMA offset `O` to `base_pa + O`
    /// directly — no PMM frame alloc, no refcount, no copy. Used for
    /// `/dev/fbN`: userspace writes hit the real scanout memory.
    PhysRange { base_pa: u64, cache: PhysCacheMode },
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
            VmaBacking::KernelFrame { pa } => write!(f, "KernelFrame {{ pa: {:#x} }}", pa),
            VmaBacking::PhysRange { base_pa, cache } => {
                write!(f, "PhysRange {{ base_pa: {:#x}, cache: {:?} }}", base_pa, cache)
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
            (VmaBacking::KernelFrame { pa: a }, VmaBacking::KernelFrame { pa: b }) => a == b,
            (VmaBacking::PhysRange { base_pa: a, cache: ac },
             VmaBacking::PhysRange { base_pa: b, cache: bc }) => a == b && ac == bc,
            _ => false,
        }
    }
}
impl Eq for VmaBacking {}

/// Single virtual memory area. `start` ≤ `va` < `end` covers this VMA.
/// Per `11§4`. `rss` is the per-VMA resident-page count.
///
/// `anon_vma` is the rmap reverse-link for the mapping's anonymous family.
/// `anon_pages` records whether that family has received a page; reclaim does
/// not clear it, so the mapping's private-data classification remains stable.
pub struct Vma {
    pub start: UserVirtAddr,
    pub end:   UserVirtAddr,
    pub prot:  VmaProt,
    pub may_prot: VmaProt,
    /// Linux `vma_pkey(vma)`: the sole protection-key owner for every leaf
    /// installed from this mapping. Key zero is the initial/default key.
    pub pkey: u8,
    pub flags: VmaFlags,
    pub backing: VmaBacking,
    pub rss: AtomicU64,
    pub anon_vma: Option<Arc<crate::anon_vma::AnonVma>>,
    pub anon_pages: AtomicBool,
    /// File-backed counterpart of `anon_vma`: one shared inode owner whose
    /// interval edges name MAP_SHARED mappings. Never synthesized from inode
    /// numbers or VAs.
    pub file_rmap: Option<Arc<FileRmap>>,
    /// Linux `vm_area_struct::anon_name`, set by
    /// `prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, ...)`.
    pub anon_name: Option<Arc<str>>,
    /// userfaultfd(2) `vm_userfaultfd_ctx` — the fd's inode state, set on
    /// `UFFDIO_REGISTER(MODE_MISSING)` (see `flags & UFFD_MISSING`). The
    /// fault handler calls `missing_fault` on a NotPresent fault here.
    /// `None` for the overwhelming majority of VMAs.
    pub uffd: Option<Arc<dyn crate::uffd::UffdContext>>,
    /// Linux `vm_area_struct::vm_policy` — the NUMA policy `mbind(2)` installed
    /// over this range. `None` is Linux's NULL `vm_policy`, which makes
    /// allocation fall back to the task policy and makes
    /// `get_mempolicy(MPOL_F_ADDR)` report `MPOL_DEFAULT`.
    pub mempolicy: Option<crate::mempolicy::MemPolicy>,
}

impl core::fmt::Debug for Vma {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Vma")
            .field("start", &self.start)
            .field("end", &self.end)
            .field("prot", &self.prot)
            .field("may_prot", &self.may_prot)
            .field("pkey", &self.pkey)
            .field("flags", &self.flags)
            .field("backing", &self.backing)
            .field("rss", &self.rss.load(Ordering::Relaxed))
            .field("anon_vma_id", &self.anon_vma.as_ref().map(|a| a.id))
            .field("anon_pages", &self.anon_pages.load(Ordering::Relaxed))
            .field("file_rmap", &self.file_rmap.is_some())
            .field("anon_name", &self.anon_name)
            .field("uffd", &self.uffd.is_some())
            .field("mempolicy", &self.mempolicy)
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
        Self::new_with_may(start, end, prot, VmaProt::READ | VmaProt::WRITE | VmaProt::EXEC,
            flags, backing)
    }

    /// Construct a VMA with Linux `VM_MAY*` rights.
    /// # C: O(1)
    pub fn new_with_may(
        start: UserVirtAddr,
        end:   UserVirtAddr,
        prot:  VmaProt,
        may_prot: VmaProt,
        flags: VmaFlags,
        backing: VmaBacking,
    ) -> Self {
        // Anonymous VMAs get their family at map time. Private file mappings
        // acquire one at their first COW page in the fault path.
        let anon_vma = if matches!(backing, VmaBacking::Anonymous) {
            Some(crate::anon_vma::AnonVma::new())
        } else { None };
        let file_rmap = match &backing {
            VmaBacking::File { backing, .. } if flags.contains(VmaFlags::SHARED) => backing.file_rmap(),
            _ => None,
        };
        Self {
            start, end, prot, may_prot, pkey: 0, flags, backing,
            rss: AtomicU64::new(0),
            anon_vma,
            anon_pages: AtomicBool::new(false),
            file_rmap,
            anon_name: None,
            uffd: None,
            mempolicy: None,
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

    /// PTE permissions for this VMA, including its canonical key. # C: O(1)
    pub fn page_flags(&self) -> hal::PageFlags { self.prot.to_page_flags().with_pkey(self.pkey) }

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
        if self.may_prot != next.may_prot { return false; }
        if self.pkey != next.pkey { return false; }
        if self.flags != next.flags { return false; }
        if self.anon_name != next.anon_name { return false; }
        // Different userfaultfd registrations never coalesce (Linux
        // `is_mergeable_vma` compares `vm_userfaultfd_ctx`). The flag
        // check above already blocks registered↔unregistered; this
        // blocks two ranges bound to distinct uffd fds.
        if !crate::uffd::uffd_ptr_eq(&self.uffd, &next.uffd) { return false; }
        // Linux `can_vma_merge_after` → `mpol_equal(vma_policy(vma), policy)`:
        // two ranges under different mbind(2) policies never coalesce, or the
        // survivor would silently acquire the other's policy.
        if !crate::mempolicy::mpol_equal(&self.mempolicy, &next.mempolicy) { return false; }
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
            (VmaBacking::KernelFrame { .. }, _) | (_, VmaBacking::KernelFrame { .. }) => false,
            (VmaBacking::Special, _) | (_, VmaBacking::Special) => false,
            _ => false,
        }
    }

}
