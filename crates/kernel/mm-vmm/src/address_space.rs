// Per-process address space per `11§3` + `11§9`.
//
// Wraps `VmaTree` in a `RwLock` (class `AddressSpace` per `06§3.6`).
// `mmap` / `munmap` / `mprotect` execute under the write lock; lookup
// (`find_vma`) takes the read lock so multiple page-fault handlers can
// run concurrently once that path lands.
//
// v1 scope:
// - anonymous + file-placeholder backings (no `Arc<File>` — VFS not
//   yet frozen at the impl level)
// - hint + `fixed` mmap flag (MAP_FIXED-equivalent: clear overlap then
//   place); without `fixed`, hint is advisory and we fall back to
//   first-fit hole search
// - per-AS PT spinlock + page-fault handler + COW + TLB shootdown all
//   land in subsequent P1-N branches alongside HAL `MmuOps`.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use hal::{MmuOps, Pa, PageSize, UserVirtAddr, Va, PAGE_SIZE_BYTES, USER_VA_END};
use sync::{AddressSpace as AddressSpaceClass, RwLock, RwReadGuard, Spinlock};

use crate::tree::VmaTree;
use crate::vma::{FaultAccess, FaultKind, Vma, VmaBacking, VmaFlags, VmaProt};
use crate::{Error, KResult};

/// Lowest user VA this allocator hands out. Page 0 is reserved as the
/// canonical null-pointer trap region per `11§4` (`USER_VA_END` upper
/// bound is in `01§1`).
pub const MIN_USER_VA: u64 = PAGE_SIZE_BYTES;

/// Top of the mmap arena used by anon mmap with no hint. Linux places
/// anonymous mmaps in a high-address region below the stack and grows
/// downward (`arch_get_unmapped_area_topdown`). Our v1 uses a fixed
/// mmap_base = USER_VA_END - 0x40000 (256 KiB below the top), with the
/// initial-exec stack reserving the top 128 KiB at `USER_VA_END - 0x20000`.
/// 256 KiB headroom keeps the stack VMA out of the mmap-search path.
pub const MMAP_TOP: u64 = USER_VA_END - 0x40000;

/// Per-process AS. Public surface mirrors `11§3`. The Page Table side
/// (`11§9`) lives in `root_pa`: the PA of this AS's top-level table
/// (PML4 on x86_64; L0 on aarch64). `MmuOps::activate(root_pa)`
/// installs it as the active CR3 / TTBR0_EL1 per `13§8`.
pub struct AddressSpace {
    vmas:    RwLock<VmaTree, AddressSpaceClass>,
    root_pa: u64,
    /// Current `brk` per docs/15§5. Initialised by the ELF loader
    /// to the page-rounded end of the last PT_LOAD; `sys_brk` adjusts
    /// in `[initial, brk_max]` and demand-pages from a co-registered
    /// Anonymous VMA covering the heap region.
    brk:     core::sync::atomic::AtomicU64,
    /// Upper bound of the loader-reserved heap region. `sys_brk(N)`
    /// fails for `N > brk_max`.
    brk_max: core::sync::atomic::AtomicU64,
    /// Optional teardown callback invoked from `Drop` with `root_pa`.
    /// Stored as a raw fn-ptr cast to u64 in an atomic so an Arc'd
    /// AS can install it after construction without violating shared-
    /// reference aliasing. Zero means no teardown (boot-anchor AS,
    /// hosted tests).
    teardown: core::sync::atomic::AtomicU64,
    /// Linux `mm_struct::exe_file` analogue. Captured at `execve`
    /// time as the path the user named, NOT the inode-canonical path.
    /// `/proc/<pid>/exe` readlinks to this. Threads sharing this mm
    /// (CLONE_VM) all see the same value; fork copies it to the
    /// child mm. Hardlinks to the same inode produce different
    /// `exe_path`s — the dentry-of-record is what the user invoked.
    exe_path: Spinlock<Option<alloc::string::String>, AddressSpaceClass>,
}

impl Drop for AddressSpace {
    fn drop(&mut self) {
        let raw = self.teardown.load(core::sync::atomic::Ordering::Acquire);
        if raw != 0 {
            // SAFETY: `set_teardown` installs `td` as an `unsafe extern "C" fn(u64)` cast through `as usize` to a u64; the inverse transmute restores the same fn-ptr, ABI guarantees match, and zero is checked above so we never transmute a null.
            let td: unsafe extern "C" fn(u64) = unsafe {
                core::mem::transmute(raw as usize)
            };
            // SAFETY: `td` accepts the AS's own `root_pa` per the installer contract; the AS is in its final Drop (Arc strong count hit zero) so the root is no longer active on any CPU and no concurrent walker remains.
            unsafe { td(self.root_pa); }
        }
    }
}

impl AddressSpace {
    /// Construct an empty AS over the page-table root at `root_pa`,
    /// returning a reference-counted handle so `fork` can share VMA-
    /// tree state once COW is wired (`11§7`).
    ///
    /// `root_pa` is the PA of the top-level page-table frame this AS
    /// owns: PML4 (x86_64, kernel-half cloned from the master per
    /// `11§2` invariant 5) or L0 (aarch64, user-half only — kernel
    /// rides TTBR1_EL1 unchanged). Production callers obtain it via
    /// `hal_<arch>::mmu_ops::new_user_pml4` / `::new_user_l0`. The
    /// `0` sentinel is reserved for hosted tests that exercise only
    /// VMA-tree behaviour and never activate the AS.
    /// # C: O(1)
    pub fn new(root_pa: u64) -> KResult<Arc<Self>> {
        Ok(Arc::new(Self {
            vmas: RwLock::new(VmaTree::new()),
            root_pa,
            brk:     core::sync::atomic::AtomicU64::new(0),
            brk_max: core::sync::atomic::AtomicU64::new(0),
            teardown: core::sync::atomic::AtomicU64::new(0),
            exe_path: Spinlock::new(None),
        }))
    }

    /// Install a teardown callback fired from `Drop` with this AS's
    /// `root_pa`. The kernel passes its arch-specific walker that
    /// recursively frees user-half PT levels + each leaf frame +
    /// the root frame itself. Without this, every fork/exec leaks a
    /// few KiB of page tables plus every demand-faulted user page.
    ///
    /// Idempotent: a second call replaces the prior callback. The
    /// boot-anchor AS deliberately leaves it unset (its root is the
    /// shared master kernel-half template; freeing would crash).
    /// # C: O(1)
    pub fn set_teardown(&self, td: unsafe extern "C" fn(u64)) {
        // SAFETY: cast a function pointer to u64 for atomic storage.
        // ABI guarantees fn-ptr fits in usize; usize fits in u64 on
        // both arches we target.
        let raw = (td as usize) as u64;
        self.teardown.store(raw, core::sync::atomic::Ordering::Release);
    }

    /// Wrap an ELF / shm staging buffer as `Arc<[u8]>` for use as a
    /// `VmaBacking::KernelBytes` backing. Refcount-based lifetime: a
    /// child AS that fork-clones the VMA tree bumps each Arc, so
    /// child KernelBytes references stay valid even after the parent
    /// AS drops. Pre-Arc design used `&'static [u8]` views into a
    /// per-AS `Vec<Box<[u8]>>`, which dangled in fork children when
    /// the parent dropped first.
    /// # C: O(N) — converts `Box<[u8]>` to `Arc<[u8]>` (one alloc).
    pub fn stash_bytes(&self, b: alloc::boxed::Box<[u8]>) -> alloc::sync::Arc<[u8]> {
        // `Box<[u8]>` → `Arc<[u8]>` is a noop conversion under the
        // hood (Arc grows the box's header to add a strong+weak
        // count); no byte copy.
        alloc::sync::Arc::from(b)
    }

    /// Initialise the brk region. Called by the ELF loader once the
    /// last PT_LOAD has been registered: pass page-aligned start
    /// (=> the initial brk) and the upper-bound max (initial + heap
    /// reservation). Caller must also have inserted the Anonymous
    /// VMA covering `[start, max)` so demand-paging works for the
    /// heap pages.
    /// # C: O(1)
    pub fn set_brk_window(&self, start: u64, max: u64) {
        use core::sync::atomic::Ordering;
        self.brk.store(start, Ordering::Release);
        self.brk_max.store(max, Ordering::Release);
    }

    /// Current `brk` value (0 before the loader runs).
    /// # C: O(1)
    pub fn brk(&self) -> u64 {
        self.brk.load(core::sync::atomic::Ordering::Acquire)
    }

    /// Upper-bound of the brk region (page-aligned). 0 means
    /// "loader didn't reserve a heap region".
    /// # C: O(1)
    pub fn brk_max(&self) -> u64 {
        self.brk_max.load(core::sync::atomic::Ordering::Acquire)
    }

    /// Try to set `brk` to `new`. Returns the post-operation brk
    /// value (matching glibc's `brk(2)` ABI: success ⇒ `new`,
    /// failure ⇒ unchanged old value).
    /// # C: O(1)
    pub fn try_set_brk(&self, new: u64) -> u64 {
        use core::sync::atomic::Ordering;
        let cur = self.brk.load(Ordering::Acquire);
        let max = self.brk_max.load(Ordering::Acquire);
        if max == 0 { return cur; }                  // no heap reserved
        if new < (cur & !0xfff) || new > max { return cur; }
        // Page-round up.
        let rounded = (new + 0xfff) & !0xfff;
        if rounded > max { return cur; }
        self.brk.store(rounded, Ordering::Release);
        rounded
    }

    /// PA of this AS's top-level page-table frame. Pass to
    /// `MmuOps::activate` to make this AS the live address space.
    /// `0` for hosted-test stub ASes.
    /// # C: O(1)
    pub fn root_pa(&self) -> u64 { self.root_pa }

    /// Read-locked snapshot of the VMA tree for tests + diagnostics.
    /// Hot-path callers should use the per-method internal lock; this
    /// is a coarse read borrow used by hosted tests in tests_rmap_cow
    /// to assert chain attach/detach invariants.
    /// # C: O(1) lock acquire
    pub fn vmas_for_test(&self) -> RwReadGuard<'_, VmaTree, AddressSpaceClass> {
        self.vmas.read()
    }

    /// Set the per-mm exe path captured at `execve`. Linux's
    /// `mm_struct::exe_file` analogue: stores the dentry-of-record
    /// path (e.g. `/bin/echo`), NOT the inode-canonical path.
    /// `/proc/<pid>/exe` readlinks to this.
    /// # C: O(1)
    pub fn set_exe_path(&self, path: alloc::string::String) {
        *self.exe_path.lock() = Some(path);
    }

    /// Snapshot current exe path. None until `execve` runs against
    /// this AS, or fork-copied from parent.
    /// # C: O(1)
    pub fn exe_path(&self) -> Option<alloc::string::String> {
        self.exe_path.lock().clone()
    }

    /// Clone VMA tree into a new AS with the supplied PT root.
    /// Mapped pages are NOT copied; child entries demand-page on
    /// first access (KernelBytes copy, Anonymous zero-fill).
    /// For full POSIX fork incl. Anonymous-page copy see
    /// [`fork_copy_pages`].
    /// # C: O(N) over VMA count.
    pub fn fork(&self, new_root_pa: u64) -> KResult<Arc<Self>> {
        let src = self.vmas.read();
        let mut dst = VmaTree::new();
        for vma in src.iter() {
            dst.insert(vma.clone()).map_err(|_| Error::NoMem)?;
        }
        Ok(Arc::new(Self {
            vmas: RwLock::new(dst),
            root_pa: new_root_pa,
            brk:     core::sync::atomic::AtomicU64::new(self.brk()),
            brk_max: core::sync::atomic::AtomicU64::new(self.brk_max()),
            teardown: core::sync::atomic::AtomicU64::new(0),
            exe_path: Spinlock::new(self.exe_path.lock().clone()),
        }))
    }

    /// Full POSIX fork per docs/11§7: clone VMA tree + copy every
    /// mapped Anonymous page into fresh frames in `new_root_pa`.
    /// KernelBytes re-fault in child against the shared slice.
    /// `new_root_pa` must be a PT root with kernel-half cloned
    /// from master per `11§2` invariant 5.
    ///
    /// # SAFETY: source AS is the active CR3 / TTBR0 (so
    /// `M::translate` resolves source PTEs); single-CPU UP;
    /// preempt-off; caller is the `sys_fork` handler.
    /// # C: O(N_vmas + P_anon_pages)
    /// F157: COW fork (Linux equivalent). Replaces the eager-copy
    /// `fork_copy_pages` with refcount-based page sharing per
    /// `mm/memory.c` `copy_present_pte`:
    /// 1. Clone the VMA tree.
    /// 2. Walk parent's mapped pages: for each present leaf,
    ///    - bump struct-page refcount via `inc_ref`,
    ///    - install the SAME PA in the child PT,
    ///    - if the VMA is writable, clear the W bit on BOTH PTEs
    ///      (parent + child) and TLB-flush parent's VA so the next
    ///      write fault dispatches to `handle_page_fault` for COW
    ///      split.
    /// Read-only VMAs (.text / .rodata) keep their RO PTEs and
    /// share frames forever — same Linux behaviour for shared file
    /// pages.
    ///
    /// `new_root_pa` must be an already-allocated PT root with
    /// kernel-half cloned from master per `11§2` invariant 5.
    /// `inc_ref(pa)` bumps the struct-page refcount for shared frames.
    ///
    /// # SAFETY: source AS is the active CR3 / TTBR0; preempt-off;
    /// single-CPU UP; caller is `sys_fork` / `sys_clone` handler.
    /// # C: O(N_vmas + P_mapped_pages)
    pub fn fork_cow_pages<M: MmuOps, IR: FnMut(u64)>(
        &self,
        new_root_pa: u64,
        _hhdm_offset: u64,
        mut inc_ref: IR,
    ) -> KResult<Arc<Self>> {
        let src = self.vmas.read();
        let mut dst = VmaTree::new();
        for vma in src.iter() {
            dst.insert(vma.clone()).map_err(|_| Error::NoMem)?;
        }
        for vma in src.iter() {
            let writable = vma.prot.contains(VmaProt::WRITE);
            // For COW we share both Anonymous and KernelBytes frames.
            // Only Anonymous + KernelBytes ever get faulted leaves;
            // File / Special are is a follow-up.
            let share_pages = matches!(
                vma.backing,
                VmaBacking::Anonymous | VmaBacking::KernelBytes { .. }
            );
            if !share_pages { continue; }
            let mut va = vma.start.as_u64();
            let end = vma.end.as_u64();
            while va < end {
                // SAFETY: M::translate reads the active PT for the parent.
                if let Some((src_pa, _)) = unsafe { Some(M::translate(Va(va))).flatten() } {
                    let pa = src_pa.0 & !0xfff;
                    // Bump per-page refcount: child + parent both ref it.
                    inc_ref(pa);
                    // Compute child PTE flags. If the VMA is writable,
                    // strip the W bit so first-write triggers
                    // copy-on-write split. Else use the VMA prot
                    // verbatim (RO/RX pages stay shared forever).
                    let child_prot = if writable {
                        let mut p = vma.prot;
                        p.remove(VmaProt::WRITE);
                        p
                    } else {
                        vma.prot
                    };
                    let child_flags = child_prot.to_page_flags();
                    // SAFETY: new_root_pa carries kernel-half clone; va aligned in user range; flags carry USER per `11§5`; pa is the parent's mapped frame whose refcount we just bumped.
                    unsafe {
                        M::map_at(new_root_pa, Va(va), Pa(pa), child_flags, PageSize::P4K);
                    }
                    // If parent's PTE was writable, remap RO so the
                    // next parent write also triggers COW split. The
                    // M::map writes through the active CR3 (parent's
                    // root). M::map's own implementation flushes the
                    // VA on x86; aarch64 may need an explicit flush.
                    if writable {
                        // SAFETY: parent's CR3 is active; same-PA remap
                        // with W bit cleared; pa is current mapping per
                        // translate above.
                        unsafe { M::map(Va(va), Pa(pa), child_flags, PageSize::P4K); }
                        // SAFETY: privileged TLB invalidation is legal at CPL=0/EL1.
                        unsafe { M::flush_va(Va(va)); }
                    }
                }
                va += PAGE_SIZE_BYTES;
            }
        }
        let child = Arc::new(Self {
            vmas: RwLock::new(dst),
            root_pa: new_root_pa,
            brk:     core::sync::atomic::AtomicU64::new(self.brk()),
            brk_max: core::sync::atomic::AtomicU64::new(self.brk_max()),
            teardown: core::sync::atomic::AtomicU64::new(0),
            exe_path: Spinlock::new(self.exe_path.lock().clone()),
        });
        // Linux `anon_vma_fork`: each anonymous VMA in the child
        // inherits the parent's `Arc<AnonVma>` (already cloned by
        // `Vma::clone` above) and adds an rmap chain edge for the
        // child's own (mm, vma_range). Without this, rmap_walk on a
        // shared frame would only enumerate the parent — child PTEs
        // would be invisible to migration / KSM / pageout.
        let child_weak = Arc::downgrade(&child);
        let child_tree = child.vmas.read();
        for cv in child_tree.iter() {
            if let Some(av) = cv.anon_vma.as_ref() {
                av.attach(child_weak.clone(), cv.start.as_u64(), cv.end.as_u64());
            }
        }
        drop(child_tree);
        Ok(child)
    }

    /// Eager-copy fork — pre-COW path retained for callers that
    /// haven't migrated. Prefer `fork_cow_pages` (Linux-equivalent
    /// COW). This path allocates fresh frames for every writable
    /// page in the parent.
    /// # SAFETY: same as `fork_cow_pages`.
    /// # C: O(N_vmas + P_writable_pages) eager-copy.
    pub fn fork_copy_pages<M: MmuOps, F: FnMut() -> Option<u64>>(
        &self,
        new_root_pa: u64,
        hhdm_offset: u64,
        mut alloc_frame: F,
    ) -> KResult<Arc<Self>> {
        let src = self.vmas.read();
        let mut dst = VmaTree::new();
        for vma in src.iter() {
            dst.insert(vma.clone()).map_err(|_| Error::NoMem)?;
        }
        for vma in src.iter() {
            // Copy mapped pages for any writable VMA, regardless of
            // backing. KernelBytes-backed PT_LOAD-with-write segments
            // (BSS + .data) get their own per-task frame on first
            // fault, then accumulate runtime writes; if we don't copy
            // those frames at fork time, the child re-faults from the
            // original read-only Box and silently loses every
            // post-init write the parent made (e.g. svcd's units[]
            // table). Read-only KernelBytes segments (.text, .rodata)
            // can be skipped — both PTs map the same shared Box.
            let writable = vma.prot.contains(VmaProt::WRITE);
            let copy_backing = match vma.backing {
                VmaBacking::Anonymous       => true,
                VmaBacking::KernelBytes { .. } => writable,
                _                           => false,
            };
            if !copy_backing { continue; }
            let mut va = vma.start.as_u64();
            let end = vma.end.as_u64();
            while va < end {
                if let Some((src_pa, _)) = M::translate(Va(va)) {
                    let dst_pa = match alloc_frame() {
                        Some(p) => p,
                        None    => return Err(Error::NoMem),
                    };
                    // SAFETY: src_pa came from the active PT walk; HHDM mirror at hhdm + (src_pa&!0xfff) is read-mapped; dst_pa is fresh PMM frame; non-overlapping copy.
                    unsafe {
                        let s = (hhdm_offset + (src_pa.0 & !0xfff)) as *const u8;
                        let d = (hhdm_offset + dst_pa) as *mut u8;
                        core::ptr::copy_nonoverlapping(s, d, PAGE_SIZE_BYTES as usize);
                    }
                    let pte_flags = vma.prot.to_page_flags();
                    // SAFETY: new_root_pa carries kernel-half clone of master per P2-19; va page-aligned in user range; dst_pa fresh; flags carry USER per `11§5`.
                    unsafe {
                        M::map_at(new_root_pa, Va(va), Pa(dst_pa), pte_flags, PageSize::P4K);
                    }
                }
                va += PAGE_SIZE_BYTES;
            }
        }
        Ok(Arc::new(Self {
            vmas: RwLock::new(dst),
            root_pa: new_root_pa,
            brk:     core::sync::atomic::AtomicU64::new(self.brk()),
            brk_max: core::sync::atomic::AtomicU64::new(self.brk_max()),
            teardown: core::sync::atomic::AtomicU64::new(0),
            exe_path: Spinlock::new(self.exe_path.lock().clone()),
        }))
    }

    /// Number of VMAs currently mapped.
    /// # C: O(1)
    pub fn vma_count(&self) -> usize {
        self.vmas.read().len()
    }

    /// Find the VMA covering `va` and return a snapshot. The returned
    /// `Vma` is independent of the tree (so the caller doesn't pin the
    /// read lock).
    /// # C: O(log N)
    pub fn find_vma(&self, va: UserVirtAddr) -> Option<Vma> {
        let g: RwReadGuard<'_, _, _> = self.vmas.read();
        g.find_containing(va).cloned()
    }

    /// F158: try to extend a `MAP_GROWSDOWN` VMA whose `start` is
    /// just above `va` to cover `va`. Linux uses a 64 KiB guard
    /// distance — a fault below that is treated as a stack
    /// underflow (SIGSEGV) rather than auto-extension. Returns
    /// `true` if the VMA was extended (caller can retry the fault),
    /// `false` if no GROWSDOWN VMA covers the access.
    /// # C: O(log N)
    pub fn try_grow_stack(&self, va: UserVirtAddr) -> bool {
        const STACK_GUARD_GAP: u64 = 64 * 1024;
        let mut tree = self.vmas.write();
        let cur_start = match tree.find_growsdown_above(va, STACK_GUARD_GAP) {
            Some(v) => v.start,
            None    => return false,
        };
        let new_start = UserVirtAddr::new(va.as_u64() & !0xfff)
            .expect("va in user range");
        tree.extend_growsdown_start(cur_start, new_start).is_ok()
    }

    /// Snapshot every VMA into a Vec for callers that need a stable
    /// view (e.g. /proc/self/maps). Read-locks the tree briefly.
    /// # C: O(N) clone
    pub fn snapshot_vmas(&self) -> alloc::vec::Vec<Vma> {
        let g: RwReadGuard<'_, _, _> = self.vmas.read();
        g.iter().cloned().collect()
    }

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
        validate_len(len)?;
        let len_u64 = len as u64;

        let mut tree = self.vmas.write();

        let start_va = if fixed {
            let h = hint.ok_or(Error::Inval)?;
            validate_aligned(h)?;
            let end = end_of(h, len_u64)?;
            // MAP_FIXED clears overlap before placing per `11§6`.
            tree.remove_range(h, end);
            h
        } else {
            // Try the hint first.
            let from_hint = match hint {
                Some(h) if is_aligned(h) => {
                    end_of(h, len_u64).ok().and_then(|end| {
                        if hole_clear(&tree, h, end) { Some(h) } else { None }
                    })
                }
                _ => None,
            };
            match from_hint {
                Some(h) => h,
                None => find_hole(&tree, len_u64).ok_or(Error::NoMem)?,
            }
        };

        let end_va = end_of(start_va, len_u64)?;
        tree.insert(Vma::new(start_va, end_va, prot, flags, backing))
            .map_err(|_| Error::Inval)?;
        Ok(start_va)
    }

    /// Unmap any VMAs (or VMA fragments) intersecting `[addr, addr+len)`.
    /// Per `11§6`. PT walk + TLB shootdown + page free are out of scope
    /// here; this is the VMA-side bookkeeping only.
    /// # C: O(K + log N)
    pub fn munmap(&self, addr: UserVirtAddr, len: usize) -> KResult<()> {
        validate_len(len)?;
        validate_aligned(addr)?;
        let end = end_of(addr, len as u64)?;
        let mut tree = self.vmas.write();
        let _ = tree.remove_range(addr, end);
        Ok(())
    }

    /// Change the protection bits over `[addr, addr+len)`. Holes are
    /// rejected with `Inval` per `11§6` ("walk affected VMAs"). VMA
    /// tree is updated; the kernel-side caller (sys_mprotect) walks
    /// affected PT leaves via `mprotect_pages` to flush stale PTEs.
    /// # C: O(K log N)
    pub fn mprotect(
        &self,
        addr: UserVirtAddr,
        len: usize,
        prot: VmaProt,
    ) -> KResult<()> {
        validate_len(len)?;
        validate_aligned(addr)?;
        let end = end_of(addr, len as u64)?;
        let mut tree = self.vmas.write();
        tree.mprotect_range(addr, end, prot)
    }

    /// Audit hook: invariant 1 (non-overlap, `11§2`). Used by tests
    /// and by `debug-vmm` per `11§13`.
    /// # C: O(N)
    pub fn audit(&self) -> KResult<()> {
        self.vmas.read().audit_no_overlap()
    }

    /// Demand-fault handler per `11§5`. v1 covers `NotPresent` of
    /// an `Anonymous` VMA: zero-fill a fresh frame from `alloc_frame`,
    /// install the leaf via `M::map`, return Ok. Other variants land
    /// in subsequent PRs:
    ///
    /// - `NotPresent` of a `File`-backed VMA: needs page cache (`16`).
    /// - `Protection` write on a private writable VMA: COW per `11§5`
    ///   second match arm; needs `PageMeta::refcount` per `11§8`.
    ///
    /// Returns `Ok(())` when the PTE is installed (caller should
    /// retry the faulting instruction). Returns `Err(EFAULT)` when
    /// no VMA covers `va` or the VMA's prot rejects the access —
    /// upstream raises SIGSEGV per `11§5`.
    ///
    /// `hhdm_offset` is the kernel HHDM base for zero-filling the
    /// freshly allocated frame (we write `va + hhdm_offset .. + 4096`
    /// to clear it before exposing to user).
    ///
    /// # SAFETY: `M` is the live per-arch MmuOps with PMM + HHDM
    /// state initialised; `alloc_frame` returns physically-valid
    /// page-aligned PFNs from PMM. Caller's fault context already
    /// disabled IRQs; AS read-lock acquisition here is safe (no
    /// recursion).
    /// # C: O(log N) VMA lookup + O(1) frame zero + O(walk depth) map
    /// # Ctx: fault, IRQ-off
    /// Back-compat wrapper: handle_page_fault without per-page
    /// refcount awareness. Always copies on Protection-write
    /// (correct for refcount==1 owner-only writes; suboptimal for
    /// COW-shared frames where a refcount-aware handler could
    /// short-circuit the copy when count==1). Real COW-aware path:
    /// `handle_page_fault_cow`.
    /// # SAFETY: same as `handle_page_fault_cow`.
    /// # C: same as `handle_page_fault_cow`.
    pub unsafe fn handle_page_fault<M: MmuOps, F: FnMut() -> Option<u64>>(
        &self,
        va: UserVirtAddr,
        fault: FaultKind,
        hhdm_offset: u64,
        alloc_frame: F,
    ) -> KResult<()> {
        // SAFETY: forward to COW path with no-op refcount/dec hooks.
        unsafe {
            self.handle_page_fault_cow::<M, _, _, _>(
                va, fault, hhdm_offset, alloc_frame,
                |_pa: u64| 2u32, // pretend always shared so the
                                  // copy path runs (matches old
                                  // behaviour: copy on Protection-write).
                |_pa: u64| {},
            )
        }
    }

    /// COW-aware page-fault handler. Adds two callbacks to the
    /// classic resolver:
    ///   - `frame_refcount(pa) -> u32`: per-PA struct-page refcount.
    ///     If 1, the faulting AS is the sole owner — flip the W bit
    ///     in place (no copy).
    ///   - `dec_ref(pa)`: drop one reference (used when COW splits a
    ///     shared frame; the faulting AS now points at a fresh frame
    ///     and no longer references the shared one).
    /// # SAFETY: same as `handle_page_fault`.
    /// # C: O(log N_vmas) + O(1) on Anonymous; +O(page) on COW-copy.
    pub unsafe fn handle_page_fault_cow<M, A, RC, DR>(
        &self,
        va: UserVirtAddr,
        fault: FaultKind,
        hhdm_offset: u64,
        alloc_frame: A,
        frame_refcount: RC,
        dec_ref: DR,
    ) -> KResult<()>
    where
        M:  MmuOps,
        A:  FnMut() -> Option<u64>,
        RC: FnMut(u64) -> u32,
        DR: FnMut(u64),
    {
        // Forward to the rmap-aware variant with no-op rmap hooks.
        // Hosted tests + boot-only callers that don't need page->mapping
        // bookkeeping go through this thin wrapper; the kernel's
        // user-fault dispatcher uses `handle_page_fault_cow_rmap`.
        // SAFETY: forwarded preconditions per `handle_page_fault_cow_rmap`.
        unsafe {
            self.handle_page_fault_cow_rmap::<M, _, _, _, _, _>(
                va, fault, hhdm_offset,
                alloc_frame, frame_refcount, dec_ref,
                |_pa, _av, _idx| {},
                |_pa| {},
            )
        }
    }

    /// rmap-aware COW + demand-page handler. Identical to
    /// `handle_page_fault_cow` but invokes `set_rmap` after every
    /// successful frame install so the kernel side can record the
    /// new (page → AnonVma, page_index) edge per Linux
    /// `page_add_anon_rmap`. Hosted tests pin no-op `set_rmap`.
    /// # SAFETY: per `handle_page_fault_cow`.
    /// # C: O(N_vmas) on lookup + O(walk) on install.
    pub unsafe fn handle_page_fault_cow_rmap<M, A, RC, DR, SR, IR>(
        &self,
        va: UserVirtAddr,
        fault: FaultKind,
        hhdm_offset: u64,
        mut alloc_frame: A,
        mut frame_refcount: RC,
        mut dec_ref: DR,
        mut set_rmap: SR,
        mut inc_ref: IR,
    ) -> KResult<()>
    where
        M:  MmuOps,
        A:  FnMut() -> Option<u64>,
        RC: FnMut(u64) -> u32,
        DR: FnMut(u64),
        SR: FnMut(u64, &Arc<crate::AnonVma>, u32),
        IR: FnMut(u64),
    {
        // Protection write to a writable VMA — CoW-style
        // upgrade. Three causes hit this:
        //   (a) eager-copy at fork installed the leaf with the
        //       VMA's prot, but the prot translation cleared
        //       the W bit due to a to_page_flags quirk —
        //       resolved by re-installing fresh with the same
        //       flags.
        //   (b) shared KernelBytes leaf (loader installed the
        //       RO master Box for a PT_LOAD with W flag) — the
        //       child needs its own writable copy of the page.
        //   (c) future real CoW — a child wrote to a page the
        //       parent shared at fork time. Same handler works:
        //       allocate fresh frame, copy current bytes, install
        //       writable PTE.
        // VMA-prot mismatch (write to RO VMA) → Err(Inval) →
        // upstream EFAULT or SIGSEGV per fault context.
        if let FaultKind::Protection { access: FaultAccess::Write } = fault {
            let vma = match self.vmas.read().find_containing(va) {
                Some(v) => v.clone(),
                None    => return Err(Error::Inval),
            };
            if !vma.prot.contains(VmaProt::WRITE) {
                return Err(Error::Inval);
            }
            let va_page = va.as_u64() & !(PAGE_SIZE_BYTES - 1);
            // SAFETY: va_page is in user-half; M::translate reads the active PT for the running task's CR3 / TTBR0; vma is the live snapshot for `va`.
            let cur = unsafe { M::translate(Va(va_page)) };
            // COW fast path: if we're the sole owner of the frame
            // (refcount==1), no copy needed — flip the W bit in
            // place. Linux `mm/memory.c` `wp_page_copy` short-circuit.
            if let Some((src_pa, _)) = cur {
                let pa = src_pa.0 & !0xfff;
                if frame_refcount(pa) <= 1 {
                    let pte_flags = vma.prot.to_page_flags();
                    // SAFETY: same-PA remap with W bit set; no other
                    // AS holds this frame per refcount==1; flush_va
                    // ensures hardware re-walks.
                    unsafe {
                        M::map(Va(va_page), Pa(pa), pte_flags, PageSize::P4K);
                        M::flush_va(Va(va_page));
                    }
                    let _ = hhdm_offset;
                    return Ok(());
                }
            }
            // Shared frame (refcount > 1) or no current mapping:
            // alloc fresh + copy + install writable + dec_ref shared.
            let new_pa = alloc_frame().ok_or(Error::NoMem)?;
            // SAFETY: dst is the freshly-allocated PMM frame's HHDM mirror; src is the previously-mapped frame's HHDM mirror (when present); 4 KiB non-overlapping copy. If no prior leaf was present we zero the new page.
            unsafe {
                let dst = (hhdm_offset + new_pa) as *mut u8;
                if let Some((src_pa, _)) = cur {
                    let src = (hhdm_offset + (src_pa.0 & !0xfff)) as *const u8;
                    core::ptr::copy_nonoverlapping(src, dst, PAGE_SIZE_BYTES as usize);
                } else {
                    core::ptr::write_bytes(dst, 0, PAGE_SIZE_BYTES as usize);
                }
            }
            let pte_flags = vma.prot.to_page_flags();
            // SAFETY: va_page page-aligned in user-half; new_pa fresh PMM frame; flags carry USER + WRITE since vma.prot.WRITE checked above.
            unsafe {
                M::map(Va(va_page), Pa(new_pa), pte_flags, PageSize::P4K);
                M::flush_va(Va(va_page));
            }
            // F156-rmap: bind new private page to the VMA's anon_vma
            // family with the page-offset index per Linux
            // `page_add_anon_rmap`. Caller's `set_rmap` is the kernel
            // adapter that bumps the Arc and stashes it in PageMeta.
            if let Some(av) = vma.anon_vma.as_ref() {
                let idx = ((va_page - vma.start.as_u64()) / PAGE_SIZE_BYTES) as u32;
                set_rmap(new_pa, av, idx);
            }
            // F157: drop our reference to the shared frame. If its
            // refcount hits zero (other AS already unmapped), the
            // dec_ref callback chains into pmm::setup::dec_and_maybe_free
            // and returns the page to the allocator.
            if let Some((src_pa, _)) = cur {
                dec_ref(src_pa.0 & !0xfff);
            }
            return Ok(());
        }
        let access = match fault {
            FaultKind::NotPresent { access } => access,
            FaultKind::Protection { .. }     => return Err(Error::NotImplemented),
        };

        // Per spec §5: read VMA tree (concurrent with other faults).
        let g = self.vmas.read();
        let vma = match g.find_containing(va) {
            Some(v) => v,
            None    => return Err(Error::Inval),    // EFAULT upstream
        };
        if !vma.permits(access) {
            return Err(Error::Inval);                // EFAULT upstream
        }

        match &vma.backing {
            VmaBacking::Anonymous => {
                let pa = alloc_frame().ok_or(Error::NoMem)?;
                // Zero-fill via HHDM kernel mirror per `11§5` "zero_or_loaded".
                // SAFETY: pa is a freshly-allocated PMM frame; HHDM
                // mirror at `hhdm_offset + pa` is mapped writable in
                // the kernel's page tables (Limine-installed); 4096
                // bytes is the page granule.
                unsafe {
                    let dst = (hhdm_offset + pa) as *mut u8;
                    core::ptr::write_bytes(dst, 0, PAGE_SIZE_BYTES as usize);
                }
                let va_page = va.as_u64() & !(PAGE_SIZE_BYTES - 1);
                let pte_flags = vma.prot.to_page_flags();
                // SAFETY: va_page is the page-aligned faulting user-half VA per find_containing; pa is a fresh PMM frame; flags carry USER for the leaf U bit per `11§5` to_pte_flags; MmuOps state initialised by the live per-arch impl.
                unsafe { M::map(Va(va_page), Pa(pa), pte_flags, PageSize::P4K); }
                // F156-rmap: bind the freshly-allocated anonymous
                // page to its VMA family per `page_add_anon_rmap`.
                if let Some(av) = vma.anon_vma.as_ref() {
                    let idx = ((va_page - vma.start.as_u64()) / PAGE_SIZE_BYTES) as u32;
                    set_rmap(pa, av, idx);
                }
                Ok(())
            }
            VmaBacking::KernelBytes { data, off: backing_off } => {
                // ELF-loader-style demand-fault path per docs/31 §4
                // step 3: copy the file-backed bytes for this page
                // into a fresh PMM frame; bytes past the slice length
                // (BSS tail of a PT_LOAD with `p_memsz > p_filesz`)
                // are zero-filled. `backing_off` lets sub-range VMAs
                // (from `clone_subrange`) start mid-Arc without
                // copying the underlying buffer.
                let pa = alloc_frame().ok_or(Error::NoMem)?;
                let va_page = va.as_u64() & !(PAGE_SIZE_BYTES - 1);
                let vma_off = (va_page - vma.start.as_u64()) as usize;
                let off = backing_off.saturating_add(vma_off);
                let page = PAGE_SIZE_BYTES as usize;
                let data_slice: &[u8] = &data[..];
                // SAFETY: pa is a freshly-allocated PMM frame; HHDM
                // mirror at hhdm_offset+pa is mapped writable; we
                // own the full page exclusively until M::map below
                // makes it user-visible.
                unsafe {
                    let dst = (hhdm_offset + pa) as *mut u8;
                    if off >= data_slice.len() {
                        // Entirely BSS (past file-backed extent).
                        core::ptr::write_bytes(dst, 0, page);
                    } else {
                        let avail = (data_slice.len() - off).min(page);
                        // SAFETY: src is a valid Arc<[u8]> slice covering [off..off+avail]; dst owns `page` bytes; non-overlapping.
                        core::ptr::copy_nonoverlapping(
                            data_slice.as_ptr().add(off), dst, avail,
                        );
                        if avail < page {
                            // SAFETY: dst+avail is within the freshly-allocated frame; tail zero-fills the BSS portion of this page.
                            core::ptr::write_bytes(dst.add(avail), 0, page - avail);
                        }
                    }
                }
                let pte_flags = vma.prot.to_page_flags();
                // SAFETY: va_page page-aligned per find_containing; pa is fresh PMM frame; flags carry USER per `11§5`.
                unsafe { M::map(Va(va_page), Pa(pa), pte_flags, PageSize::P4K); }
                Ok(())
            }
            VmaBacking::File { backing, off: backing_off } => {
                // File-backed demand-fault per `11§5` + `17§5`. The
                // backing impl reads through the page cache; bytes
                // past file end zero-fill.
                let pa = alloc_frame().ok_or(Error::NoMem)?;
                let va_page = va.as_u64() & !(PAGE_SIZE_BYTES - 1);
                let vma_off = (va_page - vma.start.as_u64()) as u64;
                let file_off = backing_off.saturating_add(vma_off);
                let page = PAGE_SIZE_BYTES as usize;
                // SAFETY: pa is a freshly-allocated PMM frame; HHDM mirror at hhdm_offset+pa is mapped writable; full page owned exclusively until M::map below makes it user-visible.
                unsafe {
                    let dst = (hhdm_offset + pa) as *mut u8;
                    core::ptr::write_bytes(dst, 0, page);
                    let slice = core::slice::from_raw_parts_mut(dst, page);
                    let _ = backing.read_at(file_off, slice);
                }
                let pte_flags = vma.prot.to_page_flags();
                // SAFETY: va_page page-aligned per find_containing; pa is fresh PMM frame; flags carry USER per `11§5`.
                unsafe { M::map(Va(va_page), Pa(pa), pte_flags, PageSize::P4K); }
                Ok(())
            }
            VmaBacking::KernelFrame { pa } => {
                // Shared kernel frame (vvar); inc_ref balances AS-drop dec.
                let va_page = va.as_u64() & !(PAGE_SIZE_BYTES - 1);
                let pte_flags = vma.prot.to_page_flags();
                // SAFETY: pa is a kernel-owned frame whose lifetime exceeds every user mapping; va_page is page-aligned per find_containing; flags carry USER per `11§5`.
                unsafe { M::map(Va(va_page), Pa(*pa), pte_flags, PageSize::P4K); }
                inc_ref(*pa);
                Ok(())
            }
            VmaBacking::Special => Err(Error::NotImplemented),
        }
    }
}

#[inline]
fn is_aligned(va: UserVirtAddr) -> bool {
    va.as_u64() % PAGE_SIZE_BYTES == 0
}

#[inline]
fn validate_aligned(va: UserVirtAddr) -> KResult<()> {
    if is_aligned(va) { Ok(()) } else { Err(Error::Inval) }
}

#[inline]
fn validate_len(len: usize) -> KResult<()> {
    if len == 0 || (len as u64) % PAGE_SIZE_BYTES != 0 {
        Err(Error::Inval)
    } else {
        Ok(())
    }
}

#[inline]
fn end_of(start: UserVirtAddr, len: u64) -> KResult<UserVirtAddr> {
    let end = start.as_u64().checked_add(len).ok_or(Error::Inval)?;
    UserVirtAddr::new(end).ok_or(Error::Inval)
}

/// True iff `[start, end)` overlaps no existing VMA.
/// # C: O(N)
fn hole_clear(tree: &VmaTree, start: UserVirtAddr, end: UserVirtAddr) -> bool {
    let s = start.as_u64();
    let e = end.as_u64();
    for v in tree.iter() {
        if v.start.as_u64() >= e { break; }
        if v.end.as_u64()   >  s { return false; }
    }
    true
}

/// Top-down hole search starting at `MMAP_TOP`, descending toward
/// `MIN_USER_VA`. Mirrors Linux `arch_get_unmapped_area_topdown` —
/// anonymous mmap with no hint lands in the high-address mmap arena,
/// not at low addresses where userspace doesn't expect them
/// (programs assume mmap returns strictly above `.text`). The search
/// returns the *highest* candidate `cand` in `[MIN_USER_VA, MMAP_TOP)`
/// such that `[cand, cand+len)` is hole.
/// # C: O(N) over VMAs (one ascending walk + reverse over a small Vec)
fn find_hole(tree: &VmaTree, len: u64) -> Option<UserVirtAddr> {
    if len == 0 || len > MMAP_TOP - MIN_USER_VA { return None; }
    // Snapshot VMA spans clipped to [MIN_USER_VA, MMAP_TOP) into a
    // Vec we can reverse-iterate.
    let mut vmas: alloc::vec::Vec<(u64, u64)> = alloc::vec::Vec::new();
    for v in tree.iter() {
        let s = v.start.as_u64().max(MIN_USER_VA);
        let e = v.end.as_u64().min(MMAP_TOP);
        if e > s { vmas.push((s, e)); }
    }
    // Walk gaps from highest to lowest.
    let mut top = MMAP_TOP;
    for &(s, e) in vmas.iter().rev() {
        // Gap is [e, top). If it fits, place at top-len (highest).
        if top.saturating_sub(e) >= len {
            return UserVirtAddr::new(top - len);
        }
        top = s;
    }
    // Final gap: [MIN_USER_VA, top).
    if top.saturating_sub(MIN_USER_VA) >= len {
        UserVirtAddr::new(top - len)
    } else {
        None
    }
}

impl AddressSpace {
    /// `mremap` per `mremap(2)`. Tier-2 work fn per `docs/53§3`.
    /// Returns the new mapping address. Behaviour:
    ///   new_size < old_size  → shrink in place, drop tail
    ///   new_size == old_size → no-op, return old
    ///   new_size > old_size  → copy to a new region (MAYMOVE/FIXED)
    /// # C: O(VMA-tree ops + min(old,new) byte copy)
    pub fn mremap(
        &self,
        old: UserVirtAddr,
        old_size: usize,
        new_size: usize,
        maymove: bool,
        fixed: bool,
        new_addr: Option<UserVirtAddr>,
    ) -> KResult<UserVirtAddr> {
        if old.as_u64() == 0 || (old.as_u64() & 0xFFF) != 0 || new_size == 0 {
            return Err(Error::Inval);
        }
        // Shrink: drop the tail.
        if new_size < old_size {
            let drop_va = old.as_u64() + new_size as u64;
            if let Some(da) = UserVirtAddr::new(drop_va) {
                let _ = self.munmap(da, old_size - new_size);
            }
            return Ok(old);
        }
        // Same size: no-op.
        if new_size == old_size && !fixed {
            return Ok(old);
        }
        // Grow path. Need MAYMOVE or FIXED.
        if !maymove && !fixed { return Err(Error::NoMem); }
        let hint = if fixed { new_addr.or(Some(old)) } else { None };
        let new_va = self.mmap(
            hint, new_size,
            VmaProt::READ | VmaProt::WRITE,
            VmaFlags::ANONYMOUS | VmaFlags::PRIVATE,
            VmaBacking::Anonymous,
            fixed,
        )?;
        // Best-effort byte copy.
        let copy_len = core::cmp::min(old_size, new_size);
        let dst = new_va.as_u64();
        // SAFETY: both regions live in caller's AS, validated by mmap/munmap; CPL=0 reads/writes through caller's PT.
        unsafe {
            for i in 0..copy_len {
                let v = core::ptr::read_volatile((old.as_u64() + i as u64) as *const u8);
                core::ptr::write_volatile((dst + i as u64) as *mut u8, v);
            }
        }
        // Unmap the old region.
        let _ = self.munmap(old, old_size);
        Ok(new_va)
    }
}
