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
use alloc::sync::{Arc, Weak};
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

/// Fallback mmap arena top for ASes whose `mmap_base` was never
/// set (boot anchor, hosted tests). Production ASes get their
/// `mmap_base` programmed at execve time from `arch_pick_mmap_base`
/// (= `stack_top - rlim_stack - MMAP_BASE_GAP`) so this constant is
/// only the safe-default for non-user contexts. We keep it well
/// below USER_VA_END so any unintentional use still has stack room.
pub const MMAP_TOP: u64 = USER_VA_END - 0x100_0000;

/// Linux `STACK_RND_MASK`/`mmap_base` gap below the top of the
/// stack reservation, per `arch/x86/mm/mmap.c arch_pick_mmap_base`.
/// Linux uses 128 MiB plus a randomised slice; v1 uses a fixed
/// 128 MiB (no ASLR yet) so the mmap arena starts that far below
/// the bottom of the rlim_stack reservation. Result: stack can
/// grow up to RLIMIT_STACK without crossing into the mmap arena,
/// and the mmap arena has gigabytes of room beneath it.
pub const MMAP_BASE_GAP: u64 = 128 * 1024 * 1024;

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
    /// Top of the anon-mmap arena per Linux `mm_struct::mmap_base`
    /// (`arch_pick_mmap_base`). Set at exec time to
    /// `stack_top - rlim_stack - GAP` so anonymous mmaps grow
    /// top-down from a position that leaves the stack room to
    /// expand up to RLIMIT_STACK. Default 0 means "not initialised"
    /// — `find_hole` falls back to the legacy `MMAP_TOP` constant
    /// (used by boot-anchor AS + hosted tests).
    mmap_base: core::sync::atomic::AtomicU64,
    /// A4-rmap: this AS's own `Weak<Self>`, captured at construction via
    /// `Arc::new_cyclic`. Linux's `vma->vm_mm` back-pointer analogue:
    /// `mmap` uses it to attach the owning VMA's anon_vma chain edge so
    /// `rmap_walk_anon` can enumerate the originating mapping (GAP A4-1
    /// — previously only fork children attached edges, leaving a
    /// never-forked anon page invisible to the rmap walk). `munmap` /
    /// `mprotect` use it to detach + re-attach split fragments.
    self_weak: Weak<Self>,
    /// Linux `mm_cpumask` analogue: bit `c` set ⇔ logical CPU `c` may
    /// hold this mm's user-half TLB entries (it has the root in CR3 /
    /// TTBR0, or is lazy-TLB on it). The context-switch path sets this
    /// CPU's bit BEFORE the CR3 reload that loads the mm and clears it
    /// AFTER the reload that leaves it; `execve` does the same around its
    /// direct activate. The cross-CPU TLB shootdown targets ONLY these
    /// CPUs (`flush_tlb_others`), not every online CPU — over-inclusion
    /// is a harmless spurious flush, under-inclusion is corruption, so
    /// the set/clear ordering (mark-before-activate, clear-after-activate)
    /// is load-bearing. `u64` exactly covers `cpu::MAX_CPUS == 64`.
    cpumask: core::sync::atomic::AtomicU64,
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
        Ok(Arc::new_cyclic(|w| Self {
            vmas: RwLock::new(VmaTree::new()),
            root_pa,
            brk:     core::sync::atomic::AtomicU64::new(0),
            brk_max: core::sync::atomic::AtomicU64::new(0),
            teardown: core::sync::atomic::AtomicU64::new(0),
            exe_path: Spinlock::new(None),
            mmap_base: core::sync::atomic::AtomicU64::new(0),
            self_weak: w.clone(),
            // Fresh/forked AS: no CPU has loaded it yet (Linux clears
            // mm_cpumask on mm init; the activating CPU sets its bit).
            cpumask: core::sync::atomic::AtomicU64::new(0),
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

    /// Per-AS mmap arena top per Linux `mm_struct::mmap_base`.
    /// `execve` computes this from RLIMIT_STACK + a fixed GAP per
    /// `arch_pick_mmap_base`. `find_hole` searches downward from
    /// it. Zero = uninitialised; callers fall back to the legacy
    /// global `MMAP_TOP` const.
    /// # C: O(1)
    pub fn set_mmap_base(&self, base: u64) {
        self.mmap_base.store(base, core::sync::atomic::Ordering::Release);
    }
    /// # C: O(1)
    pub fn mmap_base(&self) -> u64 {
        self.mmap_base.load(core::sync::atomic::Ordering::Acquire)
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

    /// Snapshot of this mm's `cpumask` (Linux `mm_cpumask`): the set of
    /// logical CPUs that may hold its user TLB entries. The TLB-shootdown
    /// sender intersects this with the online set to target only the CPUs
    /// that actually need invalidating.
    /// # C: O(1)
    pub fn cpumask(&self) -> u64 {
        self.cpumask.load(core::sync::atomic::Ordering::Acquire)
    }

    /// Set logical CPU `cpu`'s bit. Called BEFORE the CR3/TTBR0 reload
    /// that loads this mm on `cpu` (context switch / execve). Over-marking
    /// only costs a spurious IPI; the strict before-activate ordering
    /// guarantees a peer shootdown never skips a CPU that has the mm.
    /// # C: O(1)
    pub fn mark_cpu(&self, cpu: usize) {
        if cpu < 64 {
            self.cpumask.fetch_or(1u64 << cpu, core::sync::atomic::Ordering::AcqRel);
        }
    }

    /// Clear logical CPU `cpu`'s bit. Called AFTER the CR3/TTBR0 reload
    /// that leaves this mm on `cpu` (the reload flushes that CPU's old
    /// user TLB first, so clearing afterwards is sound). Must be gated on
    /// an actual switch to a DIFFERENT real root — clearing while the CPU
    /// still holds the root in CR3 (lazy-TLB) reintroduces the
    /// write-while-shared / use-after-free corruption.
    /// # C: O(1)
    pub fn clear_cpu(&self, cpu: usize) {
        if cpu < 64 {
            self.cpumask.fetch_and(!(1u64 << cpu), core::sync::atomic::Ordering::AcqRel);
        }
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
        Ok(Arc::new_cyclic(|w| Self {
            vmas: RwLock::new(dst),
            root_pa: new_root_pa,
            brk:     core::sync::atomic::AtomicU64::new(self.brk()),
            brk_max: core::sync::atomic::AtomicU64::new(self.brk_max()),
            teardown: core::sync::atomic::AtomicU64::new(0),
            exe_path: Spinlock::new(self.exe_path.lock().clone()),
            mmap_base: core::sync::atomic::AtomicU64::new(self.mmap_base()),
            self_weak: w.clone(),
            // Fresh/forked AS: no CPU has loaded it yet (Linux clears
            // mm_cpumask on mm init; the activating CPU sets its bit).
            cpumask: core::sync::atomic::AtomicU64::new(0),
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
            // MAP_SHARED VMAs are NOT copy-on-write: parent and child keep
            // writing the SAME frame (Linux shmem / MAP_SHARED|MAP_ANON). The
            // child maps it writable and the parent stays writable — no W-strip,
            // no COW split. Critical now that tmpfs/memfd MAP_SHARED aliases real
            // frames: COW-splitting them on fork would silently fork the journal
            // page away from journald's shared view.
            // REVERTED fix #8: keeping VMAs writable-across-fork for the SHARED
            // flag caused WRITE-WHILE-SHARED corruption — a private page stayed
            // writable in both parent and child, so parallel-forked children
            // (systemd's generators) clobbered each other's memory (garbage
            // syscall args, futex wedge). PROOF: forcing COW for all VMAs made
            // the garbage corruption vanish (no PID1 crash either). Linux maps
            // EVERY fork-shared anon/private page READ-ONLY and copies on first
            // write; genuine MAP_SHARED needs a real shared backing object (the
            // tmpfs/memfd path, fix #7), NOT in-place writable COW frames.
            //
            // CORRECTED (refcount-safe, Linux mm/memory.c): the blanket
            // `shared=false` ALSO caught genuine inode-backed MAP_SHARED
            // (memfd/tmpfs File VMAs whose pages ARE the inode's shared
            // frames). Forcing those through COW W-stripped the shared frame
            // and copied it private on first write, so a forked peer silently
            // froze its shared view at fork time and never saw later writes
            // (lost-write / stale-read corruption — a random journald/systemd
            // shared-memfd page read garbage -> SIGSEGV). Linux DOES share
            // these across fork (one backing object, no anon_vma, no COW).
            // Restrict the share decision to File-backed SHARED VMAs: anon
            // (incl. MAP_SHARED|ANON, which we lack a shmem backing for) stays
            // on the COW path so the reverted anon write-while-shared bug stays
            // fixed; only true file backings keep their frame writable+shared.
            // Refcount is unaffected — `inc_ref` + `map_at` below run for both
            // branches; `shared` only gates the W-strip + parent RO-remap.
            let shared = vma.flags.contains(VmaFlags::SHARED)
                && matches!(vma.backing, VmaBacking::File { .. });
            // B18 fix: COW-share Anonymous + KernelBytes + File-backed
            // frames. File backings are required so child processes
            // inherit their parent's mmap'd shared-library mappings
            // (libpam.so, libc.so, …) — Linux mm/memory.c semantic.
            // Skipping File backings caused pam_unix's helper-fork
            // child to SIGSEGV the moment it called any libpam.so
            // function: child's PT had no entries for the libpam.so
            // VMA range. Read-only File pages (.text/.rodata) stay
            // shared forever; writable File pages (.data) get the
            // same RO-remap + COW-on-first-write treatment as anon.
            let share_pages = matches!(
                vma.backing,
                VmaBacking::Anonymous
                | VmaBacking::KernelBytes { .. }
                | VmaBacking::File { .. }
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
                    let child_prot = if writable && !shared {
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
                    if writable && !shared {
                        // SAFETY: parent's CR3 is active; same-PA remap
                        // with W bit cleared; pa is current mapping per
                        // translate above.
                        unsafe { M::map(Va(va), Pa(pa), child_flags, PageSize::P4K); }
                        // SAFETY: privileged TLB invalidation is legal at CPL=0/EL1.
                        unsafe { M::flush_va(Va(va)); }
                        // debug-cow: this frame is now RO-shared between
                        // parent + child. Snapshot its content; any later
                        // change before a COW copy = a peer wrote a RO-shared
                        // page (stale TLB / wrong frame). No-op when feature
                        // off. ANON → [COW-CORRUPT]; FILE-private (shared-lib
                        // .data/GOT/.bss W-stripped at fork) → [FILE-CORRUPT].
                        if matches!(vma.backing, VmaBacking::Anonymous) {
                            crate::debug_cow::record(pa, _hhdm_offset);
                        } else if matches!(vma.backing, VmaBacking::File { .. }) {
                            crate::debug_cow::record_file(pa, _hhdm_offset);
                        }
                    }
                }
                va += PAGE_SIZE_BYTES;
            }
        }
        // SMP TLB coherence (`20§5`): we just write-protected the parent's
        // own PTEs (the W-strip above) on THIS CPU only. Other CPUs running
        // a peer thread of the SAME mm still hold the old WRITABLE entries in
        // their TLB and would write straight into frames now COW-shared with
        // the child — write-while-shared corruption invisible to refcount.
        // x86 invlpg is local-only (no hardware broadcast like aarch64
        // tlbi-is), so broadcast a full remote flush. No-op on UP / aarch64 /
        // hosted. One full flush beats a per-page IPI across the whole AS.
        // Target only the CPUs that have THIS mm loaded (the parent's
        // cpumask) per Linux flush_tlb_others — not every online CPU.
        hal::tlb::shootdown_others_all(self.cpumask());
        let child = Arc::new_cyclic(|w| Self {
            vmas: RwLock::new(dst),
            root_pa: new_root_pa,
            brk:     core::sync::atomic::AtomicU64::new(self.brk()),
            brk_max: core::sync::atomic::AtomicU64::new(self.brk_max()),
            teardown: core::sync::atomic::AtomicU64::new(0),
            exe_path: Spinlock::new(self.exe_path.lock().clone()),
            mmap_base: core::sync::atomic::AtomicU64::new(self.mmap_base()),
            self_weak: w.clone(),
            // Fresh/forked AS: no CPU has loaded it yet (Linux clears
            // mm_cpumask on mm init; the activating CPU sets its bit).
            cpumask: core::sync::atomic::AtomicU64::new(0),
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
        Ok(Arc::new_cyclic(|w| Self {
            vmas: RwLock::new(dst),
            root_pa: new_root_pa,
            brk:     core::sync::atomic::AtomicU64::new(self.brk()),
            brk_max: core::sync::atomic::AtomicU64::new(self.brk_max()),
            teardown: core::sync::atomic::AtomicU64::new(0),
            exe_path: Spinlock::new(self.exe_path.lock().clone()),
            mmap_base: core::sync::atomic::AtomicU64::new(self.mmap_base()),
            self_weak: w.clone(),
            // Fresh/forked AS: no CPU has loaded it yet (Linux clears
            // mm_cpumask on mm init; the activating CPU sets its bit).
            cpumask: core::sync::atomic::AtomicU64::new(0),
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

    /// Try to extend a `MAP_GROWSDOWN` VMA. D32: cap = 8 MiB
    /// (Linux RLIMIT_STACK default); was 64 KiB which SIGSEGV'd
    /// musl's wide init frames.
    /// # C: O(log N)
    pub fn try_grow_stack(&self, va: UserVirtAddr) -> bool {
        const STACK_GROW_MAX: u64 = 8 * 1024 * 1024;
        let mut tree = self.vmas.write();
        let cur_start = match tree.find_growsdown_above(va, STACK_GROW_MAX) {
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
                None => {
                    let top = match self.mmap_base.load(core::sync::atomic::Ordering::Acquire) {
                        0 => MMAP_TOP,
                        v => v,
                    };
                    find_hole(&tree, len_u64, top).ok_or(Error::NoMem)?
                },
            }
        };

        let end_va = end_of(start_va, len_u64)?;
        let is_anon_vma = matches!(backing, VmaBacking::Anonymous);
        tree.insert(Vma::new(start_va, end_va, prot, flags, backing))
            .map_err(|_| Error::Inval)?;
        // A4-rmap (GAP A4-1): attach the owning-AS chain edge for the
        // newly mapped range. Linux `anon_vma_prepare`: the originating
        // mapping MUST be on the chain, or `rmap_walk_anon` enumerates
        // zero targets for a never-forked page (the AS that owns it is
        // invisible). Previously only `fork_cow_pages` attached edges,
        // and only for the child — the parent self-edge was attached
        // nowhere. Bind to the VMA actually in the tree at `start_va`
        // (which may have absorbed `[start_va,end_va)` via an abutting
        // merge), attaching only the newly added sub-range so a merged
        // family never gets an overlapping (double-counting) edge.
        if is_anon_vma {
            if let Some(av) = tree.find_containing(start_va).and_then(|v| v.anon_vma.clone()) {
                av.attach(self.self_weak.clone(), start_va.as_u64(), end_va.as_u64());
            }
        }
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
        // A4-rmap (GAP A4-2): detach the anon_vma chain edges of every
        // VMA the unmap touches (their pre-split ranges), then re-attach
        // the surviving fragments' new ranges after the tree mutation.
        // Linux `unlink_anon_vmas` / `__split_vma` keep the chain in
        // lock-step with the VMA tree; lazy weak-pruning alone leaves
        // stale wide edges (still PTE-checked by the walker, so this is
        // hygiene, not a soundness fix — but it keeps the chain bounded).
        self.rmap_resplit(&mut tree, addr.as_u64(), end.as_u64(), |t, s, e| { let _ = t.remove_range(
            UserVirtAddr::new(s).expect("uva"), UserVirtAddr::new(e).expect("uva")); Ok(()) })?;
        Ok(())
    }

    /// A4-rmap helper: snapshot the anon edges overlapping `[s,e)`,
    /// detach them, run `op` (the tree mutation), then re-attach every
    /// anon VMA fragment still present in the touched super-range. Used
    /// by `munmap` and `mprotect` so VMA splits keep precise rmap edges.
    /// # C: O(K_touched · N_edges)
    fn rmap_resplit<O>(&self, tree: &mut VmaTree, s: u64, e: u64, op: O) -> KResult<()>
    where O: FnOnce(&mut VmaTree, u64, u64) -> KResult<()> {
        // Pass 1: the super-range [lo,hi) spanned by every VMA the op
        // touches (overlaps [s,e)). Splits stay within this span.
        let (mut lo, mut hi) = (u64::MAX, 0u64);
        for v in tree.iter() {
            if v.end.as_u64() > s && v.start.as_u64() < e {
                lo = lo.min(v.start.as_u64());
                hi = hi.max(v.end.as_u64());
            }
        }
        if lo > hi { return op(tree, s, e); } // nothing anon to re-key
        // Pass 2: detach EVERY anon edge inside [lo,hi) (not just the
        // [s,e)-overlapping ones) so a fully-contained but untouched VMA
        // is detached and re-attached with the SAME range (net no-op) —
        // never double-attached. Detach matches one (weak,start,end).
        let detach: Vec<(Arc<crate::AnonVma>, u64, u64)> = tree.iter()
            .filter(|v| v.end.as_u64() > lo && v.start.as_u64() < hi)
            .filter_map(|v| v.anon_vma.as_ref()
                .map(|av| (Arc::clone(av), v.start.as_u64(), v.end.as_u64())))
            .collect();
        for (av, vs, ve) in &detach { av.detach(&self.self_weak, *vs, *ve); }
        op(tree, s, e)?;
        // Pass 3: re-attach every surviving anon fragment in [lo,hi).
        for v in tree.iter() {
            if v.end.as_u64() > lo && v.start.as_u64() < hi {
                if let Some(av) = v.anon_vma.as_ref() {
                    av.attach(self.self_weak.clone(), v.start.as_u64(), v.end.as_u64());
                }
            }
        }
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
        // A4-rmap: mprotect splits VMAs at the range boundaries; keep the
        // anon_vma chain edges in step with the new fragments.
        self.rmap_resplit(&mut tree, addr.as_u64(), end.as_u64(), |t, s, e| {
            t.mprotect_range(
                UserVirtAddr::new(s).expect("uva"),
                UserVirtAddr::new(e).expect("uva"), prot)
        })
    }

    /// True if any VMA in `[addr, addr+len)` is mseal'd. The syscall layer
    /// (sys_mprotect/munmap/mremap) checks this and returns EPERM when true,
    /// per mseal(2). Kernel-internal teardown (exec/exit) bypasses it — only
    /// userspace ops are sealed, matching Linux.
    /// # C: O(K)
    pub fn range_sealed(&self, addr: UserVirtAddr, len: usize) -> bool {
        match end_of(addr, len as u64) {
            Ok(end) => self.vmas.read().any_sealed(addr, end),
            Err(_)  => false,
        }
    }

    /// mseal(2): seal `[addr, addr+len)` so later userspace mprotect/munmap/
    /// mremap fail with EPERM. Full coverage required (hole → Inval, which the
    /// shim maps to ENOMEM). Idempotent.
    /// # C: O(K log N)
    pub fn mseal(&self, addr: UserVirtAddr, len: usize) -> KResult<()> {
        validate_len(len)?;
        validate_aligned(addr)?;
        let end = end_of(addr, len as u64)?;
        self.vmas.write().seal_range(addr, end)
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
            self.handle_page_fault_cow_rmap::<M, _, _, _, _, _, _>(
                va, fault, hhdm_offset,
                alloc_frame, frame_refcount, dec_ref,
                |_pa, _av, _idx| {},
                |_pa| {},
                |_pa| false, // no PageMeta exclusivity proof → copy-always
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
    pub unsafe fn handle_page_fault_cow_rmap<M, A, RC, DR, SR, IR, XR>(
        &self,
        va: UserVirtAddr,
        fault: FaultKind,
        hhdm_offset: u64,
        mut alloc_frame: A,
        mut frame_refcount: RC,
        mut dec_ref: DR,
        mut set_rmap: SR,
        mut inc_ref: IR,
        mut reuse_ok: XR,
    ) -> KResult<()>
    where
        M:  MmuOps,
        A:  FnMut() -> Option<u64>,
        RC: FnMut(u64) -> u32,
        DR: FnMut(u64),
        SR: FnMut(u64, &Arc<crate::AnonVma>, u32),
        IR: FnMut(u64),
        // A3: `reuse_ok(pa)` returns true iff `pa` is an exclusively-owned
        // anonymous frame (Linux `PageAnonExclusive` + mapcount==1) — the
        // sole-mapper proof that lets a write fault reuse the frame in
        // place (`wp_page_reuse`) instead of COW-copying. The kernel
        // adapter implements it as `is_anon && is_anon_exclusive &&
        // mapcount==1` over `PageMeta`; hosted no-op callers pass
        // `|_| false` (copy-always, the previous behaviour).
        XR: FnMut(u64) -> bool,
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
            // DIAG (debug-mount): trace COW write to the libc lock page. If a
            // fork-shared lock page takes the fast path (refcount<=1 → flip W
            // in place) while a peer still maps it, the write corrupts the
            // peer's lock → the wedge. Logs the refcount + fast/slow decision.
            #[cfg(feature = "debug-mount")]
            if let VmaBacking::File { backing, off } = &vma.backing {
                let foff = off.wrapping_add(va_page - vma.start.as_u64());
                if foff == 0x1e7000 && backing.ino() == 0x6e54000000062076 {
                    let srcpa = cur.map(|(p, _)| p.0 & !0xfff).unwrap_or(0);
                    let rc = if srcpa != 0 { frame_refcount(srcpa) } else { 0 };
                    // Read the actual stuck lock word (glibc .bss `lock`,
                    // page offset 0xb68 — uaddr 0x..db68) from the old COW
                    // frame. Non-zero ⇒ the page holds stale FILE bytes
                    // (ld.so's .bss memset was reverted) → glibc sees the
                    // lock held → futex_wait forever, no waker.
                    let lockw = if srcpa != 0 { unsafe {
                        core::ptr::read_volatile((hhdm_offset + srcpa + 0xb68) as *const u32)
                    } } else { 0 };
                    klog::write_raw(b"[mnt] COW-LOCK va="); klog::write_hex_u64(va_page);
                    klog::write_raw(b" srcpa=");             klog::write_hex_u64(srcpa);
                    klog::write_raw(b" rc=");                klog::write_dec_u64(rc as u64);
                    klog::write_raw(b" lockw=");             klog::write_hex_u64(lockw as u64);
                    klog::write_raw(if rc <= 1 { b" FAST\n" } else { b" slow\n" });
                }
            }
            // COW fast path: reuse the frame in place (flip W, no copy) ONLY
            // for an exclusively-owned ANONYMOUS page — Linux `wp_page_reuse`
            // requires `PageAnonExclusive`. A private File/KernelBytes page is
            // NEVER reused in place: it must COW-copy, because the frame can be
            // aliased through the page cache or a fork peer in ways the bare
            // struct-page refcount doesn't capture. Reusing a file page in
            // place let one process's loader-scratch write land in a fork
            // peer's still-shared libc page (the .bss lock → glibc deadlock).
            // A3 (re-enabled, Linux `wp_page_reuse`): reuse the frame in
            // place — flip W, no alloc/copy/refcount-change — iff `reuse_ok`
            // proves the page is exclusively owned. The kernel adapter
            // computes that from `PageMeta` as `is_anon && PageAnonExclusive
            // && mapcount==1`, the reliable replacement for the old
            // `frame_refcount<=1` proxy that under-counted and corrupted a
            // fork peer (random glibc-.data byte flips / "Failed to spawn
            // executor" storm / futex wedge). The exclusive bit is CLEARED on
            // every fork-share (`pmm::setup::inc_ref`), so a still-shared frame
            // never satisfies `reuse_ok` and always COW-copies below. Gated on
            // an Anonymous backing: File/KernelBytes private pages can alias
            // the page cache / fork peers in ways struct-page state misses, so
            // they must always copy.
            if matches!(vma.backing, VmaBacking::Anonymous) {
                if let Some((src_pa, _)) = cur {
                    let cur_pa = src_pa.0 & !(PAGE_SIZE_BYTES - 1);
                    if reuse_ok(cur_pa) {
                        let pte_flags = vma.prot.to_page_flags();
                        // SAFETY: va_page page-aligned per find_containing; cur_pa is the
                        // sole-owned anon frame already mapped here (mapcount==1, exclusive);
                        // flags carry USER+WRITE since vma.prot.WRITE checked above. No
                        // refcount/mapcount change: the same frame keeps its single mapping.
                        unsafe {
                            M::map(Va(va_page), Pa(cur_pa), pte_flags, PageSize::P4K);
                            M::flush_va(Va(va_page));
                        }
                        // debug-cow: the frame is now writable + exclusively
                        // owned (Linux wp_page_reuse) — it will legitimately be
                        // mutated, so drop any RO-shared snapshot to avoid a
                        // false [COW-CORRUPT] at free. No-op when feature off.
                        crate::debug_cow::forget(cur_pa);
                        return Ok(());
                    }
                }
            }
            // MAP_SHARED of a page-frame-backed file (memfd/tmpfs): a write
            // fault must make the SHARED frame itself writable in place (Linux
            // shmem dirty path) — never COW-copy, or this write diverges from
            // the file + every peer mapper (lost-write corruption). The page is
            // RO here only because a prior fork W-stripped it (or mprotect did);
            // re-install the SAME inode frame writable. No alloc, no copy, no
            // refcount change (we keep our existing reference to `cur`).
            if vma.flags.contains(VmaFlags::SHARED) && !cfg!(feature = "debug-no-shmem") {
                if let (VmaBacking::File { backing, off }, Some((src_pa, _))) = (&vma.backing, cur) {
                    let cur_pa = src_pa.0 & !(PAGE_SIZE_BYTES - 1);
                    let foff = off.wrapping_add(va_page - vma.start.as_u64());
                    if backing.shared_frame(foff) == Some(cur_pa) {
                        let pte_flags = vma.prot.to_page_flags();
                        // SAFETY: va_page page-aligned per find_containing; cur_pa is the
                        // inode-owned shared frame already mapped here (refcount held);
                        // flags carry USER+WRITE since vma.prot.WRITE checked above.
                        unsafe {
                            M::map(Va(va_page), Pa(cur_pa), pte_flags, PageSize::P4K);
                            M::flush_va(Va(va_page));
                        }
                        return Ok(());
                    }
                }
            }
            // debug-cow: we are about to COW-copy this anon frame, i.e. we
            // treat it as still RO-shared (reuse_ok was false). If the
            // struct-page refcount says it is exclusively owned (rc<=1) the
            // accounting under-counted a live PTE — the residual-bug signature
            // (a peer still maps a frame we believe nobody else holds). Cheap
            // O(1) read; no walk. Anonymous-only: File/KernelBytes private
            // pages legitimately copy while rc==1.
            #[cfg(feature = "debug-cow")]
            if matches!(vma.backing, VmaBacking::Anonymous) {
                if let Some((src_pa, _)) = cur {
                    let cur_pa = src_pa.0 & !(PAGE_SIZE_BYTES - 1);
                    let rc = frame_refcount(cur_pa);
                    if rc <= 1 {
                        klog::write_raw(b"[COW-RC] under-count frame="); klog::write_hex_u64(cur_pa);
                        klog::write_raw(b" va="); klog::write_hex_u64(va_page);
                        klog::write_raw(b" rc="); klog::write_dec_u64(rc as u64);
                        klog::write_raw(b"\n");
                    }
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
            let displaced = unsafe {
                let d = M::map(Va(va_page), Pa(new_pa), pte_flags, PageSize::P4K);
                M::flush_va(Va(va_page));
                d
            };
            // F156-rmap: bind new private page to the VMA's anon_vma
            // family with the page-offset index per Linux
            // `page_add_anon_rmap`. Caller's `set_rmap` is the kernel
            // adapter that bumps the Arc and stashes it in PageMeta.
            if let Some(av) = vma.anon_vma.as_ref() {
                let idx = ((va_page - vma.start.as_u64()) / PAGE_SIZE_BYTES) as u32;
                set_rmap(new_pa, av, idx);
            }
            // SMP TLB coherence (`20§5`): this COW split rewrote the shared
            // page-table entry `va_page -> new_pa` (writable). Peer threads of
            // the SAME mm on other CPUs still cache `va_page -> old` (the
            // shared frame) and must invalidate it BEFORE we drop our
            // reference below — otherwise `old` can be freed + realloc'd while
            // a peer still reads/writes it through the stale entry. Local
            // flush already happened in `M::map`; broadcast to the others.
            // No-op on UP / aarch64 / hosted. Target only the CPUs that
            // have this mm loaded (self.cpumask), per flush_tlb_others.
            hal::tlb::shootdown_others_va(va_page, self.cpumask());
            // F157-A1: drop our reference to the displaced (formerly
            // W-stripped shared) frame. `M::map` above tore the old leaf down
            // and returned its PA; `dec_ref` chains into
            // pmm::setup::dec_and_maybe_free, freeing the frame iff no peer AS
            // still maps it. This REPLACES the previous manual `dec_ref(cur)`:
            // the displaced return is the authoritative torn-down PA (== `cur`
            // on UP), so accounting it here — and ONLY here — keeps refcount ==
            // live-PTE count. (Keeping both would double-dec → free-while-
            // mapped, the inverse RANK-1 corruption.)
            if let Some(old) = displaced {
                dec_ref(old.0 & !(PAGE_SIZE_BYTES - 1));
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
                // F157-A1: a demand fault normally installs over an empty slot
                // (`None`); if a stale present leaf is displaced, dec_ref it so
                // refcount stays == live-PTE count (the RANK-1 fix).
                if let Some(old) = unsafe { M::map(Va(va_page), Pa(pa), pte_flags, PageSize::P4K) } {
                    // GAP-1 (displaced-frame UAF): this fault displaced a
                    // present leaf; dec_ref below may free `old`. A peer CPU
                    // of the same mm with a stale TLB entry for va_page->old
                    // could touch a freed+realloc'd frame. Flush peers (this
                    // mm's cpumask only) BEFORE dropping our reference. No-op
                    // on UP / aarch64 / hosted.
                    hal::tlb::shootdown_others_va(va_page, self.cpumask());
                    dec_ref(old.0 & !(PAGE_SIZE_BYTES - 1));
                }
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
                // F157-A1: dec_ref any frame displaced by a stale present leaf.
                if let Some(old) = unsafe { M::map(Va(va_page), Pa(pa), pte_flags, PageSize::P4K) } {
                    // GAP-1 (displaced-frame UAF): this fault displaced a
                    // present leaf; dec_ref below may free `old`. A peer CPU
                    // of the same mm with a stale TLB entry for va_page->old
                    // could touch a freed+realloc'd frame. Flush peers (this
                    // mm's cpumask only) BEFORE dropping our reference. No-op
                    // on UP / aarch64 / hosted.
                    hal::tlb::shootdown_others_va(va_page, self.cpumask());
                    dec_ref(old.0 & !(PAGE_SIZE_BYTES - 1));
                }
                Ok(())
            }
            VmaBacking::File { backing, off: backing_off } => {
                // File-backed demand-fault per `11§5` + `17§5`. The
                // backing impl reads through the page cache; bytes
                // past file end zero-fill.
                let va_page = va.as_u64() & !(PAGE_SIZE_BYTES - 1);
                let vma_off = (va_page - vma.start.as_u64()) as u64;
                let file_off = backing_off.saturating_add(vma_off);
                let page = PAGE_SIZE_BYTES as usize;
                // MAP_SHARED of a page-frame-backed file (tmpfs/memfd): install
                // the backing's PERSISTENT frame directly so user writes alias
                // the file's storage and propagate to read/write + every other
                // mapper (Linux shmem). The read_at-copy below is MAP_PRIVATE-
                // only (a COW snapshot). The frame stays alive while mapped: the
                // FileBacking Arc in this VMA pins the inode (which holds the
                // frame's base refcount), and our inc_ref here is balanced by
                // the AS-teardown dec on this leaf.
                if vma.flags.contains(VmaFlags::SHARED) && !cfg!(feature = "debug-no-shmem") {
                    if let Some(spa) = backing.shared_frame(file_off) {
                        #[cfg(feature = "debug-boot")]
                        {
                            klog::write_raw(b"[shmem map] va="); klog::write_hex_u64(va_page);
                            klog::write_raw(b" pa="); klog::write_hex_u64(spa);
                            klog::write_raw(b" ino="); klog::write_hex_u64(backing.ino());
                            klog::write_raw(b"\n");
                        }
                        inc_ref(spa);
                        let pte_flags = vma.prot.to_page_flags();
                        // SAFETY: va_page page-aligned per find_containing; spa is
                        // the inode-owned shared frame whose refcount we just
                        // bumped; flags carry USER per `11§5`.
                        // F157-A1: dec_ref any frame displaced by a stale leaf
                        // (e.g. a private COW snapshot being replaced by the
                        // shared inode frame). `inc_ref(spa)` above is balanced
                        // by AS-teardown; the displaced frame is separate.
                        if let Some(old) = unsafe { M::map(Va(va_page), Pa(spa), pte_flags, PageSize::P4K) } {
                            // GAP-1 (displaced-frame UAF): a private COW snapshot
                            // displaced here may be freed by dec_ref; flush peers
                            // holding a stale va_page->old entry first. cpumask-
                            // targeted; no-op on UP / aarch64 / hosted.
                            hal::tlb::shootdown_others_va(va_page, self.cpumask());
                            dec_ref(old.0 & !(PAGE_SIZE_BYTES - 1));
                        }
                        return Ok(());
                    }
                }
                let pa = alloc_frame().ok_or(Error::NoMem)?;
                // B240: a non-EOF page MUST be filled completely before its PTE
                // is installed. `read_at` is permitted to return SHORT (page-
                // cache build race, block/extent boundary, or a short
                // `Inode::read`); discarding that count and installing the leaf
                // anyway left the unread bytes ZERO — ld.so then read zeros where
                // library code / relocation data belonged and exit(127)'d ("error
                // while loading shared libraries"). Retry-fill the file-valid
                // extent until full, a real EOF (no progress), or an FS error;
                // only the genuine-EOF tail is legitimately zero. On an
                // unrecoverable short, surface a fatal fault (Linux
                // filemap_fault VM_FAULT_SIGBUS leg, `17§5`) — never a partial page.
                let fsize = backing.size_hint();
                // Bytes that genuinely belong to the file in this page: whole
                // PAGE for an in-file page, `fsize - file_off` for a page
                // straddling EOF, 0 for a page wholly past EOF (pure BSS).
                let valid = if file_off >= fsize { 0usize }
                            else { core::cmp::min(page as u64, fsize - file_off) as usize };
                // SAFETY: pa is a freshly-allocated PMM frame; HHDM mirror at hhdm_offset+pa is mapped writable; full page owned exclusively until M::map below makes it user-visible.
                let short = unsafe {
                    let dst = (hhdm_offset + pa) as *mut u8;
                    core::ptr::write_bytes(dst, 0, page);
                    let slice = core::slice::from_raw_parts_mut(dst, page);
                    let mut filled = 0usize;
                    let mut err = false;
                    while filled < valid {
                        match backing.read_at(file_off + filled as u64, &mut slice[filled..valid]) {
                            Ok(0)   => break,                 // no progress → real short/EOF
                            Ok(n)   => {
                                #[cfg(feature = "debug-shortfill")]
                                if filled + n < valid {
                                    // A non-EOF region returned short — the exact B240 symptom,
                                    // caught here even when the retry below recovers it.
                                    klog::write_raw(b"[SHORT-FILE-FAULT ino="); klog::write_hex_u64(backing.ino());
                                    klog::write_raw(b" off="); klog::write_hex_u64(file_off + filled as u64);
                                    klog::write_raw(b" n="); klog::write_hex_u64(n as u64);
                                    klog::write_raw(b" valid="); klog::write_hex_u64(valid as u64);
                                    klog::write_raw(b" size="); klog::write_hex_u64(fsize);
                                    klog::write_raw(b"]\n");
                                }
                                filled += n;
                            }
                            Err(()) => { err = true; break; }
                        }
                    }
                    err || filled < valid
                };
                if short {
                    // Unrecoverable: the backing could not supply the full
                    // file-valid extent. Do NOT install a partially-zero page
                    // (silent corruption). Free the fresh frame and fail the
                    // fault → SIGBUS-equivalent at the dispatcher (false→fatal).
                    #[cfg(feature = "debug-shortfill")]
                    {
                        klog::write_raw(b"[SHORT-FILE-FAULT-FATAL ino="); klog::write_hex_u64(backing.ino());
                        klog::write_raw(b" off="); klog::write_hex_u64(file_off);
                        klog::write_raw(b" valid="); klog::write_hex_u64(valid as u64);
                        klog::write_raw(b" size="); klog::write_hex_u64(fsize);
                        klog::write_raw(b"]\n");
                    }
                    dec_ref(pa);
                    return Err(Error::Io);
                }
                // debug-cow (this arm is MAP_PRIVATE: the SHARED branch
                // returned above). `pa` is a FRESH private copy of the file
                // bytes — writes to it must never reach shared storage.
                //   * If a frame-backed file (tmpfs/memfd) exposes a cache
                //     frame for this offset, we just handed its content to a
                //     private mapper: snapshot the cache frame so a later
                //     private write that wrongly mutates it surfaces as
                //     [PC-SHARED-WRITE]. Re-verify first (an earlier private
                //     mapper may already have corrupted it). tid/cpu unknown
                //     in mm-vmm here (=0); the authoritative tid is logged at
                //     the cache frame's free in pmm `check_free`.
                //   * If this private page is installed READ-ONLY (no WRITE in
                //     prot, e.g. a private RX/RO file map), track the copy for
                //     [FILE-CORRUPT] — it must stay byte-stable until COW.
                #[cfg(feature = "debug-cow")]
                {
                    if let Some(cpa) = backing.shared_frame(file_off) {
                        crate::debug_cow::check_pagecache(cpa, va_page, hhdm_offset, 0, 0);
                        crate::debug_cow::record_pagecache(cpa, hhdm_offset);
                    }
                    if !vma.flags.contains(VmaFlags::SHARED) && !vma.prot.contains(VmaProt::WRITE) {
                        crate::debug_cow::record_file(pa, hhdm_offset);
                    }
                }
                // DIAG (debug-mount): log the libc lock page's VA on File-fault
                // so a spurious zap+refault (re-read of file content over ld.so's
                // memset) is correlatable with the EVICT/MUNMAP zap tracer.
                #[cfg(feature = "debug-mount")]
                #[cfg(feature = "debug-mount")]
                if file_off == 0x1e7000 && backing.ino() == 0x6e54000000062076 {
                    klog::write_raw(b"[mnt] FFAULT-LOCK root="); klog::write_hex_u64(self.root_pa);
                    klog::write_raw(b" va=");  klog::write_hex_u64(va_page);
                    klog::write_raw(b" pa=");  klog::write_hex_u64(pa);
                    klog::write_raw(b"\n");
                }
                let pte_flags = vma.prot.to_page_flags();
                // SAFETY: va_page page-aligned per find_containing; pa is fresh PMM frame; flags carry USER per `11§5`.
                // F157-A1: dec_ref any frame displaced by a stale present leaf.
                if let Some(old) = unsafe { M::map(Va(va_page), Pa(pa), pte_flags, PageSize::P4K) } {
                    // GAP-1 (displaced-frame UAF): this fault displaced a
                    // present leaf; dec_ref below may free `old`. A peer CPU
                    // of the same mm with a stale TLB entry for va_page->old
                    // could touch a freed+realloc'd frame. Flush peers (this
                    // mm's cpumask only) BEFORE dropping our reference. No-op
                    // on UP / aarch64 / hosted.
                    hal::tlb::shootdown_others_va(va_page, self.cpumask());
                    dec_ref(old.0 & !(PAGE_SIZE_BYTES - 1));
                }
                Ok(())
            }
            VmaBacking::KernelFrame { pa } => {
                // Shared kernel frame (vvar); inc_ref balances AS-drop dec.
                let va_page = va.as_u64() & !(PAGE_SIZE_BYTES - 1);
                let pte_flags = vma.prot.to_page_flags();
                // SAFETY: pa is a kernel-owned frame whose lifetime exceeds every user mapping; va_page is page-aligned per find_containing; flags carry USER per `11§5`.
                // F157-A1: dec_ref any frame displaced by a stale present leaf
                // (separate from the KernelFrame's own `inc_ref(*pa)` below).
                if let Some(old) = unsafe { M::map(Va(va_page), Pa(*pa), pte_flags, PageSize::P4K) } {
                    // GAP-1 (displaced-frame UAF): this fault displaced a
                    // present leaf; dec_ref below may free `old`. A peer CPU
                    // of the same mm with a stale TLB entry for va_page->old
                    // could touch a freed+realloc'd frame. Flush peers (this
                    // mm's cpumask only) BEFORE dropping our reference. No-op
                    // on UP / aarch64 / hosted.
                    hal::tlb::shootdown_others_va(va_page, self.cpumask());
                    dec_ref(old.0 & !(PAGE_SIZE_BYTES - 1));
                }
                inc_ref(*pa);
                Ok(())
            }
            VmaBacking::PhysRange { base_pa } => {
                // Device physical range (Linux remap_pfn_range): map the page
                // at VMA offset O straight to base_pa + O. No PMM frame, no
                // copy, no refcount — the backing (the GPU scanout) outlives
                // every user mapping. A user write lands in the real fb.
                let va_page = va.as_u64() & !(PAGE_SIZE_BYTES - 1);
                let off = va_page - vma.start.as_u64();
                let pte_flags = vma.prot.to_page_flags();
                // SAFETY: base_pa+off is device fb memory owned by the GPU driver for the kernel lifetime; va_page is page-aligned per find_containing; flags carry USER per `11§5`.
                // F157-A1: the device frame itself is never refcounted, but a
                // real PMM frame previously mapped at this VA (displaced here)
                // must still be dec_ref'd. `dec_ref` no-ops on out-of-range
                // (device) PAs, so this is safe even if `old` is device memory.
                if let Some(old) = unsafe { M::map(Va(va_page), Pa(*base_pa + off), pte_flags, PageSize::P4K) } {
                    // GAP-1 (displaced-frame UAF): this fault displaced a
                    // present leaf; dec_ref below may free `old`. A peer CPU
                    // of the same mm with a stale TLB entry for va_page->old
                    // could touch a freed+realloc'd frame. Flush peers (this
                    // mm's cpumask only) BEFORE dropping our reference. No-op
                    // on UP / aarch64 / hosted.
                    hal::tlb::shootdown_others_va(va_page, self.cpumask());
                    dec_ref(old.0 & !(PAGE_SIZE_BYTES - 1));
                }
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

pub(crate) use crate::hole::{find_hole, hole_clear};

