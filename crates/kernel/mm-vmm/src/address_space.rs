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
use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use sync::{AddressSpace as AddressSpaceClass, Guard, KMalloc, PageTable, RwLock, RwReadGuard, Spinlock};

use crate::tree::VmaTree;
use crate::vma::{Vma, VmaBacking};
use crate::KResult;

const PAGE_MASK: u64 = hal::PAGE_SIZE_BYTES - 1;

/// Canonical ownership directory for every live user `mm_struct` analogue.
///
/// The VMM owns address-space lifetime, so cross-mm operations such as
/// swapoff must enumerate this directory instead of sampling scheduler tasks:
/// tasks may be concurrently executing, exiting, or publishing a fork child.
/// Entries are weak to avoid extending an mm's lifetime solely for discovery.
static LIVE_ADDRESS_SPACES: Spinlock<BTreeMap<u64, Weak<AddressSpace>>, KMalloc> =
    Spinlock::new(BTreeMap::new());

/// Register one production user address space after its `Arc` exists.
/// Hosted VMA-only tests use root `0`, which never has page tables or swap
/// PTEs and therefore must not share one directory key.
fn register_live_address_space(root_pa: u64, as_: Weak<AddressSpace>) {
    if root_pa != 0 { LIVE_ADDRESS_SPACES.lock().insert(root_pa, as_); }
}

/// Remove an address space before its page tables can be torn down.
fn unregister_live_address_space(root_pa: u64) {
    if root_pa != 0 { LIVE_ADDRESS_SPACES.lock().remove(&root_pa); }
}

/// Pin a point-in-time snapshot of every live production address space.
///
/// Callers must still revalidate individual leaves under each mm's page-table
/// lock: a snapshot intentionally permits normal fork, exit, and fault races.
/// # C: O(number of live address spaces)
pub fn live_address_spaces() -> KResult<Vec<Arc<AddressSpace>>> {
    let mut live = Vec::new();
    let mut directory = LIVE_ADDRESS_SPACES.lock();
    live.try_reserve(directory.len()).map_err(|_| crate::Error::NoMem)?;
    for weak in directory.values() {
        if let Some(as_) = weak.upgrade() { live.push(as_); }
    }
    directory.retain(|_, weak| weak.strong_count() != 0);
    Ok(live)
}

#[cfg(test)]
mod live_registry_tests {
    use super::*;
    use core::sync::atomic::{AtomicU64, Ordering};

    /// Hosted address spaces normally use root zero; reserve unique nonzero
    /// synthetic roots solely to exercise the production ownership directory.
    static NEXT_TEST_ROOT: AtomicU64 = AtomicU64::new(hal::PAGE_SIZE_BYTES);

    #[test]
    fn live_address_space_directory_pins_and_unregisters_mm() {
        let root = NEXT_TEST_ROOT.fetch_add(hal::PAGE_SIZE_BYTES, Ordering::Relaxed);
        let as_ = AddressSpace::new(root).expect("construct live address space");
        assert!(live_address_spaces().expect("snapshot live mms")
            .iter().any(|known| Arc::ptr_eq(known, &as_)));
        drop(as_);
        assert!(!live_address_spaces().expect("snapshot after drop")
            .iter().any(|known| known.root_pa() == root));
    }

    #[test]
    fn forked_address_space_joins_live_directory() {
        let parent_root = NEXT_TEST_ROOT.fetch_add(hal::PAGE_SIZE_BYTES, Ordering::Relaxed);
        let child_root = NEXT_TEST_ROOT.fetch_add(hal::PAGE_SIZE_BYTES, Ordering::Relaxed);
        let parent = AddressSpace::new(parent_root).expect("construct parent address space");
        let child = parent.fork(child_root).expect("fork address space");
        assert!(live_address_spaces().expect("snapshot live mms")
            .iter().any(|known| Arc::ptr_eq(known, &child)));
    }
}

mod accounting;
mod fault;
mod fork;
mod layout;
mod limits;
mod mmfields;
mod ops;

pub use limits::{MIN_USER_VA, MMAP_BASE_GAP, MMAP_TOP};
pub use accounting::{global_accounting_snapshot, page_table_frame_allocated, page_table_frame_released, swap_pte_teardown, VmAccountingSnapshot};
pub use mmfields::{
    prctl_mm_map_size, validate_mm_map, PrctlMmMap,
    PR_SET_MM_ARG_END, PR_SET_MM_ARG_START, PR_SET_MM_AUXV, PR_SET_MM_BRK,
    PR_SET_MM_END_CODE, PR_SET_MM_END_DATA, PR_SET_MM_ENV_END, PR_SET_MM_ENV_START,
    PR_SET_MM_EXE_FILE, PR_SET_MM_MAP, PR_SET_MM_MAP_SIZE, PR_SET_MM_START_BRK,
    PR_SET_MM_START_CODE, PR_SET_MM_START_DATA, PR_SET_MM_START_STACK,
};

// Module manifest:
// - limits: address-space numeric boundaries and growth caps.
// - layout: page-alignment validation helpers.
// - mmfields: mm_struct arg/env/stack/code/data/brk bounds + prctl(PR_SET_MM).
// - ops: VMA lookup, mmap/munmap/mprotect/mseal, rmap edge upkeep.
// - fork: fork tree cloning, eager copy, and COW page sharing.
// - fault: demand-fault, file-fill, COW, and rmap-aware fault paths.

/// Per-process AS. Public surface mirrors `11§3`. The Page Table side
/// (`11§9`) lives in `root_pa`: the PA of this AS's top-level table
/// (PML4 on x86_64; L0 on aarch64). `MmuOps::activate(root_pa)`
/// installs it as the active CR3 / TTBR0_EL1 per `13§8`.
pub struct AddressSpace {
    vmas:    RwLock<VmaTree, AddressSpaceClass>,
    /// Serializes page-table leaf inspection and rewrite for this address
    /// space. It is deliberately distinct from `vmas`: page faults drop the
    /// VMA lock before backing I/O, then take this lock only for PTE commit and
    /// revalidation. Lock class `PageTable` precedes `AddressSpace` per 11§9.
    pt_lock: Spinlock<(), PageTable>,
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
    /// Linux `mm_struct` argv/env/stack/code/data/start_brk bounds +
    /// saved auxv. Set at execve; rewritable via `prctl(PR_SET_MM)` under
    /// CAP_SYS_RESOURCE. Source for `/proc/<pid>/{cmdline,environ,stat}`.
    /// Getters/setters + the PR_SET_MM apply/validate logic live in the
    /// `mmfields` child module.
    mm_layout: mmfields::MmLayout,
    accounting: accounting::VmAccounting,
    /// userfaultfd fast-path guard: set true the first time any range on
    /// this AS is `UFFDIO_REGISTER`ed (see `set_uffd_missing`), never
    /// cleared. The page-fault handler checks it before the per-VMA uffd
    /// lookup so the overwhelming majority of processes (no uffd) skip the
    /// extra vmas read-lock on every NotPresent fault. Conservative: once
    /// any uffd registers, every fault pays the lookup — cheap and rare.
    has_uffd: core::sync::atomic::AtomicBool,
    /// `mlockall(MCL_FUTURE)` policy for mappings subsequently inserted into
    /// this mm. Linux keeps this in `mm->def_flags`; it is per-mm rather than
    /// task-local so CLONE_VM threads observe one locking contract.
    mlock_future: core::sync::atomic::AtomicBool,
    /// `MCL_ONFAULT` paired with `mlock_future`: mappings are VM_LOCKED now
    /// but resident frames are faulted only on first access.
    mlock_onfault: core::sync::atomic::AtomicBool,
}

impl Drop for AddressSpace {
    fn drop(&mut self) {
        self.debug_lifetime_event(b"drop-enter");
        // Remove this root from cross-mm discovery before the teardown hook
        // can free its page-table frames. Existing snapshots hold an Arc and
        // therefore cannot observe this final Drop.
        unregister_live_address_space(self.root_pa);
        #[cfg(feature = "debug-swap")]
        {
            let vma_count = self.vmas.read().len();
            klog::write_raw(b"[AS-DROP] root=");
            klog::write_hex_u64(self.root_pa);
            klog::write_raw(b" cpumask=");
            klog::write_hex_u64(self.cpumask.load(core::sync::atomic::Ordering::Acquire));
            klog::write_raw(b" vmas=");
            klog::write_dec_u64(vma_count as u64);
            klog::write_raw(b"\n");
        }
        let raw = self.teardown.load(core::sync::atomic::Ordering::Acquire);
        if raw != 0 {
            // SAFETY: `set_teardown` installs `td` as an `unsafe extern "C" fn(u64)` cast through `as usize` to a u64; the inverse transmute restores the same fn-ptr, ABI guarantees match, and zero is checked above so we never transmute a null.
            let td: unsafe extern "C" fn(u64) = unsafe {
                core::mem::transmute(raw as usize)
            };
            // SAFETY: `td` accepts the AS's own `root_pa` per the installer contract; the AS is in its final Drop (Arc strong count hit zero) so the root is no longer active on any CPU and no concurrent walker remains.
            unsafe { td(self.root_pa); }
        }
        accounting::unregister_page_table_owner(self.root_pa);
    }
}

impl AddressSpace {
    /// Emit one ownership-transition record from the canonical mm object.
    /// The record adds no shadow registry: root, VMA count, and CPU residency
    /// are read from this `mm_struct` analogue itself.
    /// # C: O(1) lock acquire; debug-only
    #[cfg(feature = "debug-as-lifetime")]
    pub fn debug_lifetime_event(&self, event: &'static [u8]) {
        let vmas = self.vmas.read().len();
        klog::write_raw(b"[AS-LIFE] event=");
        klog::write_raw(event);
        klog::write_raw(b" root=");
        klog::write_hex_u64(self.root_pa);
        klog::write_raw(b" cpumask=");
        klog::write_hex_u64(self.cpumask.load(core::sync::atomic::Ordering::Acquire));
        klog::write_raw(b" vmas=");
        klog::write_dec_u64(vmas as u64);
        klog::write_raw(b"\n");
    }

    #[cfg(not(feature = "debug-as-lifetime"))]
    #[inline]
    pub fn debug_lifetime_event(&self, _event: &'static [u8]) {}

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
        let as_ = Arc::new_cyclic(|w| Self {
            vmas: RwLock::new(VmaTree::new()),
            pt_lock: Spinlock::new(()),
            root_pa,
            brk:     core::sync::atomic::AtomicU64::new(0),
            brk_max: core::sync::atomic::AtomicU64::new(0),
            teardown: core::sync::atomic::AtomicU64::new(0),
            exe_path: Spinlock::new(None),
            mmap_base: core::sync::atomic::AtomicU64::new(0),
            self_weak: w.clone(),
            has_uffd: core::sync::atomic::AtomicBool::new(false),
            mlock_future: core::sync::atomic::AtomicBool::new(false),
            mlock_onfault: core::sync::atomic::AtomicBool::new(false),
            // Fresh/forked AS: no CPU has loaded it yet (Linux clears
            // mm_cpumask on mm init; the activating CPU sets its bit).
            cpumask: core::sync::atomic::AtomicU64::new(0),
            mm_layout: mmfields::MmLayout::new(),
            accounting: accounting::VmAccounting::new(root_pa),
        });
        accounting::register_page_table_owner(root_pa, &as_.accounting);
        register_live_address_space(root_pa, Arc::downgrade(&as_));
        as_.debug_lifetime_event(b"new");
        Ok(as_)
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

    /// Acquire this mm's page-table serialization lock. Callers must hold it
    /// only around leaf inspection/rewrite and TLB invalidation, never around
    /// allocation, backing I/O, or a blocking operation.
    /// # C: O(contention)
    /// # Lk: PageTable acquired
    pub fn lock_page_table(&self) -> Guard<'_, (), PageTable> { self.pt_lock.lock() }

    /// Wrap an ELF / shm staging buffer as `Arc<[u8]>` for use as a
    /// `VmaBacking::KernelBytes` backing. Refcount-based lifetime: a
    /// child AS that fork-clones the VMA tree bumps each Arc, so
    /// child KernelBytes references stay valid even after the parent
    /// AS drops. Pre-Arc design used `&'static [u8]` views into a
    /// per-AS `Vec<Box<[u8]>>`, which dangled in fork children when
    /// the parent dropped first.
    /// # C: O(N) — converts `Box<[u8]>` to `Arc<[u8]>` (one alloc).
    pub fn stash_bytes(&self, b: Box<[u8]>) -> alloc::sync::Arc<[u8]> {
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
        self.set_start_brk(start);
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
        let min = self.start_brk();
        if new < min || new > max { return cur; }
        let Some(rounded) = new.checked_add(PAGE_MASK).map(|v| v & !PAGE_MASK) else { return cur };
        if rounded > max { return cur; }
        self.brk.store(new, Ordering::Release);
        new
    }

    /// True when an anonymous demand fault lands inside the loader-reserved
    /// heap window but above Linux's current `PAGE_ALIGN(mm->brk)` VMA end.
    /// # C: O(1)
    pub(super) fn brk_fault_past_current(&self, vma: &Vma, va_page: u64) -> bool {
        if !matches!(vma.backing, VmaBacking::Anonymous) { return false; }
        let (start, max, cur) = (self.start_brk(), self.brk_max(), self.brk());
        if start == 0 || max == 0 || va_page < start || va_page >= max { return false; }
        if vma.start.as_u64() > start || vma.end.as_u64() < max { return false; }
        let active_end = cur.checked_add(PAGE_MASK).map(|v| v & !PAGE_MASK).unwrap_or(u64::MAX);
        va_page >= active_end
    }

    #[cfg(test)]
    /// # C: O(log N_vmas)
    pub fn brk_fault_past_current_for_test(&self, va_page: u64) -> bool {
        let Some(va) = hal::UserVirtAddr::new(va_page) else { return false };
        let Some(vma) = self.find_vma(va) else { return false };
        self.brk_fault_past_current(&vma, va_page)
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
}
