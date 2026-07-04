use super::*;

static GLOBAL_AS_PTR: AtomicPtr<AddressSpace> = AtomicPtr::new(core::ptr::null_mut());

/// HHDM offset captured at init for demand-paging zero-fill.
pub(super) static HHDM_OFFSET: AtomicU64 = AtomicU64::new(0);

/// Current logical CPU index (clamped to `MAX_CPUS`), matching the
/// shootdown sender's `this_cpu()` so a bit set here is the bit the
/// sender clears from its target set. Host builds are UP → 0.
/// # C: O(1)
#[inline]
pub(super) fn current_cpu_idx() -> usize {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    { use hal::CpuOps; (hal_x86_64::X86CpuOps::current_cpu() as usize).min(cpu::MAX_CPUS - 1) }
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    { use hal::CpuOps; (hal_aarch64::ArmCpuOps::current_cpu() as usize).min(cpu::MAX_CPUS - 1) }
    #[cfg(not(target_os = "oxide-kernel"))]
    { 0 }
}

/// Snapshot the running task's mm `cpumask` (Linux `mm_cpumask`) for
/// `flush_tlb_others` targeting at the PT-mutating glue sites. Returns 0
/// when there is no current user task (boot context / kthread) — the
/// shootdown then becomes a no-op, which is correct: no peer CPU holds a
/// user mm that isn't the current one.
/// # C: O(1)
#[inline]
pub(super) fn current_mm_cpumask() -> u64 {
    // SAFETY: read-only borrow of the running task's mm slot; the fault /
    // syscall caller runs preempt-off in IRQ context per `13§5`, so no
    // concurrent execve mutates this CPU's mm slot during the read.
    sched::live::current()
        .and_then(|c| unsafe { c.mm_ref() }.map(|m| m.cpumask()))
        .unwrap_or(0)
}

/// Initialise the global user AS, allocate its private page-table
/// root, copy kernel-half mappings from the captured master, and
/// activate it as the live CR3 / TTBR0_EL1 per `13§8`. Idempotent —
/// second-and-later calls are no-ops.
///
/// Order of operations:
/// 1. Capture the live kernel master root (CR3 on x86; TTBR1_EL1 on
///    arm). All kernel mappings (HHDM, kernel image, device MMIO)
///    must be installed *before* this call so the master sub-trees
///    referenced from PML4[256..512] are stable.
/// 2. Allocate a fresh user-AS root frame. On x86, copy entries
///    256..512 from the master so kernel-half mappings remain valid
///    after activation. On arm, the kernel rides TTBR1_EL1 — the
///    fresh L0 is zeroed, no copy needed.
/// 3. Build `AddressSpace` carrying the root PA.
/// 4. `MmuOps::activate(root_pa)` writes CR3 / TTBR0_EL1 → from
///    here on, every user-half PT op (mmap, demand-page) targets
///    this AS-private tree.
///
/// # SAFETY: caller is the boot path; single-CPU, IRQs off; PMM +
/// MmuOps state initialised; HHDM is already mapped in the master;
/// no per-AS root has been activated yet.
/// # C: O(1) on x86 (256-entry copy); O(1) on arm
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn init(hhdm_offset: u64) {
    if !GLOBAL_AS_PTR.load(Ordering::Acquire).is_null() {
        return;
    }
    HHDM_OFFSET.store(hhdm_offset, Ordering::Release);

    // Step 1: capture kernel master + step 2: alloc AS-private root.
    #[cfg(target_arch = "x86_64")]
    let root_pa = {
        // SAFETY: boot-path; CR3 holds the live kernel master PML4;
        // single-CPU pre-init.
        let _master = unsafe { hal_x86_64::mmu_ops::capture_kernel_master() };
        // SAFETY: PMM up; MASTER_PML4_PA just set; HHDM covers RAM
        // holding page-table memory; single-CPU pre-init.
        match unsafe { hal_x86_64::mmu_ops::new_user_pml4() } {
            Some(pa) => pa,
            None => {
                #[cfg(feature = "debug-vmm")]

                { klog::kerror!("user-as: new_user_pml4 failed"); }
                return;
            }
        }
    };
    #[cfg(target_arch = "aarch64")]
    let root_pa = {
        // SAFETY: boot-path; TTBR1_EL1 holds the live kernel root.
        let _master = unsafe { hal_aarch64::mmu_ops::capture_kernel_master() };
        // SAFETY: PMM up; HHDM covers page-table memory; single-CPU pre-init.
        match unsafe { hal_aarch64::mmu_ops::new_user_l0() } {
            Some(pa) => pa,
            None => {
                #[cfg(feature = "debug-vmm")]

                { klog::kerror!("user-as: new_user_l0 failed"); }
                return;
            }
        }
    };

    // Step 3: build AS over that root.
    let arc = match AddressSpace::new(root_pa) {
        Ok(a) => a,
        Err(_) => {
            #[cfg(feature = "debug-vmm")]

            { klog::kerror!("user-as: AddressSpace::new failed"); }
            return;
        }
    };

    // private root; kernel-half mappings ride the master via shared
    // L3 sub-trees (x86) or TTBR1_EL1 (arm).
    use hal::MmuOps;
    #[cfg(target_arch = "x86_64")]
    // SAFETY: root_pa carries kernel-half entries 256..512 cloned from the captured master, so kernel addresses (kernel image, HHDM, device MMIO) translate identically across the CR3 write. Single-CPU pre-init; preempt-off.
    unsafe { <hal_x86_64::mmu_ops::X86Mmu as MmuOps>::activate(root_pa); }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: TTBR1_EL1 (kernel half) is untouched; only TTBR0_EL1 is rewritten so user-half walks now target the AS-private L0. Single-CPU pre-init; preempt-off.
    unsafe { <hal_aarch64::mmu_ops::ArmMmu as MmuOps>::activate(root_pa); }

    // mm_cpumask: this CPU just loaded the global AS via the activate
    // above, so record its bit (Linux sets mm_cpumask on CR3 load). A
    // later cross-CPU shootdown against this AS then targets this CPU.
    arc.mark_cpu(current_cpu_idx());

    let raw = Arc::into_raw(arc) as *mut AddressSpace;
    GLOBAL_AS_PTR.store(raw, Ordering::Release);

    #[cfg(feature = "debug-vmm")]
    {
        klog::write_raw(b"[INFO]  user-as: root_pa=");
        klog::write_hex_u64(root_pa);
        klog::write_raw(b" activated\n");
    }
}

/// Borrow the global AS for the duration of `f`. Returns `None` if
/// `init` hasn't run.
/// # C: caller's f cost
pub fn with<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&AddressSpace) -> R,
{
    let p = GLOBAL_AS_PTR.load(Ordering::Acquire);
    if p.is_null() {
        return None;
    }
    // SAFETY: GLOBAL_AS_PTR was written by init() from a valid Arc::into_raw, never decremented; the AS is 'static once stored. Concurrent f() calls share an immutable borrow which is fine (AddressSpace's mmap/munmap take their own RwLock internally).
    let as_ref: &AddressSpace = unsafe { &*p };
    Some(f(as_ref))
}

/// Bump the global AS's strong refcount and return a fresh
/// `Arc<AddressSpace>`. The returned Arc keeps the AS alive
/// independently of the leaked `GLOBAL_AS_PTR` slot — used by
/// `Task::new_user` to attach `mm`. Returns `None` if `init`
/// hasn't run.
/// # C: O(1)
pub fn clone_global_arc() -> Option<Arc<AddressSpace>> {
    let p = GLOBAL_AS_PTR.load(Ordering::Acquire);
    if p.is_null() {
        return None;
    }
    // SAFETY: p was installed via Arc::into_raw and never freed;
    // bumping the strong count + reconstructing an Arc from the
    // same raw pointer is the canonical "borrow as Arc" idiom.
    unsafe { Arc::increment_strong_count(p); }
    // SAFETY: matching Arc::from_raw consumes the bumped count.
    Some(unsafe { Arc::from_raw(p) })
}

/// Cached HHDM offset captured at `init`. Used by demand-page
/// callers that need the kernel-VA of a freshly-allocated frame.
/// Returns 0 if `init` hasn't run.
/// # C: O(1)
pub fn hhdm_offset() -> u64 {
