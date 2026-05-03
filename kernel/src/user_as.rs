// Global user `AddressSpace` integration per `11§3`/`11§5`.
//
// v1 single-task: one process-wide `AddressSpace` referenced by every
// fault and every `mmap`/`munmap` syscall. Per-task lifecycle (Task
// carries `Arc<AddressSpace>`; switch swaps CR3/TTBR0) lands with
// P2-13 alongside the runqueue wire-up.
//
// This module owns:
//   - `GLOBAL_AS_PTR`: a raw pointer to the leak'd global AS Arc;
//     reads are wait-free for fault context.
//   - `HHDM_OFFSET`: cached for AS demand-paging zero-fill (page is
//     written via `hhdm + pa` kernel mirror before the user PTE is
//     installed).
//   - `init`: boot-path constructor, called from `kernel_main` after
//     PMM is up.
//   - `user_fault_handler`: registered via `install_fault_handler`
//     before `userspace_smoke::run`. Routes `#PF`/data-aborts in the
//     user range through `AddressSpace::handle_page_fault`. Other
//     faults (and known smoke landmarks) fall through to halt with
//     a log line.
//
// Spec references: `11§3` (public API), `11§5` (page-fault algorithm),
// `11§4` (VMA + flags). The Linux compat surface for protection bits
// + flags is in `15§6.2` (mmap).

#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

use alloc::sync::Arc;

use vmm::{AddressSpace, FaultAccess, FaultKind, VmaBacking, VmaFlags, VmaProt};
use hal::{UserVirtAddr, USER_VA_END};

/// Leaked Arc<AddressSpace>; written once by `init`, read by any
/// number of fault handlers. Null until `init` succeeds.
static GLOBAL_AS_PTR: AtomicPtr<AddressSpace> = AtomicPtr::new(core::ptr::null_mut());

/// HHDM offset captured at init for demand-paging zero-fill.
static HHDM_OFFSET: AtomicU64 = AtomicU64::new(0);

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
                debug_vmm! { klog::kerror!("user-as: new_user_pml4 failed"); }
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
                debug_vmm! { klog::kerror!("user-as: new_user_l0 failed"); }
                return;
            }
        }
    };

    // Step 3: build AS over that root.
    let arc = match AddressSpace::new(root_pa) {
        Ok(a) => a,
        Err(_) => {
            debug_vmm! { klog::kerror!("user-as: AddressSpace::new failed"); }
            return;
        }
    };

    // Step 4: activate the AS as the live address space. After this
    // point, every MmuOps walk for a user-half VA targets this AS's
    // private root; kernel-half mappings ride the master via shared
    // L3 sub-trees (x86) or TTBR1_EL1 (arm).
    use hal::MmuOps;
    #[cfg(target_arch = "x86_64")]
    // SAFETY: root_pa carries kernel-half entries 256..512 cloned from the captured master, so kernel addresses (kernel image, HHDM, device MMIO) translate identically across the CR3 write. Single-CPU pre-init; preempt-off.
    unsafe { <hal_x86_64::mmu_ops::X86Mmu as MmuOps>::activate(root_pa); }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: TTBR1_EL1 (kernel half) is untouched; only TTBR0_EL1 is rewritten so user-half walks now target the AS-private L0. Single-CPU pre-init; preempt-off.
    unsafe { <hal_aarch64::mmu_ops::ArmMmu as MmuOps>::activate(root_pa); }

    let raw = Arc::into_raw(arc) as *mut AddressSpace;
    GLOBAL_AS_PTR.store(raw, Ordering::Release);

    debug_vmm! {
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

/// Translate Linux `PROT_*` bits (per `15§6.2`) to `VmaProt`.
/// # C: O(1)
pub fn prot_from_linux(prot: u64) -> VmaProt {
    let mut p = VmaProt::empty();
    if prot & 0x1 != 0 { p |= VmaProt::READ;  }
    if prot & 0x2 != 0 { p |= VmaProt::WRITE; }
    if prot & 0x4 != 0 { p |= VmaProt::EXEC;  }
    p
}

/// Decode an x86_64 `#PF` error code into a `FaultKind` per Intel
/// SDM Vol. 3 §6.15 / `11§5`. Returns `None` if the fault is not
/// from a user-half VA (kernel-mode fault on user-space data — not
/// a demand-page case here).
/// # C: O(1)
#[cfg(target_arch = "x86_64")]
pub fn classify_x86_pf(err: u64, cr2: u64) -> Option<FaultKind> {
    if cr2 >= USER_VA_END {
        return None;
    }
    // err bit 0 (P): 1 = protection, 0 = not-present.
    // err bit 1 (W): 1 = write, 0 = read.
    // err bit 4 (I): 1 = instruction fetch (exec attempt).
    let access = if err & 0x10 != 0 {
        FaultAccess::Exec
    } else if err & 0x02 != 0 {
        FaultAccess::Write
    } else {
        FaultAccess::Read
    };
    if err & 0x01 == 0 {
        Some(FaultKind::NotPresent { access })
    } else {
        Some(FaultKind::Protection { access })
    }
}

/// Decode an aarch64 ESR for a sync-from-lower-EL data/instruction
/// abort into a `FaultKind` per ARM ARM D13.2.40 / `11§5`. Returns
/// `None` if the fault wasn't from EL0 user space.
/// # C: O(1)
#[cfg(target_arch = "aarch64")]
pub fn classify_arm_abort(esr: u64, far: u64) -> Option<FaultKind> {
    if far >= USER_VA_END {
        return None;
    }
    let ec = (esr >> 26) & 0x3F;
    // EC = 0x24 data abort lower EL; 0x20 instruction abort lower EL.
    let access = match ec {
        0x20 => FaultAccess::Exec,
        0x24 => {
            // ISS bit 6 = WnR: 0=read, 1=write.
            if esr & (1 << 6) != 0 { FaultAccess::Write } else { FaultAccess::Read }
        }
        _ => return None,
    };
    // DFSC (ISS bits 5..0): 0x04..0x07 = translation fault L0..L3.
    let dfsc = esr & 0x3F;
    if (0x04..=0x07).contains(&dfsc) {
        Some(FaultKind::NotPresent { access })
    } else {
        // Permission fault, alignment, etc → protection class.
        Some(FaultKind::Protection { access })
    }
}

/// Per-arch fault handler installed by `kernel_main`. v1 handles
/// only `NotPresent` on Anonymous VMAs (demand-paging path). Other
/// fault classes return `false` so the dispatcher halts with the
/// existing fault-printer log — that's effectively segfault behavior
/// until P2 wires SIGSEGV delivery.
/// # C: O(log N_vmas) + O(walk depth) on demand-page; O(1) reject
#[cfg(target_arch = "x86_64")]
pub fn user_fault_handler(vec: u64, err: u64, _rip: u64, cr2: u64) -> bool {
    if vec != 14 {
        return false;
    }
    let kind = match classify_x86_pf(err, cr2) {
        Some(k) => k,
        None    => return false,
    };
    handle(cr2, kind)
}

/// # C: O(log N_vmas) + O(walk depth) on demand-page; O(1) reject
#[cfg(target_arch = "aarch64")]
pub fn user_fault_handler(esr: u64, far: u64, _elr: u64) -> bool {
    let kind = match classify_arm_abort(esr, far) {
        Some(k) => k,
        None    => return false,
    };
    handle(far, kind)
}

/// Dispatch the classified fault into the global AS. Allocates a
/// PMM frame and installs the leaf via per-arch MmuOps; flushes the
/// faulting VA's TLB. Returns true to retry, false to halt.
fn handle(va_raw: u64, fault: FaultKind) -> bool {
    let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
    let uva = match UserVirtAddr::new(va_raw) {
        Some(u) => u,
        None    => return false,
    };
    let r = with(|as_| {
        // SAFETY: live per-arch MmuOps state initialised by kernel_main pre-init; alloc closure is the kernel-owned PMM allocator; AS borrow is read-only at entry (the AS internally takes its own RwLock); fault context has IRQs masked.
        unsafe {
            #[cfg(target_arch = "x86_64")]
            let r = as_.handle_page_fault::<hal_x86_64::mmu_ops::X86Mmu, _>(
                uva,
                fault,
                hhdm,
                || crate::pmm_setup::alloc_one_frame(),
            );
            #[cfg(target_arch = "aarch64")]
            let r = as_.handle_page_fault::<hal_aarch64::mmu_ops::ArmMmu, _>(
                uva,
                fault,
                hhdm,
                || crate::pmm_setup::alloc_one_frame(),
            );
            r
        }
    });
    match r {
        Some(Ok(())) => {
            // Flush the faulting VA so the retry sees the new PTE.
            // SAFETY: privileged TLB invalidation legal at CPL=0/EL1.
            #[cfg(target_arch = "x86_64")]
            unsafe { hal_x86_64::flush_local_va(va_raw); }
            #[cfg(target_arch = "aarch64")]
            {
                // arm needs a hal-side flush_va helper; reuse the
                // walker's path. For v1 single-CPU, the dsb+isb
                // sequence inside MmuOps::map already serializes
                // the PTE write, so a separate invlpg-equivalent is
                // optional. Leave a TODO for the proper invalidation
                // primitive once flush_local_va is exposed for arm.
                let _ = va_raw;
            }
            true
        }
        _ => false,
    }
}

/// Wrap `AddressSpace::mmap` for `kernel_mmap` syscall glue: takes
/// the Linux mmap arg shape, returns `(va, errno)`. v1 supports
/// only `MAP_ANONYMOUS | MAP_PRIVATE` with `addr=NULL`, `fd=-1`.
/// # C: O(N_vmas) hole search + O(1) insert
pub fn glue_mmap(
    addr: u64,
    len: u64,
    prot: u64,
    flags: u64,
    fd: i64,
) -> Result<u64, i64> {
    use syscall::errno::Errno;
    const MAP_PRIVATE: u64 = 0x02;
    const MAP_ANON:    u64 = 0x20;
    const MAP_FIXED:   u64 = 0x10;

    if flags & MAP_ANON  == 0 { return Err(-(Errno::Enosys.as_i32() as i64)); }
    if flags & MAP_PRIVATE == 0 { return Err(-(Errno::Einval.as_i32() as i64)); }
    if flags & MAP_FIXED != 0 { return Err(-(Errno::Enosys.as_i32() as i64)); }
    if fd != -1               { return Err(-(Errno::Einval.as_i32() as i64)); }
    if addr != 0              { return Err(-(Errno::Enosys.as_i32() as i64)); }
    if len == 0               { return Err(-(Errno::Einval.as_i32() as i64)); }
    let len_aligned = ((len + 0xfff) & !0xfff) as usize;

    let r = with(|as_| {
        as_.mmap(
            None,
            len_aligned,
            prot_from_linux(prot),
            VmaFlags::PRIVATE | VmaFlags::ANONYMOUS,
            VmaBacking::Anonymous,
            false,
        )
    });
    match r {
        Some(Ok(uva))  => Ok(uva.as_u64()),
        Some(Err(_))   => Err(-(Errno::Enomem.as_i32() as i64)),
        None           => Err(-(Errno::Enosys.as_i32() as i64)),  // AS not init
    }
}

/// Wrap `AddressSpace::munmap` + per-page PT unmap + frame free.
/// Walks `[addr, addr+len)`, for each present PTE: translate → unmap
/// → free PA back to PMM → flush_va. Then removes the VMA(s).
/// # C: O(pages) PT walk + O(K log N) VMA remove
pub fn glue_munmap(addr: u64, len: u64) -> i64 {
    use syscall::errno::Errno;
    use hal::{MmuOps, PageSize, Va};
    if addr == 0 || len == 0 || (addr & 0xfff) != 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let len_aligned = (len + 0xfff) & !0xfff;
    if addr.checked_add(len_aligned).map_or(true, |e| e > USER_VA_END) {
        return -(Errno::Einval.as_i32() as i64);
    }

    let mut va = addr;
    let end = addr + len_aligned;
    while va < end {
        // SAFETY: privileged read of live page tables; va is in user-half range validated above.
        #[cfg(target_arch = "x86_64")]
        let translated = <hal_x86_64::mmu_ops::X86Mmu as MmuOps>::translate(Va(va));
        #[cfg(target_arch = "aarch64")]
        let translated = <hal_aarch64::mmu_ops::ArmMmu as MmuOps>::translate(Va(va));
        if let Some((pa, _flags)) = translated {
            // SAFETY: page is mapped; unmap + frame free are the inverse of demand-page install.
            unsafe {
                #[cfg(target_arch = "x86_64")]
                <hal_x86_64::mmu_ops::X86Mmu as MmuOps>::unmap(Va(va), PageSize::P4K);
                #[cfg(target_arch = "aarch64")]
                <hal_aarch64::mmu_ops::ArmMmu as MmuOps>::unmap(Va(va), PageSize::P4K);
            }
            // Free the PA back to PMM.
            // SAFETY: pa was reachable via the live PT entry just unmapped above; we're now the sole owner since the unmap completed and the TLB flush below makes the old translation unobservable.
            unsafe { crate::pmm_setup::free_one_frame(pa.0); }
            // SAFETY: privileged TLB invalidation legal at CPL=0/EL1.
            #[cfg(target_arch = "x86_64")]
            unsafe { hal_x86_64::flush_local_va(va); }
        }
        va += 0x1000;
    }

    // VMA bookkeeping side.
    let uva = match UserVirtAddr::new(addr) {
        Some(u) => u,
        None    => return -(Errno::Einval.as_i32() as i64),
    };
    match with(|as_| as_.munmap(uva, len_aligned as usize)) {
        Some(Ok(()))  => 0,
        Some(Err(_))  => -(Errno::Einval.as_i32() as i64),
        None          => -(Errno::Enosys.as_i32() as i64),
    }
}
