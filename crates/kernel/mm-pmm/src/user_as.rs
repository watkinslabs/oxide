// + flags is in `15§6.2` (mmap).

use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

use alloc::sync::Arc;

use vmm::{AddressSpace, FaultAccess, FaultKind, VmaBacking, VmaFlags, VmaProt};
use hal::{UserVirtAddr, USER_VA_END};

mod signal;
pub use signal::{CoredumpFn, set_coredump_hook};
#[cfg(target_arch = "x86_64")]
pub use signal::deliver_sigsegv_x86;
#[cfg(target_arch = "aarch64")]
pub use signal::deliver_sigsegv_arm;
#[cfg(target_arch = "x86_64")]
use signal::try_deliver_sigsegv_via_handler_x86;

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
    HHDM_OFFSET.load(Ordering::Acquire)
}

/// Read up to `dst.len()` bytes from a foreign address space at
/// user-virtual address `va`. Walks `root_pa`'s page tables (the
/// foreign AS's `root_pa()`) for each 4 KiB page intersecting the
/// range, copies via the HHDM mapping of each leaf PA, and stops
/// early on the first page that's not mapped.
///
/// Returns the number of bytes successfully copied (0 if the
/// first page is unmapped). Used by ptrace PEEK and (later)
/// process_vm_readv. Caller must hold an Arc to the target's
/// AddressSpace so `root_pa` stays alive across the walk.
///
/// # SAFETY: `root_pa` is a valid 4 KiB-aligned page-table root
/// owned by a live AddressSpace; HHDM is initialized; the active
/// CPU has IRQs off or the foreign AS is not concurrently torn
/// down (caller's Arc enforces the latter for v1's cooperative
/// scheduler).
/// # C: O(dst.len())
pub unsafe fn read_foreign_user(root_pa: u64, va: u64, dst: &mut [u8]) -> usize {
    let hhdm = hhdm_offset();
    let total = dst.len();
    let mut copied = 0usize;
    while copied < total {
        let cur_va = va + copied as u64;
        let page_off = (cur_va & 0xFFF) as usize;
        let in_page = (4096 - page_off).min(total - copied);
        // SAFETY: root_pa came from a live foreign AS we hold an Arc to; HHDM covers PT memory; reads only.
        let leaf_pa = unsafe {
            read_foreign_leaf_pa(root_pa, cur_va & !0xFFF, hhdm)
        };
        let pa = match leaf_pa { Some(p) => p, None => break };
        // SAFETY: pa is a valid frame from the foreign AS's PT walk;
        // HHDM maps it readable; copy `in_page` bytes from it into
        // dst at offset `copied`.
        unsafe {
            let src = (hhdm + pa + page_off as u64) as *const u8;
            core::ptr::copy_nonoverlapping(src, dst.as_mut_ptr().add(copied), in_page);
        }
        copied += in_page;
    }
    copied
}

/// Symmetric write helper. Returns bytes written; stops on
/// unmapped or read-only-leaf encountered. Read-only stop is
/// honest (does NOT silently bypass W^X); ptrace POKE relies on
/// this to refuse writing to executable code pages until a real
/// CoW path is wired up.
/// # SAFETY: same as `read_foreign_user`. Writes through HHDM
/// mapping of the leaf PA; caller asserts the leaf is writable
/// (we check `is_leaf_writable` before each chunk).
/// # C: O(src.len())
pub unsafe fn write_foreign_user(root_pa: u64, va: u64, src: &[u8]) -> usize {
    let hhdm = hhdm_offset();
    let total = src.len();
    let mut written = 0usize;
    while written < total {
        let cur_va = va + written as u64;
        let page_off = (cur_va & 0xFFF) as usize;
        let in_page = (4096 - page_off).min(total - written);
        // SAFETY: root_pa came from a live foreign AS we hold an Arc to; HHDM covers PT memory; reads only.
        let leaf = unsafe {
            read_foreign_leaf(root_pa, cur_va & !0xFFF, hhdm)
        };
        let (pa, leaf_raw) = match leaf { Some(t) => t, None => break };
        if !leaf_writable(leaf_raw) { break; }
        // SAFETY: pa from a live foreign AS leaf, writable per check; HHDM gives us a kernel-side writable view.
        unsafe {
            let dst = (hhdm + pa + page_off as u64) as *mut u8;
            core::ptr::copy_nonoverlapping(src.as_ptr().add(written), dst, in_page);
        }
        written += in_page;
    }
    written
}

#[cfg(target_arch = "x86_64")]
unsafe fn read_foreign_leaf_pa(root_pa: u64, va_aligned: u64, hhdm: u64) -> Option<u64> {
    use hal_x86_64::vmm::PtWalkerX86;
    // SAFETY: root_pa is a valid PML4 frame; HHDM covers PT memory; reads only.
    unsafe { hal::pt_walker::translate_4k_at_root::<PtWalkerX86>(root_pa, va_aligned, hhdm).map(|(pa, _)| pa) }
}
#[cfg(target_arch = "aarch64")]
unsafe fn read_foreign_leaf_pa(root_pa: u64, va_aligned: u64, hhdm: u64) -> Option<u64> {
    use hal_aarch64::vmm::PtWalkerArm;
    // SAFETY: root_pa is a valid L0 frame; HHDM covers PT memory; reads only.
    unsafe { hal::pt_walker::translate_4k_at_root::<PtWalkerArm>(root_pa, va_aligned, hhdm).map(|(pa, _)| pa) }
}

#[cfg(target_arch = "x86_64")]
unsafe fn read_foreign_leaf(root_pa: u64, va_aligned: u64, hhdm: u64) -> Option<(u64, u64)> {
    use hal_x86_64::vmm::PtWalkerX86;
    // SAFETY: same as read_foreign_leaf_pa; returns leaf raw entry too.
    unsafe { hal::pt_walker::translate_4k_at_root::<PtWalkerX86>(root_pa, va_aligned, hhdm) }
}
#[cfg(target_arch = "aarch64")]
unsafe fn read_foreign_leaf(root_pa: u64, va_aligned: u64, hhdm: u64) -> Option<(u64, u64)> {
    use hal_aarch64::vmm::PtWalkerArm;
    // SAFETY: same as read_foreign_leaf_pa; returns leaf raw entry too.
    unsafe { hal::pt_walker::translate_4k_at_root::<PtWalkerArm>(root_pa, va_aligned, hhdm) }
}

#[cfg(target_arch = "x86_64")]
fn leaf_writable(leaf: u64) -> bool {
    // x86_64: PRESENT (bit 0) AND RW (bit 1) AND USER (bit 2).
    (leaf & 0b111) == 0b111
}
#[cfg(target_arch = "aarch64")]
fn leaf_writable(leaf: u64) -> bool {
    // aarch64 stage-1 EL1/EL0: AP[2:1] @ bits [7:6]; AP=01 means
    // EL0/EL1 read-write. Valid (bit 0) + page (bit 1=1 for L3
    // page descriptor) also required.
    let valid = (leaf & 0b11) == 0b11;
    let ap    = (leaf >> 6) & 0b11;
    valid && ap == 0b01
}

/// Per-PTE mprotect helper. After `AddressSpace::mprotect`
/// updates the VMA tree, call this to actually flip the PTE bits
/// for every present 4 KiB leaf in `[va, va+len)` so the live
/// page tables match the new VmaProt. Otherwise a JIT page that
/// was mapped RW and got mprotect'd to R-only is still
/// hardware-writable (or worse, was R-only and got mprotect'd to
/// RWX but stays unwritable, breaking jemalloc/mimalloc).
///
/// Caller passes the AS root_pa (typically `mm.root_pa()`) plus
/// the new `VmaProt`. Issues per-page TLB flush after rewriting
/// each page's leaf.
///
/// # SAFETY: caller asserts (a) `root_pa` is a live AS root the
/// caller has exclusive write access to (per-AS PT lock or UP +
/// preempt-off), (b) `va`/`len` are page-aligned and inside the
/// user range. HHDM-mapped table memory is read/written.
/// # C: O(len/4096 * walk_depth) + per-page TLB flush
pub unsafe fn mprotect_pages(root_pa: u64, va: u64, len: usize, prot: VmaProt) {
    let hhdm = hhdm_offset();
    let new_flags = prot.to_page_flags();
    let va_start = va & !0xFFF;
    let va_end = va.checked_add(len as u64).map_or(va_start, |e| (e + 0xFFF) & !0xFFF);
    if va_end <= va_start { return; }
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: forwards to the per-arch walker; caller's contract above.
        let _n = unsafe {
            hal::pt_walker::protect_4k_at_root::<hal_x86_64::vmm::PtWalkerX86>(
                root_pa, va_start, va_end, new_flags, hhdm,
            )
        };
        // Flush each page in the range so the new PTE bits take effect.
        let mut p = va_start;
        while p < va_end {
            // SAFETY: invlpg legal at CPL=0; flushes one TLB entry.
            unsafe { hal_x86_64::flush_local_va(p); }
            p = p.wrapping_add(0x1000);
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: forwards to the per-arch walker; caller's contract above.
        let _n = unsafe {
            hal::pt_walker::protect_4k_at_root::<hal_aarch64::vmm::PtWalkerArm>(
                root_pa, va_start, va_end, new_flags, hhdm,
            )
        };
        let mut p = va_start;
        while p < va_end {
            // SAFETY: tlbi+dsb sequence per `21§5`; flushes one EL0/EL1 user page.
            unsafe { hal_aarch64::flush_local_va(p); }
            p = p.wrapping_add(0x1000);
        }
    }
    let _ = (root_pa, new_flags, hhdm); // touch on host/test build
}

/// `extern "C"` teardown invoked from `Arc<AddressSpace>::drop`:
/// walks the user-half page tables rooted at `root_pa`, hands every
/// present leaf frame and intermediate-table page back to PMM, then
/// frees the root frame itself. Without this every fork/exec would
/// leak ~16 KiB of PT pages plus every demand-faulted user page.
///
/// # SAFETY: caller is `AddressSpace::drop` after the last Arc strong
/// ref hit zero — the root is no longer active on any CPU and no
/// concurrent walker / writer remains.
/// # C: O(N_present_leaves + N_present_tables)
#[cfg(target_arch = "x86_64")]
pub unsafe extern "C" fn as_teardown(root_pa: u64) {
    let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
    // SAFETY: per fn contract; HHDM covers PT memory; root quiesced.
    // F157: leaves go through dec_and_maybe_free so COW-shared frames
    // (multiple AS map them) only release once the last AS drops.
    // Tables (intermediate PT levels) are always per-AS — direct free.
    let mut free_leaf = |pa: u64| {
        // SAFETY: `pa` was a leaf reachable from this AS's PT; AS root
        // quiesced per fn contract; crate::setup::dec_and_maybe_free drops
        // refcount and frees on zero.
        unsafe { crate::setup::dec_and_maybe_free_frame(pa); }
    };
    let mut free_table = |pa: u64| {
        // SAFETY: PT tables are always private to this AS; free directly.
        unsafe { crate::setup::free_one_frame(pa); }
    };
    // SAFETY: per fn contract; HHDM covers PT memory; root quiesced.
    unsafe {
        hal::pt_walker::free_user_tree_leafmap::<hal_x86_64::vmm::PtWalkerX86, _, _>(
            root_pa, hhdm, &mut free_leaf, &mut free_table,
        );
    }
    // Free the root frame itself.
    // SAFETY: root_pa is the AS-private root; no longer reachable.
    unsafe { crate::setup::free_one_frame(root_pa); }
}

/// aarch64 mirror of `as_teardown`.
#[cfg(target_arch = "aarch64")]
pub unsafe extern "C" fn as_teardown(root_pa: u64) {
    let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
    // SAFETY: per fn contract; HHDM covers PT memory; root quiesced.
    let mut free_leaf = |pa: u64| {
        // SAFETY: leaf was reachable from this AS's PT; F157 dec-and-free.
        unsafe { crate::setup::dec_and_maybe_free_frame(pa); }
    };
    let mut free_table = |pa: u64| {
        // SAFETY: PT tables are always per-AS; direct free.
        unsafe { crate::setup::free_one_frame(pa); }
    };
    // SAFETY: per fn contract; HHDM covers PT memory; root quiesced.
    unsafe {
        hal::pt_walker::free_user_tree_leafmap::<hal_aarch64::vmm::PtWalkerArm, _, _>(
            root_pa, hhdm, &mut free_leaf, &mut free_table,
        );
    }
    // SAFETY: root_pa is the AS-private root; no longer reachable.
    unsafe { crate::setup::free_one_frame(root_pa); }
}

/// Convenience wrapper: install `as_teardown` on a freshly-built AS.
/// Boot-anchor + hosted-test code paths SHOULD NOT call this — their
/// roots are either fake (test) or shared kernel state (boot).
/// # C: O(1)
pub fn install_teardown(as_: &Arc<AddressSpace>) {
    as_.set_teardown(as_teardown);
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
    // EC = 0x24 data-abort-lower-el; 0x20 insn-abort-lower-el.
    // EC = 0x25 data-abort-same-el; 0x21 insn-abort-same-el.
    // Same-EL aborts arrive when the kernel reads/writes a user VA
    // (e.g. write(2) copies user buffer); demand-paging applies the
    // same way as lower-EL aborts.
    let access = match ec {
        0x20 | 0x21 => FaultAccess::Exec,
        0x24 | 0x25 => {
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
/// only `NotPresent` on Anonymous + KernelBytes VMAs (demand-paging
/// path). Returns true if the fault was resolved (caller retries
/// the faulting instruction); false otherwise. The caller (typically
/// a smoke fault handler) decides whether to deliver SIGSEGV via
/// `sigsegv_terminate_<arch>` or treat as a smoke landmark.
/// # C: O(log N_vmas) + O(walk depth) on demand-page; O(1) reject
#[cfg(target_arch = "x86_64")]
pub fn user_fault_handler(vec: u64, err: u64, _rip: u64, cr2: u64) -> bool {
    if vec != 14 {
        // B44: non-#PF traps (#GP, #UD, #DE, #SS, #AC, ...). If they
        // came from user mode (CPL=3 in saved CS), the right answer
        // is to kill the task with SIGSEGV, not halt the kernel.
        // Without this, a single user-mode #GP (e.g. dhcpcd
        // dereferencing a non-canonical heap pointer) wedges every
        // CPU forever. Kernel-mode trips still fall through to the
        // halt-and-print path so we notice them.
        let frame_ptr = hal_x86_64::current_fault_frame();
        if !frame_ptr.is_null() {
            // SAFETY: live FaultFrame published by oxide_fault_print_rust on the kernel stack; we only read cs to check CPL.
            let cs = unsafe { (*frame_ptr).cs };
            if cs & 3 == 3 {
                deliver_sigsegv_x86(vec, err, _rip, cr2);
            }
        }
        return false;
    }
    let kind = match classify_x86_pf(err, cr2) {
        Some(k) => k,
        None    => return false,
    };
    if handle(cr2, kind) {
        return true;
    }
    // Unhandled fault from user mode. F158: try Linux-style
    // catchable SIGSEGV — rewrite the live FaultFrame to call
    // the user-installed handler. If no handler is installed
    // (SIG_DFL), fall back to terminate via deliver_sigsegv.
    if err & 0x4 != 0 {
        if try_deliver_sigsegv_via_handler_x86(cr2) {
            return true;   // asm iretqs to user handler with rewritten frame
        }
        deliver_sigsegv_x86(vec, err, _rip, cr2);
    }
    false
}

/// # C: O(log N_vmas) + O(walk depth) on demand-page; O(1) reject
#[cfg(target_arch = "aarch64")]
pub fn user_fault_handler(esr: u64, far: u64, _elr: u64) -> bool {
    let kind = match classify_arm_abort(esr, far) {
        Some(k) => k,
        None    => return false,
    };
    if handle(far, kind) {
        return true;
    }
    // Same SIGSEGV-on-user-fault contract as x86. ESR EC bits 26..31
    // distinguish lower-EL (user) from same-EL (kernel-mode user-buf
    // access): EC=0x20/0x24 are EL0 (user), EC=0x21/0x25 are EL1
    // same-EL (kernel-side). Only terminate the task on the EL0 case.
    let ec = (esr >> 26) & 0x3F;
    if matches!(ec, 0x20 | 0x24) {
        deliver_sigsegv_arm(esr, far, _elr);
    }
    false
}

// SIGSEGV delivery + fault-to-signal terminator implementations
// split into `signal.rs` per `08§7` file-length cap.

/// Run the demand-page resolver against a specific AS. F157: uses
/// the COW-aware variant — passes refcount + dec_ref callbacks so
/// Protection-write faults short-circuit to a same-PA W-flip when
/// we're the sole owner, and copy + dec_ref the shared frame
/// otherwise.
/// F158: NotPresent faults try MAP_GROWSDOWN stack auto-extension
/// before falling through to the normal demand-page path.
fn do_handle(as_: &AddressSpace, uva: UserVirtAddr, fault: FaultKind, hhdm: u64)
    -> Result<(), vmm::Error>
{
    // F158: stack auto-grow. If the fault lands just below a
    // GROWSDOWN VMA's start (within Linux's 64 KiB guard distance),
    // extend the VMA to cover the faulting address. Subsequent
    // demand-page resolves it normally.
    if matches!(fault, FaultKind::NotPresent { .. }) {
        if as_.find_vma(uva).is_none() {
            as_.try_grow_stack(uva);
        }
    }
    // SAFETY: live per-arch MmuOps state initialised by kernel_main; alloc closure wraps the global PMM; fault context has IRQs masked; `as_` is borrowed read-only at entry (the AS takes its own RwLock internally). `set_rmap` invokes Linux-shape `page_add_anon_rmap` against the kernel's PageMeta-backed AnonVma slot.
    unsafe {
        #[cfg(target_arch = "x86_64")]
        let r = as_.handle_page_fault_cow_rmap::<hal_x86_64::mmu_ops::X86Mmu, _, _, _, _, _>(
            uva, fault, hhdm,
            || crate::setup::alloc_one_frame(),
            |pa| crate::setup::frame_refcount(pa),
            // SAFETY: dec_ref of a previously-mapped shared frame after COW split; rmap_aware_dec_and_maybe_free clears page->mapping before the frame returns to PMM.
            |pa| crate::setup::rmap_aware_dec_and_maybe_free(pa),
            // SAFETY: live AnonVma; pa is freshly-installed PTE frame.
            |pa, av, idx| crate::setup::set_anon_rmap_for_pa(pa, av, idx),
            // SAFETY: inc_ref for KernelFrame (vvar) so AS-drop dec balances to kernel's reference.
            |pa| unsafe { crate::setup::inc_ref(pa); });
        #[cfg(target_arch = "aarch64")]
        let r = as_.handle_page_fault_cow_rmap::<hal_aarch64::mmu_ops::ArmMmu, _, _, _, _, _>(
            uva, fault, hhdm,
            || crate::setup::alloc_one_frame(),
            |pa| crate::setup::frame_refcount(pa),
            // SAFETY: dec_ref + rmap clear; rmap_aware free path.
            |pa| crate::setup::rmap_aware_dec_and_maybe_free(pa),
            |pa, av, idx| crate::setup::set_anon_rmap_for_pa(pa, av, idx),
            // SAFETY: inc_ref for KernelFrame (vvar); balances AS-drop dec.
            |pa| unsafe { crate::setup::inc_ref(pa); });
        r
    }
}

/// Dispatch the classified fault into the **current task's** AS.
/// Falls back to the global AS for boot-time faults that arrive
/// before any task is current (e.g. the demand-page smoke). Allocates
/// a PMM frame and installs the leaf via per-arch MmuOps; flushes
/// the faulting VA's TLB. Returns true to retry, false to halt.
fn handle(va_raw: u64, fault: FaultKind) -> bool {
    let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
    let uva = match UserVirtAddr::new(va_raw) {
        Some(u) => u,
        None    => return false,
    };
    // Pick the AS the active CR3/TTBR0 actually targets: the
    // current task's mm if there is one (post-execve this is the
    // new AS, not the boot global). With `Task.mm` wrapped in
    // UnsafeCell we read via `mm_ref` under the single-mutator
    // invariant (preempt-off, single-CPU UP).
    let r = if let Some(cur) = sched::live::current() {
        // SAFETY: caller is the fault dispatcher with IRQs masked; cur is the running task on this CPU; no concurrent mm writer.
        if let Some(mm) = unsafe { cur.mm_ref() } {
            Some(do_handle(mm, uva, fault, hhdm))
        } else {
            // kthread; no user AS — fall back to global.
            with(|as_| do_handle(as_, uva, fault, hhdm))
        }
    } else {
        with(|as_| do_handle(as_, uva, fault, hhdm))
    };
    match r {
        Some(Ok(())) => {
            // Flush the faulting VA so the retry sees the new PTE.
            // SAFETY: privileged TLB invalidation legal at CPL=0/EL1.
            #[cfg(target_arch = "x86_64")]
            unsafe { hal_x86_64::flush_local_va(va_raw); }
            // aarch64: a demand-zero (not-present) fault needs no TLBI
            // (hardware doesn't cache faulting translations), but a COW
            // fault replaces a PRESENT read-only PTE with a new writable
            // one — the old translation is live in the TLB and must be
            // invalidated or the retry keeps writing the shared page.
            // SAFETY: tlbi vae1is is privileged at EL1; PTE was just installed.
            #[cfg(target_arch = "aarch64")]
            unsafe { hal_aarch64::flush_local_va(va_raw); }
            true
        }
        _ => false,
    }
}

/// Wrap `AddressSpace::mmap` for `kernel_mmap` syscall glue: takes
/// the Linux mmap arg shape, returns `(va, errno)`. Supports both
/// `MAP_ANONYMOUS` and file-backed mmap; the caller (syscall glue)
/// resolves `fd` to a `Arc<dyn FileBacking>` and passes it in.
/// File offset is honored (page-aligned per Linux EINVAL).
/// # C: O(N_vmas) hole search + O(1) insert
pub fn glue_mmap(
    addr: u64,
    len: u64,
    prot: u64,
    flags: u64,
    fd: i64,
    file_off: u64,
    backing: Option<alloc::sync::Arc<dyn vmm::FileBacking>>,
) -> Result<u64, i64> {
    use syscall::errno::Errno;
    const MAP_SHARED:  u64 = 0x01;
    const MAP_PRIVATE: u64 = 0x02;
    const MAP_FIXED:   u64 = 0x10;
    const MAP_ANON:    u64 = 0x20;
    const MAP_GROWSDOWN: u64       = 0x100;
    const MAP_DENYWRITE: u64       = 0x800;     // no-op since 2.6
    const MAP_EXECUTABLE: u64      = 0x1000;    // no-op since 2.6
    const MAP_LOCKED:    u64       = 0x2000;    // accept as no-op (no swap)
    const MAP_NORESERVE: u64       = 0x4000;    // accept; we don't overcommit
    const MAP_POPULATE:  u64       = 0x8000;    // accept; demand-fault still works
    const MAP_NONBLOCK:  u64       = 0x10000;   // accept; no readahead anyway
    const MAP_STACK:     u64       = 0x20000;   // alias for GROWSDOWN per Linux
    const MAP_HUGETLB:   u64       = 0x40000;   // reject (no huge-tlb yet)
    const MAP_SYNC:      u64       = 0x80000;   // DAX; accept as no-op
    const MAP_FIXED_NOREPLACE: u64 = 0x100000;
    const MAP_UNINITIALIZED: u64   = 0x4000000; // CONFIG_MMAP_ALLOW_UNINITIALIZED
    // Bit-field of all flags we tolerate without semantic effect.
    const MAP_KNOWN: u64 = MAP_SHARED | MAP_PRIVATE | MAP_FIXED | MAP_ANON
        | MAP_GROWSDOWN | MAP_DENYWRITE | MAP_EXECUTABLE | MAP_LOCKED
        | MAP_NORESERVE | MAP_POPULATE | MAP_NONBLOCK | MAP_STACK
        | MAP_HUGETLB | MAP_SYNC | MAP_FIXED_NOREPLACE | MAP_UNINITIALIZED;
    // Linux: unknown flags → EINVAL (kernel rejects future bits).
    if (flags & !MAP_KNOWN) != 0 { return Err(-(Errno::Einval.as_i32() as i64)); }
    // MAP_HUGETLB: huge-page backing; v1 has no huge-tlb pool. Reject.
    if (flags & MAP_HUGETLB) != 0 { return Err(-(Errno::Enosys.as_i32() as i64)); }

    // File-backed mmap requires a backing from the caller and a
    // page-aligned offset; anonymous mmap rejects a backing.
    let is_anon = flags & MAP_ANON != 0;
    let _ = fd;
    if is_anon {
        if backing.is_some() { return Err(-(Errno::Einval.as_i32() as i64)); }
    } else {
        if backing.is_none()       { return Err(-(Errno::Ebadf.as_i32() as i64)); }
        if (file_off & 0xfff) != 0 { return Err(-(Errno::Einval.as_i32() as i64)); }
    }
    if len == 0 { return Err(-(Errno::Einval.as_i32() as i64)); }
    // SHARED + PRIVATE are mutually exclusive per Linux; require
    // exactly one. Linux returns EINVAL when neither is set.
    let is_shared  = flags & MAP_SHARED  != 0;
    let is_private = flags & MAP_PRIVATE != 0;
    if is_shared == is_private { return Err(-(Errno::Einval.as_i32() as i64)); }
    let want_fixed = flags & MAP_FIXED != 0;
    let want_no_replace = flags & MAP_FIXED_NOREPLACE != 0;
    // F158: MAP_STACK is documented as an alias for MAP_GROWSDOWN
    // (sets up a stack VMA the kernel can auto-extend on PF).
    let want_grows_down = flags & (MAP_GROWSDOWN | MAP_STACK) != 0;
    let len_aligned = ((len + 0xfff) & !0xfff) as usize;
    if (want_fixed || want_no_replace) && (addr == 0 || (addr & 0xfff) != 0) {
        return Err(-(Errno::Einval.as_i32() as i64));
    }
    // F158: MAP_FIXED_NOREPLACE — Linux 4.17+. Like MAP_FIXED but
    // returns EEXIST instead of clearing overlap. Used by JIT
    // engines that want to verify no clobber. Detect overlap by
    // probing the AS before the insert.
    if want_no_replace {
        if let Some(cur) = sched::live::current() {
            // SAFETY: mm slot single-mutator per `13§5`.
            if let Some(mm) = unsafe { cur.mm_ref() } {
                let probe = match UserVirtAddr::new(addr) {
                    Some(u) => u, None => return Err(-(Errno::Einval.as_i32() as i64)),
                };
                let probe_end = addr.saturating_add(len_aligned as u64);
                let mut p = probe.as_u64();
                while p < probe_end {
                    if let Some(u) = UserVirtAddr::new(p) {
                        if mm.find_vma(u).is_some() {
                            return Err(-(Errno::Eexist.as_i32() as i64));
                        }
                    }
                    p = p.saturating_add(0x1000);
                }
            }
        }
    }
    // MAP_FIXED is destructive per 11§6: tear down the overlap
    // (PTEs + frames + TLB) via glue_munmap, then insert into the
    // now-hole range via the non-fixed path.
    if want_fixed && !want_no_replace {
        let _ = glue_munmap(addr, len_aligned as u64);
    }
    let is_fixed = false;
    let mut vma_flags = if is_shared {
        if is_anon { VmaFlags::SHARED | VmaFlags::ANONYMOUS }
        else       { VmaFlags::SHARED }
    } else if is_anon {
        VmaFlags::PRIVATE | VmaFlags::ANONYMOUS
    } else {
        VmaFlags::PRIVATE
    };
    // MAP_GROWSDOWN: stack-style auto-grow on PF within Linux's
    // 64 KiB guard distance below vma.start (used by pthread stacks
    // and ld.so's main stack).
    if want_grows_down { vma_flags |= VmaFlags::GROWSDOWN; }
    let vma_backing = match backing {
        Some(b) => VmaBacking::File { backing: b, off: file_off },
        None    => VmaBacking::Anonymous,
    };
    let hint = if addr != 0 {
        match UserVirtAddr::new(addr) {
            Some(uva) => Some(uva),
            None      => return Err(-(Errno::Einval.as_i32() as i64)),
        }
    } else {
        None
    };

    // mmap into the current task's AS, not the boot global —
    // post-execve the running CR3 targets `cur.mm`, not the global.
    let r = if let Some(cur) = sched::live::current() {
        // SAFETY: caller is the syscall dispatcher; preempt-off; running task on this CPU is the sole writer of mm slot.
        if let Some(mm) = unsafe { cur.mm_ref() } {
            mm.mmap(
                hint,
                len_aligned,
                prot_from_linux(prot),
                vma_flags,
                vma_backing.clone(),
                is_fixed,
            )
        } else {
            match with(|as_| as_.mmap(
                hint, len_aligned, prot_from_linux(prot),
                vma_flags, vma_backing.clone(), is_fixed,
            )) {
                Some(r) => r,
                None    => return Err(-(Errno::Enosys.as_i32() as i64)),
            }
        }
    } else {
        match with(|as_| as_.mmap(
            hint, len_aligned, prot_from_linux(prot),
            vma_flags, VmaBacking::Anonymous, is_fixed,
        )) {
            Some(r) => r,
            None    => return Err(-(Errno::Enosys.as_i32() as i64)),
        }
    };
    match r {
        Ok(uva)  => Ok(uva.as_u64()),
        Err(_)   => Err(-(Errno::Enomem.as_i32() as i64)),
    }
}

/// F128: drop every mapped page in `[addr, addr+len)` WITHOUT
/// touching the VMA(s) that cover the range. Mirrors Linux
/// `MADV_DONTNEED` — anonymous pages refault as zero on next
/// access; file pages refault from the file. Refcount-aware:
/// uses `rmap_aware_dec_and_maybe_free` so COW-shared frames
/// don't get yanked from the peer.
/// # C: O(pages)
pub fn evict_pages_in_range(addr: u64, len: u64) -> i64 {
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
        // SAFETY: privileged read of live page tables; va validated user-half above.
        #[cfg(target_arch = "x86_64")]
        let translated = <hal_x86_64::mmu_ops::X86Mmu as MmuOps>::translate(Va(va));
        #[cfg(target_arch = "aarch64")]
        let translated = <hal_aarch64::mmu_ops::ArmMmu as MmuOps>::translate(Va(va));
        if let Some((pa, _flags)) = translated {
            // SAFETY: page is currently mapped; unmap is the inverse of demand-page install. The dec_ref-and-maybe-free that follows handles the COW-shared case correctly (Linux: MADV_DONTNEED on a shared page just unmaps the caller's PTE, never frees the underlying frame).
            unsafe {
                #[cfg(target_arch = "x86_64")]
                <hal_x86_64::mmu_ops::X86Mmu as MmuOps>::unmap(Va(va), PageSize::P4K);
                #[cfg(target_arch = "aarch64")]
                <hal_aarch64::mmu_ops::ArmMmu as MmuOps>::unmap(Va(va), PageSize::P4K);
            }
            // SAFETY: pa was reachable via the live PT entry just unmapped; rmap_aware_dec_and_maybe_free checks struct-page refcount and only releases when the last mapping drops.
            unsafe { crate::setup::rmap_aware_dec_and_maybe_free(pa.0 & !0xfff); }
            // SAFETY: privileged TLB invalidation legal at CPL=0/EL1.
            #[cfg(target_arch = "x86_64")]
            unsafe { hal_x86_64::flush_local_va(va); }
            // aarch64: ArmMmu::unmap issues no TLBI — without this the
            // stale entry keeps the dropped page live, so MADV_DONTNEED's
            // intended zero-on-refault never happens (musl mallocng relies
            // on it; the stale page → metadata garbage → a_crash).
            // SAFETY: tlbi vae1is is privileged at EL1; va was just unmapped.
            #[cfg(target_arch = "aarch64")]
            unsafe { hal_aarch64::flush_local_va(va); }
        }
        va += 0x1000;
    }
    0
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
            // B47: dec_ref + maybe free. Refcount-aware: a frame
            // shared with a forked peer AS (still mapped there via
            // COW) stays alive; only the unconditional free_one_frame
            // path would yank it out from under the peer. dhcpcd's
            // double-fork daemonize triggers this — the launcher's
            // free → munmap → unmap_pte for the if_options heap was
            // freeing pages still mapped in the grandchild's AS,
            // corrupting grandchild's view of the same struct.
            // SAFETY: pa was reachable via the live PT entry just unmapped; rmap_aware_dec_and_maybe_free only releases to PMM when struct-page refcount drops to zero (no other AS maps this frame).
            unsafe { crate::setup::rmap_aware_dec_and_maybe_free(pa.0 & !0xfff); }
            // SAFETY: privileged TLB invalidation legal at CPL=0/EL1.
            #[cfg(target_arch = "x86_64")]
            unsafe { hal_x86_64::flush_local_va(va); }
            // aarch64 ArmMmu::unmap clears the PTE leaf but issues no
            // TLBI, so without this the stale TLB entry keeps translating
            // the VA to the freed page. musl's mallocng munmaps a group
            // then mmaps the same address; the stale TLB served the old
            // (now-reused) page → allocator metadata read garbage →
            // a_crash() (NULL-write trap). Mirror the x86 per-page flush.
            // SAFETY: tlbi vae1is is privileged at EL1; va was just unmapped.
            #[cfg(target_arch = "aarch64")]
            unsafe { hal_aarch64::flush_local_va(va); }
        }
        va += 0x1000;
    }

    // VMA bookkeeping side. Post-execve the running CR3 targets
    // cur.mm — that's where the user's VMAs live, not the global
    // boot AS. Mirror glue_mmap so MAP_FIXED's overlap-clear
    // (via glue_munmap) hits the right AS.
    let uva = match UserVirtAddr::new(addr) {
        Some(u) => u,
        None    => return -(Errno::Einval.as_i32() as i64),
    };
    let r = if let Some(cur) = sched::live::current() {
        // SAFETY: running task on this CPU; sole mm writer.
        if let Some(mm) = unsafe { cur.mm_ref() } {
            Some(mm.munmap(uva, len_aligned as usize))
        } else {
            with(|as_| as_.munmap(uva, len_aligned as usize))
        }
    } else {
        with(|as_| as_.munmap(uva, len_aligned as usize))
    };
    match r {
        Some(Ok(()))  => 0,
        Some(Err(_))  => -(Errno::Einval.as_i32() as i64),
        None          => -(Errno::Enosys.as_i32() as i64),
    }
}
