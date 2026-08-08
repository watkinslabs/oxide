// Architecture fault-vector entry: classify the trap, dispatch it into the
// running task's address space, and turn an unresolved user fault into the
// signal the architecture names.

use super::super::*;
use super::resolve::do_handle;

#[cfg(all(feature = "debug-mount", target_arch = "x86_64"))]
use crate::user_as::debug::{STEP_ROOT, STEP_RIP, STEP_VA};

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
            // SAFETY: live PtRegs published by oxide_fault_print_rust on the kernel stack; we only read cs to check CPL.
            let cs = unsafe { (*frame_ptr).cs };
            if cs & 3 == 3 {
                // Linux `do_error_trap`/`exc_general_protection`: a synchronous
                // trap from CPL=3 becomes the signal the ARCHITECTURE names
                // (SIGILL for #UD, SIGFPE for #DE, SIGBUS for #AC, …), queued
                // with its `_sigfault` record. Reporting every one as a
                // terminating SIGSEGV made a handled SIGFPE unhandleable.
                signal::trace_user_fault_x86(vec, err, _rip, cr2);
                return force_user_fault_x86(vec, err, _rip, cr2, None);
            }
        }
        return false;
    }
    let kind = match classify_x86_pf(err, cr2) {
        Some(k) => k,
        None    => return false,
    };
    // DIAG (debug-mount): the libc lock page is mapped RO (File arm) so its
    // first write traps here — log the writing instruction's RIP. RIP inside
    // glibc lll_lock = the lock pointer is right (a different bug); RIP inside
    // a str/mem* or a stray addr (cr2 != the lock word) = the corruptor.
    #[cfg(feature = "debug-mount")]
    if matches!(kind, FaultKind::Protection { access: FaultAccess::Write }) {
        if let Some(cur) = sched::live::current() {
            // SAFETY: single-mutator mm slot per 13§5; read-only VMA query.
            if let Some(mm) = unsafe { cur.mm_ref() } {
                if let Some(uva) = UserVirtAddr::new(cr2 & !super::PAGE_MASK) {
                    if let Some(v) = mm.find_vma(uva) {
                        if let VmaBacking::File { off, backing } = &v.backing {
                            let foff = off.wrapping_add((cr2 & !super::PAGE_MASK).wrapping_sub(v.start.as_u64()));
                            if foff == 0x1e7000 && backing.ino() == 0x6e54000000062076
                                && STEP_VA.load(Ordering::Acquire) == 0 {
                                // Single-step write-trap: make the page writable
                                // in place, arm RFLAGS.TF so a #DB fires right
                                // after THIS write instruction, and stash the
                                // target/RIP. The #DB hook (lock_step_hook) then
                                // reads the bytes just written — when they're an
                                // ASCII path ("/lib…") that RIP is the corruptor
                                // — re-protects the page RO, and clears TF.
                                let root = mm.root_pa();
                                // SAFETY: `root` is the faulting task's own live
                                // root, mutated here on the CPU that took the
                                // fault for exactly one page inside the VMA `v`
                                // that was just looked up in that same mm.
                                unsafe { mprotect_pages(root, cr2 & !super::PAGE_MASK, super::PAGE_BYTES as usize, VmaProt::READ | VmaProt::WRITE, v.pkey); }
                                let f = hal_x86_64::current_fault_frame();
                                if !f.is_null() {
                                    // SAFETY: live PtRegs on the kernel stack; set TF (bit 8).
                                    unsafe { (*f).rflags |= 0x100; }
                                    STEP_ROOT.store(root, Ordering::Release);
                                    STEP_RIP.store(_rip, Ordering::Release);
                                    STEP_VA.store(cr2, Ordering::Release);
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    // Linux `FAULT_FLAG_USER`: #PF error-code bit 2 (U/S) is set when the
    // access that faulted was issued at CPL=3. Kernel-mode faults on a user VA
    // (uaccess, exec's direct stack pushes) clear it, and a
    // `UFFD_USER_MODE_ONLY` context refuses to intercept those.
    let failure = match handle(cr2, kind, err & 0x4 != 0) {
        Ok(())   => return true,
        Err(f)   => f,
    };
    // debug-cow probe 2: the fault is now fatal (the demand-page resolver
    // refused it). Dump the failing VA + VMA + PTE/frame before SIGSEGV.
    #[cfg(feature = "debug-cow")]
    segv_dump(_rip, cr2, err);
    // Unhandled fault from user mode. Linux `bad_area` -> `force_sig_fault`:
    // queue the signal the RESOLVER's reason earns — a hardware-classified
    // SIGSEGV (SEGV_MAPERR / SEGV_ACCERR / SEGV_PKUERR) for an absent or
    // forbidden mapping, SIGBUS/BUS_ADRERR for a mapping whose backing could
    // not supply the page, and no signal at all for the out-of-memory and
    // retry reasons, which resume userspace so the instruction re-faults.
    if err & 0x4 != 0 {
        signal::trace_user_fault_x86(vec, err, _rip, cr2);
        return force_user_fault_x86(vec, err, _rip, cr2, Some(failure));
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
    // Linux `FAULT_FLAG_USER`: EC 0x20/0x24 are instruction/data aborts from a
    // LOWER exception level (EL0 user); 0x21/0x25 are the same-EL (kernel
    // uaccess) forms, which clear the flag.
    let user_mode = matches!((esr >> 26) & 0x3F, 0x20 | 0x24);
    let failure = match handle(far, kind, user_mode) {
        Ok(())  => return true,
        Err(f)  => f,
    };
    #[cfg(feature = "debug-displaystack")]
    if let Some(cur) = sched::live::current() {
        // SAFETY: the synchronous EL0 fault runs against the current task;
        // this trace only snapshots the task-owned AddressSpace VMA tree.
        if let Some(mm) = unsafe { cur.mm_ref() } { dump_arm_vmas(mm); }
    }
    // Retained executable-stack fault provenance.  The same display-stack
    // feature that traces wait/futex calls records the exception class and
    // exact EL0/EL1 return PC when a child fails during desktop startup.
    // This is diagnostic-only and absent from production builds.
    #[cfg(feature = "debug-displaystack")]
    if let Some(cur) = sched::live::current() {
        klog::write_raw(b"[FAULT-ARM-CTX] tid=");
        klog::write_dec_u64(cur.tid as u64);
        klog::write_raw(b" vpid=");
        klog::write_dec_u64(cur.vtgid.load(Ordering::Acquire) as u64);
        klog::write_raw(b" esr=");
        klog::write_hex_u64(esr);
        klog::write_raw(b" ec=");
        klog::write_hex_u64((esr >> 26) & 0x3F);
        klog::write_raw(b" far=");
        klog::write_hex_u64(far);
        klog::write_raw(b" elr=");
        klog::write_hex_u64(_elr);
        klog::write_raw(b"\n");
    }
    // D339: distinguish a missing VMA from a page-table/fault-fill failure
    // for the ARM userspace translation fault that blocks target verification.
    #[cfg(feature = "debug-faultdiag")]
    if let Some(cur) = sched::live::current() {
        // SAFETY: the current task's mm is read under the active-task
        // single-mutator invariant while handling its synchronous fault.
        if let Some(mm) = unsafe { cur.mm_ref() } {
            klog::write_raw(b"[FAULT-ARM-VMA] far=");
            klog::write_hex_u64(far);
            klog::write_raw(b" root=");
            klog::write_hex_u64(mm.root_pa());
            if let Some(v) = hal::UserVirtAddr::new(far).and_then(|va| mm.find_vma(va)) {
                klog::write_raw(b" hit start=");
                klog::write_hex_u64(v.start.as_u64());
                klog::write_raw(b" end=");
                klog::write_hex_u64(v.end.as_u64());
                klog::write_raw(b" prot=");
                klog::write_hex_u64(v.prot.bits() as u64);
                klog::write_raw(b" flags=");
                klog::write_hex_u64(v.flags.bits() as u64);
            } else {
                klog::write_raw(b" miss");
            }
            klog::write_raw(b"\n");
        }
    }
    // debug-cow probe 2: fatal fault — dump VA/VMA/PTE before SIGSEGV.
    // (ELR / FAR / ESR map to the rip / cr2 / err columns.)
    #[cfg(feature = "debug-cow")]
    segv_dump(_elr, far, esr);
    // Same SIGSEGV-on-user-fault contract as x86. ESR EC bits 26..31
    // distinguish lower-EL (user) from same-EL (kernel-mode user-buf
    // access): EC=0x20/0x24 are EL0 (user), EC=0x21/0x25 are EL1
    // same-EL (kernel-side). Only terminate the task on the EL0 case.
    let ec = (esr >> 26) & 0x3F;
    if matches!(ec, 0x20 | 0x24) {
        signal::trace_user_fault_arm(esr, far, _elr);
        return force_user_fault_arm(esr, far, _elr, Some(failure));
    }
    false
}

/// Falls back to the global AS for boot-time faults that arrive
/// before any task is current (e.g. the demand-page smoke). Allocates
/// a PMM frame and installs the leaf via per-arch MmuOps; flushes
/// the faulting VA's TLB.
///
/// `Ok(())` = the leaf is installed, retry the instruction. `Err(f)` names WHY
/// the fault could not be resolved, so the caller can report the signal that
/// reason earns (`vmm::fault_signal`) instead of guessing from the hardware
/// error code alone.
/// # C: O(log N_vmas) + O(walk depth)
fn handle(va_raw: u64, fault: FaultKind, user_mode: bool)
    -> Result<(), vmm::fault_signal::FaultFailure>
{
    let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
    let uva = match UserVirtAddr::new(va_raw) {
        Some(u) => u,
        None    => return Err(vmm::fault_signal::FaultFailure::BadArea),
    };
    // DIAG (debug-atexit): the File fill installs lib-arena writable pages
    // READ-ONLY, so the FIRST write to a correctly-filled library page arrives
    // here as Protection{Write}. Capture the writing RIP (user ld.so text vs
    // kernel) + the pre-write bytes at the observed corruption offset (0x20).
    // A bulk `rep stosq` memset faults on its first store, so this names a
    // memset zeroer; the RIP range names user vs kernel.
    #[cfg(all(feature = "debug-atexit", target_arch = "x86_64"))]
    if matches!(fault, FaultKind::Protection { access: FaultAccess::Write })
        && (0x7ffff6000000..0x7ffff8000000).contains(&va_raw) {
        let fp = hal_x86_64::current_fault_frame();
        // SAFETY: null-checked; a non-null `current_fault_frame` is this CPU's
        // live `PtRegs` on its own kernel stack, valid for the whole handler.
        let rip = if fp.is_null() { 0 } else { unsafe { (*fp).rip } };
        // memset lives at ld.so bias 0x40000000 + [0x24970, 0x24a40). When the
        // zeroing store faults inside memset, dump its ARGS (rdi=dst, sil=val,
        // rdx=len) — the exact range ld.so clears. A val==0 memset whose
        // [dst,dst+len) spans file-data pages is the corruption: ld.so's BSS
        // clear range is wrong (kernel gave it a bad filesz/segment view).
        // Log the EXACT faulting offset (cr2 low 12 bits) + RIP for writes near
        // a .dynamic entry boundary (offset a multiple of 0x10, i.e. an
        // Elf64_Dyn slot). A zeroed slot at offset 0x20/0x40/... = DT_NULL early
        // terminator. memset RIPs additionally dump their dst/len.
        let off = va_raw & super::PAGE_MASK;
        let in_memset = (0x40024970..0x40024a40).contains(&rip);
        static WCOUNT: AtomicU64 = AtomicU64::new(0);
        if (off < 0x400) && WCOUNT.fetch_add(1, Ordering::Relaxed) < 300 {
            klog::write_raw(b"[W] va=");
            klog::write_hex_u64(va_raw);
            klog::write_raw(b" rip=");
            klog::write_hex_u64(rip);
            if in_memset {
                let gp = hal_x86_64::current_fault_frame();
                if !gp.is_null() {
                    // SAFETY: null-checked; a non-null `current_fault_frame` is
                    // this CPU's live `PtRegs` on its own kernel stack, and the
                    // borrow ends before the handler returns.
                    let g = unsafe { &*gp };
                    klog::write_raw(b" MEMSET dst=");
                    klog::write_hex_u64(g.rdi);
                    klog::write_raw(b" len=");
                    klog::write_hex_u64(g.rdx);
                }
            }
            klog::write_raw(b" tid=");
            klog::write_dec_u64(sched::live::current().map(|c| c.tid as u64).unwrap_or(0));
            klog::write_raw(b"\n");
        }
    }
    // Pick the AS the active CR3/TTBR0 actually targets: the
    // current task's mm if there is one (post-execve this is the
    // new AS, not the boot global). With `Task.mm` wrapped in
    // UnsafeCell we read via `mm_ref` under the single-mutator
    // invariant (preempt-off, single-CPU UP).
    // Resolve against the running task's mm only. There is no global address
    // space: every user fault belongs to the current task's AS. A user-VA
    // fault with no current user task (boot context before PID 1, or a kthread)
    // is a kernel bug, not something to paper over against a shared AS — return
    // unhandled so it surfaces. The boot PID-1 stack is mapped eagerly via
    // `prefault_stack` (setup_arg_pages), so no boot-context user fault occurs.
    // Linux charges every *completed*
    // user fault to `current->min_flt`, or to `maj_flt` when the fill had to
    // reach backing store (`VM_FAULT_MAJOR`). oxide's file fill
    // (`mm-vmm address_space/fault/fill.rs`) has no page-cache short-circuit:
    // a NotPresent fault on a file-backed VMA always issues `read_at` against
    // the block device, which is exactly Linux's `filemap_fault` cache-miss
    // arm. Anonymous, COW and protection faults never touch backing store.
    let cur = sched::live::current();
    let major = matches!(fault, FaultKind::NotPresent { .. })
        && cur.as_ref().is_some_and(|c| {
            // SAFETY: synchronous fault on the running task; single-mutator mm slot per 13§5; read-only VMA query.
            unsafe { c.mm_ref() }.and_then(|mm| mm.find_vma(uva))
                .is_some_and(|v| matches!(v.backing, VmaBacking::File { .. }))
        });
    let r = match cur.as_ref() {
        // SAFETY: synchronous fault; cur is the running task and no concurrent mm writer owns its slot.
        Some(cur) => unsafe { cur.mm_ref() }.map(|mm| do_handle(mm, uva, fault, hhdm, user_mode)),
        None => None,
    };
    if matches!(r, Some(Ok(()))) {
        if let Some(c) = cur.as_ref() {
            sched::rusage_charge::fault(c, major);
            let kind = if major { sched::perf_sw::CpuSw::MajFlt } else { sched::perf_sw::CpuSw::MinFlt };
            sched::perf_sw::charge(kind, c.cpu.load(Ordering::Acquire) as usize, 1);
        }
    }
    #[cfg(all(feature = "debug-faultdiag", target_arch = "x86_64"))]
    if !matches!(&r, Some(Ok(()))) {
        klog::write_raw(b"[FAULT-RESOLVE] va=");
        klog::write_hex_u64(va_raw);
        klog::write_raw(b" rip=");
        let frame = hal_x86_64::current_fault_frame();
        if frame.is_null() {
            klog::write_raw(b"none");
        } else {
            // SAFETY: the architecture publishes the live fault frame for
            // the duration of this synchronous fault dispatch.
            klog::write_hex_u64(unsafe { (*frame).rip });
        }
        match fault {
            FaultKind::NotPresent { access: _ } => klog::write_raw(b" kind=np"),
            FaultKind::Protection { access: _ } => klog::write_raw(b" kind=prot"),
        }
        let access = match fault {
            FaultKind::NotPresent { access } | FaultKind::Protection { access } => access,
        };
        match access {
            FaultAccess::Read => klog::write_raw(b" access=read"),
            FaultAccess::Write => klog::write_raw(b" access=write"),
            FaultAccess::Exec => klog::write_raw(b" access=exec"),
        }
        match &r {
            None => klog::write_raw(b" result=no-mm"),
            Some(Err(vmm::Error::NotImplemented)) => klog::write_raw(b" result=not-implemented"),
            Some(Err(vmm::Error::NoMem)) => klog::write_raw(b" result=no-mem"),
            Some(Err(vmm::Error::Inval)) => klog::write_raw(b" result=invalid"),
            Some(Err(vmm::Error::Fault)) => klog::write_raw(b" result=fault"),
            Some(Err(vmm::Error::Perm)) => klog::write_raw(b" result=permission"),
            Some(Err(vmm::Error::Again)) => klog::write_raw(b" result=again"),
            Some(Err(vmm::Error::Access)) => klog::write_raw(b" result=access"),
            Some(Err(vmm::Error::Io)) => klog::write_raw(b" result=io"),
            Some(Ok(())) => klog::write_raw(b" result=ok"),
        }
        klog::write_raw(b" cr3=");
        klog::write_hex_u64(hal_x86_64::read_cr3() & !super::PAGE_MASK);
        // SAFETY: `mm_ref` requires no concurrent execve replacing the mm; the
        // task is the CURRENT one, which is sitting in its own fault handler
        // and so cannot be executing execve against itself.
        match sched::live::current().and_then(|cur| unsafe { cur.mm_ref() }) {
            Some(mm) => {
                klog::write_raw(b" mm=");
                klog::write_hex_u64(mm.root_pa());
                if let Some(vma) = mm.find_vma(uva) {
                    klog::write_raw(b" vma=");
                    klog::write_hex_u64(vma.start.as_u64());
                    klog::write_raw(b"-");
                    klog::write_hex_u64(vma.end.as_u64());
                    klog::write_raw(b" prot=");
                    klog::write_hex_u64(vma.prot.bits() as u64);
                } else { klog::write_raw(b" vma=none"); }
            }
            None => klog::write_raw(b" mm=none"),
        }
        klog::write_raw(b"\n");
    }
    match r {
        Some(Ok(())) => {
            // Flush the faulting VA so the retry sees the new PTE.
            // SAFETY: privileged TLB invalidation legal at CPL=0/EL1.
            #[cfg(target_arch = "x86_64")]
            unsafe { hal_x86_64::flush_local_va(va_raw); }
            // Prior no-op left a stale TLB entry on a remapped VA (heap
            // churn); the inner-shareable tlbi is also mandatory once APs
            // share the page tables. Use the existing ArmMmu::flush_va.
            #[cfg(target_arch = "aarch64")]
            // SAFETY: tlbi vae1is invalidates the just-mapped VA so the faulting instruction's retry walks the new PTE; privileged but legal at EL1.
            unsafe { <hal_aarch64::mmu_ops::ArmMmu as hal::MmuOps>::flush_va(hal::Va(va_raw)); }
            Ok(())
        }
        // The resolver's reason survives to the caller. Collapsing it to a
        // bare bool made a mapping whose backing could not be read
        // indistinguishable from an address with no mapping at all, so the
        // signal had to be guessed from the hardware error code — and a failed
        // file fill was reported as a segmentation fault.
        Some(Err(e)) => Err(vmm::fault_signal::failure_of(e)),
        // No mm, or an address outside the user range: there is nothing this
        // fault could have been resolved against.
        None => Err(vmm::fault_signal::FaultFailure::BadArea),
    }
}
