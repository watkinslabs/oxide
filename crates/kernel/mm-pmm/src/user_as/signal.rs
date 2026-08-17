// Synchronous-fault -> signal delivery, split out of user_as.rs per `08§7`.
//
// This file used to hand-write a `siginfo_t` onto the user stack and rewrite
// the live fault frame to jump straight at the handler — a SECOND, parallel
// signal path that never touched the pending queue. Consequences: `signalfd`
// and `rt_sigtimedwait` could never observe a fault signal, si_code was always
// SEGV_MAPERR whatever the fault was, the frame carried no ucontext so a
// handler that returned resumed with garbage registers, and the `force_sig_info`
// ladder (a blocked or ignored fault signal must be forcibly unblocked and reset
// to SIG_DFL, not dropped) never ran.
//
// Now there is ONE path: classify the trap (`hal::fault_class`), queue it via
// `sched::live::force_sig_fault` (Linux `force_sig_fault`), and let the fault
// vector's existing `oxide_irq_exit_to_user` epilogue run the return-to-user
// work loop, which builds a real `rt_sigframe` through the same builder every
// other signal uses. The `coredump_then_terminate` path below survives only for
// the callers that have no live user frame to return through.

/// Linux `force_sig_fault(sig, code, addr)` for an unresolved USER-MODE
/// exception: classify the trap, queue the signal with its full `_sigfault`
/// record against the faulting thread, and return so the fault vector's
/// `oxide_irq_exit_to_user` epilogue delivers it through the ONE
/// return-to-user work loop.
///
/// `vec` is the IDT vector, `err` its error code (`#PF` bits, else 0) and `pc`
/// the faulting RIP. Returns `true` unconditionally — "resume to user mode",
/// which is what lets the work loop run. The signal is already pending, so
/// either a handler frame is built or the SIG_DFL fatal action ends the group;
/// neither outcome comes back here.
///
/// `failure` is the demand-page resolver's reason, present for a `#PF` the
/// resolver refused and absent for a trap that never reached it. The hardware
/// status word cannot tell an absent mapping from a mapping whose backing
/// could not supply the page, so the reason — not the error code — picks the
/// signal (`vmm::fault_signal`).
/// # C: O(1)
#[cfg(target_arch = "x86_64")]
pub fn force_user_fault_x86(vec: u64, err: u64, pc: u64, cr2: u64,
                            failure: Option<vmm::fault_signal::FaultFailure>) -> bool {
    use hal::fault_class::x86_64 as fc;
    let (arch_cls, addr) = if vec == fc::TRAP_PF { (fc::page_fault(err), cr2) }
                           else { (fc::trap(vec), fc::trap_addr(vec, pc)) };
    let Some(cls) = resolver_signal(failure, arch_cls) else { return true; };
    // The entry publisher snapshots RSP with the live frame. Never
    // dereference the CPU-global frame pointer here: a fault resolver may
    // switch tasks before signal reporting, and a stale pointer can name a
    // released task stack.
    let sp = hal_x86_64::current_fault_rsp();
    sched::signal_report::report_user_fault(signum_from(cls.signo).as_u8() as u32, addr, pc, sp, err, vma_at(pc));
    raise(cls, addr);
    true
}

/// aarch64 form. `esr` is ESR_EL1, `far` FAR_EL1 (the faulting address for the
/// abort classes) and `elr` the faulting PC. `failure` carries the same
/// resolver reason as the x86 form and is consulted through the same one
/// mapping — the two architectures do not each own a copy of this decision.
/// # C: O(1)
#[cfg(target_arch = "aarch64")]
pub fn force_user_fault_arm(esr: u64, far: u64, elr: u64,
                            failure: Option<vmm::fault_signal::FaultFailure>) -> bool {
    use hal::fault_class::aarch64 as fc;
    let Some(cls) = resolver_signal(failure, fc::sync(esr)) else { return true; };
    // The abort classes report FAR_EL1; every other synchronous EL0 exception
    // (BRK, illegal state, FP) names the instruction that raised it.
    let addr = if fc::from_el0(esr) || matches!(fc::ec(esr), fc::EC_PC_ALIGN | fc::EC_SP_ALIGN)
               { far } else { elr };
    let sp_el0: u64;
    // SAFETY: `mrs sp_el0` is a side-effect-free privileged read at EL1; SP_EL0 still holds the interrupted EL0 stack pointer inside the fault vector.
    unsafe { core::arch::asm!("mrs {}, sp_el0", out(reg) sp_el0, options(nomem, nostack, preserves_flags)); }
    // The reference reports ESR in the `error` position on this arch.
    sched::signal_report::report_user_fault(signum_from(cls.signo).as_u8() as u32, addr, elr, sp_el0, esr, vma_at(elr));
    raise(cls, addr);
    true
}

/// Fold the resolver's failure reason into the hardware classification.
///
/// `None` in, `Some(arch)` out: a synchronous trap that never went through the
/// demand-page resolver (`#UD`, `#DE`, a BRK) is classified by the
/// architecture alone. `Some(reason)` in: the ONE mapping in
/// `vmm::fault_signal` decides, and it may answer `None` — no signal, resume
/// userspace, re-take the fault. Both architectures call this; neither owns a
/// second copy of the mapping.
/// # C: O(1)
fn resolver_signal(failure: Option<vmm::fault_signal::FaultFailure>,
                   arch: hal::fault_class::FaultSignal)
    -> Option<hal::fault_class::FaultSignal>
{
    let sig = match failure {
        None    => Some(arch),
        Some(f) => vmm::fault_signal::signal_for(f, arch),
    };
    // A fill that could not obtain memory raises no signal on the faulting
    // task — it runs the out-of-memory selector, which kills the process
    // consuming the machine, and then re-takes the instruction so it can use
    // what that process releases. Skipping the selector is what turns a
    // pressure spike into an unbounded refault loop: nothing else on this path
    // can change the answer the retry gets.
    if failure.is_some_and(vmm::fault_signal::invokes_out_of_memory) {
        // Out of memory with nothing left that may be killed is not a
        // condition userspace can be told about: every survivor is protected,
        // so the retry would spin the same instruction forever.
        crate::kassert!(sched::oom::pagefault_out_of_memory() != sched::oom::FaultOutcome::Deadlocked,
                        "out of memory and no killable process");
    }
    sig
}

/// Resolve the mapping covering `ip` in the faulting task's own mm, for the
/// unhandled-fault report's `print_vma_addr` tail. `None` when there is no
/// current task or the address is unmapped (the report then omits the tail).
/// # C: O(log N)
fn vma_at(ip: u64) -> Option<sched::signal_report::VmaAddr> {
    use vmm::vma::VmaBacking;
    let cur = sched::live::current()?;
    // SAFETY: synchronous fault dispatch on the faulting task's own CPU, so `cur` is the running task and its mm slot has no concurrent mutator; the query is read-only.
    let mm = unsafe { cur.mm_ref() }?;
    let v = mm.find_vma(hal::UserVirtAddr::new(ip)?)?;
    let start = v.start.as_u64();
    // The MAPPING's file, never the process's executable: a fault inside a
    // shared library belongs to that library, and the file-relative offset is
    // only meaningful against the file it is an offset into. The name is copied
    // by value inside `vma_addr_from` because it is borrowed from the backing
    // under the mm lock while the report is emitted after that borrow ends.
    let file = match &v.backing {
        VmaBacking::File { backing, off } => backing.map_path().map(|p| (p, *off)),
        _ => None,
    };
    Some(sched::signal_report::vma_addr_from(start, v.end.as_u64(), ip, file))
}

/// Queue one classified fault signal. A signo the classifier could not map
/// still becomes SIGSEGV rather than nothing — an unhandled user-mode
/// exception that raised no signal would spin the faulting instruction forever.
/// # C: O(1)
fn raise(cls: hal::fault_class::FaultSignal, addr: u64) {
    let sig = signum_from(cls.signo);
    if cls.code == hal::siginfo::code::SEGV_PKUERR {
        sched::live::force_sig_pkey_fault(sig, addr, fault_pkey(addr) as i32);
    } else {
        sched::live::force_sig_fault(sig, cls.code, addr, 0);
    }
}

/// `siginfo.si_pkey` is meaningful only for an access rejected by the
/// protection-key mechanism. The VMA is the sole mapping-level key owner,
/// including a key changed by `pkey_mprotect`; ordinary faults retain zero.
/// # C: O(log N_vmas)
fn fault_pkey(addr: u64) -> u32 {
    let Some(cur) = sched::live::current() else { return 0; };
    // SAFETY: synchronous fault dispatch runs on the faulting task; the VMA
    // lookup is read-only and the task's mm remains live for this handler.
    let Some(mm) = (unsafe { cur.mm_ref() }) else { return 0; };
    hal::UserVirtAddr::new(addr).and_then(|uva| mm.find_vma(uva))
        .map_or(0, |vma| vma.pkey as u32)
}

/// Map a classifier signo onto the typed `Signum`. The classifier only ever
/// produces the five `_sigfault` signals; anything else is a bug in the table
/// and is reported as SIGSEGV rather than silently dropped.
/// # C: O(1)
fn signum_from(signo: u8) -> sched::signum::Signum {
    use sched::signum::Signum;
    match signo {
        s if s == Signum::Sigill.as_u8()  => Signum::Sigill,
        s if s == Signum::Sigtrap.as_u8() => Signum::Sigtrap,
        s if s == Signum::Sigbus.as_u8()  => Signum::Sigbus,
        s if s == Signum::Sigfpe.as_u8()  => Signum::Sigfpe,
        _ => Signum::Sigsegv,
    }
}

/// Diagnostic dump for an unresolved user-mode fault. Runs BEFORE the signal
/// is queued so a crash under a debug build still names the faulting register
/// state; the fault itself is reported through `force_user_fault_x86`.
#[cfg(target_arch = "x86_64")]
pub(super) fn trace_user_fault_x86(vec: u64, err: u64, rip: u64, cr2: u64) {
    let _ = (vec, err, rip, cr2); // consumed only by the cfg-gated dumps below
    #[cfg(any(feature = "debug-irq", feature = "debug-faultdiag"))]
    {
        klog::write_raw(b"[FAULT] sigsegv: kill tid=");
        if let Some(c) = sched::live::current() { klog::write_dec_u64(c.tid as u64); }
        klog::write_raw(b" vec=");      klog::write_hex_u64(vec);
        klog::write_raw(b" err=");      klog::write_hex_u64(err);
        klog::write_raw(b" rip=");      klog::write_hex_u64(rip);
        klog::write_raw(b" cr2=");      klog::write_hex_u64(cr2);
        klog::write_raw(b"\n");
        // B45: dump every general-purpose register the stub captured.
        // Lets us name the bad register on a #GP without re-attaching
        // gdb. Kernel-mode trips get their dump from
        // oxide_fault_print_rust (which only fires when the handler
        // returns false); the SIGSEGV path diverges before that block
        // runs, so we mirror the dump here.
        let gp = hal_x86_64::current_fault_frame();
        if !gp.is_null() {
            // SAFETY: stub-built PtRegs on the kernel stack; valid for read while we're in fault dispatch (the stub doesn't pop until after the Rust dispatcher returns — which it doesn't here, since we diverge — so the slots stay live for the schedule()-away that follows).
            let g = unsafe { &*gp };
            klog::write_raw(b"[FAULT] rax=");  klog::write_hex_u64(g.rax);
            klog::write_raw(b" rbx=");          klog::write_hex_u64(g.rbx);
            klog::write_raw(b" rcx=");          klog::write_hex_u64(g.rcx);
            klog::write_raw(b" rdx=");          klog::write_hex_u64(g.rdx);
            klog::write_raw(b"\n[FAULT] rsi="); klog::write_hex_u64(g.rsi);
            klog::write_raw(b" rdi=");          klog::write_hex_u64(g.rdi);
            klog::write_raw(b" rbp=");          klog::write_hex_u64(g.rbp);
            klog::write_raw(b"\n[FAULT] r8=");  klog::write_hex_u64(g.r8);
            klog::write_raw(b" r9=");           klog::write_hex_u64(g.r9);
            klog::write_raw(b" r10=");          klog::write_hex_u64(g.r10);
            klog::write_raw(b" r11=");          klog::write_hex_u64(g.r11);
            klog::write_raw(b"\n[FAULT] r12="); klog::write_hex_u64(g.r12);
            klog::write_raw(b" r13=");          klog::write_hex_u64(g.r13);
            klog::write_raw(b" r14=");          klog::write_hex_u64(g.r14);
            klog::write_raw(b" r15=");          klog::write_hex_u64(g.r15);
            klog::write_raw(b"\n");
        }
    }
}

/// aarch64 form of [`trace_user_fault_x86`].
#[cfg(target_arch = "aarch64")]
pub(super) fn trace_user_fault_arm(esr: u64, far: u64, elr: u64) {
    let _ = (esr, far, elr); // consumed only by the cfg-gated dumps below
    #[cfg(any(feature = "debug-irq", feature = "debug-boot"))]
    {
        use core::sync::atomic::Ordering;
        klog::write_raw(b"[FAULT-ARM] tid=");
        if let Some(c) = sched::live::current() {
            klog::write_dec_u64(c.tid as u64);
            klog::write_raw(b" vpid=");
            klog::write_dec_u64(c.vtgid.load(Ordering::Acquire) as u64);
            klog::write_raw(b" last_nr=");
            klog::write_dec_u64(c.last_syscall_nr.load(Ordering::Relaxed) as u64);
            c.with_exe_path(|path| if let Some(path) = path {
                klog::write_raw(b" exe=");
                klog::write_raw(path.as_bytes());
            });
        }
        klog::write_raw(b" esr=");      klog::write_hex_u64(esr);
        klog::write_raw(b" ec=");       klog::write_hex_u64((esr >> 26) & 0x3f);
        klog::write_raw(b" dfsc=");     klog::write_hex_u64(esr & 0x3f);
        klog::write_raw(b" far=");      klog::write_hex_u64(far);
        klog::write_raw(b" elr=");      klog::write_hex_u64(elr);
        // Dump user SP_EL0 (= user SP at fault). EL1 fault context
        // preserves SP_EL0 — `mrs` reads it directly without
        // touching any per-task save area. Catches stack-corruption
        // bugs where x9 / x29 derived from `sp+const` look like
        // small constants (e.g. F204 dropbear sha256_compress).
        let sp_el0: u64;
        // SAFETY: `mrs sp_el0` is a privileged read at EL1 with no
        // side effects; sp_el0 holds the interrupted EL0 SP per
        // ARMv8 D1.7.
        unsafe { core::arch::asm!("mrs {}, sp_el0", out(reg) sp_el0, options(nomem, nostack, preserves_flags)); }
        klog::write_raw(b" sp=");       klog::write_hex_u64(sp_el0);
        klog::write_raw(b"\n");
    }
}
