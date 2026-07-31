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
/// # C: O(1)
#[cfg(target_arch = "x86_64")]
pub fn force_user_fault_x86(vec: u64, err: u64, pc: u64, cr2: u64) -> bool {
    use hal::fault_class::x86_64 as fc;
    let (cls, addr) = if vec == fc::TRAP_PF { (fc::page_fault(err), cr2) }
                      else { (fc::trap(vec), fc::trap_addr(vec, pc)) };
    raise(cls, addr);
    true
}

/// aarch64 form. `esr` is ESR_EL1, `far` FAR_EL1 (the faulting address for the
/// abort classes) and `elr` the faulting PC.
/// # C: O(1)
#[cfg(target_arch = "aarch64")]
pub fn force_user_fault_arm(esr: u64, far: u64, elr: u64) -> bool {
    use hal::fault_class::aarch64 as fc;
    let cls = fc::sync(esr);
    // The abort classes report FAR_EL1; every other synchronous EL0 exception
    // (BRK, illegal state, FP) names the instruction that raised it.
    let addr = if fc::from_el0(esr) || matches!(fc::ec(esr), fc::EC_PC_ALIGN | fc::EC_SP_ALIGN)
               { far } else { elr };
    raise(cls, addr);
    true
}

/// Queue one classified fault signal. A signo the classifier could not map
/// still becomes SIGSEGV rather than nothing — an unhandled user-mode
/// exception that raised no signal would spin the faulting instruction forever.
/// # C: O(1)
fn raise(cls: hal::fault_class::FaultSignal, addr: u64) {
    let sig = signum_from(cls.signo);
    sched::live::force_sig_fault(sig, cls.code, addr, 0);
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
    #[cfg(feature = "debug-irq")]
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
            // B47: walk the frame-pointer chain via [rbp]=prev_rbp,
            // [rbp+8]=return_addr per SysV. Up to 12 frames; stop
            // at non-canonical / out-of-range rbp.
            let mut bp = g.rbp;
            for _ in 0..12 {
                if bp == 0 || bp >= hal::USER_VA_END || (bp & 7) != 0 { break; }
                // SAFETY: bp validated < USER_VA_END and 8-byte aligned; CPL=0 read through caller's AS. Any unmapped page faults to user_fault_handler which can deliver a second SIGSEGV — but we're already terminating, so the recursion is bounded.
                let prev_bp = unsafe { core::ptr::read_volatile(bp as *const u64) };
                // SAFETY: same range/alignment guarantees; +8 stays within the same frame slot.
                let ret_rip = unsafe { core::ptr::read_volatile((bp + 8) as *const u64) };
                klog::write_raw(b"[FAULT] frame rbp=");
                klog::write_hex_u64(bp);
                klog::write_raw(b" ret=");
                klog::write_hex_u64(ret_rip);
                klog::write_raw(b"\n");
                if prev_bp <= bp { break; }
                bp = prev_bp;
            }
            // B53: frame-pointer-omitting libs (musl mallocng is built
            // -fomit-frame-pointer) defeat the rbp chain — the walk above
            // stops after one frame. Scan the raw user stack from rsp and
            // print any quadword that lands in a known code range so the
            // real call chain (python text + ld-musl text) is recoverable
            // without gdb. Ranges are the observed mmap layout; over-broad
            // is fine (we just want return addresses to name functions).
            let fp = hal_x86_64::current_fault_frame();
            if !fp.is_null() {
                // SAFETY: live PtRegs on the kernel stack; read-only rsp.
                let mut sp = unsafe { (*fp).rsp };
                klog::write_raw(b"[FAULT] user rsp="); klog::write_hex_u64(sp);
                klog::write_raw(b"\n");
                let mut printed = 0u32;
                let mut scanned = 0u32;
                while scanned < 512 && printed < 24 {
                    if sp == 0 || sp >= hal::USER_VA_END || (sp & 7) != 0 { break; }
                    // SAFETY: sp validated < USER_VA_END and aligned; CPL=0 read through the faulting AS. Unmapped slots fault into user_fault_handler which re-terminates — bounded since we already diverge.
                    let w = unsafe { core::ptr::read_volatile(sp as *const u64) };
                    // python ET_EXEC text ~[0x400000,0x900000); ld-musl text
                    // ~[0x40000000,0x40100000). Print stack slots holding such.
                    let in_exec = w >= 0x400000 && w < 0x900000;
                    let in_lib  = w >= 0x4000_0000 && w < 0x4010_0000;
                    if in_exec || in_lib {
                        klog::write_raw(b"[FAULT] stk+"); klog::write_hex_u64(scanned as u64 * 8);
                        klog::write_raw(b" ret="); klog::write_hex_u64(w);
                        klog::write_raw(b"\n");
                        printed += 1;
                    }
                    sp += 8;
                    scanned += 1;
                }
                // Dump 32 bytes around the faulting rax (mallocng's in-band
                // slot header it asserted on) so we can see stale vs zero.
                let a = g.rax;
                if a >= 0x1000 && a < hal::USER_VA_END {
                    let base = (a & !7).saturating_sub(16);
                    klog::write_raw(b"[FAULT] rax-mem @"); klog::write_hex_u64(base);
                    for i in 0..4u64 {
                        let p = base + i * 8;
                        if p >= hal::USER_VA_END { break; }
                        // SAFETY: p validated user-half + aligned; CPL=0 read, refaults handled as above.
                        let w = unsafe { core::ptr::read_volatile(p as *const u64) };
                        klog::write_raw(b" "); klog::write_hex_u64(w);
                    }
                    klog::write_raw(b"\n");
                }
            }
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
