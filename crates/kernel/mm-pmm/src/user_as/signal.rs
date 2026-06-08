// SIGSEGV / fault-to-signal delivery split out of user_as.rs per
// `08§7` file-length cap. F158 catchable-signal rewrite + the
// arch-specific terminate paths live here; user_as routes
// unhandled user-mode faults through `deliver_sigsegv_<arch>`.

/// Hook installed at boot from `fs::coredump::write_for_current`.
/// Avoids vmm→fs cycle.
pub type CoredumpFn = fn(i32);
static COREDUMP_HOOK: core::sync::atomic::AtomicPtr<()> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());
/// # C: O(1) — atomic store.
pub fn set_coredump_hook(f: CoredumpFn) {
    COREDUMP_HOOK.store(f as *mut (), core::sync::atomic::Ordering::Release);
}

/// Public wrapper for SIGSEGV delivery. F158: tries Linux-style
/// catchable signal first — if the user task has installed a
/// SIGSEGV handler via rt_sigaction, rewrite the live FaultFrame
/// so iretq lands at the handler with `sig=11` in rdi and a
/// minimal siginfo on the user stack. Falls back to terminate
/// when SIG_DFL or no live frame.
/// # SAFETY: caller is in fault / IRQ-off context with the
/// runqueue installed (else no current task to terminate).
/// # C: O(1) — diverges OR returns through dispatch
#[cfg(target_arch = "x86_64")]
pub fn deliver_sigsegv_x86(vec: u64, err: u64, rip: u64, cr2: u64) -> ! {
    sigsegv_terminate_x86(vec, err, rip, cr2);
}

/// F158: rewrite the live FaultFrame so iretq lands at the user's
/// SIGSEGV handler with `sig=11` in rdi (passed via fault asm
/// scratch slot). siginfo + ucontext stub pushed on user stack.
/// # SAFETY: caller is in fault dispatch, IRQs off.
/// # C: O(1)
#[cfg(target_arch = "x86_64")]
pub(super) fn try_deliver_sigsegv_via_handler_x86(cr2: u64) -> bool {
    let cur = match sched::live::current() { Some(c) => c, None => return false };
    // SAFETY: sigactions slot single-mutator per `13§5`.
    let sa = unsafe { (*cur.sigactions.get())[10] };  // SIGSEGV = 11, idx 10
    if sa.handler == 0 || sa.handler == 1 { return false; }
    let frame_ptr = hal_x86_64::current_fault_frame();
    if frame_ptr.is_null() { return false; }
    // F203: log the catchable-signal dispatch so we can see which
    // user-space RIP keeps faulting under handler-installed cover
    // (dropbear's sigsegv_handler is the canonical case — without
    // this trace the kernel-side fault is invisible because the
    // terminate path's [FAULT] block doesn't run).
    #[cfg(feature = "debug-irq")]
    {
        // SAFETY: frame published on kernel stack by oxide_fault_print_rust; read-only.
        let f = unsafe { &*frame_ptr };
        klog::write_raw(b"[FAULT] catchable-sigsegv tid=");
        klog::write_dec_u64(cur.tid as u64);
        klog::write_raw(b" rip=");      klog::write_hex_u64(f.rip);
        klog::write_raw(b" rsp=");      klog::write_hex_u64(f.rsp);
        klog::write_raw(b" cr2=");      klog::write_hex_u64(cr2);
        klog::write_raw(b" handler="); klog::write_hex_u64(sa.handler);
        klog::write_raw(b"\n");
    }
    // SAFETY: frame_ptr is the live FaultFrame for this PF, exposed by oxide_fault_print_rust on the kernel stack; mutable borrow is sound under fault dispatch context (single-CPU, IRQs off).
    let frame = unsafe { &mut *frame_ptr };

    // F411: build the FULL Linux rt_sigframe (siginfo + ucontext + FP)
    // via the shared pure builder so rt_sigreturn (which now expects
    // the full frame) restores it correctly. The fault frame is a
    // distinct GP source (analogous to the IRQ source): reconstruct the
    // interrupted GP set from the FaultGprs block + FaultFrame.
    use syscall::sigbuild::{build_x86, BuildParams, GpRegsX86};
    use syscall::sigframe::SigInfoUser;
    let gp_ptr = hal_x86_64::current_fault_gprs();
    let regs = if gp_ptr.is_null() {
        GpRegsX86 {
            rsp: frame.rsp, rip: frame.rip, eflags: frame.rflags,
            cs: frame.cs as u16, ss: frame.ss as u16, ..Default::default()
        }
    } else {
        // SAFETY: stub-built GPR block live on the kernel stack through this fault dispatch (the stub doesn't pop until after we return; we rewrite the frame and resume via iretq).
        let g = unsafe { &*gp_ptr };
        GpRegsX86 {
            r8: g.r8, r9: g.r9, r10: g.r10, r11: g.r11,
            r12: g.r12, r13: g.r13, r14: g.r14, r15: g.r15,
            rdi: g.rdi, rsi: g.rsi, rbp: g.rbp, rbx: g.rbx,
            rdx: g.rdx, rax: g.rax, rcx: g.rcx,
            rsp: frame.rsp, rip: frame.rip, eflags: frame.rflags,
            cs: frame.cs as u16, ss: frame.ss as u16, gs: 0, fs: 0,
        }
    };
    use core::sync::atomic::Ordering;
    let old_sigmask = cur.sigmask.load(Ordering::Acquire);
    let p = BuildParams {
        sig: 11, handler: sa.handler, restorer: sa.restorer,
        sa_flags: sa.flags, sa_mask: sa.mask, old_sigmask,
        info: SigInfoUser::fault(11, syscall::sigframe::si::SEGV_MAPERR, cr2),
        alt_sp: cur.sigaltstack_sp.load(Ordering::Acquire),
        alt_size: cur.sigaltstack_size.load(Ordering::Acquire),
        alt_flags: cur.sigaltstack_flags.load(Ordering::Acquire) as i32,
    };
    let fp = [0u8; 512];
    let b = build_x86(&regs, &p, &fp);
    if b.frame_addr == 0 || b.frame_addr >= hal::USER_VA_END { return false; }
    // SAFETY: fp_addr/frame_addr are user VAs below the faulting rsp (build_x86's red-zone+align math); CPL=0 writes through the active CR3; both regions are repr(C) matching rt_sigreturn's read.
    unsafe {
        core::ptr::write_volatile(b.fp_addr as *mut [u8; 512], b.fpstate);
        core::ptr::write_volatile(b.frame_addr as *mut syscall::sigframe::RtSigframeX86, b.frame);
    }
    cur.sigmask.store(b.new_sigmask, Ordering::Release);
    if (sa.flags & syscall::sigframe::sa::SA_RESETHAND) != 0 {
        // SAFETY: sigactions slot single-mutator per `13§5`; idx 10 = SIGSEGV.
        unsafe { (*cur.sigactions.get())[10].handler = 0; }
    }
    frame.rip    = sa.handler;
    frame.rsp    = b.new_rsp;
    frame.rflags = 0x202;
    // F158/F411: rewrite the saved-scratch slots that oxide_fault_common
    // pops back into rdi/rsi/rdx before iretq → Linux ABI handler args
    // (rdi=sig, rsi=&siginfo, rdx=&ucontext per SA_SIGINFO). Slots at
    // frame_ptr -0x28 (rdi), -0x20 (rsi), -0x18 (rdx) per fault.rs B45.
    let frame_addr = frame_ptr as u64;
    // SAFETY: frame_ptr is a kernel-stack address from current_fault_frame; the saved-scratch slots at -0x28/-0x20/-0x18 are within the per-task fault stack and only oxide_fault_common (after we return) reads them.
    unsafe {
        core::ptr::write_volatile((frame_addr - 0x28) as *mut u64, b.arg_rdi);
        core::ptr::write_volatile((frame_addr - 0x20) as *mut u64, b.arg_rsi);
        core::ptr::write_volatile((frame_addr - 0x18) as *mut u64, b.arg_rdx);
    }
    true
}

/// arm wrapper for SIGSEGV delivery. Same shape as the x86 form.
/// # SAFETY: caller is in fault / IRQ-off context with the
/// runqueue installed.
/// # C: O(1) — diverges
#[cfg(target_arch = "aarch64")]
pub fn deliver_sigsegv_arm(esr: u64, far: u64, elr: u64) -> ! {
    sigsegv_terminate_arm(esr, far, elr);
}

/// Minimal SIGSEGV (signal 11) delivery per docs/27 v1: log the
/// fault, mark the current user task `Zombie` with `exit_status =
/// 11` (POSIX wstatus low 7 bits = signal number), park to the
/// zombie registry, `schedule()` away. Diverges. Parent's
/// `wait4` reaps the corpse.
#[cfg(target_arch = "x86_64")]
fn sigsegv_terminate_x86(vec: u64, err: u64, rip: u64, cr2: u64) -> ! {
    use core::sync::atomic::Ordering;
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
        let gp = hal_x86_64::current_fault_gprs();
        if !gp.is_null() {
            // SAFETY: stub-built GPR block on the kernel stack; valid for read while we're in fault dispatch (the stub doesn't pop until after the Rust dispatcher returns — which it doesn't here, since we diverge — so the slots stay live for the schedule()-away that follows).
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
                // SAFETY: live FaultFrame on the kernel stack; read-only rsp.
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
    // Coredump before parking the zombie. Best-effort.
    // Hook installed at boot from `fs::coredump::write_for_current`.
    let p = COREDUMP_HOOK.load(core::sync::atomic::Ordering::Acquire);
    if !p.is_null() {
        // SAFETY: hook ptr installed at boot from a fn matching CoredumpFn ABI; load Acquire-paired with Release store in set_coredump_hook.
        let f: CoredumpFn = unsafe { core::mem::transmute(p) };
        f(11);
    }
    if let Some(rq) = sched::live::global() {
        let raw = rq.current.load(Ordering::Acquire);
        if !raw.is_null() {
            // SAFETY: rq.current non-null after install; the AtomicPtr's
            // strong-ref-via-raw keeps the pointee alive through this borrow;
            // we are running on this task's syscall stack so no concurrent freer.
            let task: &sched::Task = unsafe { &*raw };
            // exit_status low 8 = signal num, bit 8 = "killed by
            // signal" flag (per the wait4 encoder in syscall_glue).
            task.exit_status.store(11 | 0x100, Ordering::Release);
            sched::live::mark_done(task);
            sched::live::signal_child_exit(task);
        }
    }
    // SAFETY: kernel ctx (fault dispatcher), preempt-off, runqueue installed.
    // schedule() detects the Zombie state and pushes the prev_arc
    // returned by swap_current into ZOMBIES — no leak via the dead
    // task's stack frame.
    unsafe { sched::live::schedule(); }
    loop {
        // SAFETY: cli+hlt at CPL=0; final terminal halt if schedule returns.
        unsafe { core::arch::asm!("cli; hlt", options(nomem, nostack, preserves_flags)); }
    }
}

/// arm minimal SIGSEGV delivery — same shape as x86 path.
#[cfg(target_arch = "aarch64")]
fn sigsegv_terminate_arm(esr: u64, far: u64, elr: u64) -> ! {
    use core::sync::atomic::Ordering;
    #[cfg(feature = "debug-irq")]
    {
        klog::write_raw(b"[FAULT] sigsegv: kill tid=");
        if let Some(c) = sched::live::current() { klog::write_dec_u64(c.tid as u64); }
        klog::write_raw(b" esr=");      klog::write_hex_u64(esr);
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
        klog::write_raw(b" sp_el0=");   klog::write_hex_u64(sp_el0);
        klog::write_raw(b"\n");
    }
    if let Some(rq) = sched::live::global() {
        let raw = rq.current.load(Ordering::Acquire);
        if !raw.is_null() {
            // SAFETY: rq.current non-null after install; AtomicPtr's
            // strong-ref-via-raw keeps pointee alive across this borrow.
            let task: &sched::Task = unsafe { &*raw };
            task.exit_status.store(11 | 0x100, Ordering::Release);
            sched::live::mark_done(task);
            sched::live::signal_child_exit(task);
        }
    }
    // SAFETY: kernel ctx, preempt-off, runqueue installed; schedule()
    // detects Zombie prev and transfers the prev_arc into ZOMBIES.
    unsafe { sched::live::schedule(); }
    loop {
        // SAFETY: msr daifset+wfi at EL1; final halt path.
        unsafe { core::arch::asm!("msr daifset, #2; wfi", options(nomem, nostack, preserves_flags)); }
    }
}
