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
    // SAFETY: frame_ptr is the live FaultFrame for this PF, exposed by oxide_fault_print_rust on the kernel stack; mutable borrow is sound under fault dispatch context (single-CPU, IRQs off).
    let frame = unsafe { &mut *frame_ptr };
    // User stack layout (top → bottom):
    //   [old_rsp - 0x10]  restorer    ← ret addr from handler
    //   [old_rsp - 0x88]  ucontext stub (zeroed, 128 B)
    //   [old_rsp - 0x108] siginfo_t   (128 B; si_signo/si_addr/si_code)
    let new_sp = frame.rsp.saturating_sub(0x108);
    if new_sp == 0 || new_sp >= hal::USER_VA_END { return false; }
    let si  = new_sp;                   // siginfo at base
    let uc  = new_sp + 0x80;            // ucontext above
    let ret = new_sp + 0x100;           // restorer addr above ucontext
    // SAFETY: user stack pages faulted in by user code; CPL=0 writes through active CR3.
    unsafe {
        core::ptr::write_volatile( si        as *mut i32, 11);
        core::ptr::write_volatile((si +  4)  as *mut i32, 0);
        core::ptr::write_volatile((si +  8)  as *mut i32, 1);    // SEGV_MAPERR
        core::ptr::write_volatile((si + 16)  as *mut u64, cr2);
        core::ptr::write_bytes((si + 24) as *mut u8, 0, 0x80 - 24);
        core::ptr::write_bytes(uc as *mut u8, 0, 0x80);
        core::ptr::write_volatile(ret as *mut u64, sa.restorer);
    }
    frame.rip    = sa.handler;
    frame.rsp    = ret;
    frame.rflags = 0x202;
    // F158: rewrite the saved-scratch slots that oxide_fault_common
    // pops back into rdi/rsi/rdx before iretq, so the user handler
    // sees Linux ABI args:
    //   rdi = sig num (11)
    //   rsi = ptr to siginfo_t (only meaningful with SA_SIGINFO)
    //   rdx = ptr to ucontext_t (only meaningful with SA_SIGINFO)
    // Per fault.rs stack diagram (B45 layout — callee-saved pushes
    // added), the slots are at frame_ptr - 0x28 (rdi), -0x20 (rsi),
    // -0x18 (rdx).
    let frame_addr = frame_ptr as u64;
    // SAFETY: frame_ptr is a kernel-stack address from current_fault_frame; the saved-scratch slots at -0x28/-0x20/-0x18 are within the per-task syscall/fault stack and only oxide_fault_common (which runs after we return) reads them.
    unsafe {
        core::ptr::write_volatile((frame_addr - 0x28) as *mut u64, 11);
        core::ptr::write_volatile((frame_addr - 0x20) as *mut u64, si);
        core::ptr::write_volatile((frame_addr - 0x18) as *mut u64, uc);
    }
    let _ = sa.flags;
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
