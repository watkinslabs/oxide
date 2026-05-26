// Signal-handler dispatch per docs/27§5. P3-65 minimal v1:
// when a user handler is registered (sa_handler != SIG_DFL/IGN),
// the syscall-tail signal-delivery path saves a tiny "signal
// context" on the user stack, rewrites the per-task user_frame
// so sysretq lands at the user's handler with `sig` in rdi and
// the saved-rip pushed as a return address, then returns. When
// the handler does `ret`, control flows to `sa_restorer` which
// issues `rt_sigreturn` (slot 15) -- that handler restores the
// saved rip/rsp/rflags from the signal context.
//
// v1 scope:
//   - x86_64 only. arm sa_handler rides M2 follow-up.
//   - SA_SIGINFO not honoured. Handler called as `void(int sig)`;
//     no siginfo_t, no ucontext_t (full ucontext frame lands
//     with the threading + signal-mask-on-handler-entry work).
//   - Saved context = (saved_rip, saved_rsp, saved_rflags).
//   - Handler RSP = old_rsp - frame_size; frame layout:
//
//        [old_rsp - 8]   restorer addr   ← ret target
//        [old_rsp - 16]  saved_rip
//        [old_rsp - 24]  saved_rsp
//        [old_rsp - 32]  saved_rflags
//        [old_rsp - 40]  magic 0x5A55_5A55_DEAD_BEEF
//
//   - rt_sigreturn reads back from new_rsp + 8..40 and restores.

// Arch-portable now: x86_64 path saves (rip, rflags, rsp) into the
// per-task user_frame; aarch64 mirror saves (elr_el1, spsr_el1, sp_el0)
// into the same SvcFrame slots that the SVC asm already writes/reads
// for the `eret` epilogue. Same wire-frame layout on the user stack
// (magic + saved-3 + restorer = 40 bytes) so user-side sa_restorer
// thunks are arch-only in the syscall instruction they emit.

#![cfg(target_os = "oxide-kernel")]

const SIG_FRAME_MAGIC: u64 = 0x5A55_5A55_DEAD_BEEF;
// 48 B signal frame. All saved-context slots live AT OR ABOVE the
// handler-entry SP; the handler's own stack grows BELOW its SP and
// must not be allowed to clobber the saved frame. Layout, in terms
// of new_sp (handler-entry SP) — same on x86 and ARM:
//
//   x86_64 (handler `ret` pops slot 0 as the return target):
//     [new_rsp +  0]  restorer  ← ret pops, lands at restorer
//     [new_rsp +  8]  magic
//     [new_rsp + 16]  saved_rflags
//     [new_rsp + 24]  saved_rsp
//     [new_rsp + 32]  saved_rip
//     [new_rsp + 40]  saved_sigmask
//
//   aarch64 (handler `ret` is `br lr`; no stack pop; LR=restorer):
//     [new_sp  +  0]  magic
//     [new_sp  +  8]  saved_pstate
//     [new_sp  + 16]  saved_sp
//     [new_sp  + 24]  saved_pc
//     [new_sp  + 32]  saved_sigmask
//     (no restorer slot — LR carries it)
//
// x86 also reserves the 128-byte red zone below saved_rsp per the
// SysV x86_64 ABI so the interrupted frame's red-zone data stays
// intact across signal delivery.
const SIG_FRAME_BYTES: u64 = 48;
#[cfg(target_arch = "x86_64")]
const X86_RED_ZONE: u64 = 128;

/// Arch-neutral entry: route to deliver_x86 / deliver_arm.
/// # SAFETY: caller is the syscall dispatch tail on the running
/// task's per-task kernel stack; the per-arch saved frame is live;
/// active CR3/TTBR0 is the running task's user AS.
/// # C: O(1)
#[inline]
pub unsafe fn deliver(handler: u64, restorer: u64, sig: u32) {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: defers to deliver_x86 whose preconditions are exactly the caller's per fn contract.
    unsafe { deliver_x86(handler, restorer, sig); }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: defers to deliver_arm whose preconditions are exactly the caller's per fn contract.
    unsafe { deliver_arm(handler, restorer, sig); }
}

/// Arch-neutral entry: route to rt_sigreturn_x86 / rt_sigreturn_arm.
/// # SAFETY: caller is the rt_sigreturn syscall dispatch on the
/// running task's per-task kernel stack; per-arch saved frame is live.
/// # C: O(1)
#[inline]
pub unsafe fn rt_sigreturn() -> i64 {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: per fn contract; defers to rt_sigreturn_x86.
    unsafe { return rt_sigreturn_x86(); }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: per fn contract; defers to rt_sigreturn_arm.
    unsafe { return rt_sigreturn_arm(); }
}

/// Build the signal frame on the user stack and rewrite the
/// per-task user_frame so sysretq enters `handler` with `sig`
/// in rdi and `restorer` as the eventual return target.
/// # SAFETY: caller is the dispatch tail on cur's per-task syscall
/// kernel stack; current_user_frame() points at the live saved
/// tail; user-VA writes target the active CR3 (caller's user AS).
/// # C: O(1)
#[cfg(target_arch = "x86_64")]
pub unsafe fn deliver_x86(handler: u64, restorer: u64, sig: u32) {
    // Read the saved user context (rip, rflags, rsp).
    // SAFETY: per fn contract -- frame slot is at top-24..top of cur's syscall stack.
    let frame = unsafe { &mut *hal_x86_64::current_user_frame() };
    let saved_rip    = frame[0];
    let saved_rflags = frame[1];
    let saved_rsp    = frame[2];

    // Carve the signal frame BELOW the red zone and pick new_rsp so
    // the saved-context slots live at addresses ABOVE the handler's
    // entry SP (the handler's own stack grows below). SysV requires
    // rsp % 16 == 8 at function entry (post-`call` invariant) — the
    // restorer addr at [new_rsp+0] plays the role of the pushed
    // return address.
    let top = saved_rsp.saturating_sub(X86_RED_ZONE);
    // (top - SIG_FRAME_BYTES) rounded down to 16, then -8 → %16==8.
    let aligned = top.saturating_sub(SIG_FRAME_BYTES) & !0xfu64;
    let new_rsp = aligned.saturating_sub(8);

    // Block the delivered signal during its handler (POSIX
    // SA_NODEFER-off). Without this, the syscall-return path
    // re-delivers SIGCHLD nested inside the SIGCHLD handler;
    // each nested frame writes 48 B over the outer handler's
    // saved x19/x20 area on AArch64 and lands `SIG_FRAME_MAGIC`
    // in a callee-saved reg. rt_sigreturn restores this old mask.
    use core::sync::atomic::Ordering;
    let cur = sched::live::current();
    let old_sigmask = match cur.as_ref() {
        Some(c) => c.sigmask.fetch_or(1u64 << (sig - 1), Ordering::AcqRel),
        None    => 0,
    };

    // SAFETY: new_rsp validated < saved_rsp < USER_VA_END; CPL=0 writes through caller's AS via active CR3; user_fault_handler resolves any not-present page (caller's stack pages already faulted).
    unsafe {
        core::ptr::write_volatile((new_rsp +  0) as *mut u64, restorer);
        core::ptr::write_volatile((new_rsp +  8) as *mut u64, SIG_FRAME_MAGIC);
        core::ptr::write_volatile((new_rsp + 16) as *mut u64, saved_rflags);
        core::ptr::write_volatile((new_rsp + 24) as *mut u64, saved_rsp);
        core::ptr::write_volatile((new_rsp + 32) as *mut u64, saved_rip);
        core::ptr::write_volatile((new_rsp + 40) as *mut u64, old_sigmask);
    }

    #[cfg(feature = "debug-sched")]
    {
        klog::write_raw(b"[INFO]  sig: deliver sig=");
        klog::write_dec_u64(sig as u64);
        klog::write_raw(b" handler=");
        klog::write_hex_u64(handler);
        klog::write_raw(b" new_rsp=");
        klog::write_hex_u64(new_rsp);
        klog::write_raw(b"\n");
    }

    frame[0] = handler;          // user RIP = handler
    frame[1] = saved_rflags;     // RFLAGS unchanged (IF kept off via FMASK)
    frame[2] = new_rsp;          // RSP = signal frame

    // Pass `sig` to the handler in rdi. After B04 added a 16th r12
    // save slot at the top of the 16-quadword frame, rdi (slot index
    // 1 from rsp) lives at top-0x80+0x08 = top-0x78.
    let kstack_top = hal_x86_64::current_kstack_top();
    if kstack_top != 0 {
        // SAFETY: the syscall asm restore-block reads saved-rdi at offset -0x78 from top after B04's r12 save; we are running on that exact stack pre-restore; writing here makes the asm's `mov rdi, [rsp+0x08]` after restore-loop pull our `sig` into user rdi.
        unsafe {
            core::ptr::write_volatile((kstack_top - 0x78) as *mut u64, sig as u64);
        }
    }
}

/// `sys_rt_sigreturn` body. Pops the signal frame the dispatch
/// pushed, restores the saved rip/rflags/rsp into the per-task
/// user_frame so sysretq returns to the original code as if no
/// signal had fired.
/// # SAFETY: caller is the syscall dispatch on cur's syscall stack;
/// user_rsp + frame validated against USER_VA_END.
/// # C: O(1)
#[cfg(target_arch = "x86_64")]
pub unsafe fn rt_sigreturn_x86() -> i64 {
    use syscall::errno::Errno;
    // SAFETY: per fn contract -- frame slot is at top-24..top of cur's syscall stack.
    let frame = unsafe { &mut *hal_x86_64::current_user_frame() };
    let cur_rsp = frame[2];
    // Handler entered with rsp = new_rsp; `ret` popped the restorer
    // slot at [new_rsp+0] (rsp += 8) and jumped to the restorer
    // which issues `mov rax,15; syscall` without touching rsp →
    // cur_rsp at syscall = new_rsp + 8. frame_base = new_rsp.
    let frame_base = cur_rsp.saturating_sub(8);
    if frame_base == 0 || frame_base >= hal::USER_VA_END {
        return -(Errno::Einval.as_i32() as i64);
    }
    // SAFETY: frame_base validated < USER_VA_END; CPL=0 reads through caller's AS.
    let magic = unsafe { core::ptr::read_volatile((frame_base + 8) as *const u64) };
    if magic != SIG_FRAME_MAGIC {
        return -(Errno::Einval.as_i32() as i64);
    }
    // SAFETY: same validated range as the magic read; saved fields at +16/+24/+32/+40 are 8-byte aligned per the layout we wrote in deliver_x86; CPL=0 reads through caller's AS.
    let (saved_rflags, saved_rsp, saved_rip, saved_sigmask) = unsafe { (
        core::ptr::read_volatile((frame_base + 16) as *const u64),
        core::ptr::read_volatile((frame_base + 24) as *const u64),
        core::ptr::read_volatile((frame_base + 32) as *const u64),
        core::ptr::read_volatile((frame_base + 40) as *const u64),
    ) };
    frame[0] = saved_rip;
    frame[1] = saved_rflags;
    frame[2] = saved_rsp;
    if let Some(c) = sched::live::current() {
        c.sigmask.store(saved_sigmask, core::sync::atomic::Ordering::Release);
    }
    #[cfg(feature = "debug-sched")]
    {
        klog::write_raw(b"[INFO]  sig: rt_sigreturn rip=");
        klog::write_hex_u64(saved_rip);
        klog::write_raw(b" rsp=");
        klog::write_hex_u64(saved_rsp);
        klog::write_raw(b"\n");
    }
    0
}

// ---- aarch64 mirror ------------------------------------------------

/// Build the signal frame on the user stack and rewrite the saved
/// SVC frame so `eret` enters `handler` with `sig` in x0 and
/// `restorer` as the eventual return target (sa_restorer must
/// issue `mov x8, #139; svc #0` — Linux generic ABI rt_sigreturn).
/// # SAFETY: caller is the syscall dispatch tail on cur's per-task
/// kernel stack; current_svc_frame() points at the live saved frame
/// the SVC asm wrote on entry; user-VA writes target the active
/// TTBR0 (caller's user AS).
/// # C: O(1)
#[cfg(target_arch = "aarch64")]
pub unsafe fn deliver_arm(handler: u64, restorer: u64, sig: u32) {
    // SAFETY: per fn contract — frame is the live saved SVC frame at the top of cur's syscall stack; sole writer for the lifetime of this dispatch tail per `13§5`.
    let frame = unsafe { &mut *hal_aarch64::current_svc_frame() };
    let saved_pc    = frame.elr_el1;
    let saved_pstate = frame.spsr_el1;
    let saved_sp    = frame.sp_el0;

    // Carve the signal frame so saved-context slots live AT OR
    // ABOVE new_sp; the handler's own stack grows below new_sp and
    // must not be allowed to clobber the saved frame. AAPCS64
    // requires SP % 16 == 0 at any public function entry, so
    // new_sp = (saved_sp - 48) & ~0xf.
    let new_sp = saved_sp.saturating_sub(SIG_FRAME_BYTES) & !0xfu64;
    // Block the delivered signal during its handler (POSIX
    // SA_NODEFER-off). Prevents the syscall-return path from
    // re-entering deliver_arm for SIGCHLD while busybox-init is
    // still inside its SIGCHLD handler; each nested frame would
    // otherwise stomp on the outer handler's saved-callee area.
    use core::sync::atomic::Ordering;
    let cur = sched::live::current();
    let old_sigmask = match cur.as_ref() {
        Some(c) => c.sigmask.fetch_or(1u64 << (sig - 1), Ordering::AcqRel),
        None    => 0,
    };
    // SAFETY: new_sp is a user-space VA below saved_sp (which came from EL0); kernel CPL=EL1 writes through TTBR0; demand-fault resolves not-present pages via classify_arm_abort + handle.
    unsafe {
        core::ptr::write_volatile((new_sp +  0) as *mut u64, SIG_FRAME_MAGIC);
        core::ptr::write_volatile((new_sp +  8) as *mut u64, saved_pstate);
        core::ptr::write_volatile((new_sp + 16) as *mut u64, saved_sp);
        core::ptr::write_volatile((new_sp + 24) as *mut u64, saved_pc);
        core::ptr::write_volatile((new_sp + 32) as *mut u64, old_sigmask);
    }

    #[cfg(feature = "debug-sched")]
    {
        klog::write_raw(b"[INFO]  sig: deliver_arm sig=");
        klog::write_dec_u64(sig as u64);
        klog::write_raw(b" handler=");
        klog::write_hex_u64(handler);
        klog::write_raw(b" new_sp=");
        klog::write_hex_u64(new_sp);
        klog::write_raw(b"\n");
    }

    frame.elr_el1 = handler;
    frame.sp_el0  = new_sp;
    frame.gp[0]   = sig as u64;       // x0 = sig per AAPCS64
    frame.x30     = restorer;         // lr — handler `ret` lands at restorer
    // SPSR_EL1 unchanged: stays EL0t with the same DAIF bits the
    // user had when the syscall fired.
    let _ = saved_pstate;
}

/// `sys_rt_sigreturn` body for aarch64. Mirrors rt_sigreturn_x86 —
/// pops the 40-byte signal frame at sp_el0 - 40 and restores
/// (elr_el1, spsr_el1, sp_el0) into the saved SVC frame so `eret`
/// returns to the original user state.
/// # SAFETY: caller is the rt_sigreturn syscall dispatch on cur's
/// per-task kernel stack; sp_el0 + frame validated against USER_VA_END.
/// # C: O(1)
#[cfg(target_arch = "aarch64")]
pub unsafe fn rt_sigreturn_arm() -> i64 {
    use syscall::errno::Errno;
    // SAFETY: per fn contract — live saved SVC frame, sole writer per dispatch.
    let frame = unsafe { &mut *hal_aarch64::current_svc_frame() };
    let cur_sp = frame.sp_el0;
    // ARM `ret` is `br lr` — does NOT pop the stack. Handler
    // entered with SP=new_sp and LR=restorer; epilogue restores SP
    // to new_sp before `ret`; sa_restorer's `svc #0` fires with SP
    // unchanged → cur_sp == new_sp == frame_base. Saved-context
    // slots all live at addresses ≥ new_sp so the handler's stack
    // cannot clobber them.
    let frame_base = cur_sp;
    if frame_base == 0 || frame_base >= hal::USER_VA_END {
        return -(Errno::Einval.as_i32() as i64);
    }
    // SAFETY: frame_base validated < USER_VA_END; CPL=EL1 reads through caller's TTBR0.
    let magic = unsafe { core::ptr::read_volatile(frame_base as *const u64) };
    if magic != SIG_FRAME_MAGIC {
        return -(Errno::Einval.as_i32() as i64);
    }
    // SAFETY: same validated range; saved fields at +8/+16/+24/+32 are 8-byte aligned per layout in deliver_arm.
    let (saved_pstate, saved_sp, saved_pc, saved_sigmask) = unsafe { (
        core::ptr::read_volatile((frame_base +  8) as *const u64),
        core::ptr::read_volatile((frame_base + 16) as *const u64),
        core::ptr::read_volatile((frame_base + 24) as *const u64),
        core::ptr::read_volatile((frame_base + 32) as *const u64),
    ) };
    frame.elr_el1  = saved_pc;
    frame.spsr_el1 = saved_pstate;
    frame.sp_el0   = saved_sp;
    if let Some(c) = sched::live::current() {
        c.sigmask.store(saved_sigmask, core::sync::atomic::Ordering::Release);
    }
    #[cfg(feature = "debug-sched")]
    {
        klog::write_raw(b"[INFO]  sig: rt_sigreturn_arm pc=");
        klog::write_hex_u64(saved_pc);
        klog::write_raw(b" sp=");
        klog::write_hex_u64(saved_sp);
        klog::write_raw(b"\n");
    }
    0
}
