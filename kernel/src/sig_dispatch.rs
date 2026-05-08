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
const SIG_FRAME_BYTES: u64 = 40;

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

    // Pick the new user RSP. -8 for the restorer return address.
    let mut sp = saved_rsp;
    sp = sp.saturating_sub(SIG_FRAME_BYTES);

    // SAFETY: sp validated < USER_VA_END (saved_rsp came from user, was < USER_VA_END); CPL=0 writes through caller's AS via active CR3; user_fault_handler resolves any not-present page (caller's stack pages already faulted).
    unsafe {
        core::ptr::write_volatile((sp +  0) as *mut u64, SIG_FRAME_MAGIC);
        core::ptr::write_volatile((sp +  8) as *mut u64, saved_rflags);
        core::ptr::write_volatile((sp + 16) as *mut u64, saved_rsp);
        core::ptr::write_volatile((sp + 24) as *mut u64, saved_rip);
        core::ptr::write_volatile((sp + 32) as *mut u64, restorer);
    }

    // The handler will be entered with the restorer addr as if it
    // were the call's return address -- i.e. rsp points AT the
    // restorer slot (sp+32), and ret pops from there. Per SysV,
    // the handler is `void(int sig)`; place sig in rdi.
    let new_rsp = sp + 32;

    debug_sched! {
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
    // Handler entered with rsp=sp+32 (pointing at restorer addr).
    // Handler `ret` popped restorer (rsp=sp+40, jumped to restorer).
    // sa_restorer issues `mov rax, 15; syscall` — at syscall the
    // user rsp is sp+40. Our magic is at sp+0, so frame_base =
    // cur_rsp - 40.
    let frame_base = cur_rsp.saturating_sub(40);
    if frame_base == 0 || frame_base >= hal::USER_VA_END {
        return -(Errno::Einval.as_i32() as i64);
    }
    // SAFETY: frame_base validated < USER_VA_END; CPL=0 reads through caller's AS.
    let magic = unsafe { core::ptr::read_volatile(frame_base as *const u64) };
    if magic != SIG_FRAME_MAGIC {
        return -(Errno::Einval.as_i32() as i64);
    }
    // SAFETY: same validated range as the magic read; saved fields at +8/+16/+24 are 8-byte aligned per the layout we wrote in deliver_x86; CPL=0 reads through caller's AS.
    let (saved_rflags, saved_rsp, saved_rip) = unsafe { (
        core::ptr::read_volatile((frame_base +  8) as *const u64),
        core::ptr::read_volatile((frame_base + 16) as *const u64),
        core::ptr::read_volatile((frame_base + 24) as *const u64),
    ) };
    frame[0] = saved_rip;
    frame[1] = saved_rflags;
    frame[2] = saved_rsp;
    debug_sched! {
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

    // Carve a 40-byte signal frame on the user stack: same wire
    // shape as x86 so the per-arch sa_restorer thunks differ only
    // in the syscall-instruction tail.
    let mut sp = saved_sp.saturating_sub(SIG_FRAME_BYTES);
    // SAFETY: sp is a user-space VA below saved_sp (which came from EL0); kernel CPL=EL1 writes through TTBR0; demand-fault resolves not-present pages via classify_arm_abort + handle.
    unsafe {
        core::ptr::write_volatile((sp +  0) as *mut u64, SIG_FRAME_MAGIC);
        core::ptr::write_volatile((sp +  8) as *mut u64, saved_pstate);
        core::ptr::write_volatile((sp + 16) as *mut u64, saved_sp);
        core::ptr::write_volatile((sp + 24) as *mut u64, saved_pc);
        core::ptr::write_volatile((sp + 32) as *mut u64, restorer);
    }

    // The handler enters with x30 = restorer (so a final `ret`
    // tail-calls into the restorer thunk) and sp = sp+32 (pointing
    // at restorer slot). Per AAPCS64, sig goes in x0.
    let new_sp = sp + 32;

    debug_sched! {
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
    // sa_restorer's `svc #0` happens with sp at frame_base+40 (handler
    // entered at sp+32 = restorer slot, then ret popped 8 → +40).
    let frame_base = cur_sp.saturating_sub(40);
    if frame_base == 0 || frame_base >= hal::USER_VA_END {
        return -(Errno::Einval.as_i32() as i64);
    }
    // SAFETY: frame_base validated < USER_VA_END; CPL=EL1 reads through caller's TTBR0.
    let magic = unsafe { core::ptr::read_volatile(frame_base as *const u64) };
    if magic != SIG_FRAME_MAGIC {
        return -(Errno::Einval.as_i32() as i64);
    }
    // SAFETY: same validated range; saved fields at +8/+16/+24 are 8-byte aligned per layout in deliver_arm.
    let (saved_pstate, saved_sp, saved_pc) = unsafe { (
        core::ptr::read_volatile((frame_base +  8) as *const u64),
        core::ptr::read_volatile((frame_base + 16) as *const u64),
        core::ptr::read_volatile((frame_base + 24) as *const u64),
    ) };
    frame.elr_el1  = saved_pc;
    frame.spsr_el1 = saved_pstate;
    frame.sp_el0   = saved_sp;
    debug_sched! {
        klog::write_raw(b"[INFO]  sig: rt_sigreturn_arm pc=");
        klog::write_hex_u64(saved_pc);
        klog::write_raw(b" sp=");
        klog::write_hex_u64(saved_sp);
        klog::write_raw(b"\n");
    }
    0
}
