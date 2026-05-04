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

#![cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]

const SIG_FRAME_MAGIC: u64 = 0x5A55_5A55_DEAD_BEEF;
const SIG_FRAME_BYTES: u64 = 40;

/// Build the signal frame on the user stack and rewrite the
/// per-task user_frame so sysretq enters `handler` with `sig`
/// in rdi and `restorer` as the eventual return target.
/// # SAFETY: caller is the dispatch tail on cur's per-task syscall
/// kernel stack; current_user_frame() points at the live saved
/// tail; user-VA writes target the active CR3 (caller's user AS).
/// # C: O(1)
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

    // Pass `sig` to the handler in rdi. The syscall epilogue restores
    // rdi from the saved-arg slot at top of syscall stack
    // (-0x48 from top per crates/hal-x86_64::syscall.rs); we overwrite
    // that slot so sysretq leaves rdi = sig.
    let kstack_top = hal_x86_64::current_kstack_top();
    if kstack_top != 0 {
        // SAFETY: the syscall asm restore-block reads the saved-rdi at offset -0x48 from top of the syscall stack; we are running on that exact stack pre-restore; writing here makes the asm's `mov rdi, [rsp+0x08]` after restore-loop pull our `sig` into the user rdi.
        unsafe {
            core::ptr::write_volatile((kstack_top - 0x48) as *mut u64, sig as u64);
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
pub unsafe fn rt_sigreturn_x86() -> i64 {
    use syscall::errno::Errno;
    // SAFETY: per fn contract -- frame slot is at top-24..top of cur's syscall stack.
    let frame = unsafe { &mut *hal_x86_64::current_user_frame() };
    let cur_rsp = frame[2];
    // The handler did `ret` to restorer, so rsp is now AT restorer
    // (sp+32). The frame magic is at sp = rsp - 32.
    let frame_base = cur_rsp.saturating_sub(32);
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
