// aarch64 signal-frame ABI: build/restore the full Linux `rt_sigframe`
// (siginfo_t + ucontext_t) so SA_SIGINFO handlers (Go runtime, glibc/musl
// crash handlers, profilers) get `handler(sig, &siginfo, &ucontext)` and
// rt_sigreturn restores the full register set. Arch-specific layout lives
// HERE (not #[cfg]-gated in the generic fs dispatcher). The generic caller
// (`fs::sig_dispatch`) owns sigmask/sched + resolves the live SvcFrame
// pointer (the F206 per-task slot) and passes it in.
//
// Layout MUST match Linux aarch64 exactly — Go hardcodes the offsets
// (sigctxt.regs()/pc()/sp() read uc_mcontext+8/264/256). Asserted below.

use crate::SvcFrame;

const SIGCONTEXT_RESERVED_BYTES: usize = 4096;
/// Width of the AArch64 `svc #0` instruction, used when restarting an
/// interrupted syscall from its post-SVC ELR.
const SVC_INSTRUCTION_BYTES: u64 = core::mem::size_of::<u32>() as u64;

/// Linux aarch64 `struct sigcontext` (== `ucontext.uc_mcontext`). __reserved
/// holds optional fpsimd/extra records terminated by a zero magic; left zero.
#[repr(C)]
#[derive(Clone, Copy)]
struct Sigctx {
    fault_address: u64,
    regs: [u64; 31],   // x0..x30
    sp: u64,
    pc: u64,
    pstate: u64,
    __reserved: [u8; SIGCONTEXT_RESERVED_BYTES],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct StackT { ss_sp: u64, ss_flags: i32, _pad: u32, ss_size: u64 }

/// Linux aarch64 `ucontext_t`. uc_mcontext is 16-aligned at +176.
#[repr(C)]
#[derive(Clone, Copy)]
struct Ucontext {
    uc_flags: u64,
    uc_link:  u64,
    uc_stack: StackT,
    uc_sigmask: u64,
    __unused: [u8; 1024 / 8 - 8],   // pad sigmask area to 128 B (1024-bit)
    __glibc_pad: [u8; 8],           // align uc_mcontext to +176
    uc_mcontext: Sigctx,
}

/// aarch64 rt_sigframe at the handler's entry SP. siginfo first, ucontext +128.
#[repr(C)]
struct RtSigframe {
    info: [u8; 128],
    uc:   Ucontext,
}

const _: () = {
    assert!(core::mem::offset_of!(Sigctx, regs) == 8);
    assert!(core::mem::offset_of!(Sigctx, sp) == 256);
    assert!(core::mem::offset_of!(Sigctx, pc) == 264);
    assert!(core::mem::offset_of!(Sigctx, pstate) == 272);
    assert!(core::mem::offset_of!(Sigctx, __reserved) == 280);
    assert!(core::mem::size_of::<Sigctx>() == 4376);
    assert!(core::mem::offset_of!(Ucontext, uc_mcontext) == 176);
    assert!(core::mem::offset_of!(RtSigframe, uc) == 128);
};

/// Read x0..x30 out of the scattered SvcFrame slots into a contiguous array.
#[inline]
fn regs_from_frame(f: &SvcFrame) -> [u64; 31] {
    let mut r = [0u64; 31];
    for i in 0..18 { r[i] = f.gp[i]; }        // x0..x17
    r[18] = f.x18_x29[0];                      // x18
    for i in 0..10 { r[19 + i] = f.x19_x28[i]; } // x19..x28
    r[29] = f.x18_x29[1];                      // x29
    r[30] = f.x30;                             // x30
    r
}

/// Build the rt_sigframe on the user stack and rewrite `frame` so the
/// dispatch `eret` enters the handler with x1=&siginfo, x2=&ucontext, pc=
/// handler, lr=restorer, sp=frame. x0=sig is seeded by the dispatch retval
/// (the SVC restore's `ldr x0,[sp,#0xc8]`), so the caller returns `sig`.
/// `saved_ret` is the interrupted syscall's x0 (stored in the ucontext for
/// rt_sigreturn). `old_sigmask` is recorded for rt_sigreturn to restore.
/// # SAFETY: dispatch-tail ctx; `frame` is the live saved SVC frame; active
/// TTBR0 is the caller's user AS.
/// # C: O(1)
pub unsafe fn build_signal_frame(frame: *mut SvcFrame, handler: u64, restorer: u64,
                                 sig: u32, saved_ret: u64, restart: bool, old_sigmask: u64,
                                 chld: Option<hal::SigChld>) {
    // SAFETY: per fn contract — sole writer of the live SVC frame this dispatch.
    let frame = unsafe { &mut *frame };
    let saved_pc     = frame.elr_el1;
    let saved_pstate = frame.spsr_el1;
    let saved_sp     = frame.sp_el0;
    let mut regs = regs_from_frame(frame);
    if !restart { regs[0] = saved_ret; } // x0 = interrupted syscall's return value

    let fsz = core::mem::size_of::<RtSigframe>() as u64;
    let new_sp = saved_sp.saturating_sub(fsz) & !0xfu64; // AAPCS64 SP%16==0

    // SAFETY: RtSigframe is plain-old-data (repr(C) integers + byte arrays); an all-zero bit pattern is a valid instance, every meaningful field is overwritten below before the frame is read.
    let mut sf: RtSigframe = unsafe { core::mem::zeroed() };
    sf.uc.uc_mcontext = Sigctx {
        fault_address: 0, regs, sp: saved_sp,
        pc: if restart { saved_pc.saturating_sub(SVC_INSTRUCTION_BYTES) } else { saved_pc },
        pstate: saved_pstate,
        __reserved: [0; SIGCONTEXT_RESERVED_BYTES],
    };
    sf.uc.uc_sigmask = old_sigmask;
    sf.info[0..4].copy_from_slice(&(sig as i32).to_ne_bytes()); // si_signo
    // B117: SIGCHLD _sifields — same generic siginfo_t layout as
    // x86_64 (asm-generic): si_code@8, si_pid@16, si_uid@20,
    // si_status@24. si_errno@4 stays 0.
    if let Some(c) = chld {
        sf.info[8..12].copy_from_slice(&c.code.to_ne_bytes());    // si_code
        sf.info[16..20].copy_from_slice(&c.pid.to_ne_bytes());    // si_pid
        sf.info[20..24].copy_from_slice(&c.uid.to_ne_bytes());    // si_uid
        sf.info[24..28].copy_from_slice(&c.status.to_ne_bytes()); // si_status
    }
    // SAFETY: new_sp < saved_sp (EL0) < USER_VA_END; CPL=EL1 writes via TTBR0; repr(C) matches restore.
    unsafe { core::ptr::write_volatile(new_sp as *mut RtSigframe, sf); }

    let info_ptr = new_sp + core::mem::offset_of!(RtSigframe, info) as u64;
    let uc_ptr   = new_sp + core::mem::offset_of!(RtSigframe, uc) as u64;
    frame.gp[1]   = info_ptr;   // x1 = &siginfo (restored by SVC exit asm)
    frame.gp[2]   = uc_ptr;     // x2 = &ucontext
    frame.gp[0]   = sig as u64; // x0 (also seeded via dispatch retval)
    frame.elr_el1 = handler;    // pc = handler
    frame.x30     = restorer;   // lr — handler `ret` lands at restorer
    frame.sp_el0  = new_sp;
}

/// Restart an `ERESTARTSYS` call after a signal with an ignored disposition.
/// The SVC frame still holds the original x0 argument and x8 syscall number;
/// rewind the post-SVC PC and return x0 so the assembly epilogue restores the
/// exact pre-SVC register state Linux re-enters.
/// # SAFETY: syscall-return tail owns the live SVC frame exclusively.
/// # C: O(1)
pub unsafe fn restart_ignored_syscall(frame: *mut SvcFrame) -> u64 {
    // SAFETY: caller guarantees `frame` is the current task's live SVC frame.
    let frame = unsafe { &mut *frame };
    frame.elr_el1 = frame.elr_el1.saturating_sub(SVC_INSTRUCTION_BYTES);
    frame.gp[0]
}

/// Restore the full register set from the rt_sigframe's ucontext into the
/// saved SVC `frame`. Returns `(restored_sigmask, x0)` — caller stores the
/// mask (sched) and returns x0 as the dispatch retval (seeds user x0).
/// `None` on a malformed frame.
/// # SAFETY: rt_sigreturn dispatch ctx; `frame` is the live saved SVC frame.
/// # C: O(1)
pub unsafe fn restore_signal_frame(frame: *mut SvcFrame) -> Option<(u64, i64)> {
    // SAFETY: per fn contract — sole writer of the live SVC frame.
    let frame = unsafe { &mut *frame };
    // ARM `ret`=`br lr` does NOT pop; handler epilogue restores SP to new_sp
    // before `ret`, so the restorer's `svc #0` fires with sp_el0 == frame_base.
    let frame_base = frame.sp_el0;
    if frame_base == 0 || (frame_base & 15) != 0 { return None; }
    if frame_base.checked_add(core::mem::size_of::<RtSigframe>() as u64)
        .filter(|end| *end <= hal::USER_VA_END).is_none() { return None; }
    let uc_base = frame_base + core::mem::offset_of!(RtSigframe, uc) as u64;
    let mc_ptr = (uc_base + core::mem::offset_of!(Ucontext, uc_mcontext) as u64) as *const Sigctx;
    let sm_ptr = (uc_base + core::mem::offset_of!(Ucontext, uc_sigmask) as u64) as *const u64;
    // SAFETY: frame_base < USER_VA_END; CPL=EL1 reads via TTBR0; repr(C) matches build.
    let mc = unsafe { core::ptr::read_volatile(mc_ptr) };
    // SAFETY: sm_ptr is uc_sigmask inside the same validated frame_base region; CPL=EL1 read via the caller's TTBR0, identical validity to the mc_ptr read above.
    let sigmask = unsafe { core::ptr::read_volatile(sm_ptr) };
    if mc.pc >= hal::USER_VA_END || mc.sp >= hal::USER_VA_END { return None; }
    // Restore x0..x30 into the scattered SvcFrame slots.
    for i in 0..18 { frame.gp[i] = mc.regs[i]; }
    frame.x18_x29[0] = mc.regs[18];
    for i in 0..10 { frame.x19_x28[i] = mc.regs[19 + i]; }
    frame.x18_x29[1] = mc.regs[29];
    frame.x30      = mc.regs[30];
    frame.sp_el0   = mc.sp;
    frame.elr_el1  = mc.pc;
    frame.spsr_el1 = mc.pstate;
    Some((sigmask, mc.regs[0] as i64))
}

/// User rt-sigframe range for pre-copy badframe validation. # C: O(1)
pub unsafe fn rt_sigreturn_frame_range(frame: *mut SvcFrame) -> Option<(u64, u64, u64)> {
    if frame.is_null() { return None; }
    // SAFETY: rt_sigreturn dispatch supplies the live SVC frame pointer.
    let frame = unsafe { &*frame };
    let frame_base = frame.sp_el0;
    if frame_base == 0 || (frame_base & 15) != 0 { return None; }
    let len = core::mem::size_of::<RtSigframe>() as u64;
    frame_base.checked_add(len).filter(|end| *end <= hal::USER_VA_END)?;
    Some((frame_base, len, 16))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aarch64_rt_sigframe_matches_linux_uapi_shape() {
        assert_eq!(core::mem::offset_of!(Sigctx, regs), 8);
        assert_eq!(core::mem::offset_of!(Sigctx, sp), 256);
        assert_eq!(core::mem::offset_of!(Sigctx, pc), 264);
        assert_eq!(core::mem::offset_of!(Sigctx, pstate), 272);
        assert_eq!(core::mem::offset_of!(Sigctx, __reserved), 280);
        assert_eq!(core::mem::size_of::<Sigctx>(), 4376);
        assert_eq!(core::mem::offset_of!(Ucontext, uc_mcontext), 176);
        assert_eq!(core::mem::offset_of!(RtSigframe, uc), 128);
    }
}
