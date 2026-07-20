// x86_64 signal-frame ABI: build/restore the full Linux `rt_sigframe`
// (siginfo_t + ucontext_t) so SA_SIGINFO handlers (Go runtime, glibc/musl
// crash handlers, profilers) get `handler(sig, &siginfo, &ucontext)` and
// rt_sigreturn restores the full register set. Arch-specific layout lives
// HERE (not #[cfg]-gated in the generic fs dispatcher). The generic caller
// (`fs::sig_dispatch`) owns sigmask/sched orchestration and passes
// `old_sigmask` in / gets the restored mask out.
//
// Layout MUST match Linux exactly — Go hardcodes the offsets (sigctxt.rip()
// reads uc_mcontext+128). Asserted below.

use crate::{current_user_frame, current_user_full_frame};

/// Linux x86_64 `struct sigcontext` (== `ucontext.uc_mcontext`).
#[repr(C)]
#[derive(Clone, Copy)]
struct Sigctx {
    r8: u64, r9: u64, r10: u64, r11: u64, r12: u64, r13: u64, r14: u64, r15: u64,
    rdi: u64, rsi: u64, rbp: u64, rbx: u64, rdx: u64, rax: u64, rcx: u64, rsp: u64,
    rip: u64,
    eflags: u64,
    cs: u16, gs: u16, fs: u16, ss: u16,
    err: u64,
    trapno: u64,
    oldmask: u64,
    cr2: u64,
    fpstate: u64,
    reserved: [u64; 8],
}

/// Linux `stack_t` (uc_stack).
#[repr(C)]
#[derive(Clone, Copy)]
struct StackT { ss_sp: u64, ss_flags: i32, _pad: u32, ss_size: u64 }

/// Linux x86_64 `ucontext_t`.
#[repr(C)]
#[derive(Clone, Copy)]
struct Ucontext {
    uc_flags: u64,
    uc_link:  u64,
    uc_stack: StackT,
    uc_mcontext: Sigctx,
    uc_sigmask: [u64; 16],
}

/// rt_sigframe at the handler's entry SP (`new_rsp`). `pretcode` is the
/// restorer the handler's `ret` lands on; `uc` at +8, `info` after it.
#[repr(C)]
struct RtSigframe {
    pretcode: u64,
    uc:   Ucontext,
    info: [u8; 128],
}

const _: () = {
    assert!(core::mem::offset_of!(Sigctx, rip) == 128);
    assert!(core::mem::offset_of!(Sigctx, eflags) == 136);
    assert!(core::mem::offset_of!(Sigctx, cr2) == 176);
    assert!(core::mem::size_of::<Sigctx>() == 256);
    assert!(core::mem::offset_of!(Ucontext, uc_mcontext) == 40);
    assert!(core::mem::offset_of!(Ucontext, uc_sigmask) == 296);
    assert!(core::mem::offset_of!(RtSigframe, uc) == 8);
};

/// x86_64 SysV ABI red zone — 128 B below RSP callers may use across calls.
const RED_ZONE: u64 = 128;
/// Width of the x86_64 `syscall` instruction, used when restarting from the
/// hardware-saved post-syscall RIP.
const SYSCALL_INSTRUCTION_BYTES: u64 = core::mem::size_of::<u16>() as u64;

/// Build the rt_sigframe on the user stack and rewrite the saved syscall
/// frame so the dispatch return enters `handler(sig, &siginfo, &ucontext)`
/// with RSP at the frame. `old_sigmask` is recorded in the ucontext for
/// rt_sigreturn to restore. The full 16-quadword saved block (all GP regs)
/// is read via `current_user_full_frame` (indices: 0 rax,1 rdi,2 rsi,3 rdx,
/// 4 r10,5 r8,6 r9,7 rcx=rip,8 r11=rflags,9 rsp,10 rbx,11 rbp,12 r13,13 r14,
/// 14 r15,15 r12).
/// # SAFETY: dispatch-tail ctx on the running task's syscall kstack; the
/// saved frame is live; active CR3 is the caller's user AS.
/// # C: O(1)
pub unsafe fn build_signal_frame(handler: u64, restorer: u64, sig: u32,
                                 saved_ret: u64, restart: bool, old_sigmask: u64,
                                 chld: Option<hal::SigChld>) {
    let full = current_user_full_frame();
    // SAFETY: dispatch ctx; `full` points at the live 16-quadword saved block.
    let g = |i: usize| unsafe { core::ptr::read_volatile(full.add(i)) };
    // SAFETY: same saved frame, RIP/RFLAGS/RSP triple alias full[7..9].
    let frame = unsafe { &mut *current_user_frame() };
    let saved_rip    = g(7);
    let saved_rflags = g(8);
    let saved_rsp    = g(9);

    // Carve the frame below the red zone; new_rsp%16==8 at handler entry
    // (pretcode plays the pushed-return-address role). Frame sits AT/ABOVE
    // new_rsp so the handler's downward stack can't trample it.
    let top = saved_rsp.saturating_sub(RED_ZONE);
    let fsz = core::mem::size_of::<RtSigframe>() as u64;
    let new_rsp = top.saturating_sub(fsz) & !0xfu64;
    let new_rsp = new_rsp.saturating_sub(8);

    // SAFETY: RtSigframe is plain-old-data (repr(C) integers + byte arrays); an all-zero bit pattern is a valid instance, every meaningful field is overwritten below before the frame is read.
    let mut sf: RtSigframe = unsafe { core::mem::zeroed() };
    sf.pretcode = restorer;
    sf.uc.uc_mcontext = Sigctx {
        r8: g(5), r9: g(6), r10: g(4), r11: saved_rflags,
        r12: g(15), r13: g(12), r14: g(13), r15: g(14),
        rdi: g(1), rsi: g(2), rbp: g(11), rbx: g(10),
        rdx: g(3), rax: if restart { g(0) } else { saved_ret }, rcx: saved_rip, rsp: saved_rsp,
        rip: if restart { saved_rip.saturating_sub(SYSCALL_INSTRUCTION_BYTES) } else { saved_rip }, eflags: saved_rflags,
        cs: 0x33, gs: 0, fs: 0, ss: 0x2b,
        err: 0, trapno: 0, oldmask: old_sigmask, cr2: 0,
        fpstate: 0, reserved: [0; 8],
    };
    sf.uc.uc_sigmask[0] = old_sigmask;
    sf.info[0..4].copy_from_slice(&(sig as i32).to_ne_bytes()); // si_signo
    // B117: SIGCHLD _sifields per Linux siginfo_t (asm-generic):
    // si_code@8, si_pid@16, si_uid@20, si_status@24. si_errno@4
    // stays 0. These are the fields a reaper switches on.
    if let Some(c) = chld {
        sf.info[8..12].copy_from_slice(&c.code.to_ne_bytes());    // si_code
        sf.info[16..20].copy_from_slice(&c.pid.to_ne_bytes());    // si_pid
        sf.info[20..24].copy_from_slice(&c.uid.to_ne_bytes());    // si_uid
        sf.info[24..28].copy_from_slice(&c.status.to_ne_bytes()); // si_status
    }
    // SAFETY: new_rsp < saved_rsp < USER_VA_END; CPL=0 write via active CR3; repr(C) matches restore.
    unsafe { core::ptr::write_volatile(new_rsp as *mut RtSigframe, sf); }

    frame[0] = handler;          // user RIP = handler
    frame[1] = saved_rflags;
    frame[2] = new_rsp;          // user RSP = frame
    // SA_SIGINFO args: rdi=sig, rsi=&siginfo, rdx=&ucontext (exit asm restores
    // rdi/rsi/rdx from saved slots top-0x78/-0x70/-0x68).
    let kstack_top = crate::current_kstack_top();
    if kstack_top != 0 {
        let info_ptr = new_rsp + core::mem::offset_of!(RtSigframe, info) as u64;
        let uc_ptr   = new_rsp + core::mem::offset_of!(RtSigframe, uc) as u64;
        // SAFETY: writing saved rdi/rsi/rdx slots on the live syscall stack pre-restore.
        unsafe {
            core::ptr::write_volatile((kstack_top - 0x78) as *mut u64, sig as u64);
            core::ptr::write_volatile((kstack_top - 0x70) as *mut u64, info_ptr);
            core::ptr::write_volatile((kstack_top - 0x68) as *mut u64, uc_ptr);
        }
    }
}

/// Restart an `ERESTARTSYS` call after a signal with an ignored disposition.
/// The live syscall-save block retains the original RAX syscall number and
/// argument registers, so only RIP and the eventual return RAX need repair.
/// # SAFETY: syscall-return tail exclusively owns the current saved frame.
/// # C: O(1)
pub unsafe fn restart_ignored_syscall() -> u64 {
    let full = current_user_full_frame();
    // SAFETY: dispatch context owns the 16-word saved syscall register block.
    let nr = unsafe { core::ptr::read_volatile(full) };
    // SAFETY: dispatch context exclusively updates the saved RIP/RSP/RFLAGS frame.
    let frame = unsafe { &mut *current_user_frame() };
    frame[0] = frame[0].saturating_sub(SYSCALL_INSTRUCTION_BYTES);
    nr
}

/// Restore the full register set from the rt_sigframe's ucontext into the
/// saved syscall frame. Returns `(restored_sigmask, dispatch_retval)` — the
/// caller stores the mask (sched) and propagates the retval as user rax.
/// `None` on a malformed frame (caller forces SIGSEGV).
/// # SAFETY: rt_sigreturn dispatch ctx on the running task's syscall kstack.
/// # C: O(1)
pub unsafe fn restore_signal_frame() -> Option<(u64, i64)> {
    // SAFETY: dispatch ctx; RIP/RFLAGS/RSP triple of the live saved frame.
    let frame = unsafe { &*current_user_frame() };
    let cur_rsp = frame[2];               // = new_rsp + 8 (ret popped pretcode)
    let frame_base = cur_rsp.saturating_sub(8);
    if frame_base == 0 { return None; }
    if frame_base.checked_add(core::mem::size_of::<RtSigframe>() as u64)
        .filter(|end| *end <= hal::USER_VA_END).is_none() { return None; }
    let uc_base = frame_base + core::mem::offset_of!(RtSigframe, uc) as u64;
    let mc_ptr = (uc_base + core::mem::offset_of!(Ucontext, uc_mcontext) as u64) as *const Sigctx;
    let sm_ptr = (uc_base + core::mem::offset_of!(Ucontext, uc_sigmask) as u64) as *const u64;
    // SAFETY: frame_base < USER_VA_END; CPL=0 read via caller's AS; repr(C) matches build.
    let mc = unsafe { core::ptr::read_volatile(mc_ptr) };
    // SAFETY: sm_ptr is uc_sigmask inside the same validated frame_base region; CPL=0 read via the caller's user AS, identical validity to the mc_ptr read above.
    let sigmask = unsafe { core::ptr::read_volatile(sm_ptr) };
    if mc.rip >= hal::USER_VA_END || mc.rsp >= hal::USER_VA_END { return None; }
    // Restore the FULL GP set; slots rcx(7)=rip + r11(8)=eflags carry the
    // sysretq epilogue.
    let full = current_user_full_frame();
    // SAFETY: dispatch ctx; `full` is the live 16-quadword saved block.
    let s = |i: usize, v: u64| unsafe { core::ptr::write_volatile(full.add(i), v) };
    s(0, mc.rax);  s(1, mc.rdi); s(2, mc.rsi); s(3, mc.rdx);
    s(4, mc.r10);  s(5, mc.r8);  s(6, mc.r9);
    s(7, mc.rip);  s(8, mc.eflags); s(9, mc.rsp);
    s(10, mc.rbx); s(11, mc.rbp); s(12, mc.r13); s(13, mc.r14); s(14, mc.r15); s(15, mc.r12);
    Some((sigmask, mc.rax as i64))
}

/// User rt-sigframe range for pre-copy badframe validation. # C: O(1)
pub fn rt_sigreturn_frame_range() -> Option<(u64, u64, u64)> {
    // SAFETY: rt_sigreturn dispatch context owns the live syscall frame slots.
    let frame = unsafe { &*current_user_frame() };
    let frame_base = frame[2].checked_sub(8)?;
    if frame_base == 0 { return None; }
    let len = core::mem::size_of::<RtSigframe>() as u64;
    frame_base.checked_add(len).filter(|end| *end <= hal::USER_VA_END)?;
    Some((frame_base, len, 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x86_64_rt_sigframe_matches_linux_uapi_shape() {
        assert_eq!(core::mem::offset_of!(Sigctx, rip), 128);
        assert_eq!(core::mem::offset_of!(Sigctx, eflags), 136);
        assert_eq!(core::mem::offset_of!(Sigctx, cr2), 176);
        assert_eq!(core::mem::size_of::<Sigctx>(), 256);
        assert_eq!(core::mem::offset_of!(Ucontext, uc_mcontext), 40);
        assert_eq!(core::mem::offset_of!(Ucontext, uc_sigmask), 296);
        assert_eq!(core::mem::offset_of!(RtSigframe, uc), 8);
    }
}
