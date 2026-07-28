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
/// `r11` slot of the 16-quadword syscall save block — SYSCALL parks the user
/// RFLAGS there and `sysretq` reloads them from it, so this index IS the
/// user's next EFLAGS. Named because a bare `8` next to `s(8, mc.eflags)` is
/// what let an unfiltered user word reach the hardware (B1459).
const F_RFLAGS: usize = 8;
/// Handler-entry SP alignment: `new_rsp % 16 == 8` at handler entry, since the
/// `pretcode` quadword plays the role of a pushed return address (`54§3.3`).
const FRAME_ALIGN: u64 = 16;
/// Byte width of the `pretcode` slot the handler's `ret` pops.
const PRETCODE_BYTES: u64 = 8;
/// Linux `UC_SIGCONTEXT_SS` (`arch/x86/include/uapi/asm/ucontext.h`) —
/// `uc_mcontext.ss` carries the interrupted SS.
const UC_SIGCONTEXT_SS: u64 = 0x2;
/// Linux `UC_STRICT_RESTORE_SS` — sigreturn must restore SS verbatim rather
/// than run `force_valid_ss`. `frame_uc_flags()` sets it for every 64-bit-mode
/// frame. `UC_FP_XSTATE` is NOT set: this frame carries no `fpstate` area.
const UC_STRICT_RESTORE_SS: u64 = 0x4;
/// Width of the x86_64 `syscall` instruction, used when restarting from the
/// hardware-saved post-syscall RIP.
const SYSCALL_INSTRUCTION_BYTES: u64 = core::mem::size_of::<u16>() as u64;

/// The interrupted task's user RSP, out of the live saved syscall frame.
/// `sigaltstack(2)` needs it for `on_sig_stack`, and signal delivery for
/// `sigsp` — both of which Linux drives off `current_user_stack_pointer()`.
/// # SAFETY: syscall/dispatch context on the running task's kstack; the saved
/// frame is live.
/// # C: O(1)
pub unsafe fn current_user_sp() -> u64 {
    // SAFETY: per fn contract — RIP/RFLAGS/RSP triple of the live saved frame.
    let frame = unsafe { &*current_user_frame() };
    frame[2]
}

/// Linux `get_sigframe` (`arch/x86/kernel/signal.c`) placement arithmetic, as
/// a pure function so the caller's `access_ok` check and the builder's write
/// can never disagree about WHERE the frame lands. `None` when the arithmetic
/// underflows or the frame would leave user space — a process is free to run
/// `mov rsp, <kernel VA>; syscall`, so `user_sp` is hostile input.
/// # C: O(1)
pub fn sigframe_base(user_sp: u64, alt: hal::AltStack) -> Option<u64> {
    // `sigsp()`: SA_ONSTACK with a usable alternate stack puts the frame at
    // that stack's TOP; otherwise carve below the interrupted stack's red
    // zone. The red zone does not apply to a fresh alt stack — nothing owns
    // memory below its top. Without this branch a SIGSEGV-on-stack-overflow
    // handler builds its frame on the stack that just overflowed.
    let top = if alt.use_alt { alt.sp.checked_add(alt.size)? }
              else { user_sp.checked_sub(RED_ZONE)? };
    // `sp -= frame_size; sp = round_down(sp, FRAME_ALIGNMENT) - 8`.
    let base = top.checked_sub(core::mem::size_of::<RtSigframe>() as u64)?
                  & !(FRAME_ALIGN - 1);
    base.checked_sub(PRETCODE_BYTES)
}

/// `(base, len, align)` of the rt_sigframe a delivery would write, for the
/// caller's `access_ok`. Linux `x64_setup_rt_frame` does
/// `user_access_begin(frame, sizeof(*frame))` and fails the delivery with
/// `-EFAULT` → `signal_setup_done` → `force_sigsegv` when it does not hold.
/// # C: O(1)
pub fn sigframe_range(user_sp: u64, alt: hal::AltStack) -> Option<(u64, u64, u64)> {
    let base = sigframe_base(user_sp, alt)?;
    if base == 0 { return None; }
    let len = core::mem::size_of::<RtSigframe>() as u64;
    base.checked_add(len).filter(|end| *end <= hal::USER_VA_END)?;
    Some((base, len, PRETCODE_BYTES))
}

/// Build the rt_sigframe on the user stack and rewrite the saved syscall
/// frame so the dispatch return enters `handler(sig, &siginfo, &ucontext)`
/// with RSP at the frame. `old_sigmask` is recorded in the ucontext for
/// rt_sigreturn to restore. The full 16-quadword saved block (all GP regs)
/// is read via `current_user_full_frame` (indices: 0 rax,1 rdi,2 rsi,3 rdx,
/// 4 r10,5 r8,6 r9,7 rcx=rip,8 r11=rflags,9 rsp,10 rbx,11 rbp,12 r13,13 r14,
/// 14 r15,15 r12).
/// Returns `false` without touching user memory or the saved frame when the
/// frame does not fit in user space (Linux `get_sigframe` returning
/// `(void __user *)-1L` / `user_access_begin` failing); the caller must then
/// `force_sigsegv`. That check is the difference between a signal delivery and
/// an arbitrary kernel write: `mov rsp, <kernel VA>; syscall` otherwise has
/// the kernel `write_volatile` a 560-byte attacker-shaped frame there (B1459).
/// # SAFETY: dispatch-tail ctx on the running task's syscall kstack; the
/// saved frame is live; active CR3 is the caller's user AS.
/// # C: O(1)
#[must_use]
pub unsafe fn build_signal_frame(handler: u64, restorer: u64, sig: u32,
                                 saved_ret: u64, restart: bool, old_sigmask: u64,
                                 payload: Option<hal::SigPayload>, alt: hal::AltStack) -> bool {
    let full = current_user_full_frame();
    // SAFETY: dispatch ctx; `full` points at the live 16-quadword saved block.
    let g = |i: usize| unsafe { core::ptr::read_volatile(full.add(i)) };
    // SAFETY: same saved frame, RIP/RFLAGS/RSP triple alias full[7..9].
    let frame = unsafe { &mut *current_user_frame() };
    let saved_rip    = g(7);
    let saved_rflags = g(F_RFLAGS);
    let saved_rsp    = g(9);

    // Placement + `access_ok`-equivalent bound. Frame sits AT/ABOVE new_rsp so
    // the handler's downward stack can't trample it (`54§3.1`).
    let Some((new_rsp, _, _)) = sigframe_range(saved_rsp, alt) else { return false };

    // SAFETY: RtSigframe is plain-old-data (repr(C) integers + byte arrays); an all-zero bit pattern is a valid instance, every meaningful field is overwritten below before the frame is read.
    let mut sf: RtSigframe = unsafe { core::mem::zeroed() };
    sf.pretcode = restorer;
    // Linux `frame_uc_flags()`. No `UC_FP_XSTATE` — `fpstate` is null below.
    sf.uc.uc_flags = UC_SIGCONTEXT_SS | UC_STRICT_RESTORE_SS;
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
    // Linux `save_altstack_ex`: `uc_stack` records the alt-stack state as of
    // frame build, so `rt_sigreturn`'s `restore_altstack` re-arms an
    // SS_AUTODISARM stack the handler ran on.
    sf.uc.uc_stack = StackT { ss_sp: alt.sp, ss_flags: alt.flags, _pad: 0, ss_size: alt.size };
    hal::write_siginfo(&mut sf.info, sig, payload);
    // SAFETY: new_rsp < saved_rsp < USER_VA_END; CPL=0 write via active CR3; repr(C) matches restore.
    unsafe { core::ptr::write_volatile(new_rsp as *mut RtSigframe, sf); }

    frame[0] = handler;          // user RIP = handler
    // Linux `handle_signal`: DF|RF|TF cleared for handler entry. The frame's
    // `sigcontext.eflags` above keeps the PRE-clear value, so rt_sigreturn
    // restores the interrupted code's DF/TF.
    frame[1] = hal::uregs::x86_64::handler_entry_eflags(saved_rflags);
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
    true
}

/// Linux `arch_do_signal_or_restart`'s `regs->ip -= 2` with
/// `regs->ax = regs->orig_ax`: re-enter the SAME syscall number. The live
/// syscall-save block retains the original RAX and argument registers, so
/// only RIP and the eventual return RAX need repair.
/// # SAFETY: syscall-return tail exclusively owns the current saved frame.
/// # C: O(1)
pub unsafe fn restart_ignored_syscall() -> u64 {
    let full = current_user_full_frame();
    // SAFETY: dispatch context owns the 16-word saved syscall register block.
    let nr = unsafe { core::ptr::read_volatile(full) };
    // SAFETY: same saved frame the caller owns; rewind is the only edit.
    unsafe { rewind_syscall_instruction(); }
    nr
}

/// Linux `arch_do_signal_or_restart`'s ERESTART_RESTARTBLOCK arm:
/// `regs->ax = get_nr_restart_syscall(regs); regs->ip -= 2`. The argument
/// registers are irrelevant — `restart_syscall(2)` takes none and resumes
/// through the task's `restart_block`.
/// # SAFETY: syscall-return tail exclusively owns the current saved frame.
/// # C: O(1)
pub unsafe fn restart_via_restart_syscall(nr_restart_syscall: u64) -> u64 {
    // SAFETY: same saved frame the caller owns; rewind is the only edit.
    unsafe { rewind_syscall_instruction(); }
    nr_restart_syscall
}

/// Rewind the saved user RIP over the two-byte `syscall` instruction so the
/// `sysretq` re-executes it.
/// # SAFETY: syscall-return tail exclusively owns the current saved frame.
/// # C: O(1)
unsafe fn rewind_syscall_instruction() {
    // SAFETY: dispatch context exclusively updates the saved RIP/RSP/RFLAGS frame.
    let frame = unsafe { &mut *current_user_frame() };
    frame[0] = frame[0].saturating_sub(SYSCALL_INSTRUCTION_BYTES);
}

/// Restore the full register set from the rt_sigframe's ucontext into the
/// saved syscall frame. Returns `(restored_sigmask, dispatch_retval,
/// uc_stack)` — the caller stores the mask, re-arms the alternate stack from
/// `uc_stack` (Linux `restore_altstack`), and propagates the retval as user
/// rax. `None` on a malformed frame (caller forces SIGSEGV).
/// # SAFETY: rt_sigreturn dispatch ctx on the running task's syscall kstack.
/// # C: O(1)
pub unsafe fn restore_signal_frame() -> Option<(u64, i64, hal::AltStack)> {
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
    let st_ptr = (uc_base + core::mem::offset_of!(Ucontext, uc_stack) as u64) as *const StackT;
    // SAFETY: frame_base < USER_VA_END; CPL=0 read via caller's AS; repr(C) matches build.
    let mc = unsafe { core::ptr::read_volatile(mc_ptr) };
    // SAFETY: sm_ptr is uc_sigmask inside the same validated frame_base region; CPL=0 read via the caller's user AS, identical validity to the mc_ptr read above.
    let sigmask = unsafe { core::ptr::read_volatile(sm_ptr) };
    // SAFETY: st_ptr is uc_stack inside the same validated frame_base region; CPL=0 read via the caller's user AS, identical validity to the mc_ptr read above.
    let st = unsafe { core::ptr::read_volatile(st_ptr) };
    if mc.rip >= hal::USER_VA_END || mc.rsp >= hal::USER_VA_END { return None; }
    // Restore the FULL GP set; slots rcx(7)=rip + r11(8)=eflags carry the
    // sysretq epilogue.
    let full = current_user_full_frame();
    // Linux `restore_sigcontext` (`arch/x86/kernel/signal_64.c`):
    // `regs->flags = (regs->flags & ~FIX_EFLAGS) | (sc.flags & FIX_EFLAGS)`.
    // MUST be read before the write loop below overwrites the slot. `sysretq`
    // reloads RFLAGS straight from this quadword and the Intel SDM's SYSRET
    // mask (`R11 & 3C7FD7H`) passes IOPL, IF, NT and TF through, so an
    // unfiltered `mc.eflags` lets any process grant itself IOPL=3 (port I/O +
    // `cli`) or return to user with interrupts disabled (B1459).
    // SAFETY: dispatch ctx; `full` is the live 16-quadword saved block.
    let cur_rflags = unsafe { core::ptr::read_volatile(full.add(F_RFLAGS)) };
    let new_rflags = hal::uregs::x86_64::sigreturn_eflags(cur_rflags, mc.eflags);
    // SAFETY: dispatch ctx; `full` is the live 16-quadword saved block.
    let s = |i: usize, v: u64| unsafe { core::ptr::write_volatile(full.add(i), v) };
    s(0, mc.rax);  s(1, mc.rdi); s(2, mc.rsi); s(3, mc.rdx);
    s(4, mc.r10);  s(5, mc.r8);  s(6, mc.r9);
    s(7, mc.rip);  s(F_RFLAGS, new_rflags); s(9, mc.rsp);
    s(10, mc.rbx); s(11, mc.rbp); s(12, mc.r13); s(13, mc.r14); s(14, mc.r15); s(15, mc.r12);
    let alt = hal::AltStack { sp: st.ss_sp, size: st.ss_size, flags: st.ss_flags, use_alt: false };
    Some((sigmask, mc.rax as i64, alt))
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

    /// A user SP the process pointed at the kernel half of the address space
    /// (`mov rsp, <kernel VA>; syscall`) must not yield a writable placement:
    /// the builder's `write_volatile` runs at CPL0 through the live CR3 and
    /// would land a 560-byte attacker-shaped frame in kernel memory.
    #[test]
    fn kernel_stack_pointer_yields_no_signal_frame() {
        let none = hal::AltStack::default();
        for sp in [hal::USER_VA_END + 0x10000, 0xffff_ffff_8100_0000,
                   0xffff_8000_0000_0000, 0xffff_ffff_ffff_f000, u64::MAX] {
            assert!(sigframe_range(sp, none).is_none(), "sp {sp:#x} accepted");
        }
    }

    #[test]
    fn a_frame_ending_past_the_user_boundary_is_rejected() {
        let none = hal::AltStack::default();
        // The invariant, swept across the whole boundary: an accepted frame is
        // ALWAYS entirely inside user space. Near the boundary the frame still
        // lands wholly below it, which is what `access_ok` permits — it is
        // carved DOWNWARD from the SP.
        for d in 0..0x4000u64 {
            let sp = hal::USER_VA_END - 0x2000 + d;
            if let Some((base, len, _)) = sigframe_range(sp, none) {
                assert!(base + len <= hal::USER_VA_END, "sp {sp:#x} frame escapes user VA");
            }
        }
        // An alt stack whose top is in kernel space is rejected the same way.
        let alt = hal::AltStack { sp: hal::USER_VA_END - 0x1000, size: 0x4000, flags: 0, use_alt: true };
        assert!(sigframe_range(0x7fff_0000_0000, alt).is_none());
    }

    #[test]
    fn a_tiny_or_wrapping_stack_pointer_is_rejected_not_wrapped() {
        let none = hal::AltStack::default();
        let fsz = core::mem::size_of::<RtSigframe>() as u64;
        for sp in [0u64, 1, RED_ZONE, RED_ZONE + 8, RED_ZONE + fsz,
                   RED_ZONE + fsz + PRETCODE_BYTES - 1] {
            assert!(sigframe_range(sp, none).is_none(), "sp {sp:#x} accepted");
            // The `- 8` for the pretcode slot must not wrap either.
            assert!(sigframe_base(sp, none).is_none(), "sp {sp:#x} base wrapped");
        }
        // Overflowing alt-stack top must not wrap into a low user address.
        let alt = hal::AltStack { sp: u64::MAX - 0x100, size: 0x1000, flags: 0, use_alt: true };
        assert!(sigframe_range(0x7fff_0000_0000, alt).is_none());
    }

    #[test]
    fn handler_entry_sp_is_16n_plus_8_below_the_red_zone() {
        let none = hal::AltStack::default();
        let sp = 0x7fff_ffff_e000u64;
        let (base, len, align) = sigframe_range(sp, none).unwrap();
        assert_eq!(base % FRAME_ALIGN, PRETCODE_BYTES, "54§3.3 handler-entry alignment");
        assert_eq!(len, core::mem::size_of::<RtSigframe>() as u64);
        assert_eq!(align, PRETCODE_BYTES);
        assert!(base + len <= sp - RED_ZONE, "frame overlaps the red zone");
        // The alt-stack arm places the frame at the alt stack's TOP, with no
        // red zone: nothing owns memory below a fresh alt stack.
        let alt = hal::AltStack { sp: 0x1000_0000, size: 0x8000, flags: 0, use_alt: true };
        let (abase, alen, _) = sigframe_range(sp, alt).unwrap();
        assert!(abase >= alt.sp && abase + alen <= alt.sp + alt.size);
        assert_eq!(abase % FRAME_ALIGN, PRETCODE_BYTES);
    }

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
