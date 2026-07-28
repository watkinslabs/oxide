// x86_64 signal-frame ABI: build/restore the full Linux `rt_sigframe`
// (siginfo_t + ucontext_t + the FPU/extended-state area) so SA_SIGINFO
// handlers (Go runtime, glibc/musl crash handlers, profilers) get
// `handler(sig, &siginfo, &ucontext)` and rt_sigreturn restores the full
// register set. Arch-specific layout lives HERE (not #[cfg]-gated in the
// generic fs dispatcher). The generic caller (`fs::sig_dispatch`) owns
// sigmask/sched orchestration, passes `old_sigmask` in / gets the restored
// mask out, and owns the per-task XSAVE buffer this file reads and writes.
//
// Layout MUST match Linux exactly — Go hardcodes the offsets (sigctxt.rip()
// reads uc_mcontext+128). Asserted below.
//
// Module manifest:
//   `xstate` — `uc_mcontext.fpstate` area: layout, epilog, restore checks.
//   `tests`  — host unit tests, including an end-to-end frame round trip.

use crate::gdt::USER_CS_SELECTOR;
use crate::pt_regs::PtRegs;

pub(crate) mod xstate;

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
    assert!(core::mem::offset_of!(Sigctx, fpstate) == 184);
    assert!(core::mem::size_of::<Sigctx>() == 256);
    assert!(core::mem::offset_of!(Ucontext, uc_mcontext) == 40);
    assert!(core::mem::offset_of!(Ucontext, uc_sigmask) == 296);
    assert!(core::mem::offset_of!(RtSigframe, uc) == 8);
};

/// x86_64 SysV ABI red zone — 128 B below RSP callers may use across calls.
const RED_ZONE: u64 = 128;
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
/// frame.
const UC_STRICT_RESTORE_SS: u64 = 0x4;
/// Linux `UC_FP_XSTATE` — `uc_mcontext.fpstate` carries an extended (XSAVE)
/// area, not just the 512-byte legacy image. `frame_uc_flags()` sets it
/// exactly when `boot_cpu_has(X86_FEATURE_XSAVE)`.
const UC_FP_XSTATE: u64 = 0x1;
/// FXRSTOR's operand alignment (Intel SDM); XSAVE's 64 is the stricter case.
const FXSAVE_ALIGN: u64 = 16;
/// Width of the x86_64 `syscall` instruction, used when restarting from the
/// hardware-saved post-syscall RIP.
const SYSCALL_INSTRUCTION_BYTES: u64 = core::mem::size_of::<u16>() as u64;

/// Placement of one delivery's user-stack objects. Linux `get_sigframe`
/// builds this triple: the math (xstate) frame is carved first, 64-byte
/// aligned, and the rt_sigframe goes BELOW it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FrameLayout {
    /// Handler-entry RSP; `RtSigframe` starts here.
    pub sp: u64,
    /// `uc_mcontext.fpstate` — 64-byte-aligned base of the XSAVE image.
    pub fpstate: u64,
    /// Bytes reserved at `fpstate` (Linux `xstate_sigframe_size`).
    pub math: u64,
}

/// Linux `get_sigframe` (`arch/x86/kernel/signal.c`) placement arithmetic, as
/// a pure function of the math-frame size so the caller's `access_ok` check
/// and the builder's write can never disagree about WHERE the frame lands.
/// `None` when the arithmetic underflows — a process is free to run
/// `mov rsp, <kernel VA>; syscall`, so `user_sp` is hostile input.
/// # C: O(1)
pub fn frame_layout(user_sp: u64, alt: hal::AltStack, math: u64) -> Option<FrameLayout> {
    // `sigsp()`: SA_ONSTACK with a usable alternate stack puts the frame at
    // that stack's TOP; otherwise carve below the interrupted stack's red
    // zone. The red zone does not apply to a fresh alt stack — nothing owns
    // memory below its top. Without this branch a SIGSEGV-on-stack-overflow
    // handler builds its frame on the stack that just overflowed.
    let top = if alt.use_alt { alt.sp.checked_add(alt.size)? }
              else { user_sp.checked_sub(RED_ZONE)? };
    // `fpu__alloc_mathframe`: `*buf_fx = sp = round_down(sp - frame_size, 64)`.
    let fpstate = top.checked_sub(math)? & !(xstate::XSTATE_ALIGN - 1);
    // `sp -= frame_size; sp = round_down(sp, FRAME_ALIGNMENT) - 8`.
    let base = fpstate.checked_sub(core::mem::size_of::<RtSigframe>() as u64)?
                      & !(FRAME_ALIGN - 1);
    Some(FrameLayout { sp: base.checked_sub(PRETCODE_BYTES)?, fpstate, math })
}

/// Bytes of XSAVE image this CPU writes into a signal frame. Read once per
/// delivery so the placement math and the write agree.
/// # C: O(1)
fn math_size() -> u64 { xstate::math_frame_size(crate::xsave_area_bytes()) as u64 }

/// Linux `get_sigframe_size()`, exported to userspace as `AT_MINSIGSTKSZ`.
/// The legacy `MINSIGSTKSZ` (2048) has not covered a real x86_64 signal frame
/// since AVX; glibc 2.34+ takes the true size from the auxv, which is the
/// whole reason Linux exports it.
/// # C: O(1)
pub fn min_sigstksz() -> usize {
    xstate::min_sigstksz(core::mem::size_of::<RtSigframe>(), crate::xsave_area_bytes())
}

/// The interrupted task's user RSP, out of its live entry frame.
/// `sigaltstack(2)` needs it for `on_sig_stack`, and signal delivery for
/// `sigsp` — both of which Linux drives off `current_user_stack_pointer()`.
/// `0` for a null frame (no user entry on this CPU yet).
/// # SAFETY: dispatch context on the running task's kstack; `regs` is that
/// task's live entry frame.
/// # C: O(1)
pub unsafe fn current_user_sp(regs: *mut PtRegs) -> u64 {
    if regs.is_null() { return 0; }
    // SAFETY: per fn contract — `regs` is the live entry frame, read-only here.
    unsafe { (*regs).rsp }
}

/// Handler-entry RSP a delivery would use. # C: O(1)
pub fn sigframe_base(user_sp: u64, alt: hal::AltStack) -> Option<u64> {
    frame_layout(user_sp, alt, math_size()).map(|l| l.sp)
}

/// `(base, len, align)` spanning EVERY user byte a delivery writes — the
/// rt_sigframe AND the xstate area above it — for the caller's `access_ok`.
/// Linux checks the two separately (`user_access_begin(frame, sizeof(*frame))`
/// and `access_ok(buf, size)` inside `copy_fpstate_to_sigframe`); one span
/// over the contiguous region is the same guarantee. Failing it fails the
/// delivery with `-EFAULT` → `signal_setup_done` → `force_sigsegv`.
/// # C: O(1)
pub fn sigframe_range(user_sp: u64, alt: hal::AltStack) -> Option<(u64, u64, u64)> {
    frame_span(user_sp, alt, math_size())
}

/// `sigframe_range` with an explicit math size, so the span rule is testable
/// against both the XSAVE and the FXSAVE-fallback frame shapes.
/// # C: O(1)
fn frame_span(user_sp: u64, alt: hal::AltStack, math: u64) -> Option<(u64, u64, u64)> {
    let l = frame_layout(user_sp, alt, math)?;
    if l.sp == 0 { return None; }
    let end = l.fpstate.checked_add(l.math)?;
    if end > hal::USER_VA_END { return None; }
    // Linux `get_sigframe`: "If we are on the alternate signal stack and would
    // overflow it, don't. Return an always-bogus address instead so we will
    // die with SIGSEGV." `__on_sig_stack(sp)` is `sp > ss_sp && sp - ss_sp <=
    // ss_size` (`include/linux/sched/signal.h:574`).
    //
    // Load-bearing since B1466 grew the frame past the legacy `MINSIGSTKSZ`:
    // an XSAVE-carrying frame is ~3.3 KB, `sigaltstack(2)` still accepts
    // `ss_size == 2048` (Linux's own gate is the static `MINSIGSTKSZ` too —
    // `do_sigaltstack`'s `min_ss_size`, with `sigaltstack_size_valid` a no-op
    // outside `CONFIG_DYNAMIC_SIGFRAME`), and userspace is expected to size
    // from `AT_MINSIGSTKSZ` instead. Without this check a program that did not
    // would have its frame carved BELOW its alternate stack, over whatever
    // lives there.
    if alt.use_alt && !(l.sp > alt.sp && l.sp - alt.sp <= alt.size) { return None; }
    Some((l.sp, end.checked_sub(l.sp)?, PRETCODE_BYTES))
}

/// Build the rt_sigframe on the user stack and rewrite `regs` so the entry
/// return enters `handler(sig, &siginfo, &ucontext)` with RSP at the frame.
/// `old_sigmask` is recorded in the ucontext for rt_sigreturn to restore.
///
/// `regs` is the frame of WHATEVER entry is returning to user — syscall,
/// fault or IRQ (`pt_regs.rs`) — never a hardcoded syscall save block, which
/// is what let a userspace spin loop ignore signals.
///
/// `fpu` is the calling task's XSAVE image, already synced from the hardware
/// by the caller (Linux's `copy_fpstate_to_sigframe` does the `xsave` itself;
/// our per-task buffer lives in `sched`, so the sync is the caller's job).
/// Too short a slice writes `fpstate = 0`, which Linux defines as "no FPU
/// context" and answers at sigreturn by re-initialising the FPU.
///
/// Returns `false` without touching user memory or the saved frame when the
/// frame does not fit in user space (Linux `get_sigframe` returning
/// `(void __user *)-1L` / `user_access_begin` failing); the caller must then
/// `force_sigsegv`. That check is the difference between a signal delivery and
/// an arbitrary kernel write: `mov rsp, <kernel VA>; syscall` otherwise has
/// the kernel `write_volatile` an attacker-shaped frame there (B1459).
/// # SAFETY: entry-return ctx on the running task's kstack; `regs` is that
/// entry's live frame; active CR3 is the caller's user AS.
/// # C: O(n) in the XSAVE image size
#[must_use]
pub unsafe fn build_signal_frame(regs: *mut PtRegs, handler: u64, restorer: u64, sig: u32,
                                 saved_ret: u64, restart: bool, old_sigmask: u64,
                                 payload: Option<hal::SigPayload>, alt: hal::AltStack,
                                 fpu: &[u8]) -> bool {
    if regs.is_null() { return false }
    // SAFETY: per fn contract — sole writer of this entry's live frame.
    let r = unsafe { &mut *regs };
    let saved_rip    = r.rip;
    let saved_rflags = r.rflags;
    let saved_rsp    = r.rsp;

    // Placement + `access_ok`-equivalent bound. Frame sits AT/ABOVE new_rsp so
    // the handler's downward stack can't trample it (`54§3.1`).
    let area = crate::xsave_area_bytes();
    let math = xstate::math_frame_size(area);
    if frame_span(saved_rsp, alt, math as u64).is_none() { return false }
    let Some(l) = frame_layout(saved_rsp, alt, math as u64) else { return false };
    let new_rsp = l.sp;
    // The FPU image only lands in the frame when the caller supplied a full
    // one; a task-less delivery gets Linux's legal `fpstate = 0`. The task
    // buffer holds `user_size` bytes of image — the `MAGIC2` trailer is a
    // frame-only footer and lives in the extra 4 bytes of `math`, so the
    // buffer is NOT required to be `math` long.
    let user_size = xstate::user_xstate_size(area);
    let have_fpu = fpu.len() >= user_size;

    // SAFETY: RtSigframe is plain-old-data (repr(C) integers + byte arrays); an all-zero bit pattern is a valid instance, every meaningful field is overwritten below before the frame is read.
    let mut sf: RtSigframe = unsafe { core::mem::zeroed() };
    sf.pretcode = restorer;
    // Linux `frame_uc_flags()`.
    sf.uc.uc_flags = UC_SIGCONTEXT_SS | UC_STRICT_RESTORE_SS
                     | if have_fpu && area != 0 { UC_FP_XSTATE } else { 0 };
    // Linux `__unsafe_setup_sigcontext` (`arch/x86/kernel/signal_64.c`):
    // every GP register straight out of `pt_regs`, `trapno`/`err` from the
    // task's last trap, `cs`/`ss` from `pt_regs` (NOT literals — the frame
    // knows which selectors it will iretq/sysretq with). `rcx` and `r11` are
    // now the user's real rcx/r11 rather than aliases of rip/eflags, which
    // the old syscall-block-shaped reader had conflated.
    //
    // `rax`: Linux reports `regs->ax`, which for an interrupted syscall is
    // the return value the kernel was about to hand back — except on the
    // restart path, where it has been rewound to `orig_ax` so the handler
    // (and `rt_sigreturn`) see the syscall number about to be re-issued.
    // oxide keeps the number in `regs.rax` for the whole dispatch, so the
    // non-restart arm takes the caller's `saved_ret` instead.
    let (trapno, err) = if r.from_syscall() { (0, 0) } else { (r.vector, r.error) };
    sf.uc.uc_mcontext = Sigctx {
        r8: r.r8, r9: r.r9, r10: r.r10, r11: r.r11,
        r12: r.r12, r13: r.r13, r14: r.r14, r15: r.r15,
        rdi: r.rdi, rsi: r.rsi, rbp: r.rbp, rbx: r.rbx,
        rdx: r.rdx, rax: if restart { r.rax } else { saved_ret }, rcx: r.rcx, rsp: saved_rsp,
        rip: if restart { saved_rip.saturating_sub(SYSCALL_INSTRUCTION_BYTES) } else { saved_rip }, eflags: saved_rflags,
        cs: r.cs as u16, gs: 0, fs: 0, ss: r.ss as u16,
        err, trapno, oldmask: old_sigmask, cr2: 0,
        fpstate: if have_fpu { l.fpstate } else { 0 }, reserved: [0; 8],
    };
    sf.uc.uc_sigmask[0] = old_sigmask;
    // Linux `save_altstack_ex`: `uc_stack` records the alt-stack state as of
    // frame build, so `rt_sigreturn`'s `restore_altstack` re-arms an
    // SS_AUTODISARM stack the handler ran on.
    sf.uc.uc_stack = StackT { ss_sp: alt.sp, ss_flags: alt.flags, _pad: 0, ss_size: alt.size };
    hal::write_siginfo(&mut sf.info, sig, payload);
    // SAFETY: new_rsp < saved_rsp < USER_VA_END; CPL=0 write via active CR3; repr(C) matches restore.
    unsafe { core::ptr::write_volatile(new_rsp as *mut RtSigframe, sf); }
    if have_fpu {
        // Linux `copy_fpstate_to_sigframe` + `save_xstate_epilog`. The image
        // is copied rather than `xsave`d straight to the user address so the
        // SW-footer / MAGIC2 stamping stays one host-testable transform.
        // SAFETY: `frame_span` above proved `l.fpstate + math <= USER_VA_END`; CPL=0 writes go through the caller's active CR3, so this writes the calling process's own stack; the region is plain bytes aliasing no kernel object.
        let dst = unsafe { core::slice::from_raw_parts_mut(l.fpstate as *mut u8, math) };
        dst[..user_size].copy_from_slice(&fpu[..user_size]);
        let _ = xstate::write_epilog(dst, area, crate::xsave_xcr0());
    }

    // Linux `x64_setup_rt_frame`'s "Set up registers for signal handler":
    // di = sig, si = &info, dx = &uc, ip = handler, sp = frame, cs = __USER_CS.
    // These are plain field writes on the entry frame, so the SAME code
    // delivers on a syscall, fault or IRQ return.
    r.rdi = sig as u64;
    r.rsi = new_rsp + core::mem::offset_of!(RtSigframe, info) as u64;
    r.rdx = new_rsp + core::mem::offset_of!(RtSigframe, uc) as u64;
    r.rip = handler;
    r.rsp = new_rsp;
    r.cs  = USER_CS_SELECTOR;
    // Linux `handle_signal`: DF|RF|TF cleared for handler entry. The frame's
    // `sigcontext.eflags` above keeps the PRE-clear value, so rt_sigreturn
    // restores the interrupted code's DF/TF.
    r.rflags = hal::uregs::x86_64::handler_entry_eflags(saved_rflags);
    // Linux sets `regs->ax = 0` here ("in case the signal handler was declared
    // without prototypes"). oxide's syscall epilogue leaves the DISPATCH
    // return value in the live rax rather than reloading `regs.rax` (which
    // holds the syscall number for the whole dispatch, Linux's `orig_ax`), so
    // the caller seeds user rax by returning 0 from the delivery — see
    // `fs::sig_dispatch::deliver_with_info`'s x86_64 arm.
    true
}

/// Linux `arch_do_signal_or_restart`'s `regs->ip -= 2` with
/// `regs->ax = regs->orig_ax`: re-enter the SAME syscall number. The live
/// entry frame retains the original RAX (the number) and every argument
/// register, so only RIP and the eventual return RAX need repair.
/// # SAFETY: syscall-return tail exclusively owns `regs`.
/// # C: O(1)
pub unsafe fn restart_ignored_syscall(regs: *mut PtRegs) -> u64 {
    if regs.is_null() { return 0; }
    // SAFETY: per fn contract — the return tail owns this frame.
    let r = unsafe { &mut *regs };
    rewind_syscall_instruction(r);
    r.syscall_nr()
}

/// Linux `arch_do_signal_or_restart`'s ERESTART_RESTARTBLOCK arm:
/// `regs->ax = get_nr_restart_syscall(regs); regs->ip -= 2`. The argument
/// registers are irrelevant — `restart_syscall(2)` takes none and resumes
/// through the task's `restart_block`.
/// # SAFETY: syscall-return tail exclusively owns `regs`.
/// # C: O(1)
pub unsafe fn restart_via_restart_syscall(regs: *mut PtRegs, nr_restart_syscall: u64) -> u64 {
    if regs.is_null() { return nr_restart_syscall; }
    // SAFETY: per fn contract — the return tail owns this frame.
    rewind_syscall_instruction(unsafe { &mut *regs });
    nr_restart_syscall
}

/// Rewind the saved user RIP over the two-byte `syscall` instruction so the
/// return re-executes it. # C: O(1)
fn rewind_syscall_instruction(r: &mut PtRegs) {
    r.rip = r.rip.saturating_sub(SYSCALL_INSTRUCTION_BYTES);
}

/// Restore the full register set from the rt_sigframe's ucontext into the
/// live entry frame, and rebuild the task's XSAVE image from the frame's
/// `fpstate` area into `fpu`. Returns `(restored_sigmask, dispatch_retval,
/// uc_stack, fpu_dirty)` — the caller stores the mask, re-arms the alternate
/// stack from `uc_stack` (Linux `restore_altstack`), propagates the retval as
/// user rax, and reloads the FPU from `fpu` when `fpu_dirty`. `None` on a
/// malformed frame (caller forces SIGSEGV).
/// # SAFETY: rt_sigreturn dispatch ctx on the running task's kstack; `regs`
/// is that entry's live frame.
/// # C: O(n) in the XSAVE image size
pub unsafe fn restore_signal_frame(regs: *mut PtRegs, fpu: &mut [u8])
    -> Option<(u64, i64, hal::AltStack, bool)> {
    if regs.is_null() { return None; }
    // SAFETY: per fn contract — the rt_sigreturn tail owns this frame.
    let r = unsafe { &mut *regs };
    let cur_rsp = r.rsp;                  // = new_rsp + 8 (ret popped pretcode)
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
    // SAFETY: `mc.fpstate` is user-supplied; `restore_fpstate` proves the whole area lies below USER_VA_END and is alignment-legal before it reads a byte.
    let fpu_dirty = unsafe { restore_fpstate(mc.fpstate, fpu) }?;
    // Linux `restore_sigcontext` (`arch/x86/kernel/signal_64.c`):
    // `regs->flags = (regs->flags & ~FIX_EFLAGS) | (sc.flags & FIX_EFLAGS)`.
    // MUST be read before the write below overwrites it. `sysretq` reloads
    // RFLAGS straight from this slot and the Intel SDM's SYSRET mask
    // (`R11 & 3C7FD7H`) passes IOPL, IF, NT and TF through, so an unfiltered
    // `mc.eflags` lets any process grant itself IOPL=3 (port I/O + `cli`) or
    // return to user with interrupts disabled (B1459).
    let new_rflags = hal::uregs::x86_64::sigreturn_eflags(r.rflags, mc.eflags);
    r.rax = mc.rax; r.rbx = mc.rbx; r.rcx = mc.rcx; r.rdx = mc.rdx;
    r.rsi = mc.rsi; r.rdi = mc.rdi; r.rbp = mc.rbp;
    r.r8  = mc.r8;  r.r9  = mc.r9;  r.r10 = mc.r10; r.r11 = mc.r11;
    r.r12 = mc.r12; r.r13 = mc.r13; r.r14 = mc.r14; r.r15 = mc.r15;
    r.rip = mc.rip; r.rsp = mc.rsp; r.rflags = new_rflags;
    // Linux: "Get CS/SS and force CPL3" — a sigcontext CS/SS with RPL < 3
    // would otherwise return the process to a lower ring.
    r.cs = mc.cs as u64 | 3;
    r.ss = mc.ss as u64 | 3;
    // Linux additionally does `regs->orig_ax = -1` here ("disable syscall
    // checks"), i.e. mark the frame as NOT a syscall so the return tail
    // cannot re-run syscall-restart against a register set userspace chose.
    // oxide cannot mirror that on `vector`: this frame IS a `syscall` entry
    // and its epilogue is `sysretq`, so the tag has to stay. The equivalent
    // guarantee comes from the restart classifier
    // (`syscalls::dispatch::restart`) acting only on an `-ERESTART*` value
    // this path returns as `mc.rax` — see the note in the fn docs.
    let alt = hal::AltStack { sp: st.ss_sp, size: st.ss_size, flags: st.ss_flags, use_alt: false };
    Some((sigmask, mc.rax as i64, alt, fpu_dirty))
}

/// Linux `fpu__restore_sig`: rebuild the task's XSAVE image from the user's
/// `uc_mcontext.fpstate`. `Some(true)` = `fpu` now holds an image to load,
/// `Some(false)` = nothing to do, `None` = the frame is bad and the caller
/// force-SIGSEGVs (Linux `fpu__clear_user_states` then `goto badframe`).
///
/// `ptr == 0` is LEGAL and means "no FPU context": Linux answers it with
/// `fpu__clear_user_states`, i.e. reset every user component to its init
/// value — success, not an error.
/// # SAFETY: rt_sigreturn dispatch ctx; the active CR3 is the caller's user
/// address space, so a VA proved below `USER_VA_END` reads the caller's own
/// memory and nothing else.
/// # C: O(n) in the XSAVE image size
unsafe fn restore_fpstate(ptr: u64, fpu: &mut [u8]) -> Option<bool> {
    let area = crate::xsave_area_bytes();
    let user_size = xstate::user_xstate_size(area);
    let math = xstate::math_frame_size(area);
    if fpu.len() < user_size { return Some(false); }
    if ptr == 0 {
        // `fpu__clear_user_states`: everything back to `init_fpstate`.
        xstate::write_init_image(&mut fpu[..user_size], area != 0);
        return Some(true);
    }
    // Linux `access_ok(buf, size)`, where the size is the KERNEL's own
    // `xstate_sigframe_size` — never a user-claimed length.
    if ptr.checked_add(math as u64).filter(|e| *e <= hal::USER_VA_END).is_none() { return None; }
    // Linux lets `xrstor64`/`fxrstor` raise #GP on a misaligned buffer and
    // treats that #GP as fatal. We copy first, so the alignment rule has to be
    // enforced here to keep the same accept/reject set.
    let align = if area != 0 { xstate::XSTATE_ALIGN } else { FXSAVE_ALIGN };
    if ptr & (align - 1) != 0 { return None; }
    // SAFETY: `[ptr, ptr+math)` was just proved to end at or below USER_VA_END and CPL=0 reads run through the caller's active CR3, so this reads the calling process's own stack bytes.
    let user = unsafe { core::slice::from_raw_parts(ptr as *const u8, math) };
    let check = if area != 0 {
        let sw = xstate::read_sw_bytes(user)?;
        let magic2 = xstate::read_trailer(user, sw.xstate_size as usize);
        xstate::check_xstate_in_sigframe(&sw, magic2, user_size)
    } else {
        xstate::SwCheck::FxOnly
    };
    if !xstate::build_restore_image(user, &mut fpu[..user_size], check, crate::xsave_xcr0(),
                                    crate::mxcsr_feature_mask(), area != 0) {
        return None;
    }
    Some(true)
}

/// User rt-sigframe range for pre-copy badframe validation.
/// # SAFETY: rt_sigreturn dispatch ctx; `regs` is the live entry frame.
/// # C: O(1)
pub unsafe fn rt_sigreturn_frame_range(regs: *mut PtRegs) -> Option<(u64, u64, u64)> {
    if regs.is_null() { return None; }
    // SAFETY: per fn contract — the rt_sigreturn tail owns this frame.
    let frame_base = unsafe { (*regs).rsp }.checked_sub(8)?;
    if frame_base == 0 { return None; }
    let len = core::mem::size_of::<RtSigframe>() as u64;
    frame_base.checked_add(len).filter(|end| *end <= hal::USER_VA_END)?;
    Some((frame_base, len, 1))
}

#[cfg(test)]
mod tests;
