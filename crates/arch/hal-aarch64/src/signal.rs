// aarch64 signal-frame ABI: build/restore the full Linux `rt_sigframe`
// (siginfo_t + ucontext_t + the FP/SIMD record chain) so SA_SIGINFO handlers
// (Go runtime, glibc/musl crash handlers, profilers) get
// `handler(sig, &siginfo, &ucontext)` and rt_sigreturn restores the full
// register set. Arch-specific layout lives HERE (not #[cfg]-gated in the
// generic fs dispatcher). The generic caller (`fs::sig_dispatch`) owns
// sigmask/sched + resolves the live SvcFrame pointer (the F206 per-task slot)
// and passes it in, and owns the per-task FP/SIMD save area this file reads
// and writes.
//
// Layout MUST match Linux aarch64 exactly — Go hardcodes the offsets
// (sigctxt.regs()/pc()/sp() read uc_mcontext+8/264/256). Asserted below.
//
// Module manifest:
//   `records` — `sigcontext.__reserved` record chain: fpsimd, terminator,
//               `extra_context` re-base rules, and the parse/reject table.
//   `tests`   — host unit tests, including an end-to-end frame round trip.

use crate::SvcFrame;

mod records;

const SIGCONTEXT_RESERVED_BYTES: usize = records::RESERVED_BYTES;
/// AAPCS64 requires `sp % 16 == 0` at every public function entry (`54§3.4`).
const FRAME_ALIGN: u64 = 16;
/// Whether this CPU implements FEAT_BTI. PSTATE.BTYPE is RES0 without it, so
/// Linux's `setup_return` guards its `PSR_BTYPE_C` stamp on
/// `system_supports_bti()`; we do not implement `PROT_BTI` (`31§*`), so the
/// guard is a compile-time `false` until that lands.
const SYSTEM_SUPPORTS_BTI: bool = false;
/// Width of the AArch64 `svc #0` instruction, used when restarting an
/// interrupted syscall from its post-SVC ELR.
const SVC_INSTRUCTION_BYTES: u64 = core::mem::size_of::<u32>() as u64;
/// `sizeof(struct frame_record)` — the `{ fp, lr }` pair Linux plants above
/// the signal frame so an unwinder can step out of a handler.
const FRAME_RECORD_BYTES: u64 = 16;
/// Linux `minsigstksz_setup()`'s "max alignment padding" term.
const MAX_ALIGN_PADDING: usize = 16;
/// SVC-frame index of x29 inside `x18_x29`.
const X29: usize = 1;
/// Bytes of `ucontext` between the kernel's 8-byte `uc_sigmask` and
/// `uc_mcontext` — glibc's 1024-bit sigset_t tail plus the alignment pad.
const SIGMASK_PAD_BYTES: usize = 1024 / 8 - 8 + 8;

/// Linux aarch64 `struct sigcontext` (== `ucontext.uc_mcontext`). `__reserved`
/// holds the fpsimd (and optionally esr / extra) records terminated by a zero
/// magic; `records` owns that chain.
///
/// `__reserved` carries `__attribute__((__aligned__(16)))` in the UAPI header,
/// which pads it from 280 to 288 and makes the struct 4384 bytes. Rust's
/// `repr(C)` does not move a member for a struct-level alignment, so the pad
/// is explicit — and it is load-bearing now that the chain is populated:
/// `parse_user_sigframe` starts with `IS_ALIGNED((unsigned long)base, 16)`,
/// and 128 + 176 + 280 is 8 mod 16.
#[repr(C, align(16))]
#[derive(Clone, Copy)]
struct Sigctx {
    fault_address: u64,
    regs: [u64; 31],   // x0..x30
    sp: u64,
    pc: u64,
    pstate: u64,
    __pad: [u8; 8],    // UAPI `__aligned__(16)` on `__reserved`
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
    assert!(core::mem::offset_of!(Sigctx, __reserved) == 288);
    assert!(core::mem::size_of::<Sigctx>() == 4384);
    assert!(core::mem::offset_of!(Ucontext, uc_mcontext) == 176);
    assert!(core::mem::offset_of!(RtSigframe, uc) == 128);
    assert!(core::mem::size_of::<RtSigframe>() == 4688);
    // `parse_user_sigframe`'s very first check.
    assert!(RESERVED_IN_FRAME % records::RECORD_ALIGN == 0);
};

/// Byte offset of `uc.uc_mcontext.__reserved` from the rt_sigframe base.
const RESERVED_IN_FRAME: usize =
    core::mem::offset_of!(RtSigframe, uc)
    + core::mem::offset_of!(Ucontext, uc_mcontext)
    + core::mem::offset_of!(Sigctx, __reserved);

/// Placement of one delivery's user-stack objects, per Linux `get_sigframe`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FrameLayout {
    /// Handler-entry SP; `RtSigframe` starts here.
    pub sp: u64,
    /// Linux `user->next_frame` — the synthetic `{ fp, lr }` record x29 points
    /// at, so an unwinder can walk out of the handler into the interrupted
    /// frame instead of stopping dead.
    pub next_frame: u64,
    /// `sigsp()` — the top of the region the delivery writes.
    pub top: u64,
}

/// Read x0..x30 out of the scattered SvcFrame slots into a contiguous array.
#[inline]
fn regs_from_frame(f: &SvcFrame) -> [u64; 31] {
    let mut r = [0u64; 31];
    for i in 0..18 { r[i] = f.gp[i]; }        // x0..x17
    r[18] = f.x18_x29[0];                      // x18
    for i in 0..10 { r[19 + i] = f.x19_x28[i]; } // x19..x28
    r[29] = f.x18_x29[X29];                    // x29
    r[30] = f.x30;                             // x30
    r
}

/// The interrupted task's EL0 stack pointer out of its saved SVC frame.
/// `sigaltstack(2)` needs it for `on_sig_stack`, and signal delivery for
/// `sigsp` — both of which Linux drives off `current_user_stack_pointer()`.
/// # SAFETY: `frame` is the running task's live saved SVC frame.
/// # C: O(1)
pub unsafe fn svc_frame_user_sp(frame: *mut SvcFrame) -> u64 {
    if frame.is_null() { return 0; }
    // SAFETY: per fn contract — caller supplies the live saved SVC frame.
    unsafe { (*frame).sp_el0 }
}

/// Linux `get_sigframe` (`arch/arm64/kernel/signal.c:1405-1429`) placement
/// arithmetic, as a pure function so the caller's `access_ok` check and the
/// builder's write can never disagree about WHERE the frame lands. AArch64
/// has no red zone, so the non-alt top is the interrupted SP itself. `None`
/// when the arithmetic underflows — `user_sp` is hostile input, a process is
/// free to `mov sp, <kernel VA>; svc #0`.
/// # C: O(1)
pub fn frame_layout(user_sp: u64, alt: hal::AltStack) -> Option<FrameLayout> {
    // `sigsp()`: SA_ONSTACK with a usable `sigaltstack(2)` puts the frame at
    // the alternate stack's TOP. Without this a SIGSEGV-on-stack-overflow
    // handler builds its frame on the stack that just overflowed and faults
    // instead of running.
    let top = if alt.use_alt { alt.sp.checked_add(alt.size)? } else { user_sp };
    // `sp = round_down(sp - sizeof(struct frame_record), 16)`.
    let next_frame = top.checked_sub(FRAME_RECORD_BYTES)? & !(FRAME_ALIGN - 1);
    // `sp = round_down(sp, 16) - sigframe_size(user)`. `sigframe_size` is
    // `round_up(max(user->size, sizeof(struct rt_sigframe)), 16)`; our record
    // set (fpsimd + terminator, 544 B) fits inside `__reserved`, so the
    // rt_sigframe size IS the max and is already 16-aligned.
    let sp = next_frame.checked_sub(core::mem::size_of::<RtSigframe>() as u64)?;
    Some(FrameLayout { sp, next_frame, top })
}

/// Linux `minsigstksz_setup()` → the `AT_MINSIGSTKSZ` auxv entry:
/// `sigframe_size + round_up(sizeof(frame_record), 16) + 16`.
/// # C: O(1)
pub fn min_sigstksz() -> usize {
    core::mem::size_of::<RtSigframe>() + FRAME_RECORD_BYTES as usize + MAX_ALIGN_PADDING
}

/// Handler-entry SP a delivery would use. # C: O(1)
pub fn sigframe_base(user_sp: u64, alt: hal::AltStack) -> Option<u64> {
    frame_layout(user_sp, alt).map(|l| l.sp)
}

/// `(base, len, align)` of everything a delivery writes — the rt_sigframe AND
/// the frame record above it — for the caller's `access_ok`. Linux
/// `get_sigframe` runs `if (!access_ok(user->sigframe, sp_top - sp)) return
/// -EFAULT`, which `handle_signal` turns into `force_sigsegv`; `sp_top - sp`
/// is exactly this span.
/// # C: O(1)
pub fn sigframe_range(user_sp: u64, alt: hal::AltStack) -> Option<(u64, u64, u64)> {
    let l = frame_layout(user_sp, alt)?;
    if l.sp == 0 { return None; }
    if l.top > hal::USER_VA_END { return None; }
    Some((l.sp, l.top.checked_sub(l.sp)?, FRAME_ALIGN))
}

/// Build the rt_sigframe on the user stack and rewrite `frame` so the
/// dispatch `eret` enters the handler with x1=&siginfo, x2=&ucontext, pc=
/// handler, lr=restorer, sp=frame. x0=sig is seeded by the dispatch retval
/// (the SVC restore's `ldr x0,[sp,#0xc8]`), so the caller returns `sig`.
/// `saved_ret` is the interrupted syscall's x0 (stored in the ucontext for
/// rt_sigreturn). `old_sigmask` is recorded for rt_sigreturn to restore.
///
/// `fpu` is the calling task's FP/SIMD save area (`FpuStateAArch64` layout),
/// already synced from the hardware by the caller — Linux
/// `fpsimd_save_and_flush_current_state()` + `preserve_fpsimd_context()`.
/// Too short a slice omits the record, which produces a frame Linux's OWN
/// `restore_sigframe` would reject with `-EINVAL`, so the caller must always
/// supply one for a real task.
///
/// Returns `false` without touching user memory or the SVC frame when the
/// frame does not fit in user space (Linux `get_sigframe`'s `access_ok`
/// failing); the caller must then `force_sigsegv`. That check is the
/// difference between a signal delivery and an arbitrary kernel write: EL1
/// writes through TTBR1 just fine, so `mov sp, <kernel VA>; svc #0` otherwise
/// has the kernel `write_volatile` an attacker-shaped frame there (B1459).
/// # SAFETY: dispatch-tail ctx; `frame` is the live saved SVC frame; active
/// TTBR0 is the caller's user AS.
/// # C: O(n) in the 528-byte FP/SIMD record
#[must_use]
pub unsafe fn build_signal_frame(frame: *mut SvcFrame, handler: u64, restorer: u64,
                                 sig: u32, saved_ret: u64, restart: bool, old_sigmask: u64,
                                 payload: Option<hal::SigPayload>, alt: hal::AltStack,
                                 fpu: &[u8]) -> bool {
    // SAFETY: per fn contract — sole writer of the live SVC frame this dispatch.
    let frame = unsafe { &mut *frame };
    let saved_pc     = frame.elr_el1;
    let saved_pstate = frame.spsr_el1;
    let saved_sp     = frame.sp_el0;
    let saved_x29    = frame.x18_x29[X29];
    let saved_x30    = frame.x30;
    let mut regs = regs_from_frame(frame);
    if !restart { regs[0] = saved_ret; } // x0 = interrupted syscall's return value

    // Placement + `access_ok`-equivalent bound. Frame sits AT/ABOVE new_sp so
    // the handler's downward stack can't trample it (`54§3.1`).
    if sigframe_range(saved_sp, alt).is_none() { return false }
    let Some(l) = frame_layout(saved_sp, alt) else { return false };
    let new_sp = l.sp;

    // Written FIELD BY FIELD straight into user memory — Linux
    // `setup_sigframe`'s `__put_user_error` per member — NOT staged in an
    // `RtSigframe` local. The frame is 4688 bytes and `sigcontext` alone is
    // 4384; staging it costs more kernel stack than a 16 KiB guard-paged
    // kstack has (LLVM turned one by-value `sigcontext` into a 21 KiB frame
    // in `restore_signal_frame`, which overflowed on the first delivery).
    // C213 traced a whole class of heap corruption to exactly that overflow.
    let uc = new_sp + core::mem::offset_of!(RtSigframe, uc) as u64;
    let mc = uc + core::mem::offset_of!(Ucontext, uc_mcontext) as u64;
    // SAFETY: every address below lies inside `[new_sp, l.top)`, which `sigframe_range` proved is user memory ending at or below USER_VA_END; EL1 writes reach the caller's own EL0 stack through the active TTBR0; each offset comes from `offset_of!` on the repr(C) types the restore reads back.
    unsafe {
        let u64_at = |off: u64, v: u64| core::ptr::write_volatile((uc + off) as *mut u64, v);
        u64_at(core::mem::offset_of!(Ucontext, uc_flags) as u64, 0);
        u64_at(core::mem::offset_of!(Ucontext, uc_link) as u64, 0);
        // Linux `save_altstack_ex`: `uc_stack` records the alt-stack state as
        // of frame build, so `rt_sigreturn`'s `restore_altstack` re-arms an
        // SS_AUTODISARM stack the handler ran on.
        core::ptr::write_volatile((uc + core::mem::offset_of!(Ucontext, uc_stack) as u64) as *mut StackT,
                                  StackT { ss_sp: alt.sp, ss_flags: alt.flags, _pad: 0, ss_size: alt.size });
        u64_at(core::mem::offset_of!(Ucontext, uc_sigmask) as u64, old_sigmask);
        // glibc's sigset_t is 1024 bits; Linux copies only the kernel's 8 and
        // leaves the rest as-is. Zeroed here so a handler that reads the full
        // glibc-sized mask never sees its own stale stack bytes.
        let pad = uc + core::mem::offset_of!(Ucontext, __unused) as u64;
        for i in 0..(SIGMASK_PAD_BYTES as u64 / 8) { core::ptr::write_volatile((pad + i * 8) as *mut u64, 0); }

        let mc_at = |off: u64, v: u64| core::ptr::write_volatile((mc + off) as *mut u64, v);
        mc_at(core::mem::offset_of!(Sigctx, fault_address) as u64, 0);
        let rbase = mc + core::mem::offset_of!(Sigctx, regs) as u64;
        for (i, r) in regs.iter().enumerate() { core::ptr::write_volatile((rbase + (i as u64) * 8) as *mut u64, *r); }
        mc_at(core::mem::offset_of!(Sigctx, sp) as u64, saved_sp);
        mc_at(core::mem::offset_of!(Sigctx, pc) as u64,
              if restart { saved_pc.saturating_sub(SVC_INSTRUCTION_BYTES) } else { saved_pc });
        mc_at(core::mem::offset_of!(Sigctx, pstate) as u64, saved_pstate);
        mc_at(core::mem::offset_of!(Sigctx, __pad) as u64, 0);
    }
    // Linux `preserve_fpsimd_context` + the null terminator, written in place
    // in the user frame. Without this the frame is one `restore_sigframe`
    // rejects outright, AND a handler calling any NEON-optimised glibc routine
    // silently eats the interrupted code's Q registers.
    //
    // Only the records are written; the rest of `__reserved` keeps whatever
    // the process already had there, exactly as Linux leaves it — the parser
    // stops at the terminator and the bytes are the caller's own stack.
    // SAFETY: `mc + __reserved` through +4096 is inside the span `sigframe_range` validated; EL1 writes reach the caller's EL0 stack via the active TTBR0; the slice is plain bytes aliasing no kernel object.
    let reserved = unsafe {
        core::slice::from_raw_parts_mut(
            (mc + core::mem::offset_of!(Sigctx, __reserved) as u64) as *mut u8,
            SIGCONTEXT_RESERVED_BYTES)
    };
    if fpu.len() >= crate::FPU_STATE_BYTES {
        let (fpcr, fpsr) = fpcr_fpsr(fpu);
        let por = crate::por::poe_enabled().then(crate::por::read_por);
        if !records::write_chain(reserved, &fpu[..crate::FPU_VREGS_BYTES], fpcr, fpsr, por) { return false; }
    } else {
        // No FPU image to carry: still terminate the chain, or the parser
        // walks whatever the process left in `__reserved`.
        records::write_terminator(reserved);
    }
    let mut info = [0u8; 128];
    hal::write_siginfo(&mut info, sig, payload);
    // SAFETY: `new_sp + 128` is inside the validated span; EL1 write via the caller's TTBR0; `info` is a fully-initialised local byte array.
    unsafe { core::ptr::write_volatile(new_sp as *mut [u8; 128], info); }
    // Linux `setup_sigframe`: "set up the stack frame for unwinding" — the
    // AAPCS64 `{ fp, lr }` pair holding the INTERRUPTED frame's x29/x30, with
    // x29 below pointed at it. Without it a backtrace from inside a handler
    // stops at the handler.
    // SAFETY: `l.next_frame + 16 == l.top <= USER_VA_END` was proved by `sigframe_range` above; 16-aligned by construction; EL1 writes reach the caller's own EL0 stack through the active TTBR0.
    unsafe { core::ptr::write_volatile(l.next_frame as *mut [u64; 2], [saved_x29, saved_x30]); }

    let info_ptr = new_sp + core::mem::offset_of!(RtSigframe, info) as u64;
    let uc_ptr   = new_sp + core::mem::offset_of!(RtSigframe, uc) as u64;
    frame.gp[1]   = info_ptr;   // x1 = &siginfo (restored by SVC exit asm)
    frame.gp[2]   = uc_ptr;     // x2 = &ucontext
    frame.gp[0]   = sig as u64; // x0 (also seeded via dispatch retval)
    frame.elr_el1 = handler;    // pc = handler
    frame.x30     = restorer;   // lr — handler `ret` lands at restorer
    frame.x18_x29[X29] = l.next_frame; // fp — Linux `regs[29] = &next_frame->fp`
    frame.sp_el0  = new_sp;
    // Linux `setup_return`: TCO always cleared for a handler; BTYPE stamped as
    // if the handler were reached by `BLR` where FEAT_BTI exists.
    frame.spsr_el1 = hal::uregs::aarch64::handler_entry_pstate(saved_pstate, SYSTEM_SUPPORTS_BTI);
    true
}

/// `(fpcr, fpsr)` out of a `FpuStateAArch64` image — the two control words
/// live AFTER the 512 bytes of Q registers there, but BEFORE them (and in the
/// opposite order) in `struct fpsimd_context`.
/// # C: O(1)
fn fpcr_fpsr(fpu: &[u8]) -> (u32, u32) {
    let mut c = [0u8; 4]; c.copy_from_slice(&fpu[crate::FPU_FPCR_OFF..crate::FPU_FPCR_OFF + 4]);
    let mut s = [0u8; 4]; s.copy_from_slice(&fpu[crate::FPU_FPSR_OFF..crate::FPU_FPSR_OFF + 4]);
    (u32::from_le_bytes(c), u32::from_le_bytes(s))
}

/// SVC frame index of x8, the AArch64 Linux syscall-number register
/// (`15§1.2`). The `oxide_lower_sync_restore` epilogue reloads it via
/// `ldp x8, x9, [sp, #0x40]`, so rewriting this slot changes which syscall
/// the re-executed `svc #0` enters.
const SVC_FRAME_X8: usize = 8;

/// Linux `arch_do_signal_or_restart`'s same-call restart on arm64: the SVC
/// frame still holds the original x0 argument and x8 syscall number; rewind
/// the post-SVC PC and return x0 so the assembly epilogue restores the exact
/// pre-SVC register state Linux re-enters.
/// # SAFETY: syscall-return tail owns the live SVC frame exclusively.
/// # C: O(1)
pub unsafe fn restart_ignored_syscall(frame: *mut SvcFrame) -> u64 {
    // SAFETY: caller guarantees `frame` is the current task's live SVC frame.
    let frame = unsafe { &mut *frame };
    frame.elr_el1 = frame.elr_el1.saturating_sub(SVC_INSTRUCTION_BYTES);
    frame.gp[0]
}

/// Linux `arch_do_signal_or_restart`'s ERESTART_RESTARTBLOCK arm on arm64:
/// rewrite the syscall-number register to `restart_syscall(2)` and rewind the
/// PC, so the re-executed `svc #0` resumes through the task's `restart_block`
/// instead of re-running the original call for its FULL duration.
/// `nr_restart_syscall` is the AArch64-native number (128), not the x86 one —
/// the dispatcher translates x8 through `arm_abi::aarch64_nr_to_x86`.
/// # SAFETY: syscall-return tail owns the live SVC frame exclusively.
/// # C: O(1)
pub unsafe fn restart_via_restart_syscall(frame: *mut SvcFrame, nr_restart_syscall: u64) -> u64 {
    // SAFETY: caller guarantees `frame` is the current task's live SVC frame.
    let frame = unsafe { &mut *frame };
    frame.gp[SVC_FRAME_X8] = nr_restart_syscall;
    frame.elr_el1 = frame.elr_el1.saturating_sub(SVC_INSTRUCTION_BYTES);
    frame.gp[0]
}

/// Restore the full register set from the rt_sigframe's ucontext into the
/// saved SVC `frame`, and rebuild the task's FP/SIMD image from the frame's
/// record chain into `fpu`. Returns `(restored_sigmask, x0, uc_stack,
/// fpu_dirty)` — caller stores the mask, re-arms the alternate stack from
/// `uc_stack` (Linux `restore_altstack`), returns x0 as the dispatch retval
/// (seeds user x0), and reloads the FP/SIMD registers when `fpu_dirty`.
/// `None` on a malformed frame.
/// # SAFETY: rt_sigreturn dispatch ctx; `frame` is the live saved SVC frame.
/// # C: O(n) in the record chain
pub unsafe fn restore_signal_frame(frame: *mut SvcFrame, fpu: &mut [u8])
                                   -> Option<(u64, i64, hal::AltStack, bool)> {
    // SAFETY: per fn contract — sole writer of the live SVC frame.
    let frame = unsafe { &mut *frame };
    // ARM `ret`=`br lr` does NOT pop; handler epilogue restores SP to new_sp
    // before `ret`, so the restorer's `svc #0` fires with sp_el0 == frame_base.
    let frame_base = frame.sp_el0;
    if frame_base == 0 || (frame_base & 15) != 0 { return None; }
    if frame_base.checked_add(core::mem::size_of::<RtSigframe>() as u64)
        .filter(|end| *end <= hal::USER_VA_END).is_none() { return None; }
    let uc_base = frame_base + core::mem::offset_of!(RtSigframe, uc) as u64;
    let mc_base = uc_base + core::mem::offset_of!(Ucontext, uc_mcontext) as u64;
    let st_ptr = (uc_base + core::mem::offset_of!(Ucontext, uc_stack) as u64) as *const StackT;
    // Read the scalars ONE AT A TIME — Linux `__get_user_error` per member —
    // never `read_volatile` of the whole `Sigctx`. That struct is 4384 bytes
    // and LLVM turned a single by-value read of it into a 21 KiB stack frame,
    // which overflows a 16 KiB guard-paged kstack on the first sigreturn.
    // SAFETY: every address below is inside `[frame_base, frame_base + sizeof(RtSigframe))`, proved above to end at or below USER_VA_END; EL1 reads run through the caller's TTBR0 so they read the calling process's own stack; offsets come from `offset_of!` on the repr(C) types the build path wrote.
    let rd = |off: u64| unsafe { core::ptr::read_volatile((mc_base + off) as *const u64) };
    let mut regs = [0u64; 31];
    let rbase = core::mem::offset_of!(Sigctx, regs) as u64;
    for (i, r) in regs.iter_mut().enumerate() { *r = rd(rbase + (i as u64) * 8); }
    let mc_sp     = rd(core::mem::offset_of!(Sigctx, sp) as u64);
    let mc_pc     = rd(core::mem::offset_of!(Sigctx, pc) as u64);
    let mc_pstate = rd(core::mem::offset_of!(Sigctx, pstate) as u64);
    // SAFETY: uc_sigmask lies inside the same validated frame_base region, read through the caller's TTBR0 exactly like the scalars above.
    let sigmask = unsafe { core::ptr::read_volatile((uc_base + core::mem::offset_of!(Ucontext, uc_sigmask) as u64) as *const u64) };
    // SAFETY: st_ptr is uc_stack inside the same validated frame_base region; EL1 read via the caller's TTBR0, identical validity to the reads above.
    let st = unsafe { core::ptr::read_volatile(st_ptr) };
    if mc_pc >= hal::USER_VA_END || mc_sp >= hal::USER_VA_END { return None; }
    // Linux `restore_sigframe`: `err |= !valid_user_regs(&regs->user_regs,
    // current)` and `rt_sigreturn` then `goto badframe` → `force_sig(SIGSEGV)`.
    // The SVC exit asm does `msr spsr_el1, x10` from this slot before `eret`,
    // so an unfiltered `mc.pstate` with `M[3:0] = 0b0101` erets the process's
    // OWN code at EL1 — arbitrary kernel execution from any unprivileged
    // process (B1459). `single_step` is false because the ptrace software-step
    // bit is (re-)armed AFTER dispatch by `oxide_arm_arm_singlestep`, from
    // `Task.singlestep` — never from this user word.
    let (pstate, accepted) = hal::uregs::aarch64::sanitize_native_pstate(mc_pstate, false);
    if !accepted { return None; }
    // The chain is walked IN PLACE in user memory for the same reason: a
    // kernel-stack copy of `__reserved` is 4096 bytes on its own.
    // SAFETY: `__reserved` spans 4096 bytes inside the region proved to end at or below USER_VA_END; EL1 reads reach the caller's own EL0 stack via the active TTBR0; the slice is plain bytes aliasing no kernel object.
    let reserved = unsafe {
        core::slice::from_raw_parts(
            (mc_base + core::mem::offset_of!(Sigctx, __reserved) as u64) as *const u8,
            SIGCONTEXT_RESERVED_BYTES)
    };
    // SAFETY: `restore_fpsimd` proves any `extra_context` span lies below USER_VA_END before touching it; the same TTBR0 contract applies.
    let (fpu_dirty, por) = unsafe { restore_fpsimd(reserved, frame_base, fpu) }?;
    if let Some(por) = por { crate::por::write_por(por); }
    // Restore x0..x30 into the scattered SvcFrame slots.
    for i in 0..18 { frame.gp[i] = regs[i]; }
    frame.x18_x29[0] = regs[18];
    for i in 0..10 { frame.x19_x28[i] = regs[19 + i]; }
    frame.x18_x29[X29] = regs[29];
    frame.x30      = regs[30];
    frame.sp_el0   = mc_sp;
    frame.elr_el1  = mc_pc;
    frame.spsr_el1 = pstate;
    let alt = hal::AltStack { sp: st.ss_sp, size: st.ss_size, flags: st.ss_flags, use_alt: false };
    Some((sigmask, regs[0] as i64, alt, fpu_dirty))
}

/// Linux `parse_user_sigframe` + `restore_fpsimd_context`. `Some(true)` =
/// `fpu` now holds an image to load, `None` = `-EINVAL`, which
/// `sys_rt_sigreturn` turns into `arm64_notify_segfault`.
///
/// An FPSIMD record is MANDATORY: `if (!user.fpsimd) return -EINVAL`
/// (`signal.c:1044-1046`). A frame without one is invalid by Linux's own
/// rules, not merely impoverished.
/// # SAFETY: rt_sigreturn dispatch ctx; the active TTBR0 is the caller's user
/// address space, so a VA proved below `USER_VA_END` reads the caller's own
/// memory and nothing else.
/// # C: O(n) in the record chain
unsafe fn restore_fpsimd(reserved: &[u8], frame_base: u64, fpu: &mut [u8]) -> Option<(bool, Option<u64>)> {
    if fpu.len() < crate::FPU_STATE_BYTES { return Some((false, None)); }
    let reserved_va = frame_base.checked_add(RESERVED_IN_FRAME as u64)?;
    let poe_enabled = crate::por::poe_enabled();
    let scan = records::scan_region(reserved, reserved_va, frame_base, false, false, false, poe_enabled).ok()?;
    let por = match scan.poe { Some((off, size)) => Some(records::read_poe(reserved, off, size).ok()?), None => None };
    let (region, base, hit) = match scan.rebase {
        None => (reserved, reserved_va, scan.fpsimd),
        Some((datap, size)) => {
            // Linux `access_ok(base, limit)` on the extra area before walking
            // it. `scan_region` already proved `datap` 16-aligned, contiguous
            // with the terminator, and within `SIGFRAME_MAXSZ`.
            datap.checked_add(size as u64).filter(|e| *e <= hal::USER_VA_END)?;
            // SAFETY: `[datap, datap+size)` was just proved to end at or below USER_VA_END and EL1 reads run through the caller's active TTBR0, so this reads the calling process's own memory.
            let extra = unsafe { core::slice::from_raw_parts(datap as *const u8, size) };
            let s2 = records::scan_region(extra, datap, frame_base, scan.fpsimd.is_some(), scan.poe.is_some(), true, poe_enabled).ok()?;
            match (scan.fpsimd, s2.fpsimd) {
                (Some(h), None) => (reserved, reserved_va, Some(h)),
                (None, Some(h)) => (extra, datap, Some(h)),
                (None, None)    => (reserved, reserved_va, None),
                // A duplicate across regions is `if (user->fpsimd) goto invalid`.
                (Some(_), Some(_)) => return None,
            }
        }
    };
    let _ = base;
    let (off, size) = hit?;   // `!user.fpsimd` ⇒ -EINVAL
    let (fpsr, fpcr, vregs) = records::read_fpsimd(region, off, size).ok()?;
    fpu[..32 * 16].copy_from_slice(&region[vregs..vregs + 32 * 16]);
    fpu[crate::FPU_FPCR_OFF..crate::FPU_FPCR_OFF + 4].copy_from_slice(&fpcr.to_le_bytes());
    fpu[crate::FPU_FPSR_OFF..crate::FPU_FPSR_OFF + 4].copy_from_slice(&fpsr.to_le_bytes());
    Some((true, por))
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
    Some((frame_base, len, FRAME_ALIGN))
}

#[cfg(test)]
mod tests;
