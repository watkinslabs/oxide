use super::*;

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
    let st_ptr = uc_base + core::mem::offset_of!(Ucontext, uc_stack) as u64;
    // Read the scalars through exception-table usercopy. Never materialize the
    // 4384-byte `Sigctx` on the kernel stack: the old by-value read became a
    // 21 KiB frame and overflowed the 16 KiB guard-paged kstack.
    let mut rd_bytes = [0u8; 8];
    let rd = |off: u64, bytes: &mut [u8; 8]| copy_from_user(bytes, mc_base + off);
    let mut regs = [0u64; 31];
    let rbase = core::mem::offset_of!(Sigctx, regs) as u64;
    for (i, r) in regs.iter_mut().enumerate() {
        if !rd(rbase + (i as u64) * 8, &mut rd_bytes) { return None; }
        *r = u64::from_ne_bytes(rd_bytes);
    }
    if !rd(core::mem::offset_of!(Sigctx, sp) as u64, &mut rd_bytes) { return None; }
    let mc_sp = u64::from_ne_bytes(rd_bytes);
    if !rd(core::mem::offset_of!(Sigctx, pc) as u64, &mut rd_bytes) { return None; }
    let mc_pc = u64::from_ne_bytes(rd_bytes);
    if !rd(core::mem::offset_of!(Sigctx, pstate) as u64, &mut rd_bytes) { return None; }
    let mc_pstate = u64::from_ne_bytes(rd_bytes);
    if !copy_from_user(&mut rd_bytes, uc_base + core::mem::offset_of!(Ucontext, uc_sigmask) as u64) { return None; }
    let sigmask = u64::from_ne_bytes(rd_bytes);
    let mut stack_bytes = [0u8; core::mem::size_of::<StackT>()];
    if !copy_from_user(&mut stack_bytes, st_ptr) { return None; }
    let st = unsafe { core::ptr::read_unaligned(stack_bytes.as_ptr().cast::<StackT>()) };
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
    let mut reserved = alloc::vec![0u8; SIGCONTEXT_RESERVED_BYTES];
    if !copy_from_user(&mut reserved, mc_base + core::mem::offset_of!(Sigctx, __reserved) as u64) { return None; }
    // SAFETY: `restore_fpsimd` proves any `extra_context` span lies below USER_VA_END before touching it; the same TTBR0 contract applies.
    let (fpu_dirty, por) = unsafe { restore_fpsimd(&reserved, frame_base, fpu) }?;
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
/// An FPSIMD record is MANDATORY: a frame that carries none is EINVAL by the
/// reference's own rule, not merely impoverished.
/// # SAFETY: rt_sigreturn dispatch ctx; the active TTBR0 is the caller's user
/// address space, so a VA proved below `USER_VA_END` reads the caller's own
/// memory and nothing else.
/// # C: O(n) in the record chain
unsafe fn restore_fpsimd(reserved: &[u8], frame_base: u64, fpu: &mut [u8]) -> Option<(bool, Option<u64>)> {
    if fpu.len() < crate::FPU_STATE_BYTES { return Some((false, None)); }
    let reserved_va = frame_base.checked_add(RESERVED_IN_FRAME as u64)?;
    let poe_enabled = crate::por::poe_enabled();
    let scan = records::scan_region(reserved, reserved_va, frame_base, false, false, false, poe_enabled).ok()?;
    let extra_storage = match scan.rebase {
        None => None,
        Some((datap, size)) => {
            datap.checked_add(size as u64).filter(|e| *e <= hal::USER_VA_END)?;
            let mut extra = alloc::vec![0u8; size];
            if !copy_from_user(&mut extra, datap) { return None; }
            Some(extra)
        }
    };
    let (region, hit, por) = match (&extra_storage, scan.rebase) {
        (None, None) => (reserved, scan.fpsimd, match scan.poe { Some((off, size)) => Some(records::read_poe(reserved, off, size).ok()?), None => None }),
        (Some(extra), Some((datap, _size))) => {
            let s2 = records::scan_region(extra, datap, frame_base, scan.fpsimd.is_some(), scan.poe.is_some(), true, poe_enabled).ok()?;
            let por = match (scan.poe, s2.poe) {
                (Some((off, size)), None) => Some(records::read_poe(reserved, off, size).ok()?),
                (None, Some((off, size))) => Some(records::read_poe(extra, off, size).ok()?),
                (None, None) => None, (Some(_), Some(_)) => return None,
            };
            let (region, hit) = match (scan.fpsimd, s2.fpsimd) {
                (Some(h), None) => (reserved, Some(h)),
                (None, Some(h)) => (extra.as_slice(), Some(h)),
                (None, None)    => (reserved, None),
                (Some(_), Some(_)) => return None,
            };
            (region, hit, por)
        }
        _ => return None,
    };
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
