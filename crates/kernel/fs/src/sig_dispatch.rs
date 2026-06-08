// Signal-handler dispatch per docs/24§4 (R02/R03) + docs/27§5.
//
// F411 Stage C+D: build + restore the FULL Linux rt_sigframe
// (siginfo_t + ucontext_t + full mcontext + FP state) on the user
// stack, replacing the old minimal 40/56-byte frame. The pure
// build/restore math lives in `frame.rs` (host-testable, no unsafe);
// this module is the unsafe plumbing that reads the live per-arch
// frame, writes the computed bytes to user memory, and rewrites the
// saved syscall frame so sysretq/eret enters the handler / resumes.
//
// Invariants (docs/54§3): frame at-or-above handler entry SP; x86
// skips the 128-B red zone and lands rsp%16==8; arm sp%16==0; the
// delivered sig is masked during the handler (unless SA_NODEFER) and
// rt_sigreturn restores the saved mask. Go's async-preempt requires
// the FULL GP set to round-trip and the handler to be able to edit
// uc_mcontext.PC/SP (asyncPreempt) — restore reads back whatever the
// handler left in the on-stack ucontext.

#[cfg(target_os = "oxide-kernel")]
mod imp {
    use syscall::sigbuild::*;
    use sched::SigInfo;
    use syscall::sigframe::{si, SigInfoUser};
    #[cfg(target_arch = "x86_64")]
    use syscall::sigframe::RtSigframeX86;
    #[cfg(target_arch = "aarch64")]
    use syscall::sigframe::RtSigframeArm;

    /// Synthesise the siginfo_t for `sig` from an optional RT-queue
    /// record. No record ⇒ SI_USER with pid/uid 0.
    /// # C: O(1)
    fn make_siginfo(sig: u32, rec: Option<&SigInfo>) -> SigInfoUser {
        match rec {
            Some(r) => {
                if r.code == si::SI_QUEUE {
                    SigInfoUser::queue(sig as i32, r.pid as i32, r.uid, r.value)
                } else {
                    let mut s = SigInfoUser::new(sig as i32, 0, r.code);
                    s._sifields[0..4].copy_from_slice(&(r.pid as i32).to_ne_bytes());
                    s._sifields[4..8].copy_from_slice(&r.uid.to_ne_bytes());
                    s
                }
            }
            None => SigInfoUser::user(sig as i32, 0, 0),
        }
    }

    /// Assemble the delivery parameters for the current task.
    /// # C: O(1)
    fn build_params(
        sig: u32,
        handler: u64,
        restorer: u64,
        sa_flags: u64,
        sa_mask: u64,
        info_rec: Option<&SigInfo>,
    ) -> BuildParams {
        use core::sync::atomic::Ordering;
        let cur = sched::live::current();
        let old_sigmask = cur.as_ref().map(|c| c.sigmask.load(Ordering::Acquire)).unwrap_or(0);
        let (alt_sp, alt_size, alt_flags) = match cur.as_ref() {
            Some(c) => (
                c.sigaltstack_sp.load(Ordering::Acquire),
                c.sigaltstack_size.load(Ordering::Acquire),
                c.sigaltstack_flags.load(Ordering::Acquire) as i32,
            ),
            None => (0, 0, syscall::sigframe::ss::SS_DISABLE),
        };
        BuildParams {
            sig, handler, restorer, sa_flags, sa_mask, old_sigmask,
            info: make_siginfo(sig, info_rec),
            alt_sp, alt_size, alt_flags,
        }
    }

    /// Install the new blocked mask on the current task.
    /// # C: O(1)
    fn install_mask(mask: u64) {
        if let Some(c) = sched::live::current() {
            c.sigmask.store(mask, core::sync::atomic::Ordering::Release);
        }
    }

    /// SA_RESETHAND: reset this sigaction to SIG_DFL after build.
    /// # C: O(1)
    fn maybe_resethand(sig: u32, sa_flags: u64) {
        use syscall::sigframe::sa;
        if (sa_flags & sa::SA_RESETHAND) == 0 { return; }
        if let Some(c) = sched::live::current() {
            // SAFETY: running task on this CPU; preempt-off; sole mutator
            // of the sigactions slot per the single-mutator invariant in
            // `13§5`; index sig-1 is in-bounds for 1..=64.
            unsafe {
                let table = &mut *c.sigactions.get();
                let slot = &mut table[(sig - 1) as usize];
                slot.handler = 0;
                slot.flags &= !sa::SA_RESETHAND;
            }
        }
    }

    // ---- x86_64 -----------------------------------------------------

    /// Read the live x86 GP set from the interrupted frame source.
    /// # SAFETY: caller is the dispatch/IRQ tail; the corresponding
    /// per-arch frame is live on the current task's kernel stack.
    /// # C: O(1)
    #[cfg(target_arch = "x86_64")]
    unsafe fn read_regs_x86(src: FrameSrc) -> GpRegsX86 {
        match src {
            FrameSrc::Syscall => {
                // Full syscall frame base = top-0x80; u64 indices:
                //  0 rax(nr) 1 rdi 2 rsi 3 rdx 4 r10 5 r8 6 r9
                //  7 rcx(rip) 8 r11(rflags) 9 user rsp 10 rbx 11 rbp
                //  12 r13 13 r14 14 r15 15 r12
                let f = hal_x86_64::current_user_full_frame();
                // SAFETY: per fn contract — `f` is the live 16-quad frame.
                let g = |i: usize| unsafe { core::ptr::read(f.add(i)) };
                let rip = g(7);
                let rflags = g(8);
                GpRegsX86 {
                    rax: g(0), rdi: g(1), rsi: g(2), rdx: g(3),
                    r10: g(4), r8: g(5), r9: g(6),
                    rcx: rip, r11: rflags,
                    rsp: g(9), rbx: g(10), rbp: g(11),
                    r13: g(12), r14: g(13), r15: g(14), r12: g(15),
                    rip, eflags: rflags,
                    cs: 0x33, ss: 0x2b, gs: 0, fs: 0,
                }
            }
            FrameSrc::Irq => {
                // SAFETY: per fn contract — IRQ frame live during dispatch.
                let p = unsafe { hal_x86_64::current_irq_frame() };
                // SAFETY: `p` is the live IrqFrameX86 written at IRQ entry.
                let i = unsafe { &*p };
                GpRegsX86 {
                    r8: i.r8, r9: i.r9, r10: i.r10, r11: i.r11,
                    r12: i.r12, r13: i.r13, r14: i.r14, r15: i.r15,
                    rdi: i.rdi, rsi: i.rsi, rbp: i.rbp, rbx: i.rbx,
                    rdx: i.rdx, rax: i.rax, rcx: i.rcx, rsp: i.rsp,
                    rip: i.rip, eflags: i.rflags,
                    cs: i.cs as u16, ss: i.ss as u16, gs: 0, fs: 0,
                }
            }
        }
    }

    /// Save the current task's live FPU into a 512-B FXSAVE image.
    /// # C: O(1)
    #[cfg(target_arch = "x86_64")]
    fn snapshot_fp_x86() -> [u8; 512] {
        let mut img = [0u8; 512];
        if let Some(c) = sched::live::current() {
            hal_x86_64::fpu_enable();
            // SAFETY: running task; preempt-off; fpu_state slot is
            // single-mutator per `13§5`; FXSAVE writes 512 B into the
            // 16-aligned ArchFpuBuf; FPU enabled by the clts above.
            unsafe {
                let buf = (*c.fpu_state.get()).0.as_mut_ptr() as *mut hal_x86_64::FpuStateX86_64;
                hal_x86_64::fpu_save(buf);
                core::ptr::copy_nonoverlapping(buf as *const u8, img.as_mut_ptr(), 512);
            }
        }
        img
    }

    /// Build the full rt_sigframe and rewrite the saved syscall frame
    /// so sysretq enters `handler`. `src` selects the GP source.
    /// # SAFETY: caller is the dispatch tail on cur's syscall kstack;
    /// current_user_frame() is the live saved tail; user writes target
    /// the active CR3.
    /// # C: O(1)
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn deliver_x86(
        src: FrameSrc,
        handler: u64,
        restorer: u64,
        sig: u32,
        sa_flags: u64,
        sa_mask: u64,
        saved_ret: u64,
        info_rec: Option<&SigInfo>,
    ) {
        // SAFETY: caller is the dispatch tail; the x86 syscall/IRQ
        // frame selected by `src` is live on this CPU's kernel stack.
        let mut regs = unsafe { read_regs_x86(src) };
        // Syscall source: frame slot 0 still holds the syscall NR, not
        // the dispatch return value. The sigcontext must carry the
        // syscall's RETVAL in rax so rt_sigreturn restores it (the
        // $(cmd)-empty-capture bug: a read() that returned N must not
        // be clobbered by the SIGCHLD handler). IRQ source already has
        // the genuine interrupted rax.
        if src == FrameSrc::Syscall { regs.rax = saved_ret; }
        let fp = snapshot_fp_x86();
        let p = build_params(sig, handler, restorer, sa_flags, sa_mask, info_rec);
        let b = build_x86(&regs, &p, &fp);

        // Write the FXSAVE image then the rt_sigframe.
        // SAFETY: fp_addr/frame_addr are user VAs below the interrupted
        // rsp (validated by build_x86's red-zone+align math); CPL=0
        // writes through the active CR3; demand-fault resolves
        // not-present pages; both regions are repr(C) matching restore.
        unsafe {
            core::ptr::write_volatile(b.fp_addr as *mut [u8; 512], b.fpstate);
            core::ptr::write_volatile(b.frame_addr as *mut RtSigframeX86, b.frame);
        }

        install_mask(b.new_sigmask);
        maybe_resethand(sig, sa_flags);

        match src {
            FrameSrc::Syscall => {
                // Rewrite the saved (rip, rflags, rsp) tail.
                // SAFETY: per fn contract — frame slot at top-0x48..top-0x30.
                let uf = unsafe { &mut *hal_x86_64::current_user_frame() };
                uf[0] = handler;
                uf[1] = regs.eflags;
                uf[2] = b.new_rsp;

                // Inject handler args into the saved-arg slots so the
                // restore block's `mov rdi/rsi/rdx, [rsp+...]` loads them.
                // After B04's 16-quad frame: rdi@top-0x78, rsi@top-0x70,
                // rdx@top-0x68.
                let top = hal_x86_64::current_kstack_top();
                if top != 0 {
                    // SAFETY: writing the saved-arg slots the syscall asm
                    // restore block reloads into user rdi/rsi/rdx before sysretq.
                    unsafe {
                        core::ptr::write_volatile((top - 0x78) as *mut u64, b.arg_rdi);
                        core::ptr::write_volatile((top - 0x70) as *mut u64, b.arg_rsi);
                        core::ptr::write_volatile((top - 0x68) as *mut u64, b.arg_rdx);
                    }
                }
            }
            FrameSrc::Irq => {
                // F412 Stage E: rewrite the IRQ frame IN PLACE. The IRQ
                // epilogue (`oxide_irq_resume_user`) pops these GP slots
                // then iretq's → lands the handler with correct args+SP.
                // SAFETY: caller gated cs&3==3 (user frame); ptr live for
                // the in-flight IRQ; sole writer in IRQ-off dispatch.
                let f = unsafe { &mut *hal_x86_64::current_irq_frame() };
                f.rip = handler;
                f.rsp = b.new_rsp;
                f.rdi = b.arg_rdi;        // sig
                if (sa_flags & syscall::sigframe::sa::SA_SIGINFO) != 0 {
                    f.rsi = b.arg_rsi;    // &siginfo
                    f.rdx = b.arg_rdx;    // &ucontext
                }
            }
        }

        #[cfg(feature = "debug-sched")]
        {
            klog::write_raw(b"[INFO]  sig: deliver_x86 sig=");
            klog::write_dec_u64(sig as u64);
            klog::write_raw(b" handler=");
            klog::write_hex_u64(handler);
            klog::write_raw(b" new_rsp=");
            klog::write_hex_u64(b.new_rsp);
            klog::write_raw(b"\n");
        }
    }

    /// `sys_rt_sigreturn` body. Reads the on-stack (possibly
    /// handler-edited) ucontext, restores the FULL mcontext + FP +
    /// sigmask into the syscall frame, and returns the restored rax
    /// (the interrupted syscall's value) so sysretq reports it.
    /// # SAFETY: caller is the rt_sigreturn dispatch on cur's syscall
    /// kstack; the syscall frame is the single restore target.
    /// # C: O(1)
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn rt_sigreturn_x86() -> i64 {
        use syscall::errno::Errno;
        // Handler entered with rsp = frame_addr (pretcode slot). `ret`
        // popped pretcode (rsp += 8); the restorer issues `syscall`
        // without touching rsp → user rsp at syscall = frame_addr + 8.
        // SAFETY: per fn contract — frame tail live.
        let uf = unsafe { &mut *hal_x86_64::current_user_frame() };
        let frame_addr = uf[2].saturating_sub(8);
        if frame_addr == 0 || frame_addr >= hal::USER_VA_END {
            return -(Errno::Einval.as_i32() as i64);
        }
        // SAFETY: frame_addr validated < USER_VA_END; CPL=0 read through
        // the active CR3; repr(C) matching deliver_x86's write.
        let frame = unsafe { core::ptr::read_volatile(frame_addr as *const RtSigframeX86) };
        // Read the FXSAVE image the handler may reference.
        let fp_ptr = frame.uc.uc_mcontext.fpstate;
        let mut fp = [0u8; 512];
        if fp_ptr != 0 && fp_ptr < hal::USER_VA_END {
            // SAFETY: fpstate ptr in-range; 512 B written by deliver_x86.
            unsafe { core::ptr::copy_nonoverlapping(fp_ptr as *const u8, fp.as_mut_ptr(), 512); }
        }
        let r = restore_x86(&frame, &fp);

        // Restore the FULL GP set into the syscall full frame so a Go
        // asyncPreempt-style PC/SP edit takes effect and every other
        // GPR is the interrupted thread's real value.
        // SAFETY: per fn contract — full frame is the live 16-quad block.
        let ff = unsafe { hal_x86_64::current_user_full_frame() };
        // SAFETY: writes to the live syscall frame slots (see layout).
        unsafe {
            core::ptr::write(ff.add(1), r.regs.rdi);
            core::ptr::write(ff.add(2), r.regs.rsi);
            core::ptr::write(ff.add(3), r.regs.rdx);
            core::ptr::write(ff.add(4), r.regs.r10);
            core::ptr::write(ff.add(5), r.regs.r8);
            core::ptr::write(ff.add(6), r.regs.r9);
            core::ptr::write(ff.add(10), r.regs.rbx);
            core::ptr::write(ff.add(11), r.regs.rbp);
            core::ptr::write(ff.add(12), r.regs.r13);
            core::ptr::write(ff.add(13), r.regs.r14);
            core::ptr::write(ff.add(14), r.regs.r15);
            core::ptr::write(ff.add(15), r.regs.r12);
        }
        // rip/rflags/rsp tail (drives sysretq).
        uf[0] = r.regs.rip;
        uf[1] = r.regs.eflags;
        uf[2] = r.regs.rsp;

        install_mask(r.sigmask);

        // Reload FP live + mark dirty so resume keeps it.
        if r.fp_addr != 0 {
            if let Some(c) = sched::live::current() {
                hal_x86_64::fpu_enable();
                // SAFETY: running task; 512-B image copied into the
                // 16-aligned fpu_state buffer then FXRSTOR'd; FPU enabled.
                unsafe {
                    let buf = (*c.fpu_state.get()).0.as_mut_ptr();
                    core::ptr::copy_nonoverlapping(r.fpstate.as_ptr(), buf, 512);
                    hal_x86_64::fpu_restore(buf as *const hal_x86_64::FpuStateX86_64);
                }
            }
        }

        #[cfg(feature = "debug-sched")]
        {
            klog::write_raw(b"[INFO]  sig: rt_sigreturn_x86 rip=");
            klog::write_hex_u64(r.regs.rip);
            klog::write_raw(b" rsp=");
            klog::write_hex_u64(r.regs.rsp);
            klog::write_raw(b" rax=");
            klog::write_hex_u64(r.regs.rax);
            klog::write_raw(b"\n");
        }
        r.regs.rax as i64
    }

    // ---- aarch64 ----------------------------------------------------

    /// Resolve the per-task SVC frame (race-free across schedule()).
    /// # SAFETY: caller is the dispatch tail; returned ptr is the live
    /// saved SVC frame.
    /// # C: O(1)
    #[cfg(target_arch = "aarch64")]
    unsafe fn svc_frame_ptr() -> *mut hal_aarch64::SvcFrame {
        use core::sync::atomic::Ordering;
        let per_task = sched::live::current()
            .map(|c| c.svc_frame.load(Ordering::Acquire))
            .unwrap_or(0);
        if per_task != 0 {
            per_task as *mut hal_aarch64::SvcFrame
        } else {
            hal_aarch64::current_svc_frame()
        }
    }

    /// Reconstruct the full x0..x30 GP set from the SVC frame.
    /// SvcFrame: gp[0..18]=x0..x17, x18_x29=[x18,x29], x30, x19_x28[10].
    /// # SAFETY: `f` is the live saved SVC frame.
    /// # C: O(1)
    #[cfg(target_arch = "aarch64")]
    fn regs_from_svc(f: &hal_aarch64::SvcFrame) -> GpRegsArm {
        let mut regs = [0u64; 31];
        regs[..18].copy_from_slice(&f.gp[..18]); // x0..x17
        regs[18] = f.x18_x29[0];                 // x18
        regs[19..29].copy_from_slice(&f.x19_x28[..10]); // x19..x28
        regs[29] = f.x18_x29[1];                 // x29
        regs[30] = f.x30;                        // x30
        GpRegsArm { regs, sp: f.sp_el0, pc: f.elr_el1, pstate: f.spsr_el1 }
    }

    /// Read the live arm GP set from the interrupted frame source.
    /// # SAFETY: caller is the dispatch/IRQ tail; the frame is live.
    /// # C: O(1)
    #[cfg(target_arch = "aarch64")]
    unsafe fn read_regs_arm(src: FrameSrc) -> GpRegsArm {
        match src {
            FrameSrc::Syscall => {
                // SAFETY: caller is the dispatch tail; svc_frame_ptr()
                // returns the live saved SVC frame for this task.
                let f = unsafe { &*svc_frame_ptr() };
                regs_from_svc(f)
            }
            FrameSrc::Irq => {
                // SAFETY: per fn contract — IRQ frame live during dispatch.
                let p = unsafe { hal_aarch64::current_irq_frame() };
                // SAFETY: p is the live IrqFrameArm written at IRQ entry.
                let i = unsafe { &*p };
                let mut regs = [0u64; 31];
                regs[..19].copy_from_slice(&i.x[..19]);   // x0..x18
                regs[19..29].copy_from_slice(&i.x19_28[..10]); // x19..x28
                regs[29] = i.x29;
                regs[30] = i.x30;
                GpRegsArm { regs, sp: i.sp_el0, pc: i.elr_el1, pstate: i.spsr_el1 }
            }
        }
    }

    /// Save the current task's live FP/SIMD into q/fpsr/fpcr.
    /// # C: O(1)
    #[cfg(target_arch = "aarch64")]
    fn snapshot_fp_arm() -> ([[u8; 16]; 32], u32, u32) {
        let mut q = [[0u8; 16]; 32];
        let (mut fpsr, mut fpcr) = (0u32, 0u32);
        if let Some(c) = sched::live::current() {
            hal_aarch64::fpu_enable();
            // SAFETY: running task; preempt-off; fpu_state slot single-
            // mutator; FpuStateAArch64 layout matches ArchFpuBuf; FPEN
            // set by fpu_enable above.
            unsafe {
                let buf = (*c.fpu_state.get()).0.as_mut_ptr() as *mut hal_aarch64::FpuStateAArch64;
                hal_aarch64::fpu_save(buf);
                let s = &*buf;
                q = s.q;
                fpcr = s.fpcr;
                fpsr = s.fpsr;
            }
        }
        (q, fpsr, fpcr)
    }

    /// Build the full rt_sigframe and rewrite the saved SVC frame so
    /// `eret` enters `handler`. The arch-neutral router returns `sig`
    /// (the dispatcher propagates it as its u64 retval — the SVC
    /// restore seeds x0 from the retval slot; docs/54§2.3).
    /// # SAFETY: caller is the dispatch tail; SVC frame live; user
    /// writes target the active TTBR0.
    /// # C: O(1)
    #[cfg(target_arch = "aarch64")]
    pub unsafe fn deliver_arm(
        src: FrameSrc,
        handler: u64,
        restorer: u64,
        sig: u32,
        sa_flags: u64,
        sa_mask: u64,
        saved_ret: u64,
        info_rec: Option<&SigInfo>,
    ) {
        // SAFETY: caller is the dispatch tail; the arm syscall/IRQ
        // frame selected by `src` is live on this CPU's kernel stack.
        let mut regs = unsafe { read_regs_arm(src) };
        // Syscall source: x0 in the SVC frame still holds the user's
        // first syscall arg, not the retval. Restore the syscall RETVAL
        // into x0 (mirror of the x86 rax fix above).
        if src == FrameSrc::Syscall { regs.regs[0] = saved_ret; }
        let (q, fpsr, fpcr) = snapshot_fp_arm();
        let p = build_params(sig, handler, restorer, sa_flags, sa_mask, info_rec);
        let b = build_arm(&regs, &p, &q, fpsr, fpcr);

        // SAFETY: frame_addr is a user VA below the interrupted sp
        // (build_arm's align math); CPL=EL1 write through TTBR0;
        // demand-fault resolves not-present pages; repr(C) match.
        unsafe { core::ptr::write_volatile(b.frame_addr as *mut RtSigframeArm, b.frame); }

        install_mask(b.new_sigmask);
        maybe_resethand(sig, sa_flags);

        match src {
            FrameSrc::Syscall => {
                // SAFETY: per fn contract — live SVC frame, sole writer.
                let f = unsafe { &mut *svc_frame_ptr() };
                f.elr_el1 = handler;
                f.sp_el0 = b.new_sp;
                f.x30 = b.arg_x30;       // lr → handler `ret` lands at restorer
                f.gp[0] = b.arg_x0;      // x0 = sig (also seeded via retval)
                f.gp[1] = b.arg_x1;      // x1 = &info (SA_SIGINFO) else 0
                f.gp[2] = b.arg_x2;      // x2 = &uc  (SA_SIGINFO) else 0
            }
            FrameSrc::Irq => {
                // F412 Stage E: rewrite the IRQ frame IN PLACE. The IRQ
                // epilogue restores x0..x30 + sp_el0 + elr/spsr then erets
                // → lands the handler with correct args + SP.
                // SAFETY: caller gated spsr&0xf==0 (EL0t user frame); ptr
                // live for the in-flight IRQ; sole writer in IRQ-off dispatch.
                let f = unsafe { &mut *hal_aarch64::current_irq_frame() };
                f.elr_el1 = handler;
                f.sp_el0 = b.new_sp;
                f.x30 = b.arg_x30;       // lr → handler `ret` lands at restorer
                f.x[0] = b.arg_x0;       // x0 = sig
                f.x[1] = b.arg_x1;       // x1 = &info (SA_SIGINFO) else 0
                f.x[2] = b.arg_x2;       // x2 = &uc  (SA_SIGINFO) else 0
            }
        }

        #[cfg(feature = "debug-sched")]
        {
            klog::write_raw(b"[INFO]  sig: deliver_arm sig=");
            klog::write_dec_u64(sig as u64);
            klog::write_raw(b" handler=");
            klog::write_hex_u64(handler);
            klog::write_raw(b" new_sp=");
            klog::write_hex_u64(b.new_sp);
            klog::write_raw(b"\n");
        }
    }

    /// `sys_rt_sigreturn` body for aarch64. Mirrors rt_sigreturn_x86 —
    /// restores the FULL mcontext + FP + sigmask from the on-stack
    /// (possibly edited) ucontext into the SVC frame.
    /// # SAFETY: caller is the rt_sigreturn dispatch on cur's syscall
    /// kstack; SVC frame is the single restore target.
    /// # C: O(1)
    #[cfg(target_arch = "aarch64")]
    pub unsafe fn rt_sigreturn_arm() -> i64 {
        use syscall::errno::Errno;
        // SAFETY: per fn contract — live SVC frame.
        let f = unsafe { &mut *svc_frame_ptr() };
        // ARM `ret` = `br lr` (no pop); handler restored sp to new_sp
        // before `ret`; the restorer's `svc` fires with sp unchanged →
        // frame_addr == sp_el0.
        let frame_addr = f.sp_el0;
        if frame_addr == 0 || frame_addr >= hal::USER_VA_END {
            return -(Errno::Einval.as_i32() as i64);
        }
        // SAFETY: frame_addr validated < USER_VA_END; CPL=EL1 read
        // through TTBR0; repr(C) match with deliver_arm's write.
        let frame = unsafe { core::ptr::read_volatile(frame_addr as *const RtSigframeArm) };
        let r = restore_arm(&frame);

        // Restore the full x0..x30 + sp + pc + pstate into the SVC frame.
        f.gp[..18].copy_from_slice(&r.regs.regs[..18]); // x0..x17
        f.x18_x29[0] = r.regs.regs[18];                 // x18
        f.x19_x28[..10].copy_from_slice(&r.regs.regs[19..29]); // x19..x28
        f.x18_x29[1] = r.regs.regs[29];                 // x29
        f.x30 = r.regs.regs[30];                        // x30
        f.sp_el0 = r.regs.sp;
        f.elr_el1 = r.regs.pc;
        f.spsr_el1 = r.regs.pstate;

        install_mask(r.sigmask);

        // Reload FP live if a valid fpsimd_context was present.
        if r.fp_valid {
            if let Some(c) = sched::live::current() {
                hal_aarch64::fpu_enable();
                // SAFETY: running task; image copied into the 16-aligned
                // fpu_state buffer then restored via the FP load asm.
                unsafe {
                    let buf = (*c.fpu_state.get()).0.as_mut_ptr() as *mut hal_aarch64::FpuStateAArch64;
                    (*buf).q = r.fp_q;
                    (*buf).fpsr = r.fpsr;
                    (*buf).fpcr = r.fpcr;
                    hal_aarch64::fpu_restore(buf as *const hal_aarch64::FpuStateAArch64);
                }
            }
        }

        #[cfg(feature = "debug-sched")]
        {
            klog::write_raw(b"[INFO]  sig: rt_sigreturn_arm pc=");
            klog::write_hex_u64(r.regs.pc);
            klog::write_raw(b" sp=");
            klog::write_hex_u64(r.regs.sp);
            klog::write_raw(b" x0=");
            klog::write_hex_u64(r.regs.regs[0]);
            klog::write_raw(b"\n");
        }
        // The SVC restore seeds user x0 from the dispatch retval; return
        // x0 so the interrupted syscall reports the value it produced.
        r.regs.regs[0] as i64
    }

    // ---- async IRQ-exit delivery (F412 Stage E) ---------------------

    /// `kernel-internal` SIG_DFL / SIG_IGN sentinels (Linux sa_handler
    /// convention). Async IRQ delivery only fires for a real handler;
    /// SIG_DFL/SIG_IGN are LEFT pending so the syscall-return path runs
    /// the default-action triage (terminate/core/ignore).
    const SIG_DFL: u64 = 0;
    const SIG_IGN: u64 = 1;

    /// Pick the lowest deliverable pending signal that has a registered
    /// user handler (not SIG_DFL / SIG_IGN). Clears the pending bit (or
    /// pops one RT-queue record) on take, mirroring
    /// `syscalls::signal::take_lowest_pending`. Signals whose
    /// disposition is SIG_DFL/SIG_IGN are SKIPPED (left pending) — the
    /// syscall-return tail owns their default action; async IRQ exit
    /// only rewrites a frame to enter a real handler.
    /// # C: O(deliverable bits)
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn take_async_handler_signal() -> Option<(u32, u64, u64, u64, u64, Option<SigInfo>)> {
        use core::sync::atomic::Ordering;
        let cur = sched::live::current()?;
        let masked = cur.sigmask.load(Ordering::Acquire);
        let mut remaining = cur.sigpending.load(Ordering::Acquire) & !masked;
        while remaining != 0 {
            let sig = remaining.trailing_zeros() + 1;
            remaining &= remaining - 1; // clear lowest set bit for the scan
            // SAFETY: running task on this CPU in IRQ-dispatch (preempt-off,
            // single mutator of sigactions per `13§5`); idx sig-1 in 1..=64.
            let h = unsafe { (&*cur.sigactions.get())[(sig - 1) as usize] };
            if h.handler == SIG_DFL || h.handler == SIG_IGN {
                continue; // leave pending for the syscall-return default path
            }
            // Commit the take: pop RT record / clear the bitmap bit.
            let mut info = None;
            if (33..=64).contains(&sig) {
                let (rec, empty) = cur.rt_pop(sig);
                info = rec;
                if empty {
                    cur.sigpending.fetch_and(!(1u64 << (sig - 1)), Ordering::Release);
                }
            } else {
                cur.sigpending.fetch_and(!(1u64 << (sig - 1)), Ordering::Release);
            }
            return Some((sig, h.handler, h.flags, h.restorer, h.mask, info));
        }
        None
    }

    /// F412 Stage E — async signal delivery on IRQ-return-to-user.
    ///
    /// Invoked from the per-arch IRQ dispatcher AFTER EOI + tick +
    /// resched decision. GATE: only proceeds if the interrupted frame
    /// was at USER level (x86 `cs & 3 == 3`; arm `spsr_el1 & 0xf == 0`
    /// = EL0t). On a kernel-mode IRQ frame this is a NO-OP — rewriting
    /// a kernel return frame to enter a user handler would corrupt the
    /// kernel resume = instant crash.
    ///
    /// On a deliverable handler-signal, builds the rt_sigframe FROM the
    /// IRQ frame (`FrameSrc::Irq`) and rewrites the IRQ frame IN PLACE
    /// (rip/elr→handler, rsp/sp_el0→new_sp, arg regs→sig/&info/&uc) so
    /// the IRQ epilogue eret/iretq's straight into the handler. Delivers
    /// at most ONE signal per IRQ, to `current()` on the interrupted
    /// frame (correct whether or not a ctx-switch was staged this tick).
    ///
    /// # SAFETY: caller is the IRQ dispatcher; the per-arch IRQ frame is
    /// live (OXIDE_IRQ_FRAME{,_ARM} just stored); the interrupted USER
    /// task holds no kernel lock, so the user-AS sigframe write is safe.
    /// # C: O(1)
    /// # Ctx: IRQ
    pub unsafe fn try_deliver_async_irq() {
        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: caller is the IRQ dispatch tail; frame ptr live.
            let p = unsafe { hal_x86_64::current_irq_frame() };
            if p.is_null() { return; }
            // SAFETY: p is the live IrqFrameX86 stored at IRQ entry.
            let from_user = unsafe { (*p).cs & 3 } == 3;
            if !from_user { return; } // kernel-mode IRQ: never deliver
            if let Some((sig, handler, flags, restorer, mask, info)) =
                take_async_handler_signal()
            {
                // saved_ret unused for FrameSrc::Irq (the IRQ frame
                // already carries the genuine interrupted rax).
                // SAFETY: USER frame (gated above); cur holds no kernel
                // lock; deliver_x86 rewrites the IRQ frame + user sigstack.
                unsafe {
                    deliver_x86(FrameSrc::Irq, handler, restorer, sig, flags, mask, 0, info.as_ref());
                }
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            // SAFETY: caller is the IRQ dispatch tail; frame ptr live.
            let p = unsafe { hal_aarch64::current_irq_frame() };
            if p.is_null() { return; }
            // SAFETY: p is the live IrqFrameArm stored at IRQ entry.
            let from_user = unsafe { (*p).spsr_el1 & 0xf } == 0; // EL0t
            if !from_user { return; }
            if let Some((sig, handler, flags, restorer, mask, info)) =
                take_async_handler_signal()
            {
                // SAFETY: USER frame (gated above); cur holds no kernel
                // lock; deliver_arm rewrites the IRQ frame + user sigstack.
                unsafe {
                    deliver_arm(FrameSrc::Irq, handler, restorer, sig, flags, mask, 0, info.as_ref());
                }
            }
        }
    }

    // ---- arch-neutral routers --------------------------------------

    /// Deliver a signal built from the SYSCALL frame source (the
    /// normal syscall-return-tail path). Returns the dispatcher retval
    /// (sig on arm so the SVC restore seeds x0; 0 on x86).
    /// # SAFETY: caller is the syscall dispatch tail; per-arch saved
    /// frame is live; active CR3/TTBR0 is the task's user AS.
    /// # C: O(1)
    #[inline]
    pub unsafe fn deliver(
        handler: u64,
        restorer: u64,
        sig: u32,
        sa_flags: u64,
        sa_mask: u64,
        saved_ret: u64,
        info_rec: Option<&SigInfo>,
    ) -> u64 {
        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: defers to deliver_x86; preconditions = caller's.
            unsafe { deliver_x86(FrameSrc::Syscall, handler, restorer, sig, sa_flags, sa_mask, saved_ret, info_rec); }
            0
        }
        #[cfg(target_arch = "aarch64")]
        {
            // SAFETY: defers to deliver_arm; preconditions = caller's.
            unsafe { deliver_arm(FrameSrc::Syscall, handler, restorer, sig, sa_flags, sa_mask, saved_ret, info_rec); }
            sig as u64
        }
    }

    /// `sys_rt_sigreturn` arch-neutral entry.
    /// # SAFETY: caller is the rt_sigreturn dispatch; per-arch saved
    /// frame is live.
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
}

#[cfg(target_os = "oxide-kernel")]
pub use imp::{deliver, rt_sigreturn, try_deliver_async_irq};
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
pub use imp::{deliver_x86, rt_sigreturn_x86};
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
pub use imp::{deliver_arm, rt_sigreturn_arm};
