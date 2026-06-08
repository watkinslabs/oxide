// Pure (host-testable) build/restore math for the FULL Linux
// rt_sigframe (docs/24§4 R02/R03). The unsafe frame-pointer plumbing
// lives in mod.rs; everything here is plain data → data so the hosted
// round-trip test in `tests.rs` drives it with no kernel, no QEMU.
//
// Build: GP snapshot + delivery params → on-stack RtSigframe bytes +
// the handler's entry SP + handler arg registers. Restore: on-stack
// RtSigframe bytes (which the handler MAY have edited — Go rewrites
// uc_mcontext.PC/SP) → the GP set to load back into the syscall frame.
//
// All structs are arch-independent repr(C) (syscall::sigframe), so the
// x86_64 host checks BOTH arches' layouts.

use crate::sigframe::{
    sa, ss, Aarch64Ctx, FpSimdContext, RtSigframeArm, RtSigframeX86, SigContextArm, SigContextX86,
    SigInfoUser, Stack, UContextArm, UContextX86, FPSIMD_MAGIC,
};

/// x86_64 SysV red zone (skipped before carving the frame).
pub const X86_RED_ZONE: u64 = 128;

/// Which interrupted context the GP snapshot came from. Build path is
/// identical; the snapshot reader (mod.rs) differs.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FrameSrc {
    /// rt_sigframe rides a syscall-return tail (full syscall frame).
    Syscall,
    /// rt_sigframe rides a timer/IRQ-interrupted user thread.
    Irq,
}

/// Full GP register snapshot of the interrupted x86_64 user thread,
/// in sigcontext field order. Populated by mod.rs from either the
/// syscall full-frame or the IRQ frame.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct GpRegsX86 {
    pub r8: u64, pub r9: u64, pub r10: u64, pub r11: u64,
    pub r12: u64, pub r13: u64, pub r14: u64, pub r15: u64,
    pub rdi: u64, pub rsi: u64, pub rbp: u64, pub rbx: u64,
    pub rdx: u64, pub rax: u64, pub rcx: u64, pub rsp: u64,
    pub rip: u64, pub eflags: u64,
    pub cs: u16, pub gs: u16, pub fs: u16, pub ss: u16,
}

/// Full GP register snapshot of the interrupted aarch64 user thread.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct GpRegsArm {
    pub regs: [u64; 31], // x0..x30
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

/// Delivery parameters threaded from the PendingSignal / sigaction.
#[derive(Copy, Clone)]
pub struct BuildParams {
    pub sig: u32,
    pub handler: u64,
    pub restorer: u64,
    pub sa_flags: u64,
    /// sa_mask to OR into the blocked set during the handler.
    pub sa_mask: u64,
    /// Old (pre-delivery) sigmask — saved into the frame for restore.
    pub old_sigmask: u64,
    /// siginfo to deliver (already synthesised by mod.rs).
    pub info: SigInfoUser,
    /// Alt-stack base/size/flags (sigaltstack). Used iff SA_ONSTACK set.
    pub alt_sp: u64,
    pub alt_size: u64,
    pub alt_flags: i32,
}

/// Result of the x86 build: the frame bytes + where they go + the
/// handler entry state.
pub struct BuiltX86 {
    pub frame: RtSigframeX86,
    pub fpstate: [u8; 512],
    /// User VA the RtSigframeX86 is written at (== handler entry RSP).
    pub frame_addr: u64,
    /// User VA the 512-B FXSAVE image is written at.
    pub fp_addr: u64,
    /// Handler entry RSP (== frame_addr; %16==8 invariant).
    pub new_rsp: u64,
    /// rdi (always sig), rsi (&info or junk), rdx (&uc or junk).
    pub arg_rdi: u64,
    pub arg_rsi: u64,
    pub arg_rdx: u64,
    /// New blocked sigmask to install for the handler.
    pub new_sigmask: u64,
}

/// Compute the x86 rt_sigframe. Pure: no memory writes, no unsafe.
/// `fp` is the 512-B FXSAVE image to embed (zeros if FPU not owned).
/// # C: O(1)
pub fn build_x86(regs: &GpRegsX86, p: &BuildParams, fp: &[u8; 512]) -> BuiltX86 {
    // Pick the base stack: alt stack iff SA_ONSTACK and it's enabled.
    let on_alt = (p.sa_flags & sa::SA_ONSTACK) != 0
        && p.alt_sp != 0
        && p.alt_size != 0
        && (p.alt_flags & ss::SS_DISABLE) == 0;
    let base_top = if on_alt {
        // Alt stack grows down from sp + size.
        p.alt_sp.saturating_add(p.alt_size)
    } else {
        regs.rsp.saturating_sub(X86_RED_ZONE)
    };

    // Lay out (high→low): [FXSAVE 512B][RtSigframe]. fpstate 16-aligned;
    // frame_addr 16-aligned then -8 so handler entry RSP%16==8 (the
    // pretcode slot plays the role of the pushed return address).
    let fp_addr = base_top.saturating_sub(512) & !0xfu64;
    let frame_sz = core::mem::size_of::<RtSigframeX86>() as u64;
    let frame_addr = ((fp_addr.saturating_sub(frame_sz)) & !0xfu64).saturating_sub(8);
    let new_rsp = frame_addr;

    // ucontext addr = frame_addr + offset_of(uc); info addr likewise.
    let uc_addr = frame_addr + offset_of_uc_x86();
    let info_addr = frame_addr + offset_of_info_x86();

    let mc = SigContextX86 {
        r8: regs.r8, r9: regs.r9, r10: regs.r10, r11: regs.r11,
        r12: regs.r12, r13: regs.r13, r14: regs.r14, r15: regs.r15,
        rdi: regs.rdi, rsi: regs.rsi, rbp: regs.rbp, rbx: regs.rbx,
        rdx: regs.rdx, rax: regs.rax, rcx: regs.rcx, rsp: regs.rsp,
        rip: regs.rip, eflags: regs.eflags,
        cs: regs.cs, gs: regs.gs, fs: regs.fs, ss: regs.ss,
        err: 0, trapno: 0, oldmask: p.old_sigmask, cr2: 0,
        fpstate: fp_addr,
        reserved: [0; 8],
    };
    let uc = UContextX86 {
        uc_flags: 0,
        uc_link: 0,
        uc_stack: Stack {
            ss_sp: p.alt_sp,
            ss_flags: if on_alt { ss::SS_ONSTACK } else { p.alt_flags },
            _pad: 0,
            ss_size: p.alt_size,
        },
        uc_mcontext: mc,
        uc_sigmask: p.old_sigmask,
    };
    let frame = RtSigframeX86 { pretcode: p.restorer, uc, info: p.info };

    // SA_SIGINFO → 3-arg handler. Always sig in rdi.
    let (arg_rsi, arg_rdx) = if (p.sa_flags & sa::SA_SIGINFO) != 0 {
        (info_addr, uc_addr)
    } else {
        (0, 0)
    };

    let new_sigmask = compute_new_mask(p);

    BuiltX86 {
        frame, fpstate: *fp, frame_addr, fp_addr, new_rsp,
        arg_rdi: p.sig as u64, arg_rsi, arg_rdx, new_sigmask,
    }
}

/// Restored x86 GP set, read back from a (possibly handler-edited)
/// on-stack ucontext.
pub struct RestoredX86 {
    pub regs: GpRegsX86,
    pub sigmask: u64,
    /// FXSAVE image to reload (from uc_mcontext.fpstate).
    pub fpstate: [u8; 512],
    /// fpstate user VA (0 → no FP reload).
    pub fp_addr: u64,
}

/// Restore the x86 GP set from a (possibly edited) on-stack frame.
/// `fp` is the FXSAVE image read from uc_mcontext.fpstate by mod.rs.
/// # C: O(1)
pub fn restore_x86(frame: &RtSigframeX86, fp: &[u8; 512]) -> RestoredX86 {
    let m = &frame.uc.uc_mcontext;
    RestoredX86 {
        regs: GpRegsX86 {
            r8: m.r8, r9: m.r9, r10: m.r10, r11: m.r11,
            r12: m.r12, r13: m.r13, r14: m.r14, r15: m.r15,
            rdi: m.rdi, rsi: m.rsi, rbp: m.rbp, rbx: m.rbx,
            rdx: m.rdx, rax: m.rax, rcx: m.rcx, rsp: m.rsp,
            rip: m.rip, eflags: m.eflags,
            cs: m.cs, gs: m.gs, fs: m.fs, ss: m.ss,
        },
        sigmask: frame.uc.uc_sigmask,
        fpstate: *fp,
        fp_addr: m.fpstate,
    }
}

/// # C: O(1)
#[inline]
fn offset_of_uc_x86() -> u64 {
    core::mem::offset_of!(RtSigframeX86, uc) as u64
}
/// # C: O(1)
#[inline]
fn offset_of_info_x86() -> u64 {
    core::mem::offset_of!(RtSigframeX86, info) as u64
}

/// New blocked mask for the handler: old | signo-self (unless
/// SA_NODEFER) | sa_mask.
/// # C: O(1)
fn compute_new_mask(p: &BuildParams) -> u64 {
    let mut m = p.old_sigmask | p.sa_mask;
    if (p.sa_flags & sa::SA_NODEFER) == 0 {
        m |= 1u64 << (p.sig - 1);
    }
    m
}

// ---------------------------------------------------------------------
// aarch64
// ---------------------------------------------------------------------

/// Result of the arm build.
pub struct BuiltArm {
    pub frame: RtSigframeArm,
    /// User VA the RtSigframeArm is written at (== handler entry SP).
    pub frame_addr: u64,
    pub new_sp: u64,
    /// x0 (sig), x1 (&info or junk), x2 (&uc or junk), x30 (restorer).
    pub arg_x0: u64,
    pub arg_x1: u64,
    pub arg_x2: u64,
    pub arg_x30: u64,
    pub new_sigmask: u64,
}

/// Compute the arm rt_sigframe. The FPSIMD context is placed in
/// `uc_mcontext.__reserved` (magic 0x46508001). `fp_q`/`fpsr`/`fpcr`
/// are the live FP/SIMD state to embed.
/// # C: O(1)
pub fn build_arm(
    regs: &GpRegsArm,
    p: &BuildParams,
    fp_q: &[[u8; 16]; 32],
    fpsr: u32,
    fpcr: u32,
) -> BuiltArm {
    let on_alt = (p.sa_flags & sa::SA_ONSTACK) != 0
        && p.alt_sp != 0
        && p.alt_size != 0
        && (p.alt_flags & ss::SS_DISABLE) == 0;
    let base_top = if on_alt {
        p.alt_sp.saturating_add(p.alt_size)
    } else {
        regs.sp
    };
    // AAPCS64: SP%16==0 at handler entry. No red zone on arm.
    let frame_sz = core::mem::size_of::<RtSigframeArm>() as u64;
    let frame_addr = base_top.saturating_sub(frame_sz) & !0xfu64;
    let new_sp = frame_addr;

    let info_addr = frame_addr + core::mem::offset_of!(RtSigframeArm, info) as u64;
    let uc_addr = frame_addr + core::mem::offset_of!(RtSigframeArm, uc) as u64;

    // Build the fpsimd_context record into a zeroed __reserved area.
    let mut reserved = [0u8; 4096];
    let fpc = FpSimdContext {
        head: Aarch64Ctx {
            magic: FPSIMD_MAGIC,
            size: core::mem::size_of::<FpSimdContext>() as u32,
        },
        fpsr,
        fpcr,
        vregs: vregs_from_bytes(fp_q),
    };
    // SAFETY-free copy: FpSimdContext is repr(C); serialise its bytes
    // into the head of __reserved (host + kernel identical layout).
    let fpc_bytes = fpsimd_as_bytes(&fpc);
    reserved[..fpc_bytes.len()].copy_from_slice(&fpc_bytes);

    let mut mc = SigContextArm {
        fault_address: 0,
        regs: regs.regs,
        sp: regs.sp,
        pc: regs.pc,
        pstate: regs.pstate,
        __reserved: reserved,
    };
    let _ = &mut mc;

    let uc = UContextArm {
        uc_flags: 0,
        uc_link: 0,
        uc_stack: Stack {
            ss_sp: p.alt_sp,
            ss_flags: if on_alt { ss::SS_ONSTACK } else { p.alt_flags },
            _pad: 0,
            ss_size: p.alt_size,
        },
        uc_sigmask: p.old_sigmask,
        __unused: [0; 120],
        uc_mcontext: mc,
    };
    let frame = RtSigframeArm { info: p.info, uc };

    let (arg_x1, arg_x2) = if (p.sa_flags & sa::SA_SIGINFO) != 0 {
        (info_addr, uc_addr)
    } else {
        (0, 0)
    };
    let new_sigmask = compute_new_mask(p);

    BuiltArm {
        frame, frame_addr, new_sp,
        arg_x0: p.sig as u64, arg_x1, arg_x2, arg_x30: p.restorer,
        new_sigmask,
    }
}

/// Restored arm GP set.
pub struct RestoredArm {
    pub regs: GpRegsArm,
    pub sigmask: u64,
    pub fp_q: [[u8; 16]; 32],
    pub fpsr: u32,
    pub fpcr: u32,
    /// True iff a valid fpsimd_context (magic) was found in __reserved.
    pub fp_valid: bool,
}

/// Restore the arm GP set from a (possibly edited) on-stack frame.
/// # C: O(1)
pub fn restore_arm(frame: &RtSigframeArm) -> RestoredArm {
    let m = &frame.uc.uc_mcontext;
    // Decode the fpsimd_context from the head of __reserved.
    let (fp_q, fpsr, fpcr, fp_valid) = decode_fpsimd(&m.__reserved);
    RestoredArm {
        regs: GpRegsArm { regs: m.regs, sp: m.sp, pc: m.pc, pstate: m.pstate },
        sigmask: frame.uc.uc_sigmask,
        fp_q, fpsr, fpcr, fp_valid,
    }
}

/// # C: O(1)
fn vregs_from_bytes(q: &[[u8; 16]; 32]) -> [u128; 32] {
    let mut out = [0u128; 32];
    for i in 0..32 {
        out[i] = u128::from_ne_bytes(q[i]);
    }
    out
}

/// Serialise an FpSimdContext to its repr(C) bytes (528 B).
/// # C: O(1)
fn fpsimd_as_bytes(fpc: &FpSimdContext) -> [u8; 528] {
    // SAFETY: FpSimdContext is repr(C, align(16)) sized exactly 528 B
    // (asserted in sigframe.rs); reading it as a byte array is a pure
    // reinterpret of its own storage with no aliasing or lifetime
    // hazard — the source outlives the copy.
    unsafe { core::mem::transmute_copy::<FpSimdContext, [u8; 528]>(fpc) }
}

/// Decode the leading fpsimd_context from a sigcontext __reserved
/// area. Returns (q, fpsr, fpcr, valid). valid=false ⇒ no FP reload.
/// # C: O(1)
fn decode_fpsimd(reserved: &[u8; 4096]) -> ([[u8; 16]; 32], u32, u32, bool) {
    let magic = u32::from_ne_bytes([reserved[0], reserved[1], reserved[2], reserved[3]]);
    if magic != FPSIMD_MAGIC {
        return ([[0; 16]; 32], 0, 0, false);
    }
    let fpsr = u32::from_ne_bytes([reserved[8], reserved[9], reserved[10], reserved[11]]);
    let fpcr = u32::from_ne_bytes([reserved[12], reserved[13], reserved[14], reserved[15]]);
    let mut q = [[0u8; 16]; 32];
    for i in 0..32 {
        let off = 16 + i * 16;
        q[i].copy_from_slice(&reserved[off..off + 16]);
    }
    (q, fpsr, fpcr, true)
}

#[cfg(test)]
#[path = "sigbuild_tests.rs"]
mod tests;
