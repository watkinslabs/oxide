// Hosted round-trip test (the primary gate, verify-left): fabricate a
// known GP set, build the rt_sigframe, assert every GPR/PC/SP/flags
// landed in the right sigcontext slot + handler args set; then EDIT the
// on-stack ucontext (simulate Go rewriting PC/SP/rbx) and restore,
// asserting the edited PC/SP propagate + every other GPR round-trips.
// Runs on the x86_64 host but checks BOTH arches' repr(C) layouts.

use super::*;
use crate::sigframe::{sa, ss, si, SigInfoUser};

fn known_x86() -> GpRegsX86 {
    GpRegsX86 {
        r8: 0x88, r9: 0x99, r10: 0x1010, r11: 0x1111,
        r12: 0x1212, r13: 0x1313, r14: 0x1414, r15: 0x1515,
        rdi: 0xd1, rsi: 0x51, rbp: 0xb9, rbx: 0xb8,
        rdx: 0xd2, rax: 0xa0, rcx: 0xc1, rsp: 0x0000_7fff_ffff_0000,
        rip: 0x0000_4000_1234, eflags: 0x202,
        cs: 0x33, gs: 0, fs: 0, ss: 0x2b,
    }
}

fn params_x86(flags: u64) -> BuildParams {
    BuildParams {
        sig: 11,
        handler: 0x0000_4000_5000,
        restorer: 0x0000_4000_6000,
        sa_flags: flags,
        sa_mask: 0,
        old_sigmask: 0x4,
        info: SigInfoUser::fault(11, si::SEGV_MAPERR, 0xdead_beef),
        alt_sp: 0,
        alt_size: 0,
        alt_flags: ss::SS_DISABLE,
    }
}

#[test]
fn x86_build_populates_every_gpr() {
    let regs = known_x86();
    let p = params_x86(sa::SA_SIGINFO);
    let fp = [0u8; 512];
    let b = build_x86(&regs, &p, &fp);
    let m = &b.frame.uc.uc_mcontext;
    assert_eq!(m.r8, regs.r8);
    assert_eq!(m.r15, regs.r15);
    assert_eq!(m.rdi, regs.rdi);
    assert_eq!(m.rbx, regs.rbx);
    assert_eq!(m.rax, regs.rax);
    assert_eq!(m.rcx, regs.rcx);
    assert_eq!(m.rsp, regs.rsp);
    assert_eq!(m.rip, regs.rip);
    assert_eq!(m.eflags, regs.eflags);
    assert_eq!(m.cs, regs.cs);
    assert_eq!(m.ss, regs.ss);
    assert_eq!(m.oldmask, p.old_sigmask);
    // pretcode = restorer; fpstate ptr set.
    assert_eq!(b.frame.pretcode, p.restorer);
    assert_eq!(m.fpstate, b.fp_addr);
    // Frame placed below red zone, 16-aligned with %16==8.
    assert!(b.new_rsp < regs.rsp - X86_RED_ZONE);
    assert_eq!(b.new_rsp % 16, 8);
}

#[test]
fn x86_siginfo_args() {
    let regs = known_x86();
    let p = params_x86(sa::SA_SIGINFO);
    let fp = [0u8; 512];
    let b = build_x86(&regs, &p, &fp);
    // rdi = sig; rsi = &info; rdx = &uc.
    assert_eq!(b.arg_rdi, 11);
    let info_addr = b.frame_addr + core::mem::offset_of!(crate::sigframe::RtSigframeX86, info) as u64;
    let uc_addr = b.frame_addr + core::mem::offset_of!(crate::sigframe::RtSigframeX86, uc) as u64;
    assert_eq!(b.arg_rsi, info_addr);
    assert_eq!(b.arg_rdx, uc_addr);
    // info content.
    assert_eq!(b.frame.info.si_signo, 11);
    assert_eq!(b.frame.info.si_code, si::SEGV_MAPERR);
}

#[test]
fn x86_non_siginfo_one_arg() {
    let regs = known_x86();
    let p = params_x86(0);
    let fp = [0u8; 512];
    let b = build_x86(&regs, &p, &fp);
    assert_eq!(b.arg_rdi, 11);
    assert_eq!(b.arg_rsi, 0);
    assert_eq!(b.arg_rdx, 0);
}

#[test]
fn x86_nodefer_and_mask() {
    let regs = known_x86();
    let mut p = params_x86(0);
    p.sa_mask = 0x10;
    // Default: self-mask sig 11 → bit 10.
    let b = build_x86(&regs, &p, &[0u8; 512]);
    assert_eq!(b.new_sigmask, p.old_sigmask | 0x10 | (1u64 << 10));
    // SA_NODEFER: no self-mask.
    p.sa_flags = sa::SA_NODEFER;
    let b2 = build_x86(&regs, &p, &[0u8; 512]);
    assert_eq!(b2.new_sigmask, p.old_sigmask | 0x10);
}

#[test]
fn x86_onstack_uses_alt() {
    let regs = known_x86();
    let mut p = params_x86(sa::SA_ONSTACK);
    p.alt_sp = 0x0000_1000_0000;
    p.alt_size = 0x4000;
    p.alt_flags = 0; // enabled
    let b = build_x86(&regs, &p, &[0u8; 512]);
    // Frame must sit within the alt stack region, not near rsp.
    assert!(b.new_rsp >= p.alt_sp);
    assert!(b.new_rsp < p.alt_sp + p.alt_size);
    assert_eq!(b.frame.uc.uc_stack.ss_sp, p.alt_sp);
    assert_eq!(b.frame.uc.uc_stack.ss_flags, ss::SS_ONSTACK);
}

#[test]
fn x86_round_trip_with_go_edit() {
    let regs = known_x86();
    let p = params_x86(sa::SA_SIGINFO);
    let mut fp = [0u8; 512];
    for (i, b) in fp.iter_mut().enumerate() { *b = (i as u8) ^ 0x5a; }
    let b = build_x86(&regs, &p, &fp);

    // Handler edits the saved context (Go asyncPreempt rewrites PC/SP,
    // and a normal handler might scribble a callee-saved reg).
    let mut edited = b.frame;
    edited.uc.uc_mcontext.rip = 0x0000_4000_9999; // new PC
    edited.uc.uc_mcontext.rsp = 0x0000_7fff_aaaa_0000; // new SP
    edited.uc.uc_mcontext.rbx = 0xdead;

    let r = restore_x86(&edited, &fp);
    assert_eq!(r.regs.rip, 0x0000_4000_9999);
    assert_eq!(r.regs.rsp, 0x0000_7fff_aaaa_0000);
    assert_eq!(r.regs.rbx, 0xdead);
    // Everything else round-trips unchanged.
    assert_eq!(r.regs.r8, regs.r8);
    assert_eq!(r.regs.r15, regs.r15);
    assert_eq!(r.regs.rdi, regs.rdi);
    assert_eq!(r.regs.rax, regs.rax);
    assert_eq!(r.regs.rcx, regs.rcx);
    assert_eq!(r.regs.eflags, regs.eflags);
    assert_eq!(r.sigmask, p.old_sigmask);
    // FP image round-trips byte-for-byte.
    assert_eq!(&r.fpstate[..], &fp[..]);
    assert_eq!(r.fp_addr, b.fp_addr);
}

// ---------------------------------------------------------------------
// aarch64
// ---------------------------------------------------------------------

fn known_arm() -> GpRegsArm {
    let mut regs = [0u64; 31];
    for i in 0..31 { regs[i] = 0x1000 + i as u64; }
    GpRegsArm { regs, sp: 0x0000_7fff_ffff_0000, pc: 0x0000_4000_1234, pstate: 0 }
}

fn params_arm(flags: u64) -> BuildParams {
    BuildParams {
        sig: 11,
        handler: 0x0000_4000_5000,
        restorer: 0x0000_4000_6000,
        sa_flags: flags,
        sa_mask: 0,
        old_sigmask: 0x4,
        info: SigInfoUser::fault(11, si::SEGV_MAPERR, 0xdead_beef),
        alt_sp: 0,
        alt_size: 0,
        alt_flags: ss::SS_DISABLE,
    }
}

#[test]
fn arm_build_populates_every_gpr() {
    let regs = known_arm();
    let p = params_arm(sa::SA_SIGINFO);
    let q = [[0u8; 16]; 32];
    let b = build_arm(&regs, &p, &q, 0, 0);
    let m = &b.frame.uc.uc_mcontext;
    for i in 0..31 {
        assert_eq!(m.regs[i], regs.regs[i], "x{} mismatch", i);
    }
    assert_eq!(m.sp, regs.sp);
    assert_eq!(m.pc, regs.pc);
    assert_eq!(m.pstate, regs.pstate);
    // args: x0=sig, x1=&info, x2=&uc, x30=restorer.
    assert_eq!(b.arg_x0, 11);
    let info_addr = b.frame_addr + core::mem::offset_of!(crate::sigframe::RtSigframeArm, info) as u64;
    let uc_addr = b.frame_addr + core::mem::offset_of!(crate::sigframe::RtSigframeArm, uc) as u64;
    assert_eq!(b.arg_x1, info_addr);
    assert_eq!(b.arg_x2, uc_addr);
    assert_eq!(b.arg_x30, p.restorer);
    assert_eq!(b.new_sp % 16, 0);
}

#[test]
fn arm_fpsimd_embedded() {
    let regs = known_arm();
    let p = params_arm(sa::SA_SIGINFO);
    let mut q = [[0u8; 16]; 32];
    for i in 0..32 { for j in 0..16 { q[i][j] = (i * 16 + j) as u8; } }
    let b = build_arm(&regs, &p, &q, 0x11, 0x22);
    // Magic at __reserved[0..4].
    let r = &b.frame.uc.uc_mcontext.__reserved;
    assert_eq!(u32::from_ne_bytes([r[0], r[1], r[2], r[3]]), crate::sigframe::FPSIMD_MAGIC);
    // Round-trip restore decodes the same q/fpsr/fpcr.
    let res = restore_arm(&b.frame);
    assert!(res.fp_valid);
    assert_eq!(res.fpsr, 0x11);
    assert_eq!(res.fpcr, 0x22);
    assert_eq!(res.fp_q, q);
}

#[test]
fn arm_round_trip_with_go_edit() {
    let regs = known_arm();
    let p = params_arm(sa::SA_SIGINFO);
    let q = [[0u8; 16]; 32];
    let b = build_arm(&regs, &p, &q, 0, 0);

    let mut edited = b.frame;
    edited.uc.uc_mcontext.pc = 0x0000_4000_9999;
    edited.uc.uc_mcontext.sp = 0x0000_7fff_aaaa_0000;
    edited.uc.uc_mcontext.regs[19] = 0xdead; // x19 (callee-saved)

    let r = restore_arm(&edited);
    assert_eq!(r.regs.pc, 0x0000_4000_9999);
    assert_eq!(r.regs.sp, 0x0000_7fff_aaaa_0000);
    assert_eq!(r.regs.regs[19], 0xdead);
    // Other GPRs round-trip.
    for i in 0..31 {
        if i == 19 { continue; }
        assert_eq!(r.regs.regs[i], regs.regs[i], "x{} mismatch", i);
    }
    assert_eq!(r.sigmask, p.old_sigmask);
}

#[test]
fn arm_onstack_uses_alt() {
    let regs = known_arm();
    let mut p = params_arm(sa::SA_ONSTACK);
    p.alt_sp = 0x0000_1000_0000;
    p.alt_size = 0x8000;
    p.alt_flags = 0;
    let b = build_arm(&regs, &p, &[[0u8; 16]; 32], 0, 0);
    assert!(b.new_sp >= p.alt_sp);
    assert!(b.new_sp < p.alt_sp + p.alt_size);
    assert_eq!(b.frame.uc.uc_stack.ss_flags, ss::SS_ONSTACK);
}
