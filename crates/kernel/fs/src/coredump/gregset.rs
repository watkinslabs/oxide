// The register block `NT_PRSTATUS` embeds, materialised from the saved user
// frame the crashing thread entered the kernel through.
//
// The frame itself has ONE owner per arch (`PtRegs` on x86-64, `SvcFrame` on
// aarch64): every entry — syscall, exception, interrupt — saves user state in
// that exact shape, so a dump reads the same words a signal frame and a tracer
// read. Nothing here snapshots a second copy of the registers; the arch shims
// at the bottom only pick fields out of the live frame and hand them to the
// ungated serialisers above, which is what keeps the field order testable
// without a kernel target.

use alloc::vec::Vec;

/// Bytes of one register in the block.
const GREG_BYTES: usize = 8;

// `struct user_regs_struct` (x86-64) — quadword indexes, the order a debugger
// decodes the block in. ONE owner (`hal::uregs`), shared with the live
// `PTRACE_GETREGS` path so a dump and a tracer cannot disagree about which
// word is which register.
pub use hal::uregs::x86_64::user_regs::{
    CS as X86_U_CS, DS as X86_U_DS, EFLAGS as X86_U_EFLAGS, ES as X86_U_ES,
    FS as X86_U_FS, FS_BASE as X86_U_FS_BASE, GS as X86_U_GS,
    GS_BASE as X86_U_GS_BASE, N as X86_NGREG,
    ORIG_RAX as X86_U_ORIG_RAX, R10 as X86_U_R10, R11 as X86_U_R11,
    R12 as X86_U_R12, R13 as X86_U_R13, R14 as X86_U_R14, R15 as X86_U_R15,
    R8 as X86_U_R8, R9 as X86_U_R9, RAX as X86_U_RAX, RBP as X86_U_RBP,
    RBX as X86_U_RBX, RCX as X86_U_RCX, RDI as X86_U_RDI, RDX as X86_U_RDX,
    RIP as X86_U_RIP, RSI as X86_U_RSI, RSP as X86_U_RSP, SS as X86_U_SS,
};

// `struct user_pt_regs` (aarch64): `regs[31]`, then the three named words.
pub use hal::uregs::aarch64::user_pt_regs::{
    N as ARM_NGREG, NGPR as ARM_NGPR, PC as ARM_U_PC, PSTATE as ARM_U_PSTATE,
    SP as ARM_U_SP,
};

/// Everything the x86-64 block carries that a saved frame does not: the two
/// segment bases live in the thread's saved context rather than in the frame.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct X86SegBases { pub fs_base: u64, pub gs_base: u64 }

/// x86-64 general registers as a saved frame holds them, in frame terms.
///
/// `rax` is the ABI return-value register. `orig_rax` is the syscall number a
/// `syscall` entry parked there, or the independently saved entry word on a
/// trap.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct X86Frame {
    pub r15: u64, pub r14: u64, pub r13: u64, pub r12: u64,
    pub rbp: u64, pub rbx: u64,
    pub r11: u64, pub r10: u64, pub r9: u64, pub r8: u64,
    pub rdi: u64, pub rsi: u64, pub rdx: u64, pub rcx: u64,
    pub rax: u64, pub orig_rax: u64,
    pub rip: u64, pub cs: u64, pub rflags: u64, pub rsp: u64, pub ss: u64,
}

fn pack(words: &[u64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(words.len() * GREG_BYTES);
    for w in words.iter() { out.extend_from_slice(&w.to_le_bytes()) }
    out
}

/// Serialise an x86-64 register block.
/// # C: O(1)
pub fn x86_64_block(f: &X86Frame, seg: &X86SegBases) -> Vec<u8> {
    let mut u = [0u64; X86_NGREG];
    u[X86_U_R15] = f.r15;
    u[X86_U_R14] = f.r14;
    u[X86_U_R13] = f.r13;
    u[X86_U_R12] = f.r12;
    u[X86_U_RBP] = f.rbp;
    u[X86_U_RBX] = f.rbx;
    u[X86_U_R11] = f.r11;
    u[X86_U_R10] = f.r10;
    u[X86_U_R9]  = f.r9;
    u[X86_U_R8]  = f.r8;
    u[X86_U_RAX] = f.rax;
    u[X86_U_RCX] = f.rcx;
    u[X86_U_RDX] = f.rdx;
    u[X86_U_RSI] = f.rsi;
    u[X86_U_RDI] = f.rdi;
    u[X86_U_ORIG_RAX] = f.orig_rax;
    u[X86_U_RIP]    = f.rip;
    u[X86_U_CS]     = f.cs;
    u[X86_U_EFLAGS] = f.rflags;
    u[X86_U_RSP]    = f.rsp;
    u[X86_U_SS]     = f.ss;
    u[X86_U_FS_BASE] = seg.fs_base;
    u[X86_U_GS_BASE] = seg.gs_base;
    // The four data selectors are not saved by any entry on this port and are
    // fixed by the user code model; zero is what a debugger sees for them.
    pack(&u)
}

/// Serialise an aarch64 register block.
/// # C: O(1)
pub fn aarch64_block(gpr: &[u64; ARM_NGPR], sp: u64, pc: u64, pstate: u64) -> Vec<u8> {
    let mut u = [0u64; ARM_NGREG];
    u[..ARM_NGPR].copy_from_slice(gpr);
    u[ARM_U_SP] = sp;
    u[ARM_U_PC] = pc;
    u[ARM_U_PSTATE] = pstate;
    pack(&u)
}

/// The crashing thread's block, read out of its live entry frame.
///
/// `from_syscall` is the entry tag: a frame a `syscall` instruction built
/// reports its syscall number as `orig_ax`; a trap frame reports its saved
/// entry word.
/// # SAFETY: `regs` is the live entry frame of the calling thread.
/// # C: O(1)
#[cfg(target_arch = "x86_64")]
pub unsafe fn current_block(regs: *const hal_x86_64::PtRegs, seg: &X86SegBases) -> Vec<u8> {
    // SAFETY: caller's contract — `regs` is this thread's own entry frame on
    // its kernel stack, live and singly owned for the duration of the read.
    let r = unsafe { &*regs };
    let from_syscall = r.vector == hal_x86_64::PT_REGS_VECTOR_SYSCALL;
    x86_64_block(&X86Frame {
        r15: r.r15, r14: r.r14, r13: r.r13, r12: r.r12, rbp: r.rbp, rbx: r.rbx,
        r11: r.r11, r10: r.r10, r9: r.r9, r8: r.r8,
        rdi: r.rdi, rsi: r.rsi, rdx: r.rdx, rcx: r.rcx,
        rax: r.rax, orig_rax: if from_syscall { r.rax } else { r.error },
        rip: r.rip, cs: r.cs, rflags: r.rflags, rsp: r.rsp, ss: r.ss,
    }, seg)
}

/// aarch64 counterpart. The frame packs `x18`/`x29` together and keeps
/// `x19`..`x28` in a trailing block, so the general registers are gathered
/// before the ungated serialiser sees them.
/// # SAFETY: `regs` is the live entry frame of the calling thread.
/// # C: O(1)
#[cfg(target_arch = "aarch64")]
pub unsafe fn current_block(regs: *const hal_aarch64::SvcFrame) -> Vec<u8> {
    /// `x18` and `x29` share one store pair in the frame.
    const F_X18: usize = 0;
    const F_X29: usize = 1;
    // SAFETY: caller's contract — `regs` is this thread's own entry frame on
    // its kernel stack, live and singly owned for the duration of the read.
    let r = unsafe { &*regs };
    let mut gpr = [0u64; ARM_NGPR];
    gpr[..r.gp.len()].copy_from_slice(&r.gp);
    gpr[18] = r.x18_x29[F_X18];
    gpr[19..29].copy_from_slice(&r.x19_x28);
    gpr[29] = r.x18_x29[F_X29];
    gpr[30] = r.x30;
    aarch64_block(&gpr, r.sp_el0, r.elr_el1, r.spsr_el1)
}

/// Vector registers the aarch64 floating-point block carries.
pub const ARM_NVREG: usize = 32;

/// Bytes of one vector register.
pub const ARM_VREG_BYTES: usize = 16;

/// Bytes of the aarch64 floating-point block: the vector file, the status and
/// control words, and the tail that pads the descriptor to its alignment.
pub const ARM_FPREG_BYTES: usize = ARM_NVREG * ARM_VREG_BYTES + 4 + 4 + 8;

/// Serialise an aarch64 floating-point block.
///
/// The status word precedes the control word, which is the opposite of the
/// order the kernel's own save area stores them in — a straight copy of that
/// area would hand a debugger each as the other.
/// # C: O(1)
pub fn aarch64_fpregs_block(v: &[[u8; ARM_VREG_BYTES]; ARM_NVREG], fpsr: u32, fpcr: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(ARM_FPREG_BYTES);
    for q in v.iter() { out.extend_from_slice(q) }
    out.extend_from_slice(&fpsr.to_le_bytes());
    out.extend_from_slice(&fpcr.to_le_bytes());
    out.resize(ARM_FPREG_BYTES, 0);
    out
}
