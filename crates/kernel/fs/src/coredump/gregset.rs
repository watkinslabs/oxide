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
// decodes the block in.
pub const X86_U_R15: usize = 0;
pub const X86_U_R14: usize = 1;
pub const X86_U_R13: usize = 2;
pub const X86_U_R12: usize = 3;
pub const X86_U_RBP: usize = 4;
pub const X86_U_RBX: usize = 5;
pub const X86_U_R11: usize = 6;
pub const X86_U_R10: usize = 7;
pub const X86_U_R9:  usize = 8;
pub const X86_U_R8:  usize = 9;
pub const X86_U_RAX: usize = 10;
pub const X86_U_RCX: usize = 11;
pub const X86_U_RDX: usize = 12;
pub const X86_U_RSI: usize = 13;
pub const X86_U_RDI: usize = 14;
pub const X86_U_ORIG_RAX: usize = 15;
pub const X86_U_RIP:     usize = 16;
pub const X86_U_CS:      usize = 17;
pub const X86_U_EFLAGS:  usize = 18;
pub const X86_U_RSP:     usize = 19;
pub const X86_U_SS:      usize = 20;
pub const X86_U_FS_BASE: usize = 21;
pub const X86_U_GS_BASE: usize = 22;
pub const X86_U_DS:      usize = 23;
pub const X86_U_ES:      usize = 24;
pub const X86_U_FS:      usize = 25;
pub const X86_U_GS:      usize = 26;

/// Registers in the x86-64 block.
pub const X86_NGREG: usize = 27;

// `struct user_pt_regs` (aarch64): `regs[31]`, then the three named words.
/// General registers the aarch64 block leads with: `x0`..`x30`.
pub const ARM_NGPR: usize = 31;
pub const ARM_U_SP:     usize = 31;
pub const ARM_U_PC:     usize = 32;
pub const ARM_U_PSTATE: usize = 33;

/// Registers in the aarch64 block.
pub const ARM_NGREG: usize = 34;

/// `orig_ax` outside a syscall. A frame that did not come from a `syscall`
/// instruction has no syscall number to report, and a debugger reading a
/// plausible number there would show the crash as an interrupted call.
pub const NO_SYSCALL: u64 = u64::MAX;

/// Everything the x86-64 block carries that a saved frame does not: the two
/// segment bases live in the thread's saved context rather than in the frame.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct X86SegBases { pub fs_base: u64, pub gs_base: u64 }

/// x86-64 general registers as a saved frame holds them, in frame terms.
///
/// `rax` is the ABI return-value register; `orig_rax` is the syscall number a
/// `syscall` entry parked there, or [`NO_SYSCALL`] on a trap.
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
/// reports its syscall number as `orig_ax`, a trap frame reports [`NO_SYSCALL`].
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
        rax: r.rax, orig_rax: if from_syscall { r.rax } else { NO_SYSCALL },
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
