// ptrace register-set materialisation. Converts between the kernel's saved
// entry frame and the ABI struct a tracer expects
// (`struct user_regs_struct` on x86_64, `struct user_pt_regs` on arm64).
//
// The frame has ONE owner per arch — the struct the entry asm actually
// pushes (`PtRegs` on x86_64, `SvcFrame` on aarch64), the same struct the
// signal-frame builder and the core-dump `NT_PRSTATUS` block read. Fields are
// reached by NAME, so this file restates no offset and cannot drift from the
// asm: a reordered frame is a compile error here, not a tracer quietly
// reporting register B when it asked for register A.
//
// The ABI-side indexes have one owner too (`hal::uregs`), shared with the
// core-dump path.
//
// Field mapping is hosted-testable — a wrong mapping is silent (a tracer
// reads a plausible-looking garbage register), which is exactly the class of
// bug a unit test catches and a boot does not. Both arch modules therefore
// compile under `test` on either host, via the dev-dependency on the two HAL
// crates.

/// x86_64: the entry frame every kernel entry pushes.
#[cfg(any(target_arch = "x86_64", test))]
pub mod x86 {
    use hal_x86_64::PtRegs;
    use syscall::errno::Errno;

    /// The saved frame, by its owning definition.
    pub type Frame = PtRegs;

    /// `struct user_regs_struct` field indexes (quadword units), owned by
    /// `hal::uregs` because the core-dump register block indexes the same way.
    pub use hal::uregs::x86_64::user_regs::{
        CS as U_CS, DS as U_DS, EFLAGS as U_EFLAGS, ES as U_ES, FS as U_FS,
        FS_BASE as U_FS_BASE, GS as U_GS, GS_BASE as U_GS_BASE, N, NO_SYSCALL,
        ORIG_RAX as U_ORIG_RAX, R10 as U_R10, R11 as U_R11, R12 as U_R12,
        R13 as U_R13, R14 as U_R14, R15 as U_R15, R8 as U_R8, R9 as U_R9,
        RAX as U_RAX, RBP as U_RBP, RBX as U_RBX, RCX as U_RCX, RDI as U_RDI,
        RDX as U_RDX, RIP as U_RIP, RSI as U_RSI, RSP as U_RSP, SS as U_SS,
    };

    /// Linux x86_64 `FLAG_MASK` = `FLAG_MASK_32 | X86_EFLAGS_NT` — the EFLAGS
    /// bits a tracer may install (CF PF AF ZF SF TF DF OF RF AC NT).
    /// Everything else keeps the kernel's value, so IF/IOPL cannot be forged
    /// from userspace. Owned by `hal::uregs` so this and `rt_sigreturn`'s
    /// stricter `FIX_EFLAGS` cannot drift apart.
    pub const FLAG_MASK: u64 = hal::uregs::x86_64::PTRACE_FLAG_MASK;

    /// Segment-register context the frame does not carry. `cs` and `ss` are
    /// NOT here: the frame holds the real pair the entry pushed, so reporting
    /// a fixed selector instead would be the same restatement this file
    /// exists to avoid.
    #[derive(Debug, Clone, Copy, Eq, PartialEq)]
    pub struct SegState {
        pub ds: u64, pub es: u64, pub fs: u64, pub gs: u64,
        pub fs_base: u64, pub gs_base: u64,
    }

    /// Build `struct user_regs_struct` from the saved frame.
    ///
    /// The frame's `rax` slot plays Linux's `orig_ax` role on a `syscall`
    /// entry — it keeps the syscall number for the whole dispatch — so the
    /// ABI return register comes from `stop_rax`, the value recorded at the
    /// stop (Linux reports `-ENOSYS` at a syscall-entry stop and the result at
    /// a syscall-exit stop). On a trap frame there is no syscall: `rax` is the
    /// user's own register and `orig_rax` reads back as [`NO_SYSCALL`], which
    /// is what the core-dump block reports for the same frame.
    /// # C: O(1)
    pub fn to_user_regs(f: &Frame, stop_rax: u64, seg: &SegState) -> [u64; N] {
        let from_syscall = f.from_syscall();
        let mut u = [0u64; N];
        u[U_R15] = f.r15;
        u[U_R14] = f.r14;
        u[U_R13] = f.r13;
        u[U_R12] = f.r12;
        u[U_RBP] = f.rbp;
        u[U_RBX] = f.rbx;
        u[U_R11] = f.r11;
        u[U_R10] = f.r10;
        u[U_R9]  = f.r9;
        u[U_R8]  = f.r8;
        u[U_RAX] = if from_syscall { stop_rax } else { f.rax };
        u[U_RCX] = f.rcx;
        u[U_RDX] = f.rdx;
        u[U_RSI] = f.rsi;
        u[U_RDI] = f.rdi;
        u[U_ORIG_RAX] = if from_syscall { f.rax } else { NO_SYSCALL };
        u[U_RIP]    = f.rip;
        u[U_CS]     = f.cs;
        u[U_EFLAGS] = f.rflags;
        u[U_RSP]    = f.rsp;
        u[U_SS]     = f.ss;
        u[U_FS_BASE] = seg.fs_base;
        u[U_GS_BASE] = seg.gs_base;
        u[U_DS] = seg.ds;
        u[U_ES] = seg.es;
        u[U_FS] = seg.fs;
        u[U_GS] = seg.gs;
        u
    }

    /// Linux `invalid_selector`: a non-zero selector must carry RPL 3.
    /// # C: O(1)
    pub fn invalid_selector(v: u64) -> bool {
        let v = v as u16;
        v != 0 && (v & 3) != 3
    }

    /// Apply a tracer-supplied `struct user_regs_struct` to the saved frame.
    /// Returns the ABI return-register value the caller must record alongside
    /// the frame. Rejects the same values Linux `putreg` rejects (bad
    /// selector, or a non-canonical FS/GS base) with EIO, leaving the frame
    /// untouched.
    ///
    /// Which supplied word lands in the frame's single `rax` slot follows the
    /// entry tag, mirroring [`to_user_regs`]: the syscall number on a
    /// `syscall` frame, the architectural `rax` on a trap frame.
    /// # C: O(1)
    pub fn from_user_regs(u: &[u64; N], f: &mut Frame, seg: &mut SegState,
                          user_va_end: u64) -> Result<u64, Errno> {
        for idx in [U_CS, U_SS, U_DS, U_ES, U_FS, U_GS] {
            if invalid_selector(u[idx]) { return Err(Errno::Eio); }
        }
        if u[U_FS_BASE] >= user_va_end || u[U_GS_BASE] >= user_va_end {
            return Err(Errno::Eio);
        }
        f.r15 = u[U_R15];
        f.r14 = u[U_R14];
        f.r13 = u[U_R13];
        f.r12 = u[U_R12];
        f.rbp = u[U_RBP];
        f.rbx = u[U_RBX];
        f.r11 = u[U_R11];
        f.r10 = u[U_R10];
        f.r9  = u[U_R9];
        f.r8  = u[U_R8];
        f.rcx = u[U_RCX];
        f.rdx = u[U_RDX];
        f.rsi = u[U_RSI];
        f.rdi = u[U_RDI];
        f.rax = if f.from_syscall() { u[U_ORIG_RAX] } else { u[U_RAX] };
        f.rip = u[U_RIP];
        f.rsp = u[U_RSP];
        f.rflags = hal::uregs::x86_64::ptrace_eflags(f.rflags, u[U_EFLAGS]);
        seg.ds = u[U_DS]; seg.es = u[U_ES];
        seg.fs = u[U_FS]; seg.gs = u[U_GS];
        seg.fs_base = u[U_FS_BASE];
        seg.gs_base = u[U_GS_BASE];
        Ok(u[U_RAX])
    }
}

/// arm64: the `SvcFrame` the EL0-sync save block writes.
#[cfg(any(target_arch = "aarch64", test))]
pub mod arm64 {
    use hal_aarch64::SvcFrame;

    /// The saved frame, by its owning definition.
    pub type Frame = SvcFrame;

    /// `x18` and `x29` share one store pair in the frame.
    const P_X18: usize = 0;
    const P_X29: usize = 1;
    /// Register indexes the frame's scattered blocks land on.
    const X18: usize = 18;
    const X19: usize = 19;
    const X29: usize = 29;
    const X30: usize = 30;

    /// `struct user_pt_regs` indexes, owned by `hal::uregs`.
    pub use hal::uregs::aarch64::user_pt_regs::{
        N, NGPR, PC as U_PC, PSTATE as U_PSTATE, SP as U_SP,
    };

    /// `SPSR_EL1` fields consulted by Linux `valid_native_regs`. Owned by
    /// `hal::uregs::aarch64` — the same rule `rt_sigreturn` applies.
    pub use hal::uregs::aarch64::{
        PSR_A_BIT, PSR_D_BIT, PSR_F_BIT, PSR_I_BIT, PSR_MODE32_BIT, PSR_MODE_EL0T,
        PSR_MODE_MASK, PSR_NZCV, PSR_SS_BIT,
    };

    const _: () = assert!(NGPR == X30 + 1);

    /// Linux `valid_native_regs`: a tracer-supplied PSTATE is accepted whole
    /// only when it still describes unmasked EL0t AArch64 execution; anything
    /// else collapses to the condition flags, so a tracer can never promote
    /// the tracee's exception level or mask its interrupts. RES0 bits (IL,
    /// PAN, UAO, bits 63:32) are masked off either way.
    ///
    /// Linux's `gpr_set` rejects an invalid set with `-EINVAL` and writes
    /// NOTHING; we sanitize in place, which is strictly narrower (the tracee
    /// still cannot escalate) but reports success. Tracked as a fidelity gap.
    /// # C: O(1)
    pub fn sanitize_pstate(new: u64) -> u64 {
        // `single_step` is false: the software-step bit is (re-)armed after
        // dispatch from `Task.singlestep`, never from the tracer's word.
        hal::uregs::aarch64::sanitize_native_pstate(new, false).0
    }

    /// Materialise `struct user_pt_regs`. `x0` is supplied separately for the
    /// same reason as x86's `rax`: at a syscall-exit stop the ABI value is the
    /// return value, which the frame keeps in its own `retval` slot.
    /// # C: O(1)
    pub fn to_user_pt_regs(f: &Frame, x0: u64) -> [u64; N] {
        let mut u = [0u64; N];
        u[..f.gp.len()].copy_from_slice(&f.gp);
        u[0] = x0;
        u[X18] = f.x18_x29[P_X18];
        u[X19..X29].copy_from_slice(&f.x19_x28);
        u[X29] = f.x18_x29[P_X29];
        u[X30] = f.x30;
        u[U_SP] = f.sp_el0;
        u[U_PC] = f.elr_el1;
        u[U_PSTATE] = f.spsr_el1;
        u
    }

    /// Apply a tracer-supplied `struct user_pt_regs`. PSTATE is masked to the
    /// user-settable bits so a tracer cannot promote the tracee's exception
    /// level (Linux `valid_user_regs`).
    /// # C: O(1)
    pub fn from_user_pt_regs(u: &[u64; N], f: &mut Frame) {
        let gp = f.gp.len();
        f.gp.copy_from_slice(&u[..gp]);
        f.x18_x29[P_X18] = u[X18];
        f.x19_x28.copy_from_slice(&u[X19..X29]);
        f.x18_x29[P_X29] = u[X29];
        f.x30 = u[X30];
        f.sp_el0 = u[U_SP];
        f.elr_el1 = u[U_PC];
        f.spsr_el1 = sanitize_pstate(u[U_PSTATE]);
        f.retval = u[0];
    }
}

#[cfg(test)]
#[path = "regs/tests.rs"] mod tests;
