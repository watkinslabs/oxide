// ptrace register-set materialisation. Converts between the kernel's saved
// entry frame and the ABI struct a tracer expects
// (`struct user_regs_struct` on x86_64, `struct user_pt_regs` on arm64).
//
// Pure array-in / array-out so the field mapping is hosted-testable: a
// wrong index here is silent (a tracer reads a plausible-looking garbage
// register), which is exactly the class of bug a unit test catches and a
// boot does not.

use syscall::errno::Errno;

/// x86_64: the syscall-entry frame written by `oxide_syscall_entry`
/// (`crates/arch/hal-x86_64/src/syscall.rs`), 16 quadwords at
/// `kstack_top - 0x80`.
pub mod x86 {
    use super::*;

    pub const FRAME_N: usize = 16;
    pub const F_ORIG_RAX: usize = 0;
    pub const F_RDI:      usize = 1;
    pub const F_RSI:      usize = 2;
    pub const F_RDX:      usize = 3;
    pub const F_R10:      usize = 4;
    pub const F_R8:       usize = 5;
    pub const F_R9:       usize = 6;
    /// `rcx` slot — SYSCALL parks the user RIP here, exactly like Linux `pt_regs.cx`.
    pub const F_RIP:      usize = 7;
    /// `r11` slot — SYSCALL parks the user RFLAGS here, like Linux `pt_regs.r11`.
    pub const F_RFLAGS:   usize = 8;
    pub const F_RSP:      usize = 9;
    pub const F_RBX:      usize = 10;
    pub const F_RBP:      usize = 11;
    pub const F_R13:      usize = 12;
    pub const F_R14:      usize = 13;
    pub const F_R15:      usize = 14;
    pub const F_R12:      usize = 15;

    /// `struct user_regs_struct` field indexes (quadword units).
    pub const N: usize = crate::s101_ptrace_uapi::X86_USER_REGS_N;
    pub const U_R15: usize = 0;
    pub const U_R14: usize = 1;
    pub const U_R13: usize = 2;
    pub const U_R12: usize = 3;
    pub const U_RBP: usize = 4;
    pub const U_RBX: usize = 5;
    pub const U_R11: usize = 6;
    pub const U_R10: usize = 7;
    pub const U_R9:  usize = 8;
    pub const U_R8:  usize = 9;
    pub const U_RAX: usize = 10;
    pub const U_RCX: usize = 11;
    pub const U_RDX: usize = 12;
    pub const U_RSI: usize = 13;
    pub const U_RDI: usize = 14;
    pub const U_ORIG_RAX: usize = 15;
    pub const U_RIP:     usize = 16;
    pub const U_CS:      usize = 17;
    pub const U_EFLAGS:  usize = 18;
    pub const U_RSP:     usize = 19;
    pub const U_SS:      usize = 20;
    pub const U_FS_BASE: usize = 21;
    pub const U_GS_BASE: usize = 22;
    pub const U_DS:      usize = 23;
    pub const U_ES:      usize = 24;
    pub const U_FS:      usize = 25;
    pub const U_GS:      usize = 26;

    /// Linux `FLAG_MASK` — the EFLAGS bits a tracer may install
    /// (CF PF AF ZF SF TF DF OF RF AC). Everything else keeps the
    /// kernel's value, so IF/IOPL cannot be forged from userspace.
    pub const FLAG_MASK: u64 = 0x0005_0DD5;

    /// Segment-register context the frame does not carry.
    #[derive(Debug, Clone, Copy, Eq, PartialEq)]
    pub struct SegState {
        pub cs: u64, pub ss: u64,
        pub ds: u64, pub es: u64, pub fs: u64, pub gs: u64,
        pub fs_base: u64, pub gs_base: u64,
    }

    /// Build `struct user_regs_struct` from the saved frame. `rax` is
    /// supplied by the caller because the frame slot keeps the syscall
    /// number (`orig_ax`): Linux reports `-ENOSYS` at a syscall-entry stop
    /// and the return value at a syscall-exit stop.
    /// # C: O(1)
    pub fn to_user_regs(f: &[u64; FRAME_N], rax: u64, seg: &SegState) -> [u64; N] {
        let mut u = [0u64; N];
        u[U_R15] = f[F_R15];
        u[U_R14] = f[F_R14];
        u[U_R13] = f[F_R13];
        u[U_R12] = f[F_R12];
        u[U_RBP] = f[F_RBP];
        u[U_RBX] = f[F_RBX];
        u[U_R11] = f[F_RFLAGS];
        u[U_R10] = f[F_R10];
        u[U_R9]  = f[F_R9];
        u[U_R8]  = f[F_R8];
        u[U_RAX] = rax;
        u[U_RCX] = f[F_RIP];
        u[U_RDX] = f[F_RDX];
        u[U_RSI] = f[F_RSI];
        u[U_RDI] = f[F_RDI];
        u[U_ORIG_RAX] = f[F_ORIG_RAX];
        u[U_RIP]    = f[F_RIP];
        u[U_CS]     = seg.cs;
        u[U_EFLAGS] = f[F_RFLAGS];
        u[U_RSP]    = f[F_RSP];
        u[U_SS]     = seg.ss;
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
    /// Returns the new `(rax, SegState)` the caller must store alongside.
    /// Rejects the same values Linux `putreg` rejects (bad selector, or a
    /// non-canonical FS/GS base) with EIO, leaving the frame untouched.
    /// # C: O(1)
    pub fn from_user_regs(u: &[u64; N], f: &mut [u64; FRAME_N], seg: &mut SegState,
                          user_va_end: u64) -> Result<u64, Errno> {
        for idx in [U_CS, U_SS, U_DS, U_ES, U_FS, U_GS] {
            if invalid_selector(u[idx]) { return Err(Errno::Eio); }
        }
        if u[U_FS_BASE] >= user_va_end || u[U_GS_BASE] >= user_va_end {
            return Err(Errno::Eio);
        }
        f[F_R15] = u[U_R15];
        f[F_R14] = u[U_R14];
        f[F_R13] = u[U_R13];
        f[F_R12] = u[U_R12];
        f[F_RBP] = u[U_RBP];
        f[F_RBX] = u[U_RBX];
        f[F_R10] = u[U_R10];
        f[F_R9]  = u[U_R9];
        f[F_R8]  = u[U_R8];
        f[F_RDX] = u[U_RDX];
        f[F_RSI] = u[U_RSI];
        f[F_RDI] = u[U_RDI];
        f[F_ORIG_RAX] = u[U_ORIG_RAX];
        f[F_RIP] = u[U_RIP];
        f[F_RSP] = u[U_RSP];
        f[F_RFLAGS] = (f[F_RFLAGS] & !FLAG_MASK) | (u[U_EFLAGS] & FLAG_MASK);
        seg.cs = u[U_CS]; seg.ss = u[U_SS];
        seg.ds = u[U_DS]; seg.es = u[U_ES];
        seg.fs = u[U_FS]; seg.gs = u[U_GS];
        seg.fs_base = u[U_FS_BASE];
        seg.gs_base = u[U_GS_BASE];
        Ok(u[U_RAX])
    }
}

/// arm64: the 288-byte `SvcFrame` written by the EL0-sync save block
/// (`crates/arch/hal-aarch64/src/vbar.rs`), read as 36 quadwords at
/// `kstack_top - 0x120`.
pub mod arm64 {

    pub const FRAME_N: usize = 36;
    /// `gp[0..18]` = x0..x17.
    pub const F_X0: usize = 0;
    /// `x18_x29` packs [x18, x29] (one `stp`).
    pub const F_X18: usize = 18;
    pub const F_X29: usize = 19;
    pub const F_X30: usize = 20;
    pub const F_ELR: usize = 22;
    pub const F_SPSR: usize = 23;
    pub const F_SP_EL0: usize = 24;
    pub const F_RETVAL: usize = 25;
    /// `x19_x28[0..10]` = x19..x28.
    pub const F_X19: usize = 26;

    /// `struct user_pt_regs`: `regs[31]`, `sp`, `pc`, `pstate`.
    pub const N: usize = crate::s101_ptrace_uapi::ARM64_USER_PT_REGS_N;
    pub const U_SP: usize = 31;
    pub const U_PC: usize = 32;
    pub const U_PSTATE: usize = 33;

    /// `SPSR_EL1` fields consulted by Linux `valid_native_regs`.
    pub const PSR_MODE_MASK:  u64 = 0x0000_000f;
    pub const PSR_MODE_EL0T:  u64 = 0x0000_0000;
    pub const PSR_MODE32_BIT: u64 = 0x0000_0010;
    pub const PSR_F_BIT:      u64 = 0x0000_0040;
    pub const PSR_I_BIT:      u64 = 0x0000_0080;
    pub const PSR_A_BIT:      u64 = 0x0000_0100;
    pub const PSR_D_BIT:      u64 = 0x0000_0200;
    /// N|Z|C|V — the only bits kept when a tracer supplies an invalid PSTATE.
    pub const PSR_NZCV: u64 = 0xf000_0000;

    /// Linux `valid_native_regs`: a tracer-supplied PSTATE is accepted whole
    /// only when it still describes unmasked EL0t AArch64 execution; anything
    /// else collapses to the condition flags, so a tracer can never promote
    /// the tracee's exception level or mask its interrupts.
    /// # C: O(1)
    pub fn sanitize_pstate(new: u64) -> u64 {
        let ok = (new & PSR_MODE_MASK) == PSR_MODE_EL0T
            && (new & PSR_MODE32_BIT) == 0
            && (new & PSR_D_BIT) == 0
            && (new & PSR_A_BIT) == 0
            && (new & PSR_I_BIT) == 0
            && (new & PSR_F_BIT) == 0;
        if ok { new } else { new & PSR_NZCV }
    }

    /// Materialise `struct user_pt_regs`. `x0` is supplied separately for the
    /// same reason as x86's `rax`: at a syscall-exit stop the ABI value is the
    /// return value, which the frame keeps in its own `retval` slot.
    /// # C: O(1)
    pub fn to_user_pt_regs(f: &[u64; FRAME_N], x0: u64) -> [u64; N] {
        let mut u = [0u64; N];
        for i in 0..18 { u[i] = f[F_X0 + i]; }
        u[0] = x0;
        u[18] = f[F_X18];
        for i in 0..10 { u[19 + i] = f[F_X19 + i]; }
        u[29] = f[F_X29];
        u[30] = f[F_X30];
        u[U_SP] = f[F_SP_EL0];
        u[U_PC] = f[F_ELR];
        u[U_PSTATE] = f[F_SPSR];
        u
    }

    /// Apply a tracer-supplied `struct user_pt_regs`. PSTATE is masked to the
    /// user-settable bits so a tracer cannot promote the tracee's exception
    /// level (Linux `valid_user_regs`).
    /// # C: O(1)
    pub fn from_user_pt_regs(u: &[u64; N], f: &mut [u64; FRAME_N]) {
        for i in 0..18 { f[F_X0 + i] = u[i]; }
        f[F_X18] = u[18];
        for i in 0..10 { f[F_X19 + i] = u[19 + i]; }
        f[F_X29] = u[29];
        f[F_X30] = u[30];
        f[F_SP_EL0] = u[U_SP];
        f[F_ELR] = u[U_PC];
        f[F_SPSR] = sanitize_pstate(u[U_PSTATE]);
        f[F_RETVAL] = u[0];
    }
}

#[cfg(test)]
#[path = "regs/tests.rs"] mod tests;
