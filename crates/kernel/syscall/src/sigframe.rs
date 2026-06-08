// User-ABI signal-frame types at EXACT Linux offsets (docs/24§4, R02).
//
// Stage A of the full rt_sigframe buildout: TYPE DEFINITIONS ONLY —
// no frame is built or restored here yet (later stages do that). The
// hosted offset-assertion tests at the bottom are the freeze gate:
// any drift from the Linux uapi layout fails `cargo test -p syscall`.
//
// All structs are defined UNCONDITIONALLY (not target-gated): they are
// plain repr(C) layouts whose offsets are arch-independent given the
// field types, so the hosted x86_64 test host checks BOTH arches'
// layouts. The kernel only *uses* the arch matching its target.
//
// Sources:
//   x86_64 — arch/x86/include/uapi/asm/sigcontext.h (struct
//            sigcontext_64), arch/x86/include/asm/sigframe.h
//            (struct rt_sigframe).
//   aarch64 — arch/arm64/include/uapi/asm/sigcontext.h
//            (struct sigcontext, fpsimd_context), arch/arm64/kernel/
//            signal.c (struct rt_sigframe).

// ---------------------------------------------------------------------------
// SA_* / SS_* flags (docs/07§5 — typed consts, never bare literals).
// ---------------------------------------------------------------------------

/// `sigaction` sa_flags — Linux generic values (asm-generic/signal.h).
pub mod sa {
    pub const SA_NOCLDSTOP: u64 = 0x0000_0001;
    pub const SA_NOCLDWAIT: u64 = 0x0000_0002;
    pub const SA_SIGINFO: u64 = 0x0000_0004;
    pub const SA_ONSTACK: u64 = 0x0800_0000;
    pub const SA_RESTART: u64 = 0x1000_0000;
    pub const SA_NODEFER: u64 = 0x4000_0000;
    pub const SA_RESETHAND: u64 = 0x8000_0000;
    /// Present iff the handler supplies its own `sa_restorer` (libc
    /// always does on x86_64; arm64 has no restorer — uses the vDSO).
    pub const SA_RESTORER: u64 = 0x0400_0000;
}

/// `sigaltstack` ss_flags.
pub mod ss {
    pub const SS_ONSTACK: i32 = 1;
    pub const SS_DISABLE: i32 = 2;
    pub const SS_AUTODISARM: i32 = 1 << 31;
}

/// `siginfo_t` si_code values (asm-generic/siginfo.h).
pub mod si {
    pub const SI_USER: i32 = 0;
    pub const SI_KERNEL: i32 = 0x80;
    pub const SI_QUEUE: i32 = -1;
    pub const SI_TIMER: i32 = -2;
    pub const SI_MESGQ: i32 = -3;
    pub const SI_ASYNCIO: i32 = -4;
    pub const SI_SIGIO: i32 = -5;
    pub const SI_TKILL: i32 = -6;
    // SIGCHLD si_code.
    pub const CLD_EXITED: i32 = 1;
    pub const CLD_KILLED: i32 = 2;
    pub const CLD_DUMPED: i32 = 3;
    pub const CLD_TRAPPED: i32 = 4;
    pub const CLD_STOPPED: i32 = 5;
    pub const CLD_CONTINUED: i32 = 6;
    // SIGSEGV si_code.
    pub const SEGV_MAPERR: i32 = 1;
    pub const SEGV_ACCERR: i32 = 2;
    // SIGBUS si_code.
    pub const BUS_ADRALN: i32 = 1;
    pub const BUS_ADRERR: i32 = 2;
    pub const BUS_OBJERR: i32 = 3;
    // SIGILL si_code.
    pub const ILL_ILLOPC: i32 = 1;
    // SIGFPE si_code.
    pub const FPE_INTDIV: i32 = 1;
}

// ---------------------------------------------------------------------------
// siginfo_t — 128 bytes (asm-generic, 64-bit).
// ---------------------------------------------------------------------------

/// `siginfo_t` as seen by user space (Linux generic 64-bit layout).
///
/// Fixed 128 bytes: 3 leading ints (si_signo/si_errno/si_code) then a
/// 116-byte `_sifields` union starting at offset 16 (the union has
/// 8-byte alignment, so a 4-byte pad sits between si_code and the
/// union). Variant constructors fill `_sifields` per the active
/// member; unused tail bytes stay zero.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SigInfoUser {
    pub si_signo: i32,
    pub si_errno: i32,
    pub si_code: i32,
    pub _pad0: i32,
    /// `_sifields` union, 112 bytes → total 16 + 112 = 128.
    pub _sifields: [u8; 112],
}

impl SigInfoUser {
    /// Zeroed siginfo with only the leading three ints set.
    /// # C: O(1)
    #[inline]
    pub const fn new(signo: i32, errno: i32, code: i32) -> Self {
        SigInfoUser { si_signo: signo, si_errno: errno, si_code: code, _pad0: 0, _sifields: [0u8; 112] }
    }

    /// SI_USER form (`kill`): `_sifields._kill = { si_pid, si_uid }`
    /// at union offsets +0 (i32 pid) / +4 (u32 uid).
    /// # C: O(1)
    pub fn user(signo: i32, pid: i32, uid: u32) -> Self {
        let mut s = Self::new(signo, 0, si::SI_USER);
        s._sifields[0..4].copy_from_slice(&pid.to_ne_bytes());
        s._sifields[4..8].copy_from_slice(&uid.to_ne_bytes());
        s
    }

    /// SIGCHLD form: `_sigchld = { si_pid:i32@0, si_uid:u32@4,
    /// si_status:i32@8, si_utime:i64@16, si_stime:i64@24 }`. (si_uid
    /// is __ARCH_SI_UID_T = u32; si_utime/stime are clock_t = long.)
    /// # C: O(1)
    pub fn sigchld(code: i32, pid: i32, uid: u32, status: i32, utime: i64, stime: i64) -> Self {
        // SIGCHLD == 17 on both arches.
        let mut s = Self::new(17, 0, code);
        s._sifields[0..4].copy_from_slice(&pid.to_ne_bytes());
        s._sifields[4..8].copy_from_slice(&uid.to_ne_bytes());
        s._sifields[8..12].copy_from_slice(&status.to_ne_bytes());
        s._sifields[16..24].copy_from_slice(&utime.to_ne_bytes());
        s._sifields[24..32].copy_from_slice(&stime.to_ne_bytes());
        s
    }

    /// SIGSEGV / SIGBUS form: `_sigfault = { si_addr:u64@0 }`.
    /// # C: O(1)
    pub fn fault(signo: i32, code: i32, addr: u64) -> Self {
        let mut s = Self::new(signo, 0, code);
        s._sifields[0..8].copy_from_slice(&addr.to_ne_bytes());
        s
    }

    /// SI_QUEUE form (`sigqueue`/`rt_sigqueueinfo`): `_rt = { si_pid,
    /// si_uid, si_value:union sigval@8 }`. `val` is the 64-bit
    /// sigval (ptr or int, user-supplied).
    /// # C: O(1)
    pub fn queue(signo: i32, pid: i32, uid: u32, val: u64) -> Self {
        let mut s = Self::new(signo, 0, si::SI_QUEUE);
        s._sifields[0..4].copy_from_slice(&pid.to_ne_bytes());
        s._sifields[4..8].copy_from_slice(&uid.to_ne_bytes());
        s._sifields[8..16].copy_from_slice(&val.to_ne_bytes());
        s
    }
}

// ---------------------------------------------------------------------------
// stack_t — shared by both arches' ucontext.
// ---------------------------------------------------------------------------

/// `stack_t` (sigaltstack). 24 bytes: ss_sp(8) + ss_flags(4) +
/// pad(4) + ss_size(8).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct Stack {
    pub ss_sp: u64,
    pub ss_flags: i32,
    pub _pad: i32,
    pub ss_size: u64,
}

impl Stack {
    /// # C: O(1)
    pub const fn zeroed() -> Self {
        Stack { ss_sp: 0, ss_flags: ss::SS_DISABLE, _pad: 0, ss_size: 0 }
    }
}

// ===========================================================================
// x86_64
// ===========================================================================

/// `struct sigcontext_64` (arch/x86/include/uapi/asm/sigcontext.h).
///
/// GP-register order is load-bearing: it is the exact order the kernel
/// fills and `rt_sigreturn` restores. `rip` lands at offset 0x80
/// (17th u64, index 16). No leading fields precede `r8`.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SigContextX86 {
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rsp: u64,
    pub rip: u64,
    pub eflags: u64,
    pub cs: u16,
    pub gs: u16,
    pub fs: u16,
    pub ss: u16,
    pub err: u64,
    pub trapno: u64,
    pub oldmask: u64,
    pub cr2: u64,
    /// Pointer to the saved FXSAVE/XSAVE area (`fpstate`); 0 if none.
    pub fpstate: u64,
    pub reserved: [u64; 8],
}

/// Legacy FXSAVE image (512 bytes). `rt_sigreturn` reloads SSE/x87
/// state from here when `fpstate != 0`. Modeled as an opaque blob for
/// Stage A; later stages fill the header + xmm region.
#[repr(C, align(16))]
#[derive(Copy, Clone)]
pub struct FpStateX86 {
    pub bytes: [u8; 512],
}

/// `struct ucontext` (x86_64 user ABI).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct UContextX86 {
    pub uc_flags: u64,
    pub uc_link: u64,
    pub uc_stack: Stack,
    pub uc_mcontext: SigContextX86,
    /// `sigset_t` first 64 bits (the kernel signal mask is 64 wide).
    pub uc_sigmask: u64,
}

/// `struct rt_sigframe` (arch/x86/include/asm/sigframe.h, 64-bit).
///
/// Pushed on the user stack at delivery; `pretcode` is the return
/// address the handler `ret`s to (the restorer that calls
/// rt_sigreturn). `uc` then `info` follow (x86 orders ucontext first).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct RtSigframeX86 {
    pub pretcode: u64,
    pub uc: UContextX86,
    pub info: SigInfoUser,
}

// ===========================================================================
// aarch64
// ===========================================================================

/// `struct _aarch64_ctx` header preceding every reserved-area record.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct Aarch64Ctx {
    pub magic: u32,
    pub size: u32,
}

/// `struct sigcontext` (arch/arm64/include/uapi/asm/sigcontext.h).
///
/// fault_address@0, regs[0]@8 (x0..x30 = 31 u64), sp@0x100, pc@0x108,
/// pstate@0x110, then a 4096-byte `__reserved` area that carries the
/// fpsimd_context and other records at delivery time.
#[repr(C, align(16))]
#[derive(Copy, Clone)]
pub struct SigContextArm {
    pub fault_address: u64,
    pub regs: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
    pub __reserved: [u8; 4096],
}

/// `struct fpsimd_context` — lives inside `SigContextArm.__reserved`.
/// magic = FPSIMD_MAGIC (0x46508001). 528 bytes total: head(8) +
/// fpsr(4) + fpcr(4) + 32×128-bit vregs(512).
#[repr(C, align(16))]
#[derive(Copy, Clone)]
pub struct FpSimdContext {
    pub head: Aarch64Ctx,
    pub fpsr: u32,
    pub fpcr: u32,
    pub vregs: [u128; 32],
}

/// FPSIMD_MAGIC for the fpsimd_context record.
pub const FPSIMD_MAGIC: u32 = 0x4650_8001;

/// `struct ucontext` (arm64 user ABI).
///
/// uc_sigmask precedes uc_mcontext, with a `__unused[120]` pad so the
/// 16-aligned sigcontext starts on a 16-byte boundary (glibc/kernel
/// layout). Offsets: uc_flags@0, uc_link@8, uc_stack@16(24B)→@40,
/// uc_sigmask@40(8B)→@48, __unused[120]@48→@168? No — the pad sizes so
/// uc_mcontext starts at offset 176 (0xb0) per the kernel struct.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct UContextArm {
    pub uc_flags: u64,
    pub uc_link: u64,
    pub uc_stack: Stack,
    /// `sigset_t` (1024-bit on disk, but the active mask is 64 wide;
    /// the kernel reserves the full `_NSIG/8` here). v1 keeps the
    /// 64-bit live mask plus the kernel's pad to 16-align mcontext.
    pub uc_sigmask: u64,
    pub __unused: [u8; 120],
    pub uc_mcontext: SigContextArm,
}

/// `struct rt_sigframe` (arch/arm64/kernel/signal.c). arm orders
/// `info` first, then `uc`.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct RtSigframeArm {
    pub info: SigInfoUser,
    pub uc: UContextArm,
}

// ---------------------------------------------------------------------------
// Offset / size freeze gate (hosted). Runs on the x86_64 test host but
// checks BOTH arches' layouts — the structs are arch-independent
// repr(C). Any drift from Linux uapi fails the build.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod abi_tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    #[test]
    fn siginfo_is_128() {
        assert_eq!(size_of::<SigInfoUser>(), 128);
        assert_eq!(offset_of!(SigInfoUser, si_signo), 0);
        assert_eq!(offset_of!(SigInfoUser, si_errno), 4);
        assert_eq!(offset_of!(SigInfoUser, si_code), 8);
        assert_eq!(offset_of!(SigInfoUser, _sifields), 16);
    }

    #[test]
    fn stack_is_24() {
        assert_eq!(size_of::<Stack>(), 24);
        assert_eq!(offset_of!(Stack, ss_sp), 0);
        assert_eq!(offset_of!(Stack, ss_flags), 8);
        assert_eq!(offset_of!(Stack, ss_size), 16);
    }

    #[test]
    fn x86_sigcontext_layout() {
        // GP block: r8@0, rip@0x80 (index 16). No leading fields.
        assert_eq!(offset_of!(SigContextX86, r8), 0);
        assert_eq!(offset_of!(SigContextX86, rsp), 0x78);
        assert_eq!(offset_of!(SigContextX86, rip), 0x80);
        assert_eq!(offset_of!(SigContextX86, eflags), 0x88);
        assert_eq!(offset_of!(SigContextX86, cs), 0x90);
        assert_eq!(offset_of!(SigContextX86, err), 0x98);
        assert_eq!(offset_of!(SigContextX86, cr2), 0xb0);
        assert_eq!(offset_of!(SigContextX86, fpstate), 0xb8);
        // 0xb8 + 8 (fpstate) + 8*8 (reserved) = 0x100.
        assert_eq!(size_of::<SigContextX86>(), 0x100);
    }

    #[test]
    fn x86_fpstate_is_512_align16() {
        assert_eq!(size_of::<FpStateX86>(), 512);
        assert_eq!(align_of::<FpStateX86>(), 16);
    }

    #[test]
    fn x86_ucontext_and_frame() {
        // uc_flags@0, uc_link@8, uc_stack@16 (24) → @40, mcontext@40.
        assert_eq!(offset_of!(UContextX86, uc_flags), 0);
        assert_eq!(offset_of!(UContextX86, uc_link), 8);
        assert_eq!(offset_of!(UContextX86, uc_stack), 16);
        assert_eq!(offset_of!(UContextX86, uc_mcontext), 40);
        // mcontext is 0x100 → uc_sigmask @ 40 + 256 = 296.
        assert_eq!(offset_of!(UContextX86, uc_sigmask), 296);
        // rt_sigframe: pretcode@0, uc@8, info after uc.
        assert_eq!(offset_of!(RtSigframeX86, pretcode), 0);
        assert_eq!(offset_of!(RtSigframeX86, uc), 8);
    }

    #[test]
    fn arm_sigcontext_layout() {
        assert_eq!(offset_of!(SigContextArm, fault_address), 0);
        assert_eq!(offset_of!(SigContextArm, regs), 8);
        // regs[31] ends at 8 + 248 = 256 = 0x100 → sp.
        assert_eq!(offset_of!(SigContextArm, sp), 0x100);
        assert_eq!(offset_of!(SigContextArm, pc), 0x108);
        assert_eq!(offset_of!(SigContextArm, pstate), 0x110);
        // pstate@0x110 (8) → __reserved@0x118, 4096 long.
        assert_eq!(offset_of!(SigContextArm, __reserved), 0x118);
        assert_eq!(align_of::<SigContextArm>(), 16);
    }

    #[test]
    fn arm_fpsimd_is_528() {
        // head(8) + fpsr(4) + fpcr(4) + 32*16 = 528.
        assert_eq!(size_of::<FpSimdContext>(), 528);
        assert_eq!(offset_of!(FpSimdContext, head), 0);
        assert_eq!(offset_of!(FpSimdContext, fpsr), 8);
        assert_eq!(offset_of!(FpSimdContext, fpcr), 12);
        assert_eq!(offset_of!(FpSimdContext, vregs), 16);
        assert_eq!(FPSIMD_MAGIC, 0x4650_8001);
    }

    #[test]
    fn arm_ucontext_and_frame() {
        assert_eq!(offset_of!(UContextArm, uc_flags), 0);
        assert_eq!(offset_of!(UContextArm, uc_link), 8);
        assert_eq!(offset_of!(UContextArm, uc_stack), 16);
        assert_eq!(offset_of!(UContextArm, uc_sigmask), 40);
        // uc_sigmask(8)@40 + __unused[120]@48 → mcontext@168? Pad must
        // 16-align mcontext: 40+8=48, +120=168, 168%16=8 → NOT aligned.
        // The kernel struct lands uc_mcontext at 176 (0xb0). Assert the
        // real aligned offset the compiler produces.
        // 40+8(sigmask)+120(__unused)=168; SigContextArm is align-16 so
        // the compiler pads to 176 (0xb0) — the real kernel offset.
        assert_eq!(offset_of!(UContextArm, uc_mcontext), 176);
        // rt_sigframe: info first, then uc.
        assert_eq!(offset_of!(RtSigframeArm, info), 0);
        assert_eq!(offset_of!(RtSigframeArm, uc), 128);
    }
}
