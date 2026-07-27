// ptrace(2) argument validation — the scalar checks Linux performs in
// `kernel/ptrace.c` (`check_ptrace_options`, `valid_signal`, the SEIZE arm of
// `ptrace_attach`, `ptrace_regset`) and `arch/x86/kernel/ptrace.c`
// (`arch_ptrace` PEEKUSR/POKEUSR bounds).
//
// Hosted-testable: scalars in, `Errno` out. The shim never open-codes any of
// these, so an errno divergence is a unit-test failure rather than a boot
// mystery.

use syscall::errno::Errno;
use crate::s101_ptrace_uapi as uapi;

/// Linux `valid_signal(sig)` — `sig <= _NSIG`; `0` means "no signal".
/// Used by CONT/SYSCALL/SINGLESTEP/DETACH, which return **EIO** (not EINVAL)
/// on a bad signal number.
/// # C: O(1)
pub fn valid_signal(data: u64) -> bool { data <= uapi::NSIG }

/// Linux `check_ptrace_options`. Unknown option bits are EINVAL.
/// `PTRACE_O_SUSPEND_SECCOMP` additionally needs CAP_SYS_ADMIN and a caller
/// that is not itself seccomp-confined, else EPERM.
/// # C: O(1)
pub fn check_options(data: u64, cap_sys_admin: bool, caller_seccomp: bool)
    -> Result<u32, Errno>
{
    if data & !(uapi::O_MASK as u64) != 0 { return Err(Errno::Einval); }
    let opts = data as u32;
    if opts & uapi::O_SUSPEND_SECCOMP != 0 {
        if !cap_sys_admin { return Err(Errno::Eperm); }
        if caller_seccomp { return Err(Errno::Eperm); }
    }
    Ok(opts)
}

/// Linux `ptrace_attach` SEIZE arm: `addr` must be zero and the option word
/// must be clean — both diagnosed as **EIO** here, deliberately differing
/// from `PTRACE_SETOPTIONS`' EINVAL for the same bad bits (Linux keeps the
/// historical split; a tracer library distinguishes them).
/// # C: O(1)
pub fn check_seize(addr: u64, flags: u64, cap_sys_admin: bool, caller_seccomp: bool)
    -> Result<u32, Errno>
{
    if addr != 0 { return Err(Errno::Eio); }
    if flags & !(uapi::O_MASK as u64) != 0 { return Err(Errno::Eio); }
    check_options(flags, cap_sys_admin, caller_seccomp)
}

/// What `PTRACE_PEEKUSER`/`POKEUSER` at byte offset `addr` addresses inside
/// x86_64's `struct user`.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum UserArea {
    /// Quadword index into `struct user_regs_struct`.
    Reg(usize),
    /// Index into `u_debugreg[0..8]`.
    DebugReg(usize),
    /// Inside `struct user` but not a register — Linux PEEKs 0 and POKEs
    /// are dropped (the `tmp = 0` default arm), without an error.
    Padding,
}

/// Linux `arch_ptrace` PEEKUSR/POKEUSR bounds check (x86_64). Misaligned or
/// past `sizeof(struct user)` is EIO — importantly *not* a silent zero.
/// # C: O(1)
pub fn user_area(addr: u64) -> Result<UserArea, Errno> {
    if addr & 7 != 0 { return Err(Errno::Eio); }
    if addr >= uapi::X86_SIZEOF_USER { return Err(Errno::Eio); }
    if (addr as usize) < crate::s101_ptrace_regs::x86::N * 8 {
        return Ok(UserArea::Reg(addr as usize / 8));
    }
    let dr0 = uapi::X86_USER_DEBUGREG_OFF;
    if addr >= dr0 && addr <= dr0 + 7 * 8 {
        return Ok(UserArea::DebugReg(((addr - dr0) / 8) as usize));
    }
    Ok(UserArea::Padding)
}

/// Bytes a regset note type occupies for this arch. Linux `ptrace_regset`
/// returns EINVAL for an unknown note type, and clamps `iov_len` down to the
/// regset's own size.
/// # C: O(1)
pub fn regset_bytes(nt_type: u64, arch: Arch) -> Result<usize, Errno> {
    match (nt_type, arch) {
        (uapi::NT_PRSTATUS, Arch::X86_64) => Ok(uapi::X86_USER_REGS_N * 8),
        (uapi::NT_PRFPREG,  Arch::X86_64) => Ok(uapi::X86_USER_I387_BYTES),
        (uapi::NT_PRSTATUS, Arch::Aarch64) => Ok(uapi::ARM64_USER_PT_REGS_N * 8),
        (uapi::NT_PRFPREG,  Arch::Aarch64) => Ok(uapi::ARM64_USER_FPSIMD_BYTES),
        _ => Err(Errno::Einval),
    }
}

/// Which register-set view a target task presents.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Arch { X86_64, Aarch64 }

/// Linux `ptrace_regset`: `iov_len` must be a whole multiple of the regset's
/// element size, then it is clamped to the regset's total size. Our regsets
/// are single-element, so the multiple test degenerates to "non-zero and
/// aligned to the element" — an `iov_len` of 0 yields a 0-byte transfer,
/// which Linux also allows.
/// # C: O(1)
pub fn regset_len(nt_type: u64, arch: Arch, iov_len: usize) -> Result<usize, Errno> {
    let total = regset_bytes(nt_type, arch)?;
    Ok(if iov_len > total { total } else { iov_len })
}

/// Requests that operate on another task while it is NOT required to be
/// ptrace-stopped. Linux: `ptrace_check_attach(child, request == PTRACE_KILL
/// || request == PTRACE_INTERRUPT)`.
/// # C: O(1)
pub fn ignores_stop_state(request: u64) -> bool {
    request == uapi::KILL || request == uapi::INTERRUPT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_signal_accepts_zero_through_nsig() {
        assert!(valid_signal(0));
        assert!(valid_signal(1));
        assert!(valid_signal(64));
        assert!(!valid_signal(65));
        assert!(!valid_signal(u64::MAX));
    }

    #[test]
    fn unknown_option_bits_are_einval() {
        assert_eq!(check_options(1 << 22, false, false), Err(Errno::Einval));
        assert_eq!(check_options(0xffff_ffff_ffff_ffff, true, false), Err(Errno::Einval));
    }

    #[test]
    fn known_options_pass() {
        let all = uapi::O_TRACESYSGOOD | uapi::O_TRACEFORK | uapi::O_TRACEVFORK
            | uapi::O_TRACECLONE | uapi::O_TRACEEXEC | uapi::O_TRACEVFORKDONE
            | uapi::O_TRACEEXIT | uapi::O_TRACESECCOMP | uapi::O_EXITKILL;
        assert_eq!(check_options(all as u64, false, false), Ok(all));
    }

    #[test]
    fn suspend_seccomp_needs_cap_sys_admin() {
        let o = uapi::O_SUSPEND_SECCOMP as u64;
        assert_eq!(check_options(o, false, false), Err(Errno::Eperm));
        assert_eq!(check_options(o, true, true), Err(Errno::Eperm));
        assert_eq!(check_options(o, true, false), Ok(uapi::O_SUSPEND_SECCOMP));
    }

    #[test]
    fn seize_rejects_nonzero_addr_with_eio() {
        assert_eq!(check_seize(1, 0, false, false), Err(Errno::Eio));
    }

    #[test]
    fn seize_rejects_bad_options_with_eio_not_einval() {
        assert_eq!(check_seize(0, 1 << 22, false, false), Err(Errno::Eio));
        // Same bits through SETOPTIONS are EINVAL — the historical split.
        assert_eq!(check_options(1 << 22, false, false), Err(Errno::Einval));
    }

    #[test]
    fn user_area_rejects_misaligned_and_out_of_range() {
        assert_eq!(user_area(1), Err(Errno::Eio));
        assert_eq!(user_area(7), Err(Errno::Eio));
        assert_eq!(user_area(uapi::X86_SIZEOF_USER), Err(Errno::Eio));
        assert_eq!(user_area(u64::MAX & !7), Err(Errno::Eio));
    }

    #[test]
    fn user_area_maps_registers_and_debug_registers() {
        assert_eq!(user_area(0), Ok(UserArea::Reg(0)));
        assert_eq!(user_area(26 * 8), Ok(UserArea::Reg(26)));
        assert_eq!(user_area(27 * 8), Ok(UserArea::Padding));
        assert_eq!(user_area(uapi::X86_USER_DEBUGREG_OFF), Ok(UserArea::DebugReg(0)));
        assert_eq!(user_area(uapi::X86_USER_DEBUGREG_OFF + 7 * 8), Ok(UserArea::DebugReg(7)));
        assert_eq!(user_area(uapi::X86_USER_DEBUGREG_OFF + 8 * 8), Ok(UserArea::Padding));
    }

    #[test]
    fn regset_sizes_match_the_abi_structs() {
        assert_eq!(regset_bytes(uapi::NT_PRSTATUS, Arch::X86_64), Ok(216));
        assert_eq!(regset_bytes(uapi::NT_PRFPREG,  Arch::X86_64), Ok(512));
        assert_eq!(regset_bytes(uapi::NT_PRSTATUS, Arch::Aarch64), Ok(272));
        assert_eq!(regset_bytes(uapi::NT_PRFPREG,  Arch::Aarch64), Ok(528));
    }

    #[test]
    fn unknown_regset_note_is_einval() {
        assert_eq!(regset_bytes(uapi::NT_X86_XSTATE, Arch::X86_64), Err(Errno::Einval));
        assert_eq!(regset_bytes(0, Arch::Aarch64), Err(Errno::Einval));
    }

    #[test]
    fn regset_len_clamps_to_the_regset_size() {
        assert_eq!(regset_len(uapi::NT_PRSTATUS, Arch::X86_64, 4096), Ok(216));
        assert_eq!(regset_len(uapi::NT_PRSTATUS, Arch::X86_64, 8), Ok(8));
        assert_eq!(regset_len(uapi::NT_PRSTATUS, Arch::Aarch64, 4096), Ok(272));
    }

    #[test]
    fn only_kill_and_interrupt_skip_the_stop_requirement() {
        assert!(ignores_stop_state(uapi::KILL));
        assert!(ignores_stop_state(uapi::INTERRUPT));
        for r in [uapi::CONT, uapi::DETACH, uapi::GETREGS, uapi::PEEKDATA, uapi::LISTEN] {
            assert!(!ignores_stop_state(r));
        }
    }
}
