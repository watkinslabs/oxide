// `siginfo_t` construction shared by both arches' `build_signal_frame` and by
// every syscall that copies a signal record out to userspace. Split from
// `lib.rs` per `08§7`.
//
// The union arms OVERLAP (`_kill`, `_sigchld`, `_rt`, `_sigsys` all start at
// `_sifields`, byte 16), so the arm must be selected before any field is
// written — one writer here so the two arches cannot drift.

/// Extra siginfo_t payload an SA_SIGINFO handler reads, passed
/// arch-neutrally from the signal-delivery path into the per-arch
/// `build_signal_frame` so it can populate the `_sifields` union
/// (`27§5`, siginfo(7)). POD so it crosses the HAL boundary without a
/// crate cycle (sched/fs/hal all share this one type).
///
/// `code`→si_code, `pid`→si_pid, `uid`→si_uid are common to both union
/// arms. The +24 slot is the arm discriminator:
///   `chld_arm` — `_sigchld`: `status`→si_status (`int`, 4 bytes).
///   otherwise  — `_rt`: `value`→si_value (`sigval_t`, a full 8 bytes).
/// Truncating an `_rt` si_value to 4 bytes loses `sival_ptr`, which
/// `sigqueue(3)`/`timer_create(2)` callers dereference.
///
/// `sigsys` selects a THIRD arm and, when present, overrides both of the
/// above: see `Sigsys`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct SigPayload {
    pub code:   i32,
    pub pid:    i32,
    pub uid:    u32,
    pub status: i32,
    pub value:  u64,
    pub chld_arm: bool,
    /// `_sigsys` arm — `Some` only for a seccomp-raised `SIGSYS`.
    pub sigsys: Option<Sigsys>,
    /// `_sigfault` arm — `Some` for every synchronous fault signal
    /// (SIGSEGV/SIGBUS/SIGILL/SIGFPE/SIGTRAP). Overrides `_kill`/`_rt` the same
    /// way `sigsys` does: the arms overlap at `_sifields`.
    pub fault: Option<SigFault>,
    /// `_sigpoll` arm — `Some` for an async-I/O readiness signal raised by
    /// `fcntl(F_SETOWN)`/`O_ASYNC` (and by `F_SETSIG`'s chosen signal).
    /// Overlaps `_kill`/`_rt`/`_sigfault` at `_sifields`.
    pub poll: Option<SigPoll>,
}

/// `siginfo_t::_sifields._sigpoll` — the arm `SIGPOLL`/`SIGIO` (and any
/// `F_SETSIG` replacement) selects (`include/uapi/asm-generic/siginfo.h`).
///
/// `si_band` is an `__ARCH_SI_BAND_T` = `long` on both x86_64 and aarch64, so
/// it covers the two 4-byte words `si_pid`/`si_uid` occupy, and `si_fd` follows
/// in `si_value`'s first 4 bytes. Without this arm an `SA_SIGINFO` SIGIO
/// handler reads `si_fd == 0` and cannot tell WHICH descriptor became ready —
/// the whole reason `F_SETSIG` exists.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct SigPoll {
    /// `si_band` — the poll mask that fired, per Linux's `band_table`.
    pub band: i64,
    /// `si_fd` — the descriptor number recorded when `O_ASYNC` was enabled.
    pub fd: i32,
}

/// `siginfo_t::_sifields._sigfault` — the arm SIGSEGV, SIGBUS, SIGILL, SIGFPE
/// and SIGTRAP select (`include/uapi/asm-generic/siginfo.h`).
///
/// `addr` is the faulting instruction / memory reference. `addr_lsb` is the
/// `short` that follows it, meaningful for the SIGBUS machine-check codes; the
/// remaining inner-union members (`_addr_bnd`, `_addr_pkey`, `_perf`) start
/// past it and are written by their own producers.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct SigFault {
    /// `si_addr`.
    pub addr: u64,
    /// `si_addr_lsb` — log2 of the reported page size for the SIGBUS
    /// machine-check codes; 0 everywhere else.
    pub addr_lsb: i16,
}

/// `siginfo_t::_sifields._sigsys` (`include/uapi/asm-generic/siginfo.h`),
/// filled by `force_sig_seccomp` (`kernel/signal.c`) for both
/// `SECCOMP_RET_TRAP` and the `SECCOMP_RET_KILL_*` core dump. A `SIGSYS`
/// handler reads `si_syscall`/`si_arch` to decide which call was rejected,
/// and `si_errno` is the filter's own 16-bit data — all zero without this.
///
/// POD in `hal` so `security` (which computes it), `sched` (which queues it)
/// and the per-arch frame builders (which write it) share ONE definition.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Sigsys {
    /// `si_call_addr` — `KSTK_EIP(current)`, the user PC of the trapped call.
    pub call_addr: u64,
    /// `si_syscall` — the syscall number AS THE CALLING ABI NUMBERS IT.
    pub syscall: i32,
    /// `si_arch` — `syscall_get_arch()`, an `AUDIT_ARCH_*` token.
    pub arch: u32,
    /// `si_errno` — `SECCOMP_RET_DATA`, the filter's low 16 bits.
    pub errno: i32,
}

/// `si_code` values for the `_sigfault` signals (`asm-generic/siginfo.h`).
/// The ONE owner: every fault classifier and every test names a constant here
/// instead of open-coding `1`/`2` (`07§5`).
pub mod code {
    /// SIGSEGV — address not mapped to object.
    pub const SEGV_MAPERR: i32 = 1;
    /// SIGSEGV — invalid permissions for mapped object.
    pub const SEGV_ACCERR: i32 = 2;
    /// SIGSEGV — failed address bound checks.
    pub const SEGV_BNDERR: i32 = 3;
    /// SIGSEGV — failed protection-key check.
    pub const SEGV_PKUERR: i32 = 4;
    /// SIGSEGV — control-protection fault (shadow stack / indirect branch).
    pub const SEGV_CPERR: i32 = 10;
    /// SIGBUS — invalid address alignment.
    pub const BUS_ADRALN: i32 = 1;
    /// SIGBUS — non-existent physical address.
    pub const BUS_ADRERR: i32 = 2;
    /// SIGBUS — object-specific hardware error (SIGBUS past EOF on a file map).
    pub const BUS_OBJERR: i32 = 3;
    /// SIGILL — illegal opcode.
    pub const ILL_ILLOPC: i32 = 1;
    /// SIGILL — illegal operand.
    pub const ILL_ILLOPN: i32 = 2;
    /// SIGILL — illegal addressing mode.
    pub const ILL_ILLADR: i32 = 3;
    /// SIGILL — illegal trap.
    pub const ILL_ILLTRP: i32 = 4;
    /// SIGILL — privileged opcode.
    pub const ILL_PRVOPC: i32 = 5;
    /// SIGILL — privileged register.
    pub const ILL_PRVREG: i32 = 6;
    /// SIGILL — coprocessor error.
    pub const ILL_COPROC: i32 = 7;
    /// SIGILL — internal stack error.
    pub const ILL_BADSTK: i32 = 8;
    /// SIGFPE — integer divide by zero.
    pub const FPE_INTDIV: i32 = 1;
    /// SIGFPE — integer overflow.
    pub const FPE_INTOVF: i32 = 2;
    /// SIGFPE — floating-point divide by zero.
    pub const FPE_FLTDIV: i32 = 3;
    /// SIGFPE — floating-point overflow.
    pub const FPE_FLTOVF: i32 = 4;
    /// SIGFPE — floating-point underflow.
    pub const FPE_FLTUND: i32 = 5;
    /// SIGFPE — floating-point inexact result.
    pub const FPE_FLTRES: i32 = 6;
    /// SIGFPE — floating-point invalid operation.
    pub const FPE_FLTINV: i32 = 7;
    /// SIGFPE — subscript out of range.
    pub const FPE_FLTSUB: i32 = 8;
    /// SIGFPE — undiagnosed floating-point exception.
    pub const FPE_FLTUNK: i32 = 14;
    /// SIGTRAP — process breakpoint (`int3` / `brk`).
    pub const TRAP_BRKPT: i32 = 1;
    /// SIGTRAP — single-step / trace trap.
    pub const TRAP_TRACE: i32 = 2;
    /// SIGTRAP — hardware breakpoint / watchpoint.
    pub const TRAP_HWBKPT: i32 = 4;
    /// SIGTRAP — undiagnosed trap.
    pub const TRAP_UNK: i32 = 5;
}

/// siginfo_t field offsets (`asm-generic/siginfo.h`) — identical on x86_64 and
/// aarch64, so both frame builders share one writer.
const SI_SIGNO: usize = 0;
/// `int si_errno`, between si_signo and si_code. Only the `_sigsys` arm uses
/// it; every other path leaves it 0.
const SI_ERRNO: usize = 4;
const SI_CODE:  usize = 8;
const SI_PID:   usize = 16;
const SI_UID:   usize = 20;
/// `_sigchld.si_status` (`int`) and `_rt.si_value` (`sigval_t`) both start
/// here; only their WIDTH differs.
const SI_VALUE: usize = 24;
/// `_sigsys._call_addr` (`void __user *`) starts at `_sifields`, i.e. the same
/// byte as si_pid — the union arms overlap, which is why the arm must be
/// selected before anything is written.
const SI_CALL_ADDR: usize = 16;
const SI_SYSCALL:   usize = 24;
const SI_ARCH:      usize = 28;
/// `_sigfault._addr` — also at `_sifields`, overlapping si_pid/si_call_addr.
const SI_ADDR:      usize = 16;
/// `_sigfault._addr_lsb`, the `short` in the inner union right after `_addr`.
const SI_ADDR_LSB:  usize = 24;
/// `_sigpoll._band` (`long`) — also at `_sifields`, overlapping si_pid/si_uid.
const SI_BAND:      usize = 16;
/// `_sigpoll._fd` (`int`), immediately after the 8-byte `_band`.
const SI_FD:        usize = 24;

/// Fill a signal frame's 128-byte `siginfo_t` from an arch-neutral payload.
/// Shared by both `build_signal_frame`s so the two arches cannot drift on the
/// union arms an SA_SIGINFO handler reads.
/// # C: O(1)
pub fn write_siginfo(info: &mut [u8; 128], sig: u32, payload: Option<SigPayload>) {
    info[SI_SIGNO..SI_SIGNO + 4].copy_from_slice(&(sig as i32).to_ne_bytes());
    let Some(p) = payload else { return };
    info[SI_CODE..SI_CODE + 4].copy_from_slice(&p.code.to_ne_bytes());
    if let Some(s) = p.sigsys {
        info[SI_ERRNO..SI_ERRNO + 4].copy_from_slice(&s.errno.to_ne_bytes());
        info[SI_CALL_ADDR..SI_CALL_ADDR + 8].copy_from_slice(&s.call_addr.to_ne_bytes());
        info[SI_SYSCALL..SI_SYSCALL + 4].copy_from_slice(&s.syscall.to_ne_bytes());
        info[SI_ARCH..SI_ARCH + 4].copy_from_slice(&s.arch.to_ne_bytes());
        return;
    }
    if let Some(f) = p.fault {
        info[SI_ADDR..SI_ADDR + 8].copy_from_slice(&f.addr.to_ne_bytes());
        info[SI_ADDR_LSB..SI_ADDR_LSB + 2].copy_from_slice(&f.addr_lsb.to_ne_bytes());
        return;
    }
    if let Some(q) = p.poll {
        info[SI_BAND..SI_BAND + 8].copy_from_slice(&q.band.to_ne_bytes());
        info[SI_FD..SI_FD + 4].copy_from_slice(&q.fd.to_ne_bytes());
        return;
    }
    info[SI_PID..SI_PID + 4].copy_from_slice(&p.pid.to_ne_bytes());
    info[SI_UID..SI_UID + 4].copy_from_slice(&p.uid.to_ne_bytes());
    if p.chld_arm {
        info[SI_VALUE..SI_VALUE + 4].copy_from_slice(&p.status.to_ne_bytes());
    } else {
        info[SI_VALUE..SI_VALUE + 8].copy_from_slice(&p.value.to_ne_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_siginfo_fills_si_signo_even_without_a_payload() {
        let mut info = [0u8; 128];
        write_siginfo(&mut info, 11, None);
        assert_eq!(i32::from_ne_bytes(info[0..4].try_into().unwrap()), 11);
        assert!(info[4..].iter().all(|b| *b == 0), "no payload ⇒ nothing else is set");
    }

    #[test]
    fn write_siginfo_sigchld_arm_writes_a_four_byte_si_status() {
        let mut info = [0u8; 128];
        let p = SigPayload { code: 1, pid: 42, uid: 7, status: -9, value: u64::MAX, chld_arm: true,
                             sigsys: None, fault: None, poll: None };
        write_siginfo(&mut info, 17, Some(p));
        assert_eq!(i32::from_ne_bytes(info[8..12].try_into().unwrap()), 1);
        assert_eq!(i32::from_ne_bytes(info[16..20].try_into().unwrap()), 42);
        assert_eq!(u32::from_ne_bytes(info[20..24].try_into().unwrap()), 7);
        assert_eq!(i32::from_ne_bytes(info[24..28].try_into().unwrap()), -9);
        assert!(info[28..32].iter().all(|b| *b == 0), "si_status is an int; bytes 28..32 stay clear");
    }

    #[test]
    fn write_siginfo_rt_arm_writes_a_full_eight_byte_si_value() {
        let mut info = [0u8; 128];
        let ptr = 0x7fff_dead_beefu64;
        let p = SigPayload { code: -1, pid: 42, uid: 7, status: 0, value: ptr, chld_arm: false,
                             sigsys: None, fault: None, poll: None };
        write_siginfo(&mut info, 34, Some(p));
        assert_eq!(u64::from_ne_bytes(info[24..32].try_into().unwrap()), ptr,
                   "truncating si_value to 4 bytes loses a sigqueue(3) sival_ptr");
    }

    // `force_sig_seccomp` fills si_errno / si_call_addr / si_syscall /
    // si_arch. All four read back as 0 without the `_sigsys` arm, so a SIGSYS
    // handler could not tell which syscall the filter rejected.
    #[test]
    fn write_siginfo_sigsys_arm_writes_call_addr_syscall_arch_and_errno() {
        let mut info = [0u8; 128];
        let s = Sigsys { call_addr: 0x7fff_1234_5678, syscall: 257, arch: 0xc000_003e, errno: 0xbeef };
        let p = SigPayload { code: 1, pid: 42, uid: 7, status: -9, value: u64::MAX, chld_arm: true,
                             sigsys: Some(s), fault: None, poll: None };
        write_siginfo(&mut info, 31, Some(p));
        assert_eq!(i32::from_ne_bytes(info[0..4].try_into().unwrap()), 31);
        assert_eq!(i32::from_ne_bytes(info[4..8].try_into().unwrap()), 0xbeef);
        assert_eq!(i32::from_ne_bytes(info[8..12].try_into().unwrap()), 1, "si_code = SYS_SECCOMP");
        assert_eq!(u64::from_ne_bytes(info[16..24].try_into().unwrap()), 0x7fff_1234_5678);
        assert_eq!(i32::from_ne_bytes(info[24..28].try_into().unwrap()), 257);
        assert_eq!(u32::from_ne_bytes(info[28..32].try_into().unwrap()), 0xc000_003e);
    }

    // A synchronous fault signal's whole point is si_addr; without the
    // `_sigfault` arm a SIGSEGV handler reads si_addr == 0 and cannot tell
    // which address faulted.
    #[test]
    fn write_siginfo_sigfault_arm_writes_si_addr_and_si_addr_lsb() {
        let mut info = [0u8; 128];
        let f = SigFault { addr: 0x7fff_dead_b000, addr_lsb: 12 };
        let p = SigPayload { code: code::SEGV_MAPERR, pid: 0, uid: 0, status: 0, value: 0,
                             chld_arm: false, sigsys: None, fault: Some(f), poll: None };
        write_siginfo(&mut info, 11, Some(p));
        assert_eq!(i32::from_ne_bytes(info[0..4].try_into().unwrap()), 11);
        assert_eq!(i32::from_ne_bytes(info[8..12].try_into().unwrap()), code::SEGV_MAPERR);
        assert_eq!(u64::from_ne_bytes(info[16..24].try_into().unwrap()), 0x7fff_dead_b000);
        assert_eq!(i16::from_ne_bytes(info[24..26].try_into().unwrap()), 12);
    }

    // `_sigfault` overlaps `_kill`/`_rt` at byte 16, so si_pid/si_uid/si_value
    // must not be written over si_addr.
    #[test]
    fn the_sigfault_arm_excludes_the_pid_uid_and_value_fields() {
        let mut info = [0u8; 128];
        let f = SigFault { addr: u64::MAX, addr_lsb: 0 };
        let p = SigPayload { code: code::SEGV_ACCERR, pid: 0x4242, uid: 0x77, status: -9,
                             value: u64::MAX, chld_arm: false, sigsys: None, fault: Some(f), poll: None };
        write_siginfo(&mut info, 11, Some(p));
        assert_eq!(u64::from_ne_bytes(info[16..24].try_into().unwrap()), u64::MAX);
        assert!(info[26..].iter().all(|b| *b == 0), "nothing past si_addr_lsb is written");
    }

    // `F_SETSIG`'s whole point is telling the handler WHICH fd fired. si_band is
    // a `long` covering both `_kill` words, so si_pid/si_uid must not be written
    // over it and si_fd must land in the `si_value` slot.
    #[test]
    fn write_siginfo_sigpoll_arm_writes_si_band_and_si_fd() {
        let mut info = [0u8; 128];
        let q = SigPoll { band: 0x41, fd: 7 };
        let p = SigPayload { code: 1, pid: 0x4242, uid: 0x77, status: -9, value: u64::MAX,
                             chld_arm: false, sigsys: None, fault: None, poll: Some(q) };
        write_siginfo(&mut info, 29, Some(p));
        assert_eq!(i32::from_ne_bytes(info[0..4].try_into().unwrap()), 29);
        assert_eq!(i32::from_ne_bytes(info[8..12].try_into().unwrap()), 1, "si_code = POLL_IN");
        assert_eq!(i64::from_ne_bytes(info[16..24].try_into().unwrap()), 0x41,
                   "si_band is a long; si_pid/si_uid must not be written over it");
        assert_eq!(i32::from_ne_bytes(info[24..28].try_into().unwrap()), 7, "si_fd");
        assert!(info[28..].iter().all(|b| *b == 0), "nothing past si_fd is written");
    }

    // The `_sigsys` arm OVERLAPS `_kill`/`_sigchld`: si_pid and si_call_addr
    // share offset 16. Writing both would corrupt si_call_addr's low half.
    #[test]
    fn the_sigsys_arm_excludes_the_pid_uid_and_status_fields() {
        let mut info = [0u8; 128];
        let s = Sigsys { call_addr: u64::MAX, syscall: 0, arch: 0, errno: 0 };
        let p = SigPayload { code: 1, pid: 0x4242, uid: 0x77, status: -9, value: 0, chld_arm: false,
                             sigsys: Some(s), fault: None, poll: None };
        write_siginfo(&mut info, 31, Some(p));
        assert_eq!(u64::from_ne_bytes(info[16..24].try_into().unwrap()), u64::MAX,
                   "si_pid/si_uid must not be written over si_call_addr");
    }
}
