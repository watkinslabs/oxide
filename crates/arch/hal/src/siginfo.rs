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
                             sigsys: None };
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
                             sigsys: None };
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
                             sigsys: Some(s) };
        write_siginfo(&mut info, 31, Some(p));
        assert_eq!(i32::from_ne_bytes(info[0..4].try_into().unwrap()), 31);
        assert_eq!(i32::from_ne_bytes(info[4..8].try_into().unwrap()), 0xbeef);
        assert_eq!(i32::from_ne_bytes(info[8..12].try_into().unwrap()), 1, "si_code = SYS_SECCOMP");
        assert_eq!(u64::from_ne_bytes(info[16..24].try_into().unwrap()), 0x7fff_1234_5678);
        assert_eq!(i32::from_ne_bytes(info[24..28].try_into().unwrap()), 257);
        assert_eq!(u32::from_ne_bytes(info[28..32].try_into().unwrap()), 0xc000_003e);
    }

    // The `_sigsys` arm OVERLAPS `_kill`/`_sigchld`: si_pid and si_call_addr
    // share offset 16. Writing both would corrupt si_call_addr's low half.
    #[test]
    fn the_sigsys_arm_excludes_the_pid_uid_and_status_fields() {
        let mut info = [0u8; 128];
        let s = Sigsys { call_addr: u64::MAX, syscall: 0, arch: 0, errno: 0 };
        let p = SigPayload { code: 1, pid: 0x4242, uid: 0x77, status: -9, value: 0, chld_arm: false,
                             sigsys: Some(s) };
        write_siginfo(&mut info, 31, Some(p));
        assert_eq!(u64::from_ne_bytes(info[16..24].try_into().unwrap()), u64::MAX,
                   "si_pid/si_uid must not be written over si_call_addr");
    }
}
