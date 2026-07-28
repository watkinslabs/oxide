// Filter-return-action -> verdict. This is `__seccomp_filter`'s switch
// (`kernel/seccomp.c`) as a pure function so it is testable; the shim in
// `syscalls/src/dispatch` executes the verdict (`docs/53` hollow shell).
//
// UNGATED (`CLAUDE.md` phantom-test rule).

use super::insn::SeccompData;
use super::uapi::*;

/// The `_sigsys` siginfo arm Linux's `force_sig_seccomp` fills
/// (`kernel/signal.c`): `si_code = SYS_SECCOMP`, `si_errno` = the filter's
/// low 16 bits, `si_call_addr` = the user PC, `si_syscall` = the syscall the
/// filter rejected, `si_arch` = `syscall_get_arch()`.
///
/// ONE definition, in `hal`, shared with the signal queue (`sched::SigInfo`)
/// and the per-arch frame builders — a local copy plus a conversion at the
/// shim boundary would be a second place for the field order to drift.
pub use hal::Sigsys;

/// What the syscall shim must do with the call the filter just judged.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Verdict {
    /// `SECCOMP_RET_ALLOW` — dispatch the syscall.
    Allow,
    /// `SECCOMP_RET_LOG` — dispatch the syscall AFTER logging it. Linux
    /// `case SECCOMP_RET_LOG: seccomp_log(...); return 0;` — LOG is an
    /// allow-with-audit action, NOT a denial.
    Log { syscall: i32 },
    /// Skip the syscall and hand `ret` back to userspace. Covers
    /// `SECCOMP_RET_ERRNO` (`-data`, capped at `MAX_ERRNO`) and the two
    /// fail-closed no-supervisor paths that Linux ENOSYS-es: `RET_TRACE`
    /// with no `PTRACE_EVENT_SECCOMP` tracer and `RET_USER_NOTIF` with no
    /// listener.
    Skip { ret: i64 },
    /// `SECCOMP_RET_TRAP` — roll the syscall back, raise a CATCHABLE
    /// `SIGSYS`, skip the call.
    Trap(Sigsys),
    /// `SECCOMP_RET_KILL_THREAD` — `do_exit(SIGSYS)` for this thread alone
    /// while siblings live; a fatal, uncatchable `SIGSYS` (with core dump)
    /// when it is the last live thread in the group.
    KillThread(Sigsys),
    /// `SECCOMP_RET_KILL_PROCESS` — fatal, uncatchable `SIGSYS` with a core
    /// dump for the WHOLE thread group, regardless of sibling count.
    KillProcess(Sigsys),
    /// `SECCOMP_RET_TRACE` with a `PTRACE_O_TRACESECCOMP` tracer attached —
    /// report `PTRACE_EVENT_SECCOMP` with `data` as the event message, then
    /// re-examine the (possibly rewritten) syscall.
    TraceStop { data: u16 },
    /// `__secure_computing_strict`'s violation path and
    /// `__secure_computing`'s `SECCOMP_MODE_DEAD` arm: `do_exit(SIGKILL)` —
    /// this THREAD only, killed by SIGKILL, no SIGSYS and no core dump.
    DieSigkill,
}

/// `__secure_computing_strict` — mode 1 permits exactly `mode1_syscalls`
/// (`read`, `write`, `_exit`, `rt_sigreturn`) in the CALLING ABI's numbering,
/// and `do_exit(SIGKILL)`s on anything else. Strict mode installs NO cBPF
/// program in Linux; synthesising one would put a second, chain-visible copy
/// of the policy in `seccomp.filter_count` and in the FILTER-mode chain.
/// # C: O(1)
pub fn strict_allows(nr: i32) -> bool {
    let n = nr as u32;
    MODE1_SYSCALLS[0] == n || MODE1_SYSCALLS[1] == n
        || MODE1_SYSCALLS[2] == n || MODE1_SYSCALLS[3] == n
}

/// True when `a` is the less permissive of two raw filter returns.
///
/// The comparison is on `SECCOMP_RET_ACTION_FULL` read as a SIGNED i32 —
/// exactly `ACTION_ONLY()` in `seccomp_run_filters`. Masking with the
/// narrower `SECCOMP_RET_ACTION` (0x7fff0000) drops bit 31 and silently
/// folds `KILL_PROCESS` onto `KILL_THREAD`.
/// # C: O(1)
pub fn more_restrictive(a: u32, b: u32) -> bool {
    ((a & SECCOMP_RET_ACTION_FULL) as i32) < ((b & SECCOMP_RET_ACTION_FULL) as i32)
}

/// `__seccomp_filter`'s action switch.
///
/// `tracer_armed` is `ptrace_event_enabled(current, PTRACE_EVENT_SECCOMP)`.
///
/// The `default` arm is deliberate: an action the kernel does not recognise
/// falls into the KILL arm with Linux, never into ALLOW.
/// # C: O(1)
pub fn decide(filter_ret: u32, d: &SeccompData, tracer_armed: bool) -> Verdict {
    let data = (filter_ret & SECCOMP_RET_DATA) as u16;
    let sigsys = Sigsys { call_addr: d.ip, syscall: d.nr, arch: d.arch, errno: data as i32 };
    match filter_ret & SECCOMP_RET_ACTION_FULL {
        SECCOMP_RET_ALLOW => Verdict::Allow,
        SECCOMP_RET_LOG   => Verdict::Log { syscall: d.nr },
        SECCOMP_RET_ERRNO => {
            // `if (data > MAX_ERRNO) data = MAX_ERRNO;` then
            // `syscall_set_return_value(-data, 0)`. data == 0 therefore
            // returns 0 — a success, not EPERM.
            let capped = core::cmp::min(data as u32, MAX_ERRNO);
            Verdict::Skip { ret: -(capped as i64) }
        }
        SECCOMP_RET_TRAP  => Verdict::Trap(sigsys),
        SECCOMP_RET_TRACE => {
            if tracer_armed { Verdict::TraceStop { data } }
            // "ENOSYS these calls if there is no tracer attached." A filter
            // that denies by tracing MUST NOT let the syscall through.
            else { Verdict::Skip { ret: enosys() } }
        }
        // `seccomp_do_user_notification` opens with `err = -ENOSYS; if
        // (!match->notif) goto out;`, and `out:` sets that as the return
        // value and skips the call. No filter here can own a listener —
        // `SECCOMP_FILTER_FLAG_NEW_LISTENER` install fails, see
        // `install::listener_unsupported` — so every RET_USER_NOTIF takes
        // exactly that listener-less path.
        SECCOMP_RET_USER_NOTIF => Verdict::Skip { ret: enosys() },
        SECCOMP_RET_KILL_PROCESS => Verdict::KillProcess(sigsys),
        SECCOMP_RET_KILL_THREAD  => Verdict::KillThread(sigsys),
        _ => Verdict::KillProcess(sigsys),
    }
}

fn enosys() -> i64 { -(syscall::errno::Errno::Enosys.as_i32() as i64) }
