// wait(2)-family uapi constants and pure decision logic: option-mask
// validation, event-class selection, `waitid` idtype→pid-form mapping, and
// wstatus→siginfo decode. The syscall slot files are
// `#[cfg(target_os = "oxide-kernel")]`, so none of this may live there — a
// `#[cfg(test)] mod tests` inside a gated file compiles away silently.

pub const WNOHANG:    u64 = 0x0000_0001;
pub const WUNTRACED:  u64 = 0x0000_0002;
pub const WSTOPPED:   u64 = WUNTRACED;
pub const WEXITED:    u64 = 0x0000_0004;
pub const WCONTINUED: u64 = 0x0000_0008;
pub const WNOWAIT:    u64 = 0x0100_0000;
pub const __WNOTHREAD:u64 = 0x2000_0000;
pub const __WALL:     u64 = 0x4000_0000;
pub const __WCLONE:   u64 = 0x8000_0000;

pub const P_ALL:   u64 = 0;
pub const P_PID:   u64 = 1;
pub const P_PGID:  u64 = 2;
pub const P_PIDFD: u64 = 3;

/// `si_code` values a SIGCHLD siginfo carries (siginfo(7)).
pub const CLD_EXITED:    i32 = 1;
pub const CLD_KILLED:    i32 = 2;
pub const CLD_DUMPED:    i32 = 3;
pub const CLD_TRAPPED:   i32 = 4;
pub const CLD_STOPPED:   i32 = 5;
pub const CLD_CONTINUED: i32 = 6;
pub const SIGCONT:       i32 = 18;

/// Wait-status encoding constants. Low 7 bits = terminating signal; bit 7 =
/// core-dump flag; low byte `0x7f` = stopped; `0xffff` = continued.
pub const WSTAT_SIG_MASK:   i32 = 0x7f;
pub const WSTAT_CORE:       i32 = 0x80;
pub const WSTAT_LOW_MASK:   i32 = 0xff;
pub const WSTAT_STOPPED:    i32 = 0x7f;
pub const WSTAT_CONTINUED:  i32 = 0xffff;
pub const WSTAT_EXIT_SHIFT: u32 = 8;
/// A stop code is 16 bits wide, not 8: a ptrace event stop carries
/// `SIGTRAP | (event << 8)`, so masking it to a byte would erase the event.
pub const WSTAT_STOP_CODE_MASK: i32 = 0xffff;

const WAIT4_ALLOWED:  u64 = WNOHANG | WUNTRACED | WCONTINUED | __WNOTHREAD | __WCLONE | __WALL;
const WAITID_ALLOWED: u64 = WNOHANG | WNOWAIT | WEXITED | WSTOPPED | WCONTINUED | __WNOTHREAD | __WCLONE | __WALL;

/// Truncate one argument register to the `int` the wait(2) family declares for
/// it (`wait4`'s `int options`, `waitid`'s `int which` / `int options`). Only
/// the low 32 bits carry the ABI value: a caller whose `int` was sign-extended
/// into the 64-bit register — glibc passes `__WCLONE` as a negative `int`, so
/// the register reads `0xffff_ffff_8000_0000` — is passing a valid option set,
/// not an unknown high bit, and must not be rejected for the extension.
/// # C: O(1)
pub const fn int_arg_from_reg(reg: u64) -> u64 { reg as u32 as u64 }

/// # C: O(1)
pub const fn wait4_options_valid(options: u64) -> bool {
    (options & !WAIT4_ALLOWED) == 0
}

/// # C: O(1)
pub const fn waitid_options_valid(options: u64) -> bool {
    (options & !WAITID_ALLOWED) == 0 && (options & (WEXITED | WSTOPPED | WCONTINUED)) != 0
}

/// Which event classes this wait may report. `wait4` always implies `WEXITED`
/// (it has no bit for it); `waitid` gates each class independently, so a
/// `waitid(..., WSTOPPED)` must NOT reap a zombie.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct WaitEvents {
    pub exited:    bool,
    pub stopped:   bool,
    pub continued: bool,
}

impl WaitEvents {
    /// `wait4(2)`: `wo_flags = options | WEXITED`. # C: O(1)
    pub const fn for_wait4(options: u64) -> Self {
        Self {
            exited:    true,
            stopped:   (options & WUNTRACED)  != 0,
            continued: (options & WCONTINUED) != 0,
        }
    }
    /// `waitid(2)`: every class is opt-in. # C: O(1)
    pub const fn for_waitid(options: u64) -> Self {
        Self {
            exited:    (options & WEXITED)    != 0,
            stopped:   (options & WSTOPPED)   != 0,
            continued: (options & WCONTINUED) != 0,
        }
    }
}

/// The event a wait actually consumed. A ptrace trap and a job-control stop
/// share one wait-status encoding but report different `si_code`s, so the
/// engine must carry the distinction rather than re-derive it from the status.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum WaitEventKind { Exited, Stopped, Trapped, Continued }

/// `waitid` idtype+id → the `wait4` pid form, or the pidfd needing resolution.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum WaitTarget {
    /// Already a `wait4` pid: `-1` all, `0` caller's pgrp, `>0` pid, `<0` pgrp.
    Wait4Pid(i32),
    /// `P_PIDFD`: the fd whose task the caller must resolve.
    Pidfd(i32),
    /// Rejected idtype/id pair — `EINVAL`.
    Invalid,
}

/// Linux `kernel_waitid_prepare`'s idtype switch. `P_PGID` with id 0 means the
/// caller's own process group, which is exactly `wait4`'s `pid == 0` form.
/// # C: O(1)
pub const fn waitid_target(idtype: u64, id: i32) -> WaitTarget {
    match idtype {
        P_ALL  => WaitTarget::Wait4Pid(-1),
        P_PID  => if id <= 0 { WaitTarget::Invalid } else { WaitTarget::Wait4Pid(id) },
        P_PGID => if id < 0 { WaitTarget::Invalid } else { WaitTarget::Wait4Pid(-id) },
        P_PIDFD => if id < 0 { WaitTarget::Invalid } else { WaitTarget::Pidfd(id) },
        _ => WaitTarget::Invalid,
    }
}

/// `wait4(2)` rejects `INT_MIN` up front — `-INT_MIN` is not representable, so
/// the pgrp form cannot be built from it. Linux reports `ESRCH`, not `EINVAL`.
/// # C: O(1)
pub const fn wait4_upid_is_esrch(upid: i32) -> bool { upid == i32::MIN }

/// Wait status for a stopped/trapped child. `stop_code` is the full 16-bit
/// code, not just a signal number: a job-control stop passes the stop signal,
/// a ptrace syscall stop passes `SIGTRAP|0x80`, and a ptrace event stop passes
/// `SIGTRAP | (event << 8)`.
/// # C: O(1)
pub const fn stopped_wstatus(stop_code: i32) -> i32 {
    ((stop_code & WSTAT_STOP_CODE_MASK) << WSTAT_EXIT_SHIFT) | WSTAT_STOPPED
}

/// Recover the stop code from a stopped/trapped wait status. Inverse of
/// `stopped_wstatus`. # C: O(1)
pub const fn wstatus_stop_code(wstat: i32) -> i32 {
    (wstat >> WSTAT_EXIT_SHIFT) & WSTAT_STOP_CODE_MASK
}

/// `(si_code, si_status)` for the reported event. `si_status` is the RAW value
/// userspace expects — the exit code for `CLD_EXITED`, the signal number for
/// `CLD_KILLED`/`CLD_DUMPED`, the stop/trap code for `CLD_STOPPED`/
/// `CLD_TRAPPED`, `SIGCONT` for `CLD_CONTINUED` — never the wait-encoded
/// status. # C: O(1)
pub const fn siginfo_from_event(kind: WaitEventKind, wstat: i32) -> (i32, i32) {
    match kind {
        WaitEventKind::Continued => (CLD_CONTINUED, SIGCONT),
        WaitEventKind::Stopped   => (CLD_STOPPED, wstatus_stop_code(wstat)),
        WaitEventKind::Trapped   => (CLD_TRAPPED, wstatus_stop_code(wstat)),
        WaitEventKind::Exited    => {
            if (wstat & WSTAT_SIG_MASK) == 0 {
                (CLD_EXITED, (wstat >> WSTAT_EXIT_SHIFT) & WSTAT_LOW_MASK)
            } else if (wstat & WSTAT_CORE) != 0 {
                (CLD_DUMPED, wstat & WSTAT_SIG_MASK)
            } else {
                (CLD_KILLED, wstat & WSTAT_SIG_MASK)
            }
        }
    }
}

/// What one pass of the blocking wait loop must do once the child scan has
/// run. Owns the ordering `do_wait`/`__do_wait` fix between them, so the
/// target-gated engine obeys it rather than restating it.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum WaitStep {
    /// An event was found: report it. Outranks every other outcome, so a
    /// waiter with a signal pending still reports a child it can already see.
    Report,
    /// Nothing this wait could ever match — the `notask_error` seed survives.
    Echild,
    /// A matchable child exists but has no event and the caller said
    /// `WNOHANG`: return 0 without blocking.
    Nohang,
    /// A matchable child exists, the caller would block, and a deliverable
    /// signal is pending: `-ERESTARTSYS`. Ordered BEFORE the park, or a
    /// parked waiter is unkillable.
    Restart,
    /// Block.
    Park,
}

/// One iteration of `do_wait`'s loop. `has_event` is the child scan's result,
/// `has_children` whether any child could ever match, `signal_pending`
/// whether a deliverable (or unblockable) signal is queued.
/// # C: O(1)
pub const fn wait_step(has_event: bool, has_children: bool, options: u64, signal_pending: bool)
    -> WaitStep
{
    if has_event { return WaitStep::Report; }
    if !has_children { return WaitStep::Echild; }
    if (options & WNOHANG) != 0 { return WaitStep::Nohang; }
    if signal_pending { return WaitStep::Restart; }
    WaitStep::Park
}

#[cfg(test)]
#[path = "wait/tests.rs"]
mod tests;
