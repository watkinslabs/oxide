// `kernel_wait4` / `kernel_waitid_prepare`: everything the two wait(2)-family
// entry points decide BEFORE the child scan runs, plus `kernel_waitid`'s
// return-value tail. Pure, so the errno ORDER — the part that drifts silently
// — is checkable without a boot; the syscall slots are
// `#[cfg(target_os = "oxide-kernel")]` and can hold no test of their own.

use super::{
    int_arg_from_reg, wait4_options_valid, wait4_upid_is_esrch, waitid_options_valid,
    waitid_target, WaitEvents, WaitTarget, WNOHANG, WNOWAIT,
};
use crate::errno::Errno;

/// One wait(2)-family request as the engine sees it (`struct wait_opts`).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct WaitPlan {
    /// `wait4` pid form: -1 any, 0 caller's pgrp, >0 pid, <0 pgrp.
    pub pid:     i32,
    /// Option bits the engine forwards to child eligibility
    /// (`__WALL`/`__WCLONE`/`__WNOTHREAD`) and reads `WNOHANG` from. Already
    /// truncated to the declared `int` and, for a nonblocking pidfd, already
    /// carrying the forced `WNOHANG`.
    pub options: u64,
    /// Which event classes may be reported.
    pub events:  WaitEvents,
    /// False = `WNOWAIT`: observe the event, leave it waitable.
    pub consume: bool,
}

/// `kernel_wait4`'s prologue. The order is load-bearing: an unknown option bit
/// is `EINVAL` even when the pid is also rejectable, and `INT_MIN` is `ESRCH`
/// rather than `EINVAL` because `-INT_MIN` — the pgrp form — is not
/// representable.
/// # C: O(1)
pub fn wait4_prepare(pid_arg: i32, options_reg: u64) -> Result<WaitPlan, Errno> {
    let options = int_arg_from_reg(options_reg);
    if !wait4_options_valid(options) { return Err(Errno::Einval); }
    if wait4_upid_is_esrch(pid_arg) { return Err(Errno::Esrch); }
    Ok(WaitPlan {
        pid:     pid_arg,
        options,
        events:  WaitEvents::for_wait4(options),
        // `wait4` has no `WNOWAIT` bit, so it always consumes.
        consume: true,
    })
}

/// `kernel_waitid_prepare`'s outcome once the idtype switch has run.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum WaitidPrepare {
    /// Target derived from the idtype/id pair alone.
    Ready(WaitPlan),
    /// `P_PIDFD`: the descriptor still has to be resolved to a task, then fed
    /// back through [`pidfd_bind`] with the caller's original `options`.
    Pidfd { fd: i32, options: u64 },
}

/// `kernel_waitid_prepare`. Both `EINVAL` arms — unknown bits and an empty
/// event-class set — precede the idtype switch, so a `waitid(P_PID, 0, .., 0)`
/// reports the option error, not the id one.
/// # C: O(1)
pub fn waitid_prepare(idtype_reg: u64, id: i32, options_reg: u64)
    -> Result<WaitidPrepare, Errno>
{
    let idtype  = int_arg_from_reg(idtype_reg);
    let options = int_arg_from_reg(options_reg);
    if !waitid_options_valid(options) { return Err(Errno::Einval); }
    match waitid_target(idtype, id) {
        WaitTarget::Invalid     => Err(Errno::Einval),
        WaitTarget::Wait4Pid(p) => Ok(WaitidPrepare::Ready(waitid_plan(p, options))),
        WaitTarget::Pidfd(fd)   => Ok(WaitidPrepare::Pidfd { fd, options }),
    }
}

/// `waitid`'s per-class gating: every class is opt-in, and `WNOWAIT` is the
/// only thing that makes a report non-consuming.
/// # C: O(1)
pub const fn waitid_plan(pid: i32, options: u64) -> WaitPlan {
    WaitPlan {
        pid,
        options,
        events:  WaitEvents::for_waitid(options),
        consume: (options & WNOWAIT) == 0,
    }
}

/// What resolving a `P_PIDFD` descriptor found. Keeps the errno ladder here
/// rather than in the gated slot, which owns only the fd-table lookup.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PidfdTarget {
    /// A live thread-group leader: its VPID, and the fd's `O_NONBLOCK` state.
    Leader { vpid: i32, nonblock: bool },
    /// The fd is a pidfd whose process has already been released.
    Released,
    /// The fd names a thread that is not its group's leader. A wait keyed on
    /// it looks the target up as a thread GROUP and can never match, so the
    /// observable result is "no eligible child".
    NonLeader,
    /// Not a descriptor, or not a pidfd.
    BadFd,
}

/// Bind a resolved `P_PIDFD` target into a plan. Returns the plan and whether
/// the fd's `O_NONBLOCK` forced `WNOHANG` on a caller that did not ask for it
/// — the condition `kernel_waitid`'s tail turns a "nothing ready" 0 into
/// `EAGAIN` on.
/// # C: O(1)
pub const fn pidfd_bind(options: u64, target: PidfdTarget)
    -> Result<(WaitPlan, bool), Errno>
{
    let (vpid, nonblock) = match target {
        PidfdTarget::Leader { vpid, nonblock } => (vpid, nonblock),
        PidfdTarget::Released | PidfdTarget::NonLeader => return Err(Errno::Echild),
        PidfdTarget::BadFd => return Err(Errno::Ebadf),
    };
    let forced = nonblock && (options & WNOHANG) == 0;
    let effective = if forced { options | WNOHANG } else { options };
    Ok((waitid_plan(vpid, effective), forced))
}

/// `kernel_waitid` + `sys_waitid` tail. A reported event returns 0, not the
/// pid — `waitid`'s whole result is the siginfo. A pidfd whose `O_NONBLOCK`
/// forced `WNOHANG` reports `EAGAIN` rather than the "no children ready" 0 the
/// caller never asked for.
/// # C: O(1)
pub const fn waitid_result(rv: i64, forced_nonblock: bool) -> i64 {
    if rv < 0 { rv }
    else if rv == 0 && forced_nonblock { -(Errno::Eagain.as_i32() as i64) }
    else { 0 }
}

#[cfg(test)]
#[path = "prepare_tests.rs"]
mod tests;
