// One pass of `do_wait`'s child scan, as a decision over two injected
// lookups. The lookups themselves are registry state and live in `sched`; the
// ORDER between them, the per-class gating that decides whether a lookup runs
// at all, and the event→wait-status mapping are pure and belong here, where a
// hosted test can drive them.

use super::{stopped_wstatus, WaitEventKind, WaitPlan, WSTAT_CONTINUED};

/// One pass over the waiter's eligible children (`wait_consider_task`'s
/// per-task order, hoisted to the scan): an exit outranks a stop or continue
/// from the same child, and a class the caller did not request is not even
/// looked up — `waitid(.., WSTOPPED)` must not consume a zombie.
///
/// `zombie` takes the consume flag (`WNOWAIT` peeks) and yields the child plus
/// its already-encoded wait status. `stop` takes `(want_stop, want_cont,
/// consume)` and yields the child, the event kind, and the raw 16-bit stop
/// code. `stop` is consulted even when neither class was requested: a tracer
/// sees its tracee's trap stop with no `WUNTRACED` bit set, and it is reached
/// only after the zombie lookup missed.
/// # C: O(1) plus the injected lookups
pub fn scan_pass<C, Z, S>(plan: &WaitPlan, zombie: Z, stop: S)
    -> Option<(C, WaitEventKind, i32)>
where
    Z: FnOnce(bool) -> Option<(C, i32)>,
    S: FnOnce(bool, bool, bool) -> Option<(C, WaitEventKind, i32)>,
{
    if plan.events.exited {
        if let Some((child, wstat)) = zombie(plan.consume) {
            return Some((child, WaitEventKind::Exited, wstat));
        }
    }
    let (child, kind, stop_code) = stop(plan.events.stopped, plan.events.continued, plan.consume)?;
    Some((child, kind, stop_event_wstatus(kind, stop_code)))
}

/// Wait status for a stop/continue report. `wait_task_continued` writes the
/// fixed `0xffff`; `wait_task_stopped` writes the full 16-bit stop code
/// shifted into place, so a ptrace event stop keeps its event number.
/// # C: O(1)
pub const fn stop_event_wstatus(kind: WaitEventKind, stop_code: i32) -> i32 {
    match kind {
        WaitEventKind::Continued => WSTAT_CONTINUED,
        _                        => stopped_wstatus(stop_code),
    }
}

/// Whether reporting this event may clear the parent's pending `SIGCHLD` once
/// no waitable zombie is left. Only a CONSUMED exit drains: a `WNOWAIT` peek
/// leaves the child waitable, and a stop/continue report never reaped
/// anything, so dropping the bit either way loses a real notification.
///
/// Left set after a consuming reap, `signal_dispatch` runs a SIGCHLD handler
/// AFTER `wait4` already reaped; the shell's handler then calls
/// `waitpid(-1, WNOHANG)`, gets `ECHILD`, and corrupts `$?`.
/// # C: O(1)
pub const fn drains_sigchld(kind: WaitEventKind, consume: bool) -> bool {
    matches!(kind, WaitEventKind::Exited) && consume
}

#[cfg(test)]
#[path = "scan_tests.rs"]
mod tests;
