// ptrace(2) permission gate — single choke point for every request
// `101_ptrace.rs` / `ptrace_fpu.rs` dispatch. Mirrors Linux
// `kernel/ptrace.c`:
//   * PTRACE_TRACEME needs no check (self-registers as tracee).
//   * PTRACE_ATTACH/PTRACE_SEIZE: `__ptrace_may_access
//     (PTRACE_MODE_ATTACH_REALCREDS)` — target's real+effective+saved
//     uid/gid must all equal caller's euid/egid, OR caller holds
//     CAP_SYS_PTRACE. Refuses tracing your own thread group and a
//     target already traced by someone else.
//   * Every other request: `ptrace_check_attach` — caller must be the
//     RECORDED tracer of target (`traced_by == cur.tid`); every
//     request except PTRACE_KILL/PTRACE_INTERRUPT additionally
//     requires target be ptrace-`Stopped`. Mismatch -> ESRCH (Linux:
//     an untraced/wrong-tracer pid "doesn't exist" from ptrace's view).
//
// Compiled hosted (`test`) as well as `oxide-kernel` — the checks
// below touch only `sched::Task` fields, no arch/AS intrinsics, so
// they're unit-testable without a live scheduler.

use core::sync::atomic::Ordering;
use sched::{Task, TaskState};

/// `PTRACE_ATTACH`/`PTRACE_SEIZE` gate. True = caller may attach.
/// # C: O(1)
pub fn ptrace_may_attach(cur: &Task, target: &Task) -> bool {
    if cur.tgid.load(Ordering::Acquire) == target.tgid.load(Ordering::Acquire) { return false; }
    if target.traced_by.load(Ordering::Acquire) != 0 { return false; }
    if cur.has_cap(sched::cap::SYS_PTRACE) { return true; }
    creds_match(cur, target)
}

/// Linux `PTRACE_MODE_ATTACH_REALCREDS` credential match: target's
/// real/effective/saved uid AND gid all equal caller's euid/egid.
/// # C: O(1)
fn creds_match(cur: &Task, target: &Task) -> bool {
    let cur_uid = cur.creds.euid.load(Ordering::Acquire);
    let cur_gid = cur.creds.egid.load(Ordering::Acquire);
    target.creds.ruid.load(Ordering::Acquire) == cur_uid
        && target.creds.euid.load(Ordering::Acquire) == cur_uid
        && target.creds.suid.load(Ordering::Acquire) == cur_uid
        && target.creds.rgid.load(Ordering::Acquire) == cur_gid
        && target.creds.egid.load(Ordering::Acquire) == cur_gid
        && target.creds.sgid.load(Ordering::Acquire) == cur_gid
}

/// Every ptrace request beyond TRACEME/ATTACH/SEIZE: caller must be
/// the recorded tracer of `target`. `need_stopped` is false only for
/// PTRACE_KILL/PTRACE_INTERRUPT (Linux `ptrace_check_attach(child,
/// ignore_state)`) — every other request also requires `target` be
/// ptrace-`Stopped`.
/// # C: O(1)
pub fn require_tracer(cur: &Task, target: &Task, need_stopped: bool) -> bool {
    if target.traced_by.load(Ordering::Acquire) != cur.tid { return false; }
    !need_stopped || target.state() == TaskState::Stopped
}

#[cfg(test)]
mod tests {
    use super::*;
    use sched::{SchedClass, Task};

    fn task(tid: u32) -> Task {
        Task::new(tid, "ptrace-perm-test", SchedClass::Normal { weight: 1024 })
    }

    fn set_uids(t: &Task, ruid: u32, euid: u32, suid: u32) {
        t.creds.ruid.store(ruid, Ordering::Release);
        t.creds.euid.store(euid, Ordering::Release);
        t.creds.suid.store(suid, Ordering::Release);
    }

    #[test]
    fn attach_by_different_uid_without_cap_is_refused() {
        let cur = task(1);
        let target = task(2);
        set_uids(&cur, 1000, 1000, 1000);
        set_uids(&target, 0, 0, 0);
        // Task::new defaults to Creds::root() (CAP_FULL) — clear the
        // effective set to model a real unprivileged caller.
        cur.creds.cap_effective.store(0, Ordering::Release);
        assert!(!ptrace_may_attach(&cur, &target));
    }

    #[test]
    fn attach_by_same_uid_succeeds() {
        let cur = task(1);
        let target = task(2);
        set_uids(&cur, 1000, 1000, 1000);
        set_uids(&target, 1000, 1000, 1000);
        assert!(ptrace_may_attach(&cur, &target));
    }

    #[test]
    fn cap_sys_ptrace_bypasses_uid_mismatch() {
        let cur = task(1);
        let target = task(2);
        set_uids(&cur, 1000, 1000, 1000);
        set_uids(&target, 0, 0, 0);
        cur.creds.cap_effective.store(1u64 << sched::cap::SYS_PTRACE, Ordering::Release);
        assert!(ptrace_may_attach(&cur, &target));
    }

    #[test]
    fn attach_refuses_own_thread_group() {
        let cur = task(1);
        cur.tgid.store(1, Ordering::Release);
        // Same task (self-attach): tgid == tgid trivially.
        assert!(!ptrace_may_attach(&cur, &cur));
    }

    #[test]
    fn attach_refuses_already_traced_target() {
        let cur = task(1);
        let other_tracer = task(3);
        let target = task(2);
        set_uids(&cur, 1000, 1000, 1000);
        set_uids(&target, 1000, 1000, 1000);
        target.traced_by.store(other_tracer.tid, Ordering::Release);
        assert!(!ptrace_may_attach(&cur, &target));
    }

    #[test]
    fn non_tracer_is_refused() {
        let cur = task(1);
        let target = task(2);
        target.traced_by.store(99, Ordering::Release);
        assert!(!require_tracer(&cur, &target, true));
    }

    #[test]
    fn tracer_on_stopped_target_succeeds() {
        let cur = task(1);
        let target = task(2);
        target.traced_by.store(cur.tid, Ordering::Release);
        target.state.store(TaskState::Stopped as u8, Ordering::Release);
        assert!(require_tracer(&cur, &target, true));
    }

    #[test]
    fn tracer_on_running_target_refused_when_stop_required() {
        let cur = task(1);
        let target = task(2);
        target.traced_by.store(cur.tid, Ordering::Release);
        target.state.store(TaskState::Runnable as u8, Ordering::Release);
        assert!(!require_tracer(&cur, &target, true));
    }

    #[test]
    fn kill_ignores_stop_state() {
        let cur = task(1);
        let target = task(2);
        target.traced_by.store(cur.tid, Ordering::Release);
        target.state.store(TaskState::Runnable as u8, Ordering::Release);
        assert!(require_tracer(&cur, &target, false));
    }
}
