use super::*;
use sched::{SchedClass, Task};

fn task(tid: u32) -> Task {
    let t = Task::new(tid, "ptrace-perm-test", SchedClass::Normal { weight: 1024 });
    t.tgid.store(tid, Ordering::Release);
    t.dumpable.store(SUID_DUMP_USER, Ordering::Release);
    t
}

fn set_uids(t: &Task, ruid: u32, euid: u32, suid: u32) {
    t.creds.ruid.store(ruid, Ordering::Release);
    t.creds.euid.store(euid, Ordering::Release);
    t.creds.suid.store(suid, Ordering::Release);
}

fn set_gids(t: &Task, rgid: u32, egid: u32, sgid: u32) {
    t.creds.rgid.store(rgid, Ordering::Release);
    t.creds.egid.store(egid, Ordering::Release);
    t.creds.sgid.store(sgid, Ordering::Release);
}

/// `Task::new` seeds `Creds::root()` (CAP_FULL); model an unprivileged caller.
fn drop_caps(t: &Task) { t.creds.cap_effective.store(0, Ordering::Release); }

#[test]
fn attach_by_different_uid_without_cap_is_eperm() {
    let cur = task(1); let target = task(2);
    set_uids(&cur, 1000, 1000, 1000);
    set_uids(&target, 0, 0, 0);
    drop_caps(&cur);
    assert_eq!(may_attach(&cur, &target, false, false), Err(Errno::Eperm));
}

#[test]
fn attach_by_same_uid_succeeds() {
    let cur = task(1); let target = task(2);
    set_uids(&cur, 1000, 1000, 1000);
    set_uids(&target, 1000, 1000, 1000);
    drop_caps(&cur);
    assert_eq!(may_attach(&cur, &target, false, false), Ok(()));
}

/// REALCREDS compares the caller's REAL uid, not its effective one. A
/// setuid-root helper that dropped euid to 1000 keeps ruid 0, so it must NOT
/// match a uid-1000 target — the euid-based comparison this replaced let it.
#[test]
fn realcreds_uses_the_callers_real_uid_not_effective() {
    let cur = task(1); let target = task(2);
    set_uids(&cur, 0, 1000, 0);
    set_uids(&target, 1000, 1000, 1000);
    drop_caps(&cur);
    assert_eq!(may_attach(&cur, &target, false, false), Err(Errno::Eperm));
}

#[test]
fn gid_mismatch_alone_denies() {
    let cur = task(1); let target = task(2);
    set_uids(&cur, 1000, 1000, 1000);
    set_uids(&target, 1000, 1000, 1000);
    set_gids(&cur, 1000, 1000, 1000);
    set_gids(&target, 1000, 1000, 999);
    drop_caps(&cur);
    assert_eq!(may_attach(&cur, &target, false, false), Err(Errno::Eperm));
}

#[test]
fn cap_sys_ptrace_bypasses_uid_mismatch() {
    let cur = task(1); let target = task(2);
    set_uids(&cur, 1000, 1000, 1000);
    set_uids(&target, 0, 0, 0);
    cur.creds.cap_effective.store(1u64 << sched::cap::SYS_PTRACE, Ordering::Release);
    assert_eq!(may_attach(&cur, &target, false, false), Ok(()));
}

#[test]
fn non_dumpable_target_needs_cap_even_at_same_uid() {
    let cur = task(1); let target = task(2);
    set_uids(&cur, 1000, 1000, 1000);
    set_uids(&target, 1000, 1000, 1000);
    target.dumpable.store(0, Ordering::Release);
    drop_caps(&cur);
    assert_eq!(may_attach(&cur, &target, false, false), Err(Errno::Eperm));
    cur.creds.cap_effective.store(1u64 << sched::cap::SYS_PTRACE, Ordering::Release);
    assert_eq!(may_attach(&cur, &target, false, false), Ok(()));
}

#[test]
fn attach_refuses_own_thread_group() {
    let cur = task(1);
    assert_eq!(may_attach(&cur, &cur, false, false), Err(Errno::Eperm));
}

#[test]
fn attach_refuses_kernel_thread() {
    let cur = task(1); let target = task(2);
    set_uids(&cur, 0, 0, 0); set_uids(&target, 0, 0, 0);
    assert_eq!(may_attach(&cur, &target, true, false), Err(Errno::Eperm));
}

#[test]
fn attach_refuses_exiting_target() {
    let cur = task(1); let target = task(2);
    set_uids(&cur, 0, 0, 0); set_uids(&target, 0, 0, 0);
    assert_eq!(may_attach(&cur, &target, false, true), Err(Errno::Eperm));
}

#[test]
fn attach_refuses_already_traced_target() {
    let cur = task(1); let target = task(2);
    set_uids(&cur, 1000, 1000, 1000);
    set_uids(&target, 1000, 1000, 1000);
    target.traced_by.store(3, Ordering::Release);
    assert_eq!(may_attach(&cur, &target, false, false), Err(Errno::Eperm));
}

#[test]
fn may_access_allows_same_thread_group_regardless_of_dumpability() {
    let cur = task(1);
    let peer = task(2);
    peer.tgid.store(1, Ordering::Release);
    peer.dumpable.store(0, Ordering::Release);
    drop_caps(&cur);
    assert_eq!(may_access(&cur, &peer), Ok(()));
}

#[test]
fn non_tracer_is_esrch() {
    let cur = task(1); let target = task(2);
    target.traced_by.store(99, Ordering::Release);
    assert_eq!(check_attach(&cur, &target, true), Err(Errno::Esrch));
}

#[test]
fn tracer_on_stopped_target_succeeds() {
    let cur = task(1); let target = task(2);
    target.traced_by.store(cur.tid, Ordering::Release);
    target.state.store(TaskState::Stopped as u8, Ordering::Release);
    assert_eq!(check_attach(&cur, &target, true), Ok(()));
}

#[test]
fn tracer_on_running_target_is_esrch_when_stop_required() {
    let cur = task(1); let target = task(2);
    target.traced_by.store(cur.tid, Ordering::Release);
    target.state.store(TaskState::Runnable as u8, Ordering::Release);
    assert_eq!(check_attach(&cur, &target, true), Err(Errno::Esrch));
}

#[test]
fn kill_and_interrupt_ignore_stop_state() {
    let cur = task(1); let target = task(2);
    target.traced_by.store(cur.tid, Ordering::Release);
    target.state.store(TaskState::Runnable as u8, Ordering::Release);
    assert_eq!(check_attach(&cur, &target, false), Ok(()));
}
