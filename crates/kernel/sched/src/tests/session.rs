// POSIX session / process-group work fns against the real global registry:
// success paths, every errno in `sched::session::setpgid`'s ladder and the
// order they fire in, the pid==0/pgid==0 aliases, session-leader and
// cross-session cases, and `personality(2)`'s query form.
//
// Hosted fixtures have no vtgid stamped, so `process_vpid` falls back to the
// internal tgid and `lookup_in_namespace`'s initial-namespace shortcut resolves
// tids directly — the tid IS the pid for these tests.

use super::common::registry_test_lock;
use crate::personality;
use crate::session;
use crate::task::{SchedClass, Task};
use alloc::sync::Arc;
use core::sync::atomic::Ordering;
use syscall::errno::Errno;

fn proc(tid: u32) -> Arc<Task> {
    Arc::new(Task::new(tid, "p", SchedClass::Normal { weight: 1024 }))
}

/// One published process: its own thread group, its own pgrp+session, no parent.
fn published(tid: u32) -> Arc<Task> {
    let t = proc(tid);
    crate::registry::insert(&t);
    t
}

/// A child of `parent`, published, inheriting the parent's pgrp+session exactly
/// as `sys_clone` does.
fn child_of(parent: &Arc<Task>, tid: u32) -> Arc<Task> {
    let c = proc(tid);
    c.parent_tid.store(parent.tid, Ordering::Release);
    c.set_pgid(parent.pgid());
    c.set_sid(parent.sid());
    crate::registry::insert(&c);
    c
}

/// A second thread inside `leader`'s process (Linux CLONE_THREAD).
fn thread_in(leader: &Arc<Task>, tid: u32) -> Arc<Task> {
    let mut t = Task::new(tid, "t", SchedClass::Normal { weight: 1024 });
    t.join_thread_group(Arc::clone(&leader.thread_group));
    t.tgid.store(leader.tid, Ordering::Release);
    let t = Arc::new(t);
    crate::registry::insert(&t);
    t
}

#[test]
fn setpgid_self_creates_own_group() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let p = published(100);
    // A fresh process seeds pgid == its own pid, so move it elsewhere first to
    // prove the call does something.
    p.set_pgid(7);
    assert_eq!(session::setpgid(&p, 0, 0), Ok(()));
    assert_eq!(p.pgid(), 100, "pid==0/pgid==0 aliases to the caller's own pid");
    assert_eq!(session::getpgid(&p, 0), Ok(100));
}

#[test]
fn setpgid_negative_pgid_is_einval_before_any_lookup() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let p = published(100);
    // Linux checks `pgid < 0` before find_task_by_vpid, so a bogus pid does not
    // turn this into ESRCH.
    assert_eq!(session::setpgid(&p, 999_999, -1), Err(Errno::Einval));
    // pgid==0 aliases to pid FIRST, so a negative pid is EINVAL, not ESRCH.
    assert_eq!(session::setpgid(&p, -5, 0), Err(Errno::Einval));
}

#[test]
fn setpgid_negative_pid_with_valid_pgid_is_esrch() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let p = published(100);
    assert_eq!(session::setpgid(&p, -5, 100), Err(Errno::Esrch));
}

#[test]
fn setpgid_unknown_pid_is_esrch() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let p = published(100);
    assert_eq!(session::setpgid(&p, 4242, 4242), Err(Errno::Esrch));
}

#[test]
fn setpgid_non_thread_group_leader_is_einval() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let leader = published(100);
    let worker = thread_in(&leader, 101);
    // Targeting a THREAD (not the process leader) is EINVAL, and it outranks
    // the "not our child" ESRCH that would otherwise apply.
    assert_eq!(session::setpgid(&leader, worker.tid as i32, 100), Err(Errno::Einval));
}

#[test]
fn setpgid_stranger_is_esrch() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let me = published(100);
    let stranger = published(200);
    assert_eq!(session::setpgid(&me, stranger.tid as i32, 200), Err(Errno::Esrch));
    assert_eq!(stranger.pgid(), 200, "stranger's group must be untouched");
}

#[test]
fn setpgid_child_in_other_session_is_eperm() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let parent = published(100);
    let child = child_of(&parent, 101);
    child.set_sid(555);
    assert_eq!(session::setpgid(&parent, 101, 101), Err(Errno::Eperm));
}

#[test]
fn setpgid_child_that_already_execd_is_eacces() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let parent = published(100);
    let child = child_of(&parent, 101);
    // Linux `begin_new_exec` clears PF_FORKNOEXEC; POSIX says EACCES, NOT EPERM.
    child.forknoexec.store(false, Ordering::Release);
    assert_eq!(session::setpgid(&parent, 101, 101), Err(Errno::Eacces));
    // Session mismatch outranks the exec check — EPERM wins when both hold.
    child.set_sid(555);
    assert_eq!(session::setpgid(&parent, 101, 101), Err(Errno::Eperm));
}

#[test]
fn setpgid_child_before_exec_succeeds() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let parent = published(100);
    let child = child_of(&parent, 101);
    assert_eq!(session::setpgid(&parent, 101, 101), Ok(()));
    assert_eq!(child.pgid(), 101);
}

#[test]
fn setpgid_session_leader_target_is_eperm() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let parent = published(100);
    let child = child_of(&parent, 101);
    // The child ran setsid(): it now leads its own session and can never be
    // moved into another process group.
    assert!(child.thread_group.claim_session_leader());
    assert_eq!(session::setpgid(&parent, 101, 101), Err(Errno::Eperm));
    assert_eq!(session::setpgid(&child, 0, 0), Err(Errno::Eperm));
}

#[test]
fn setpgid_into_nonexistent_group_is_eperm() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let parent = published(100);
    let _child = child_of(&parent, 101);
    // pgid != pid, and no live task carries pgid 900 → the group does not exist.
    assert_eq!(session::setpgid(&parent, 101, 900), Err(Errno::Eperm));
}

#[test]
fn setpgid_into_group_in_another_session_is_eperm() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let parent = published(100);
    let child = child_of(&parent, 101);
    let outsider = published(300);
    outsider.set_pgid(300);
    outsider.set_sid(777);
    assert_eq!(session::setpgid(&parent, 101, 300), Err(Errno::Eperm));
    assert_eq!(child.pgid(), 100, "child stays in the parent's group");
}

#[test]
fn setpgid_into_existing_group_in_same_session_succeeds() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let parent = published(100);
    let first = child_of(&parent, 101);
    let second = child_of(&parent, 102);
    // Pipeline shape: first child leads the job, second joins it.
    assert_eq!(session::setpgid(&parent, 101, 101), Ok(()));
    assert_eq!(session::setpgid(&parent, 102, 101), Ok(()));
    assert_eq!(first.pgid(), 101);
    assert_eq!(second.pgid(), 101);
}

#[test]
fn setpgid_moves_every_thread_of_the_process() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let leader = published(100);
    let worker = thread_in(&leader, 101);
    leader.set_pgid(50);
    assert_eq!(session::setpgid(&leader, 0, 0), Ok(()));
    assert_eq!(leader.pgid(), 100);
    assert_eq!(worker.pgid(), 100,
        "pgid is process-wide (Linux task->signal), not per-thread");
}

#[test]
fn setpgid_from_a_worker_thread_targets_the_process() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let leader = published(100);
    let worker = thread_in(&leader, 101);
    leader.set_pgid(50);
    // pid==0 means "my PROCESS", so a non-leader thread still moves the group.
    assert_eq!(session::setpgid(&worker, 0, 0), Ok(()));
    assert_eq!(leader.pgid(), 100);
}

#[test]
fn getpgid_and_getsid_resolve_self_and_others() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let a = published(100);
    let b = published(200);
    b.set_pgid(55);
    b.set_sid(66);
    assert_eq!(session::getpgid(&a, 0), Ok(100));
    assert_eq!(session::getsid(&a, 0), Ok(100));
    assert_eq!(session::getpgid(&a, 200), Ok(55));
    assert_eq!(session::getsid(&a, 200), Ok(66));
}

#[test]
fn getpgid_and_getsid_reject_unknown_and_negative_pids() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let a = published(100);
    assert_eq!(session::getpgid(&a, 4242), Err(Errno::Esrch));
    assert_eq!(session::getsid(&a, 4242), Err(Errno::Esrch));
    assert_eq!(session::getpgid(&a, -1), Err(Errno::Esrch));
    assert_eq!(session::getsid(&a, -1), Err(Errno::Esrch));
}

#[test]
fn getpgid_sees_a_thread_group_as_one_process() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let leader = published(100);
    let worker = thread_in(&leader, 101);
    leader.set_pgid(42);
    assert_eq!(session::getpgid(&worker, 0), Ok(42));
    assert_eq!(session::getpgid(&leader, 101), Ok(42));
}

#[test]
fn setsid_creates_session_and_group_and_clears_ctty() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let parent = published(100);
    let child = child_of(&parent, 101);
    // Forked child inherits pgid 100, so no group is numbered 101 yet.
    assert_eq!(session::setsid(&child), Ok(101));
    assert_eq!(child.sid(), 101);
    assert_eq!(child.pgid(), 101);
    assert!(child.thread_group.is_session_leader());
    // SAFETY: hosted single-threaded test owns this task exclusively; ctty is the same UnsafeCell the syscall path writes.
    assert!(unsafe { (*child.ctty.get()).is_none() });
}

#[test]
fn setsid_twice_is_eperm() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let parent = published(100);
    let child = child_of(&parent, 101);
    assert_eq!(session::setsid(&child), Ok(101));
    assert_eq!(session::setsid(&child), Err(Errno::Eperm));
}

#[test]
fn setsid_by_a_process_group_leader_is_eperm() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    // A published process seeds pgid == its own pid, i.e. it already leads the
    // process group numbered with its pid — Linux's `pid_task(sid, PIDTYPE_PGID)`
    // check then rejects setsid.
    let p = published(100);
    assert_eq!(p.pgid(), 100);
    assert_eq!(session::setsid(&p), Err(Errno::Eperm));
    assert!(!p.thread_group.is_session_leader(), "a failed setsid must not latch");
}

#[test]
fn setsid_is_eperm_when_another_task_already_holds_that_group_number() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let parent = published(100);
    let child = child_of(&parent, 101);
    let other = child_of(&parent, 102);
    other.set_pgid(101); // a group numbered with the child's pid now exists
    assert_eq!(session::setsid(&child), Err(Errno::Eperm));
}

#[test]
fn setsid_moves_the_whole_thread_group() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let parent = published(100);
    let leader = child_of(&parent, 101);
    let worker = thread_in(&leader, 102);
    assert_eq!(session::setsid(&leader), Ok(101));
    assert_eq!(worker.sid(), 101);
    assert_eq!(worker.pgid(), 101);
}

#[test]
fn getppid_reports_the_parents_process_id() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let parent = published(100);
    let child = child_of(&parent, 101);
    assert_eq!(session::getppid(&child), 100);
    assert_eq!(session::getppid(&parent), 0, "no parent → 0, as Linux does for pid 1");
}

#[test]
fn getppid_of_a_thread_reports_the_parent_process_not_the_parent_thread() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let parent_leader = published(100);
    let parent_worker = thread_in(&parent_leader, 101);
    // The worker thread forked the child, so parent_tid names the WORKER.
    let child = proc(200);
    child.parent_tid.store(parent_worker.tid, Ordering::Release);
    crate::registry::insert(&child);
    assert_eq!(session::getppid(&child), 100,
        "Linux reports task_tgid_vnr(real_parent), i.e. the parent PROCESS");
}

#[test]
fn personality_query_form_does_not_set() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let p = published(100);
    assert_eq!(personality::get_set(&p, personality::PER_LINUX), 0);
    let want = personality::READ_IMPLIES_EXEC | personality::UNAME26;
    assert_eq!(personality::get_set(&p, want), personality::PER_LINUX);
    // 0xffffffff reads without writing, and keeps returning the same value.
    assert_eq!(personality::get_set(&p, personality::PERSONALITY_QUERY), want);
    assert_eq!(personality::get_set(&p, personality::PERSONALITY_QUERY), want);
    assert_eq!(personality::get(&p), want);
    assert!(personality::read_implies_exec(&p));
    assert!(personality::uname26(&p));
}

#[test]
fn personality_returns_previous_on_every_set() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let p = published(100);
    assert_eq!(personality::get_set(&p, personality::ADDR_NO_RANDOMIZE), 0);
    assert_eq!(personality::get_set(&p, personality::MMAP_PAGE_ZERO),
        personality::ADDR_NO_RANDOMIZE);
    assert_eq!(personality::get_set(&p, personality::PER_LINUX),
        personality::MMAP_PAGE_ZERO);
    assert_eq!(personality::get(&p), personality::PER_LINUX);
    assert!(!personality::read_implies_exec(&p));
}
