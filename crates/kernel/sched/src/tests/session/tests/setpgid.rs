use super::*;

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
