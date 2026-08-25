use super::*;

#[test]
fn the_saved_foreground_group_is_process_wide_and_starts_unset() {
    // `tty_old_pgrp` lives on the thread group for the same reason the
    // terminal does: an exiting leader reads what the hangup walk recorded,
    // and either may be a different thread of the same process.
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let leader = published(600);
    let worker = thread_in(&leader, 601);
    assert!(leader.thread_group.tty_old_pgrp().is_none(), "nothing saved yet");
    let saved = Arc::new(crate::pid::PidIdentity::new(77));
    leader.thread_group.set_tty_old_pgrp(Some(Arc::clone(&saved)));
    assert!(Arc::ptr_eq(&worker.thread_group.tty_old_pgrp().unwrap(), &saved));
    leader.thread_group.set_tty_old_pgrp(None);
    assert!(worker.thread_group.tty_old_pgrp().is_none(), "cleared once consumed");
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
fn setsid_rejects_identity_session_leader_without_explicit_flag() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let parent = published(110);
    let child = child_of(&parent, 111);
    // Model the boot/session identity shape where the session already names
    // this process but the explicit signal_struct leader bit was not latched.
    child.set_session(Arc::clone(&child.pid));
    assert!(!child.thread_group.is_session_leader());
    assert!(session::is_session_leader(&child));
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

