use super::*;

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
    assert!(child.ctty_ino().is_none());
}

