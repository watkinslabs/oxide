use super::*;

#[test]
fn setsid_clears_the_controlling_terminal_for_every_thread_of_the_process() {
    // Linux holds the terminal on `signal_struct`, so `proc_clear_tty` in
    // ONE thread drops it for the whole process. Held per-`Task` it dropped
    // only for the calling thread, and a sibling's `/dev/tty` kept resolving
    // to a terminal the process had already left.
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let parent = published(100);
    let leader = child_of(&parent, 101);
    let worker = thread_in(&leader, 102);
    leader.set_ctty(Some(tty_inode(77)));
    assert_eq!(worker.ctty_ino(), Some(77), "a terminal is process-wide state");

    assert_eq!(session::setsid(&leader), Ok(101));
    assert!(leader.ctty_ino().is_none());
    assert!(worker.ctty_ino().is_none(), "the sibling thread lost it too");
}

#[test]
fn a_terminal_claimed_by_one_thread_is_visible_to_its_siblings() {
    // The TIOCSCTTY half of the same invariant.
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let leader = published(200);
    let worker = thread_in(&leader, 201);
    worker.set_ctty(Some(tty_inode(88)));
    assert_eq!(leader.ctty_ino(), Some(88));
    assert_eq!(leader.ctty().map(|i| i.ino()), Some(88));
}

#[test]
fn a_forked_child_inherits_the_terminal_but_no_longer_shares_the_slot() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let parent = published(300);
    parent.set_ctty(Some(tty_inode(99)));
    let child = child_of(&parent, 301);
    child.set_ctty(parent.ctty());
    assert_eq!(child.ctty_ino(), Some(99));
    // Distinct thread groups: the child's setsid must not touch the parent.
    assert_eq!(session::setsid(&child), Ok(301));
    assert!(child.ctty_ino().is_none());
    assert_eq!(parent.ctty_ino(), Some(99));
}

#[test]
fn session_leadership_is_one_test_shared_by_every_path_that_needs_it() {
    // The terminal-hangup walk and the exit-time disassociation both ask "is
    // this process a session leader?". Two spellings of that question drifting
    // apart hangs the wrong session up, so there is exactly one answer.
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let parent = published(400);
    let child = child_of(&parent, 401);
    // A forked child inherits its parent's session and leads nothing.
    assert!(!session::is_session_leader(&child));
    assert_eq!(session::setsid(&child), Ok(401));
    assert!(session::is_session_leader(&child), "setsid makes it the leader");
    // Leadership is process-wide, so a sibling thread answers the same.
    let worker = thread_in(&child, 402);
    assert!(session::is_session_leader(&worker));
    // The parent still leads its own session and is unaffected.
    assert!(session::is_session_leader(&parent));
}

#[test]
fn a_member_of_someone_elses_session_is_never_a_leader() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let leader = published(500);
    let member = child_of(&leader, 501);
    assert_eq!(member.sid(), leader.sid());
    assert!(!session::is_session_leader(&member));
}
