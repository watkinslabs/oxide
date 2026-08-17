//! Which checkpoints are handed to the merge thread.

use super::*;

/// A caller that is blocked on a merged mount with a running thread.
fn waiting() -> Request {
    Request { merge: true, thread_running: true, umounting: false, waiting: true }
}

#[test]
fn a_waiting_caller_on_a_merged_mount_is_handed_over() {
    assert!(takes_the_thread(&waiting()));
}

/// The option is the mount's own statement, and it is honoured both ways.
#[test]
fn a_mount_that_did_not_ask_to_merge_writes_its_own() {
    assert!(!takes_the_thread(&Request { merge: false, ..waiting() }));
}

/// A thread that is not running would never look at the queue, so a caller
/// handed over to it would wait for a write nobody will make.
#[test]
fn no_thread_means_the_caller_keeps_the_write() {
    assert!(!takes_the_thread(&Request { thread_running: false, ..waiting() }));
}

/// The task taking the filesystem down is the one that stops the thread, so a
/// checkpoint it handed over would be waited for by its only possible server.
#[test]
fn the_task_taking_the_filesystem_down_is_never_merged() {
    assert!(!takes_the_thread(&Request { umounting: true, ..waiting() }));
}

/// Merging exists to make N waiters cost one write. A caller that is not
/// waiting has no cost to save and must not add a wait it did not have.
#[test]
fn a_checkpoint_nobody_waits_for_is_not_merged() {
    assert!(!takes_the_thread(&Request { waiting: false, ..waiting() }));
}
