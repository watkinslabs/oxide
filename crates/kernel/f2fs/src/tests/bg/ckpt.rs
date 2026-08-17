//! The merge queue: what one write serves, and what it does not.

use super::*;
use vfs::VfsError;

/// The saving is the whole point, so it is what the first case measures: three
/// callers, one write, and every one of them gets that write's answer.
#[test]
fn one_write_serves_every_caller_already_enrolled() {
    let mut c = CkptControl::new();
    let seen: alloc::vec::Vec<u64> = (0..3).map(|_| c.enrol()).collect();
    assert_eq!(c.queued(), 3);
    assert!(seen.iter().all(|&g| g == seen[0]), "all three wait on the same batch");
    let count = c.take();
    assert_eq!(count, 3, "the whole queue goes into one write");
    assert_eq!(c.queued(), 0);
    c.served(count, Ok(()));
    for &g in &seen { assert!(c.generation() != g, "a caller was left waiting"); }
    assert_eq!((c.issued(), c.total()), (1, 3), "one write, three callers served");
    assert_eq!(c.last(), Ok(()));
}

/// A caller that arrives after the take waits for the NEXT write, because its
/// own changes may not have been in the state the running write captured.
#[test]
fn a_caller_arriving_after_the_take_waits_for_the_next_write() {
    let mut c = CkptControl::new();
    let first = c.enrol();
    let count = c.take();
    let late = c.enrol();
    assert_eq!(late, first, "the batch counter has not moved yet");
    c.served(count, Ok(()));
    assert!(c.generation() != first, "the first caller is released");
    assert_eq!(c.queued(), 1, "the late caller is still enrolled");
    let count = c.take();
    c.served(count, Ok(()));
    assert_eq!((c.issued(), c.total()), (2, 2));
}

/// A failed write is the answer every caller of that batch gets: they were all
/// waiting for the same state to reach the medium and it did not.
#[test]
fn a_failed_write_is_reported_to_every_caller_of_its_batch() {
    let mut c = CkptControl::new();
    c.enrol();
    c.enrol();
    let count = c.take();
    c.served(count, Err(VfsError::Eio));
    assert_eq!(c.last(), Err(VfsError::Eio));
    assert_eq!(c.total(), 2);
}

/// The wake flag is lowered by the take, not by the write: a request arriving
/// while the write is in progress has to leave it raised so the thread comes
/// back round instead of sleeping out its interval.
#[test]
fn a_request_during_a_write_leaves_the_thread_asked_for() {
    let mut c = CkptControl::new();
    c.enrol();
    assert!(c.wake);
    let count = c.take();
    assert!(!c.wake);
    c.enrol();
    c.served(count, Ok(()));
    assert!(c.wake, "the late request was forgotten and the thread will sleep");
}

/// The thread's own scheduling starts where the reference starts it.
#[test]
fn the_thread_starts_at_the_middle_of_the_ordinary_class() {
    assert_eq!(CkptControl::new().ioprio, IoPrio { class: IoClass::BestEffort, level: 3 });
}
