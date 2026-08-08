use super::*;
use crate::io_uring_abi::ops::{IOSQE_ASYNC, IOSQE_IO_LINK};

const OK: i64 = 0;
const FAIL: i64 = -5;

#[test]
fn an_unlinked_entry_always_runs_and_leaves_no_state() {
    let mut c = Chain::default();
    assert_eq!(c.action(0), Action::Run);
    c.advance(0, FAIL);
    // A failure outside a chain must not poison the next entry.
    assert_eq!(c, Chain::default());
    assert_eq!(c.action(0), Action::Run);
}

#[test]
fn a_failed_link_cancels_the_rest_of_its_chain() {
    let mut c = Chain::default();
    // head, linked, fails
    assert_eq!(c.action(IOSQE_IO_LINK), Action::Run);
    c.advance(IOSQE_IO_LINK, FAIL);
    // second member: not executed
    assert_eq!(c.action(IOSQE_IO_LINK), Action::Cancel);
    c.advance(IOSQE_IO_LINK, -(125));
    // third and last member: still cancelled
    assert_eq!(c.action(0), Action::Cancel);
    c.advance(0, -(125));
    // the chain is over; the next entry runs
    assert_eq!(c.action(0), Action::Run);
}

#[test]
fn a_successful_chain_runs_every_member() {
    let mut c = Chain::default();
    for _ in 0..3 {
        assert_eq!(c.action(IOSQE_IO_LINK), Action::Run);
        c.advance(IOSQE_IO_LINK, OK);
    }
    assert_eq!(c.action(0), Action::Run);
    c.advance(0, OK);
    assert_eq!(c, Chain::default());
}

#[test]
fn a_hard_link_survives_its_own_failure() {
    let mut c = Chain::default();
    assert_eq!(c.action(IOSQE_IO_HARDLINK), Action::Run);
    c.advance(IOSQE_IO_HARDLINK, FAIL);
    // The whole point of a hard link: the next entry still runs.
    assert_eq!(c.action(IOSQE_IO_HARDLINK), Action::Run);
    c.advance(IOSQE_IO_HARDLINK, OK);
    assert_eq!(c.action(0), Action::Run);
}

#[test]
fn a_soft_failure_after_a_hard_link_still_breaks_the_chain() {
    let mut c = Chain::default();
    c.advance(IOSQE_IO_HARDLINK, FAIL);
    assert_eq!(c.action(IOSQE_IO_LINK), Action::Run);
    c.advance(IOSQE_IO_LINK, FAIL);
    assert_eq!(c.action(0), Action::Cancel);
}

#[test]
fn silent_success_is_silent_only_on_success() {
    assert!(!posts_cqe(IOSQE_CQE_SKIP_SUCCESS, 0));
    assert!(!posts_cqe(IOSQE_CQE_SKIP_SUCCESS, 4096));
    // A failure is always reported: skipping it would lose the error entirely.
    assert!(posts_cqe(IOSQE_CQE_SKIP_SUCCESS, FAIL));
    assert!(posts_cqe(0, 0));
    assert!(posts_cqe(IOSQE_ASYNC, 0));
}

#[test]
fn silent_success_and_drain_barriers_are_mutually_exclusive() {
    // A barrier that waits for earlier completions cannot work once some
    // completions are deliberately never posted.
    assert!(disables_drain(IOSQE_CQE_SKIP_SUCCESS));
    assert!(!disables_drain(IOSQE_IO_DRAIN));
    assert!(wants_drain(IOSQE_IO_DRAIN));
    assert!(!wants_drain(IOSQE_IO_LINK));
}
