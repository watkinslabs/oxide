// What a write to this filesystem announces to the userspace AVC.

use alloc::vec::Vec;
use core::cell::RefCell;

use super::{emit, enforce_notice, policy_notice, Notice};

std::thread_local! {
    /// Notices this test's own writes produced. Per-THREAD rather than global:
    /// the harness runs one test per thread, so a sibling test writing to the
    /// same nodes cannot land in this test's record and no lock is needed.
    static RECORD: RefCell<Vec<Notice>> = const { RefCell::new(Vec::new()) };
}

/// Record one emitted notice. # C: O(1)
pub(crate) fn record(notice: Notice) {
    RECORD.with(|r| r.borrow_mut().push(notice));
}

/// Take everything the calling test's writes announced. # C: O(notices)
pub(crate) fn announced() -> Vec<Notice> {
    RECORD.with(|r| core::mem::take(&mut *r.borrow_mut()))
}

#[test]
fn a_write_that_changes_the_mode_announces_it_and_one_that_does_not_announces_nothing() {
    assert_eq!(enforce_notice(false, true), Some(Notice::Setenforce(true)));
    assert_eq!(enforce_notice(true, false), Some(Notice::Setenforce(false)));
    assert_eq!(enforce_notice(true, true), None);
    assert_eq!(enforce_notice(false, false), None);
}

#[test]
fn a_policy_change_announces_the_sequence_number_it_produced() {
    assert_eq!(policy_notice(0), Notice::Policyload(0));
    assert_eq!(policy_notice(41), Notice::Policyload(41));
}

#[test]
fn emitting_reaches_no_subscriber_when_none_has_opened_a_socket() {
    assert_eq!(emit(Notice::Setenforce(true)), 0);
    assert_eq!(emit(Notice::Policyload(1)), 0);
    assert_eq!(announced(), alloc::vec![Notice::Setenforce(true), Notice::Policyload(1)]);
    assert!(announced().is_empty(), "taking the record clears it");
}
