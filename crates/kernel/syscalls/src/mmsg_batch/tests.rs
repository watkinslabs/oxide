// The `recvmmsg` batch contract. These are the rules the slot file used to
// hold inside a `#[cfg(target_os = "oxide-kernel")]` module, where no hosted
// test could reach them — they were believed correct and never executed once.

use super::*;

use net::uapi::{MSG_DONTWAIT, MSG_ERRQUEUE, MSG_OOB, MSG_PEEK, MSG_WAITFORONE};

/// One scripted entry outcome for the batch driver below.
enum Entry {
    /// The receive delivered a message, and whether it carried urgent data.
    Got { oob: bool },
    /// The receive failed with this negative errno.
    Failed(i64),
}

/// What one driven batch reported.
struct Report {
    result: i64,
    /// Errno latched as the socket's pending error, if any.
    latched: Option<i32>,
    /// Per-entry flags each receive actually ran with.
    seen_flags: alloc::vec::Vec<u64>,
    /// Whether the remaining timeout was written back.
    copied_timeout: bool,
    /// Entries the batch never reached.
    unreached: usize,
}

/// Drive a batch through the SAME functions the slot file calls, so the order
/// they compose in is what is under test — not just each answer alone.
/// `remaining` is the timeout observed after each delivery (`None` = none
/// supplied). # C: O(entries)
fn drive(flags: u64, vlen: u64, entries: &[Entry], remaining: &[Option<u64>]) -> Report {
    let mut seen_flags = alloc::vec::Vec::new();
    let mut delivered: i64 = 0;
    let mut latched = None;
    let mut used = 0usize;
    let len = batch_len(vlen);
    let result = 'batch: {
        for index in 0..len {
            let Some(entry) = entries.get(index as usize) else { break };
            used += 1;
            seen_flags.push(entry_flags(flags, delivered as u64));
            match entry {
                Entry::Failed(errno) => match on_failure(delivered, *errno) {
                    OnFailure::Report(failure) => break 'batch failure,
                    OnFailure::Deliver { count, latch } => { latched = latch; break 'batch count; }
                },
                Entry::Got { oob } => {
                    delivered += 1;
                    let left = remaining.get(index as usize).copied().flatten();
                    match after_delivery(left, *oob) {
                        AfterDelivery::Continue => {}
                        AfterDelivery::TimedOut | AfterDelivery::OutOfBand => break,
                    }
                }
            }
        }
        delivered
    };
    Report { result, latched, seen_flags, copied_timeout: copies_timeout_back(result),
        unreached: entries.len() - used }
}

#[test]
fn the_compat_layout_is_refused_before_anything_else() {
    assert_eq!(admit_flags(MSG_CMSG_COMPAT), Err(Errno::Einval));
    assert_eq!(admit_flags(MSG_CMSG_COMPAT | MSG_DONTWAIT), Err(Errno::Einval));
    assert_eq!(admit_flags(MSG_DONTWAIT | MSG_PEEK | MSG_WAITFORONE), Ok(()));
    assert_eq!(admit_flags(0), Ok(()));
}

#[test]
fn a_malformed_timeout_is_refused_and_a_valid_one_is_nanoseconds() {
    assert_eq!(timeout_total_ns(-1, 0), Err(Errno::Einval));
    assert_eq!(timeout_total_ns(0, -1), Err(Errno::Einval));
    assert_eq!(timeout_total_ns(0, NSEC_PER_SEC as i64), Err(Errno::Einval));
    assert_eq!(timeout_total_ns(0, NSEC_PER_SEC as i64 - 1), Ok(NSEC_PER_SEC - 1));
    assert_eq!(timeout_total_ns(0, 0), Ok(0), "a zero timeout is valid, not an error");
    assert_eq!(timeout_total_ns(2, 500), Ok(2 * NSEC_PER_SEC + 500));
    // A second count large enough to overflow saturates instead of wrapping to
    // a short deadline, which would end the batch immediately.
    assert_eq!(timeout_total_ns(i64::MAX, 999_999_999), Ok(u64::MAX));
}

#[test]
fn a_pending_error_precedes_the_batch_except_for_an_error_queue_read() {
    assert!(reports_pending_error(0));
    assert!(reports_pending_error(MSG_DONTWAIT | MSG_WAITFORONE));
    assert!(!reports_pending_error(MSG_ERRQUEUE),
        "an error-queue read is how the pending error is meant to be collected");
    assert!(!reports_pending_error(MSG_ERRQUEUE | MSG_DONTWAIT));
}

#[test]
fn the_batch_walks_the_whole_array_and_never_clamps_it() {
    // The clamp belongs to `sendmmsg`; copying it here truncated long batches.
    assert_eq!(batch_len(1024), 1024);
    assert_eq!(batch_len(1025), 1025, "UIO_MAXIOV is not a recvmmsg bound");
    assert_eq!(batch_len(u32::MAX as u64), u32::MAX as u64);
    assert_eq!(batch_len(0), 0);
    // The count arrives as an `unsigned int`; anything above is truncated by
    // the ABI, not by a policy decision.
    assert_eq!(batch_len(u32::MAX as u64 + 1), 0);
}

#[test]
fn waitforone_never_reaches_a_receive_and_becomes_dontwait_after_one_message() {
    assert_eq!(entry_flags(MSG_WAITFORONE, 0), 0, "the first receive may wait");
    assert_eq!(entry_flags(MSG_WAITFORONE, 1), MSG_DONTWAIT);
    assert_eq!(entry_flags(MSG_WAITFORONE | MSG_PEEK, 3), MSG_DONTWAIT | MSG_PEEK);
    // Without the flag the batch keeps waiting on every entry.
    assert_eq!(entry_flags(0, 0), 0);
    assert_eq!(entry_flags(0, 5), 0);
    assert_eq!(entry_flags(MSG_PEEK, 5), MSG_PEEK);
}

#[test]
fn a_delivery_ends_the_batch_on_a_spent_timeout_or_urgent_data() {
    assert_eq!(after_delivery(None, false), AfterDelivery::Continue);
    assert_eq!(after_delivery(Some(5), false), AfterDelivery::Continue);
    assert_eq!(after_delivery(Some(0), false), AfterDelivery::TimedOut);
    assert_eq!(after_delivery(None, true), AfterDelivery::OutOfBand);
    assert_eq!(after_delivery(Some(5), true), AfterDelivery::OutOfBand);
    // The timeout is re-read before the message is inspected, so a batch that
    // ran out of time reports that rather than the urgent message.
    assert_eq!(after_delivery(Some(0), true), AfterDelivery::TimedOut);
}

#[test]
fn a_failure_reports_itself_only_when_nothing_was_delivered() {
    assert_eq!(on_failure(0, neg(Errno::Econnreset)), OnFailure::Report(neg(Errno::Econnreset)));
    assert_eq!(on_failure(0, neg(Errno::Eagain)), OnFailure::Report(neg(Errno::Eagain)));
    assert_eq!(on_failure(0, neg(Errno::Efault)), OnFailure::Report(neg(Errno::Efault)));
}

#[test]
fn a_failure_after_delivery_reports_the_count_and_latches_the_errno() {
    assert_eq!(on_failure(3, neg(Errno::Econnreset)),
        OnFailure::Deliver { count: 3, latch: Some(Errno::Econnreset.as_i32()) });
    // EAGAIN says only "nothing more is queued"; it is not an error to keep.
    assert_eq!(on_failure(3, neg(Errno::Eagain)), OnFailure::Deliver { count: 3, latch: None });
    assert_eq!(on_failure(1, neg(Errno::Efault)),
        OnFailure::Deliver { count: 1, latch: Some(Errno::Efault.as_i32()) });
}

#[test]
fn the_timeout_is_written_back_only_after_a_message_landed() {
    assert!(copies_timeout_back(1));
    assert!(copies_timeout_back(64));
    assert!(!copies_timeout_back(0), "an empty return leaves the caller's timespec alone");
    assert!(!copies_timeout_back(neg(Errno::Eagain)));
}

#[test]
fn a_full_batch_delivers_every_entry_and_writes_the_timeout_back() {
    let entries = [Entry::Got { oob: false }, Entry::Got { oob: false }, Entry::Got { oob: false }];
    let report = drive(0, 3, &entries, &[Some(9), Some(8), Some(7)]);
    assert_eq!(report.result, 3);
    assert_eq!(report.latched, None);
    assert_eq!(report.unreached, 0);
    assert!(report.copied_timeout);
}

#[test]
fn urgent_data_ends_the_batch_with_what_it_already_has() {
    let entries = [Entry::Got { oob: false }, Entry::Got { oob: true }, Entry::Got { oob: false }];
    let report = drive(0, 3, &entries, &[None, None, None]);
    assert_eq!(report.result, 2, "the urgent message counts, and is the last");
    assert_eq!(report.unreached, 1, "the entry after it is never touched");
    assert!(report.copied_timeout);
}

#[test]
fn waitforone_drains_without_waiting_once_the_first_message_lands() {
    let entries = [Entry::Got { oob: false }, Entry::Got { oob: false },
        Entry::Failed(neg(Errno::Eagain))];
    let report = drive(MSG_WAITFORONE, 3, &entries, &[None, None, None]);
    assert_eq!(report.seen_flags, alloc::vec![0, MSG_DONTWAIT, MSG_DONTWAIT]);
    assert_eq!(report.result, 2, "the dry queue ends the batch at what it has");
    assert_eq!(report.latched, None, "EAGAIN is not latched");
}

#[test]
fn a_first_entry_failure_is_the_whole_answer() {
    let entries = [Entry::Failed(neg(Errno::Ebadf)), Entry::Got { oob: false }];
    let report = drive(0, 2, &entries, &[None, None]);
    assert_eq!(report.result, neg(Errno::Ebadf));
    assert_eq!(report.latched, None, "there is no count to protect, so nothing is latched");
    assert_eq!(report.unreached, 1);
    assert!(!report.copied_timeout);
}

#[test]
fn a_later_failure_is_latched_behind_the_delivered_count() {
    let entries = [Entry::Got { oob: false }, Entry::Failed(neg(Errno::Econnreset)),
        Entry::Got { oob: false }];
    let report = drive(0, 3, &entries, &[None, None, None]);
    assert_eq!(report.result, 1);
    assert_eq!(report.latched, Some(Errno::Econnreset.as_i32()),
        "the next call collects it, or getsockopt(SO_ERROR) does");
    assert_eq!(report.unreached, 1);
}

#[test]
fn a_spent_timeout_ends_the_batch_after_the_message_that_spent_it() {
    let entries = [Entry::Got { oob: false }, Entry::Got { oob: false },
        Entry::Got { oob: false }];
    let report = drive(0, 3, &entries, &[Some(4), Some(0), None]);
    assert_eq!(report.result, 2);
    assert_eq!(report.unreached, 1);
    assert!(report.copied_timeout);
}

#[test]
fn an_empty_batch_delivers_nothing_and_touches_no_user_memory() {
    let report = drive(0, 0, &[Entry::Got { oob: false }], &[None]);
    assert_eq!(report.result, 0);
    assert_eq!(report.unreached, 1);
    assert!(!report.copied_timeout);
}
