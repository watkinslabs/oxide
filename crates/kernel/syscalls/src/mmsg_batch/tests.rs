// The `recvmmsg` batch contract. These are the rules the slot file used to
// hold inside a `#[cfg(target_os = "oxide-kernel")]` module, where no hosted
// test could reach them — they were believed correct and never executed once.

use super::*;

use net::uapi::{MSG_CMSG_COMPAT, MSG_DONTWAIT, MSG_ERRQUEUE, MSG_PEEK, MSG_WAITFORONE};

use crate::msg_layout::{EntryAbi, MsgLayout, entry_layout};

use super::fake::{Entry, Fake, drive, drive_abi};

// The batch does not own the compat question any more — one owner does, for
// every message syscall — but the ANSWER it acts on is still part of this
// contract, so the rule is pinned where the batch reads it.
#[test]
fn the_compat_layout_is_refused_before_anything_else() {
    let native = EntryAbi::Native;
    assert_eq!(entry_layout(MSG_CMSG_COMPAT, native), Err(Errno::Einval));
    assert_eq!(entry_layout(MSG_CMSG_COMPAT | MSG_DONTWAIT, native), Err(Errno::Einval));
    assert_eq!(entry_layout(MSG_DONTWAIT | MSG_PEEK | MSG_WAITFORONE, native),
        Ok(MsgLayout::Native));
    assert_eq!(entry_layout(0, native), Ok(MsgLayout::Native));
}

// A compat batch does not refuse itself: the entry that set the flag is the
// one entitled to it, and the batch adopts the 32-bit shape before it reads
// the timeout, resolves the descriptor, or imports an entry.
#[test]
fn a_compat_batch_adopts_the_compat_layout_before_any_other_step() {
    let (result, fake) = drive_abi(MSG_CMSG_COMPAT, 2, Fake::queued(2), EntryAbi::Compat);
    assert_eq!(result, 2);
    assert_eq!(fake.layout, Some(MsgLayout::Compat));
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
    let mut fake = Fake::new(alloc::vec![Entry::Got { oob: false }, Entry::Got { oob: false },
        Entry::Got { oob: false }]);
    fake.remaining = alloc::vec![Some(9), Some(8), Some(7)];
    let (result, fake) = drive(0, 3, fake);
    assert_eq!(result, 3);
    assert_eq!(fake.latched, None);
    assert_eq!(fake.unreached, 0);
    assert!(fake.copied_timeout);
}

#[test]
fn urgent_data_ends_the_batch_with_what_it_already_has() {
    let (result, fake) = drive(0, 3, Fake::new(alloc::vec![Entry::Got { oob: false },
        Entry::Got { oob: true }, Entry::Got { oob: false }]));
    assert_eq!(result, 2, "the urgent message counts, and is the last");
    assert_eq!(fake.unreached, 1, "the entry after it is never touched");
    assert!(fake.copied_timeout);
}

#[test]
fn waitforone_drains_without_waiting_once_the_first_message_lands() {
    let (result, fake) = drive(MSG_WAITFORONE, 3, Fake::new(alloc::vec![Entry::Got { oob: false },
        Entry::Got { oob: false }, Entry::Failed(neg(Errno::Eagain))]));
    assert_eq!(fake.seen_flags, alloc::vec![0, MSG_DONTWAIT, MSG_DONTWAIT]);
    assert_eq!(result, 2, "the dry queue ends the batch at what it has");
    assert_eq!(fake.latched, None, "EAGAIN is not latched");
}

#[test]
fn a_first_entry_failure_is_the_whole_answer() {
    let (result, fake) = drive(0, 2, Fake::new(alloc::vec![Entry::Failed(neg(Errno::Ebadf)),
        Entry::Got { oob: false }]));
    assert_eq!(result, neg(Errno::Ebadf));
    assert_eq!(fake.latched, None, "there is no count to protect, so nothing is latched");
    assert_eq!(fake.unreached, 1);
    assert!(!fake.copied_timeout);
}

#[test]
fn a_later_failure_is_latched_behind_the_delivered_count() {
    let (result, fake) = drive(0, 3, Fake::new(alloc::vec![Entry::Got { oob: false },
        Entry::Failed(neg(Errno::Econnreset)), Entry::Got { oob: false }]));
    assert_eq!(result, 1);
    assert_eq!(fake.latched, Some(Errno::Econnreset.as_i32()),
        "the next call collects it, or getsockopt(SO_ERROR) does");
    assert_eq!(fake.unreached, 1);
}

#[test]
fn a_spent_timeout_ends_the_batch_after_the_message_that_spent_it() {
    let mut fake = Fake::new(alloc::vec![Entry::Got { oob: false }, Entry::Got { oob: false },
        Entry::Got { oob: false }]);
    fake.remaining = alloc::vec![Some(4), Some(0), None];
    let (result, fake) = drive(0, 3, fake);
    assert_eq!(result, 2);
    assert_eq!(fake.unreached, 1);
    assert!(fake.copied_timeout);
}

#[test]
fn an_empty_batch_delivers_nothing_and_touches_no_user_memory() {
    let (result, fake) = drive(0, 0, Fake::new(alloc::vec![Entry::Got { oob: false }]));
    assert_eq!(result, 0);
    assert_eq!(fake.unreached, 1);
    assert!(!fake.copied_timeout);
}

// ------------------------------------------- the order the rules compose in --

#[test]
fn the_compat_layout_outranks_the_timeout_the_descriptor_and_the_batch() {
    let mut fake = Fake::new(alloc::vec![Entry::Got { oob: false }]);
    fake.timeout_fault = true;
    fake.resolve = Err(neg(Errno::Ebadf));
    fake.pending = Errno::Econnreset.as_i32();
    let (result, fake) = drive(MSG_CMSG_COMPAT, 1, fake);
    assert_eq!(result, neg(Errno::Einval));
    assert!(!fake.resolved, "the descriptor is never touched");
    assert_eq!(fake.seen_flags.len(), 0, "no entry is imported");
}

#[test]
fn a_malformed_timeout_outranks_a_bad_descriptor() {
    let mut fake = Fake::new(alloc::vec![Entry::Got { oob: false }]);
    fake.timeout = Some((-1, 0));
    fake.resolve = Err(neg(Errno::Ebadf));
    let (result, fake) = drive(0, 1, fake);
    assert_eq!(result, neg(Errno::Einval), "the timeout is read before the descriptor");
    assert!(!fake.resolved);
}

#[test]
fn a_pending_error_is_reported_and_consumed_before_the_batch_runs() {
    let mut fake = Fake::new(alloc::vec![Entry::Got { oob: false }]);
    fake.pending = Errno::Econnrefused.as_i32();
    let (result, fake) = drive(0, 1, fake);
    assert_eq!(result, neg(Errno::Econnrefused));
    assert_eq!(fake.seen_flags.len(), 0, "no message is received");
    assert_eq!(fake.pending, 0, "reporting it consumes it");
    assert!(fake.resolved, "the descriptor is resolved first — EBADF outranks it");
}

#[test]
fn an_error_queue_read_reaches_the_queue_instead_of_the_pending_error() {
    let mut fake = Fake::new(alloc::vec![Entry::Got { oob: false }]);
    fake.pending = Errno::Econnrefused.as_i32();
    let (result, fake) = drive(MSG_ERRQUEUE, 1, fake);
    assert_eq!(result, 1);
    assert_eq!(fake.pending, Errno::Econnrefused.as_i32(), "the error stays for the reader");
}

#[test]
fn an_empty_batch_still_reports_a_pending_error() {
    let mut fake = Fake::new(alloc::vec![]);
    fake.pending = Errno::Econnreset.as_i32();
    let (result, _) = drive(0, 0, fake);
    assert_eq!(result, neg(Errno::Econnreset), "a zero-length batch is not a no-op");
}

#[test]
fn a_length_copyout_fault_follows_the_same_partial_batch_rule() {
    // Nothing delivered yet: the fault IS the answer.
    let mut fake = Fake::new(alloc::vec![Entry::Got { oob: false }, Entry::Got { oob: false }]);
    fake.publish_fault = Some((0, neg(Errno::Efault)));
    let (result, fake) = drive(0, 2, fake);
    assert_eq!(result, neg(Errno::Efault));
    assert_eq!(fake.latched, None);
    // After a delivery it becomes the latched error behind the count.
    let mut fake = Fake::new(alloc::vec![Entry::Got { oob: false }, Entry::Got { oob: false }]);
    fake.publish_fault = Some((1, neg(Errno::Efault)));
    let (result, fake) = drive(0, 2, fake);
    assert_eq!(result, 1);
    assert_eq!(fake.latched, Some(Errno::Efault.as_i32()));
}

// ------------------------------------- interrupted batches and SA_RESTART --
//
// A blocking receive that a signal interrupts reports the restart sentinel,
// not an errno, whenever the wait carried no socket timeout. The batch must
// hand that sentinel out unchanged when nothing was delivered: it is the
// syscall-return tail that decides between resuming the call and reporting
// EINTR, from the delivered handler's SA_RESTART bit. Flattening it here would
// make an SA_RESTART recvmmsg unresumable.

const RESTART: i64 = syscall::restart::restart_sys();

#[test]
fn an_interrupted_empty_batch_reports_the_restart_sentinel_unchanged() {
    let fake = Fake::new(alloc::vec![Entry::Failed(RESTART)]);
    let (result, fake) = drive(0, 4, fake);
    assert_eq!(result, RESTART, "the tail owns the restart decision, not the batch");
    assert!(syscall::restart::is_restart_sys(result));
    assert_eq!(fake.latched, None, "nothing was delivered, so nothing is remembered");
}

// The whole call restarts — there is no restart block for a socket receive,
// so the resumed call re-reads the caller's ORIGINAL timespec. Writing the
// remaining time back here would shorten every restarted batch.
#[test]
fn an_interrupted_empty_batch_leaves_the_callers_timeout_alone() {
    let mut fake = Fake::new(alloc::vec![Entry::Failed(RESTART)]);
    fake.timeout = Some((5, 0));
    fake.remaining = alloc::vec![Some(4_000_000_000)];
    let (result, fake) = drive(0, 4, fake);
    assert_eq!(result, RESTART);
    assert!(!fake.copied_timeout, "a restarted batch must see its full timeout again");
}

// With messages already delivered the count is the answer, and the sentinel
// is latched as the socket's pending error for the next call to collect —
// the same treatment any other late failure gets.
#[test]
fn a_delivered_prefix_outranks_a_later_interruption() {
    let fake = Fake::new(alloc::vec![Entry::Got { oob: false }, Entry::Failed(RESTART)]);
    let (result, fake) = drive(0, 4, fake);
    assert_eq!(result, 1);
    assert_eq!(fake.latched, Some(-RESTART as i32));
    assert!(fake.copied_timeout || fake.timeout.is_none());
}

// The decisive statement of what the sentinel buys. Only an ERESTART* value
// can resume; the batch's own EAGAIN and EINTR arms cannot, under any
// handler/SA_RESTART combination.
#[test]
fn only_the_sentinel_a_batch_returns_can_be_resumed_by_the_tail() {
    use syscall::restart::{RestartAction, signal_restart_action};
    assert_eq!(signal_restart_action(RESTART, true, true), RestartAction::RestartSame);
    assert_eq!(signal_restart_action(RESTART, true, false), RestartAction::Eintr);
    assert_eq!(signal_restart_action(RESTART, false, false), RestartAction::RestartSame);
    // Never through `restart_syscall(2)`: a socket receive keeps no restart
    // block, so a resumed batch re-runs the call itself.
    assert_ne!(signal_restart_action(RESTART, false, false), RestartAction::RestartBlockCall);
    for flat in [neg(Errno::Eagain), neg(Errno::Eintr)] {
        for handler in [false, true] {
            for sa_restart in [false, true] {
                assert_eq!(signal_restart_action(flat, handler, sa_restart), RestartAction::None,
                    "flat={flat} handler={handler} sa_restart={sa_restart}");
            }
        }
    }
}
