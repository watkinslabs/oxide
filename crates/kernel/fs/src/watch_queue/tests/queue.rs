// Depth, whole-record reads, and the loss ordering that tells a reader where
// in the stream it missed something.

use super::*;
use crate::watch_queue::queue::WatchQueue;
use syscall::errno::Errno;

fn sized(nr: usize) -> WatchQueue {
    let q = WatchQueue::new();
    q.set_size(nr).expect("a depth inside the limits");
    q
}

fn key_record(subtype: u32, id: i32) -> [u8; KEY_NOTIFICATION_SIZE] {
    key_notification(subtype, id, 0, 0)
}

// The depth is settable once, rounded up to a whole page of notes, and only
// inside the limits.
#[test]
fn depth_rules() {
    let q = WatchQueue::new();
    assert_eq!(q.capacity(), 0, "a fresh queue has no depth");
    assert_eq!(q.set_size(0), Err(Errno::Einval));
    assert_eq!(q.set_size(WATCH_QUEUE_MAX_NOTES + 1), Err(Errno::Einval));
    assert_eq!(q.set_size(1), Ok(WATCH_QUEUE_NOTES_PER_PAGE),
        "a request is rounded UP to a whole page of notes, never down");
    assert_eq!(q.set_size(1), Err(Errno::Ebusy), "a second size is refused, not applied");
    let q2 = WatchQueue::new();
    assert_eq!(q2.set_size(WATCH_QUEUE_NOTES_PER_PAGE + 1), Ok(WATCH_QUEUE_NOTES_PER_PAGE * 2));
    assert_eq!(q2.set_size(WATCH_QUEUE_MAX_NOTES), Err(Errno::Ebusy));
}

// A queue that already has its notes is EBUSY whatever depth the second call
// names — the already-sized rung is ahead of the range rung, so an out-of-range
// second call does not report the depth as the reason it failed.
#[test]
fn a_second_size_is_ebusy_before_the_depth_is_ranged() {
    use crate::watch_queue::queue::admit_set_size;
    assert_eq!(admit_set_size(0, true), Err(Errno::Ebusy));
    assert_eq!(admit_set_size(WATCH_QUEUE_MAX_NOTES + 1, true), Err(Errno::Ebusy));
    assert_eq!(admit_set_size(0, false), Err(Errno::Einval));
    assert_eq!(admit_set_size(WATCH_QUEUE_MAX_NOTES + 1, false), Err(Errno::Einval));
}

// The admitted answer is the PAGES the depth costs, which is what the memory
// reservation is charged in — one page for anything up to a page of notes.
#[test]
fn the_admitted_depth_is_counted_in_whole_pages() {
    use crate::watch_queue::queue::admit_set_size;
    assert_eq!(admit_set_size(1, false), Ok(1));
    assert_eq!(admit_set_size(WATCH_QUEUE_NOTES_PER_PAGE, false), Ok(1));
    assert_eq!(admit_set_size(WATCH_QUEUE_NOTES_PER_PAGE + 1, false), Ok(2));
    assert_eq!(admit_set_size(WATCH_QUEUE_MAX_NOTES, false),
        Ok(WATCH_QUEUE_MAX_NOTES.div_ceil(WATCH_QUEUE_NOTES_PER_PAGE)));
}

// A queue with no depth accepts nothing, and the reader is told so — a
// notification is never dropped silently.
#[test]
fn a_queue_with_no_depth_loses_everything() {
    let q = WatchQueue::new();
    assert!(!q.post(&key_record(NOTIFY_KEY_REVOKED, 42)));
    assert!(q.readable(), "the loss itself is something to read");
    let out = q.read(64).expect("room for the loss record");
    let recs = records(&out);
    assert_eq!(recs.len(), 1);
    assert_eq!(head(recs[0]), (WATCH_TYPE_META, WATCH_META_LOSS_NOTIFICATION, WATCH_HEADER_SIZE as u32));
    assert!(!q.readable(), "the loss is reported once");
}

// Records come back whole, in order, and as many as fit.
#[test]
fn records_are_returned_whole_and_in_order() {
    let q = sized(8);
    for i in 0..3 { assert!(q.post(&key_record(NOTIFY_KEY_UPDATED, 100 + i))); }
    let out = q.read(KEY_NOTIFICATION_SIZE * 3).expect("room for all three");
    let recs = records(&out);
    assert_eq!(recs.len(), 3);
    for (i, r) in recs.iter().enumerate() {
        assert_eq!(head(r).0, WATCH_TYPE_KEY_NOTIFY);
        assert_eq!(key_fields(r).0, 100 + i as i32, "delivered oldest first");
    }
    assert!(q.is_empty());
    assert_eq!(q.read(64).expect("an empty queue is not an error"), alloc::vec::Vec::new());
}

// A buffer that cannot hold the first record is ENOBUFS: a truncated record
// would be mis-parsed, and the reader would never know.
#[test]
fn a_short_buffer_is_enobufs_not_a_partial_record() {
    let q = sized(8);
    q.post(&key_record(NOTIFY_KEY_UPDATED, 7));
    assert_eq!(q.read(KEY_NOTIFICATION_SIZE - 1), Err(Errno::Enobufs));
    assert_eq!(q.len(), 1, "the record is still there for a bigger buffer");
    let out = q.read(KEY_NOTIFICATION_SIZE).expect("an exact fit");
    assert_eq!(out.len(), KEY_NOTIFICATION_SIZE);
}

// A buffer that holds the first record but not the second returns the first
// and leaves the rest queued.
#[test]
fn a_partial_batch_leaves_the_rest_queued() {
    let q = sized(8);
    q.post(&key_record(NOTIFY_KEY_UPDATED, 1));
    q.post(&key_record(NOTIFY_KEY_UPDATED, 2));
    let out = q.read(KEY_NOTIFICATION_SIZE + 4).expect("room for one");
    assert_eq!(records(&out).len(), 1);
    assert_eq!(q.len(), 1);
}

// Overflowing the queue records a loss AFTER the last record that fit, so the
// reader sees the gap where it happened rather than at the front.
#[test]
fn a_loss_is_reported_after_the_records_that_survived() {
    let q = sized(1);
    let depth = q.capacity();
    for i in 0..depth { assert!(q.post(&key_record(NOTIFY_KEY_UPDATED, i as i32))); }
    assert!(!q.post(&key_record(NOTIFY_KEY_UPDATED, 999)), "the queue is full");

    // Everything that fit comes out first, and the read STOPS at the record
    // the loss follows.
    let out = q.read(KEY_NOTIFICATION_SIZE * (depth + 4)).expect("plenty of room");
    let recs = records(&out);
    assert_eq!(recs.len(), depth, "every queued record is delivered");
    assert!(recs.iter().all(|r| head(r).0 == WATCH_TYPE_KEY_NOTIFY));

    // The NEXT read opens with the loss note.
    let out = q.read(64).expect("room");
    let recs = records(&out);
    assert_eq!(head(recs[0]), (WATCH_TYPE_META, WATCH_META_LOSS_NOTIFICATION, WATCH_HEADER_SIZE as u32));
}

// A pending loss needs eight bytes to be reported; a buffer smaller than that
// is ENOBUFS rather than the loss being forgotten.
#[test]
fn a_loss_survives_a_buffer_too_small_to_report_it() {
    let q = WatchQueue::new();
    q.post(&key_record(NOTIFY_KEY_UPDATED, 5));
    assert_eq!(q.read(WATCH_HEADER_SIZE - 1), Err(Errno::Enobufs));
    assert!(q.readable(), "the loss is still pending");
    let out = q.read(WATCH_HEADER_SIZE).expect("exactly enough");
    assert_eq!(head(records(&out)[0]).1, WATCH_META_LOSS_NOTIFICATION);
}

// The record encoding: type and subtype share the first word, the length lives
// in `info`, and the key fields follow.
#[test]
fn record_encoding() {
    let r = key_notification(NOTIFY_KEY_LINKED, 0x1234_5678, 0x9abc, 0x7f00);
    assert_eq!(head(&r), (WATCH_TYPE_KEY_NOTIFY, NOTIFY_KEY_LINKED,
        KEY_NOTIFICATION_SIZE as u32 | 0x7f00));
    assert_eq!(key_fields(&r), (0x1234_5678, 0x9abc));
    assert_eq!(r.len(), KEY_NOTIFICATION_SIZE);

    let r = removal_record(0x4142_4344_4546_4748, 0x0300);
    assert_eq!(head(&r), (WATCH_TYPE_META, WATCH_META_REMOVAL_NOTIFICATION,
        WATCH_REMOVAL_SIZE as u32 | 0x0300));
    assert_eq!(u64::from_ne_bytes(r[8..].try_into().expect("eight bytes")), 0x4142_4344_4546_4748);

    let h = header(WATCH_TYPE_META, WATCH_META_LOSS_NOTIFICATION, WATCH_HEADER_SIZE, 0);
    assert_eq!(h, loss_record());
}

// Nothing waiting means an empty read, and a blocked reader is armed instead —
// the queue never reports end-of-file, because the kernel has not stopped
// being able to produce records.
#[test]
fn read_or_arm_runs_the_arm_only_when_empty() {
    let q = sized(4);
    let mut armed = 0;
    assert_eq!(q.read_or_arm(64, || armed += 1), Ok(None));
    assert_eq!(armed, 1);
    q.post(&key_record(NOTIFY_KEY_UPDATED, 3));
    let got = q.read_or_arm(64, || armed += 1).expect("readable");
    assert_eq!(records(got.as_deref().expect("records")).len(), 1);
    assert_eq!(armed, 1, "a queue with something in it does not park its reader");
}
