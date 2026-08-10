use super::*;

use crate::io_uring_abi::ops::{IORING_OP_READ, IORING_OP_RECV, IORING_OP_RECVMSG,
                               IORING_OP_SEND, IORING_OP_SENDMSG, IOSQE_BUFFER_SELECT};

/// Every bit the send/receive flag word defines, in exactly one of two
/// states: performed, or refused with `EINVAL`. There is no third column — a
/// bit accepted and then ignored is a silent downgrade, and the caller cannot
/// tell it happened because the completion looks like the one it asked for.
///
/// The list is exhaustive by construction: the loop walks bits 0..=15 and each
/// bit outside the union of the two masks is asserted refused, so a bit added
/// to the ABI without a verdict here fails this test rather than inheriting
/// one.
#[test]
fn every_defined_per_operation_flag_is_either_performed_or_refused() {
    // (bit, performed by send?, performed by recv?)
    const TABLE: &[(u16, bool, bool)] = &[
        (POLL_FIRST,            true,  true),
        (MULTISHOT,             false, true),
        (FIXED_BUF,             true,  true),
        (SEND_ZC_REPORT_USAGE,  false, false),
        (IORING_RECVSEND_BUNDLE, true, true),
        (SEND_VECTORIZED,       true,  false),
    ];
    for &(bit, send_ok, recv_ok) in TABLE {
        assert_eq!(SEND_FLAGS & bit != 0, send_ok, "send bit {bit:#x}");
        assert_eq!(RECV_FLAGS & bit != 0, recv_ok, "recv bit {bit:#x}");
    }
    let defined: u16 = TABLE.iter().fold(0, |a, &(b, _, _)| a | b);
    for bit in 0..16u16 {
        let m = 1u16 << bit;
        if defined & m != 0 { continue; }
        assert_eq!(admit(IORING_OP_SEND, 0, m, 0), Err(Errno::Einval), "send bit {m:#x}");
        assert_eq!(admit(IORING_OP_RECV, 0, m, 0), Err(Errno::Einval), "recv bit {m:#x}");
    }
    // Both masks live inside the sixteen bits the entry carries.
    assert_eq!((SEND_FLAGS | RECV_FLAGS) & !((1u16 << 6) - 1), 0);
}

/// The zero-copy usage report names a NOTIFICATION completion — the second
/// completion a zero-copy send posts once the payload has left the caller's
/// memory. A plain send posts no such completion, so the bit describes an
/// answer this entry can never give and is refused on all four opcodes rather
/// than accepted and dropped.
#[test]
fn the_zero_copy_usage_report_is_not_a_plain_send_flag() {
    for op in [IORING_OP_SEND, IORING_OP_SENDMSG, IORING_OP_RECV, IORING_OP_RECVMSG] {
        assert_eq!(admit(op, 0, SEND_ZC_REPORT_USAGE, 0), Err(Errno::Einval), "op {op}");
        assert_eq!(admit(op, IOSQE_BUFFER_SELECT, SEND_ZC_REPORT_USAGE, 0), Err(Errno::Einval),
                   "op {op} with a group");
    }
}

/// A segment vector is the send family's shape: a receive never reads `addr`
/// as one, so the bit is not merely inert there but malformed.
#[test]
fn the_vectorized_bit_is_not_a_receive_flag() {
    for op in [IORING_OP_RECV, IORING_OP_RECVMSG] {
        assert_eq!(admit(op, 0, SEND_VECTORIZED, 0), Err(Errno::Einval), "op {op}");
    }
    assert_eq!(admit(IORING_OP_SEND, 0, SEND_VECTORIZED, 0), Ok(()));
    assert!(vectorized_send(IORING_OP_SEND, SEND_VECTORIZED));
    // A message-carrying send already describes a vector, so the bit names no
    // second behaviour there.
    assert!(!vectorized_send(IORING_OP_SENDMSG, SEND_VECTORIZED));
    assert!(!vectorized_send(IORING_OP_SEND, 0));
}

#[test]
fn multishot_is_not_a_send_flag() {
    for op in [IORING_OP_SEND, IORING_OP_SENDMSG] {
        assert_eq!(admit(op, IOSQE_BUFFER_SELECT, MULTISHOT, 0), Err(Errno::Einval));
        assert!(!multishot(op, IOSQE_BUFFER_SELECT, MULTISHOT));
    }
}

#[test]
fn multishot_needs_a_provided_buffer_group() {
    // Without a group the second delivery has nowhere to land but on top of
    // the first.
    assert_eq!(admit(IORING_OP_RECV, 0, MULTISHOT, 0), Err(Errno::Einval));
    assert_eq!(admit(IORING_OP_RECV, IOSQE_BUFFER_SELECT, MULTISHOT, 0), Ok(()));
    assert!(!multishot(IORING_OP_RECV, 0, MULTISHOT));
    assert!(multishot(IORING_OP_RECV, IOSQE_BUFFER_SELECT, MULTISHOT));
}

#[test]
fn multishot_refuses_a_wait_for_the_whole_buffer() {
    const MSG_WAITALL_BIT: u32 = 0x100;
    assert_eq!(admit(IORING_OP_RECV, IOSQE_BUFFER_SELECT, MULTISHOT, MSG_WAITALL_BIT),
               Err(Errno::Einval));
    // Without multishot the same message flag is the caller's business.
    assert_eq!(admit(IORING_OP_RECV, IOSQE_BUFFER_SELECT, 0, MSG_WAITALL_BIT), Ok(()));
}

#[test]
fn a_bundle_is_refused_on_the_message_carrying_opcodes() {
    assert_eq!(admit(IORING_OP_SENDMSG, IOSQE_BUFFER_SELECT, IORING_RECVSEND_BUNDLE, 0),
               Err(Errno::Einval));
    assert_eq!(admit(IORING_OP_RECVMSG, IOSQE_BUFFER_SELECT, IORING_RECVSEND_BUNDLE, 0),
               Err(Errno::Einval));
    assert_eq!(admit(IORING_OP_SEND, IOSQE_BUFFER_SELECT, IORING_RECVSEND_BUNDLE, 0), Ok(()));
    assert_eq!(admit(IORING_OP_RECV, IOSQE_BUFFER_SELECT, IORING_RECVSEND_BUNDLE, 0), Ok(()));
}

/// A message-carrying receive stays armed the same way the plain one does.
/// It cannot write a header back per delivery — the caller has moved on by
/// then — so each delivery frames its own header inside the buffer it landed
/// in, and the entry's `msghdr` supplies only the two capacities.
#[test]
fn multishot_is_performed_on_the_message_carrying_receive() {
    assert_eq!(admit(IORING_OP_RECVMSG, IOSQE_BUFFER_SELECT, MULTISHOT, 0), Ok(()));
    assert!(multishot(IORING_OP_RECVMSG, IOSQE_BUFFER_SELECT, MULTISHOT));
    assert!(!multishot(IORING_OP_RECVMSG, 0, MULTISHOT));
    assert!(defers_before_issue(IORING_OP_RECVMSG, IOSQE_BUFFER_SELECT, MULTISHOT));
}

#[test]
fn an_opcode_outside_the_family_does_not_read_the_word() {
    // `ioprio` really is a priority on a read: refusing a bit there would
    // refuse a valid submission.
    assert!(!reads_ioprio(IORING_OP_READ));
    assert_eq!(admit(IORING_OP_READ, 0, 0xFFFF, 0), Ok(()));
    assert!(!poll_first(IORING_OP_READ, POLL_FIRST));
    assert!(!multishot(IORING_OP_READ, IOSQE_BUFFER_SELECT, MULTISHOT));
}

#[test]
fn poll_first_is_read_by_the_whole_family() {
    for op in [IORING_OP_SEND, IORING_OP_SENDMSG, IORING_OP_RECV, IORING_OP_RECVMSG] {
        assert!(poll_first(op, POLL_FIRST), "op {op}");
        assert!(!poll_first(op, 0), "op {op}");
        assert_eq!(admit(op, 0, POLL_FIRST, 0), Ok(()));
    }
}

/// Both behaviours outlive the submission that asked for them, so neither may
/// be attempted inline: a poll-first entry armed after an attempt has already
/// made the attempt it asked to avoid, and a multishot entry run inline posts
/// one completion and is gone.
#[test]
fn both_behaviours_keep_the_entry_out_of_the_submitting_task() {
    assert!(defers_before_issue(IORING_OP_SEND, 0, POLL_FIRST));
    assert!(defers_before_issue(IORING_OP_RECV, 0, POLL_FIRST));
    assert!(defers_before_issue(IORING_OP_RECV, IOSQE_BUFFER_SELECT, MULTISHOT));
    // An ordinary transfer still runs where it was submitted.
    assert!(!defers_before_issue(IORING_OP_RECV, IOSQE_BUFFER_SELECT, 0));
    assert!(!defers_before_issue(IORING_OP_SEND, 0, 0));
    assert!(!defers_before_issue(IORING_OP_READ, 0, POLL_FIRST));
}

#[test]
fn a_delivery_that_left_data_queued_keeps_the_request_running() {
    assert_eq!(step(64, 0, true), Step::More);
    assert_eq!(step(1, 5, true), Step::More);
}

/// A delivery that drained the socket reports itself and then waits. Taking
/// another pass would draw a buffer out of the caller's group, find nothing,
/// and hand it straight back — which is the cost the queue-length report
/// exists to avoid.
#[test]
fn a_delivery_that_drained_the_socket_posts_and_then_waits() {
    assert_eq!(step(64, 0, false), Step::PostThenWait);
    assert_eq!(step(1, MULTISHOT_MAX_RETRY - 1, false), Step::PostThenWait);
}

#[test]
fn nothing_to_deliver_arms_the_description_and_posts_nothing() {
    assert_eq!(step(-(Errno::Eagain.as_i32() as i64), 0, true), Step::Wait);
    assert_eq!(step(-(Errno::Eagain.as_i32() as i64), 0, false), Step::Wait);
}

/// The queue-length report is a RECEIVE completion's flag: a send never
/// carries it, and a receive that left nothing queued does not either.
#[test]
fn the_queue_report_rides_only_a_receive_that_left_data_behind() {
    use crate::io_uring_abi::ops::IORING_CQE_F_SOCK_NONEMPTY;
    for op in [IORING_OP_RECV, IORING_OP_RECVMSG] {
        assert_eq!(sock_nonempty(op, 1), IORING_CQE_F_SOCK_NONEMPTY, "op {op}");
        assert_eq!(sock_nonempty(op, 0), 0, "op {op}");
    }
    for op in [IORING_OP_SEND, IORING_OP_SENDMSG, IORING_OP_READ] {
        assert_eq!(sock_nonempty(op, 4096), 0, "op {op}");
    }
}

/// The three ways a multishot receive ends, each reporting WHY in the
/// terminal completion: the peer finished, the group ran dry, or the
/// description failed.
#[test]
fn every_ending_is_a_terminal_completion_carrying_its_reason() {
    assert_eq!(step(0, 3, true), Step::Done(0));
    for e in [Errno::Enobufs, Errno::Econnreset, Errno::Ebadf, Errno::Enotsock] {
        let r = -(e.as_i32() as i64);
        assert_eq!(step(r, 0, true), Step::Done(r), "errno {e:?}");
    }
}

/// A socket delivering without pause must not hold its worker: the run is
/// bounded, and the request goes back on the queue still armed.
#[test]
fn a_bounded_run_of_passes_yields_the_worker() {
    assert_eq!(step(64, MULTISHOT_MAX_RETRY - 2, true), Step::More);
    assert_eq!(step(64, MULTISHOT_MAX_RETRY - 1, true), Step::Yield);
    assert_eq!(step(64, MULTISHOT_MAX_RETRY, true), Step::Yield);
    // A yield still reports the bytes it moved; only `Wait` posts nothing.
    assert_ne!(step(64, MULTISHOT_MAX_RETRY, true), Step::Wait);
}

/// Every pass runs without sleeping: the pass that finds nothing arms the
/// description, which is what makes one submission serve many deliveries
/// without holding a worker asleep between them.
#[test]
fn a_pass_never_sleeps_on_the_description() {
    assert_eq!(pass_msg_flags(0) & MSG_DONTWAIT, MSG_DONTWAIT);
    // The caller's own message flags survive.
    assert_eq!(pass_msg_flags(0x2) & 0x2, 0x2);
}
