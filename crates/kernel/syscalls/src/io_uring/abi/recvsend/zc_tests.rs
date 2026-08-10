use super::*;

use crate::io_uring_abi::bundle::IORING_RECVSEND_BUNDLE;
use crate::io_uring_abi::ops::{IORING_OP_SEND, IORING_OP_SENDMSG, IOSQE_ASYNC};
use crate::io_uring_abi::recvsend::MULTISHOT;

/// Every bit of the zero-copy send's flag word, in exactly one of two states.
/// The word is not the plain send's: the usage report is defined here and
/// nowhere else, and the bundle and multishot bits are defined nowhere here.
#[test]
fn every_zero_copy_flag_is_either_performed_or_refused() {
    for op in [IORING_OP_SEND_ZC, IORING_OP_SENDMSG_ZC] {
        for bit in [POLL_FIRST, FIXED_BUF, SEND_ZC_REPORT_USAGE, SEND_VECTORIZED] {
            assert_eq!(admit(op, 0, bit, 0, 0), Ok(()), "op {op} bit {bit:#x}");
        }
        for bit in [IORING_RECVSEND_BUNDLE, MULTISHOT] {
            assert_eq!(admit(op, 0, bit, 0, 0), Err(Errno::Einval), "op {op} bit {bit:#x}");
        }
        for shift in 0..16u16 {
            let m = 1u16 << shift;
            if ZC_FLAGS & m != 0 { continue; }
            assert_eq!(admit(op, 0, m, 0, 0), Err(Errno::Einval), "op {op} bit {m:#x}");
        }
    }
}

/// The usage report belongs to this word and to no other: a plain send has no
/// notification for it to describe.
#[test]
fn the_usage_report_is_defined_here_and_not_on_the_plain_send() {
    assert_eq!(ZC_FLAGS & SEND_ZC_REPORT_USAGE, SEND_ZC_REPORT_USAGE);
    assert_eq!(crate::io_uring_abi::recvsend::SEND_FLAGS & SEND_ZC_REPORT_USAGE, 0);
    for op in [IORING_OP_SEND, IORING_OP_SENDMSG] {
        assert!(!is_zc(op));
        assert_eq!(admit(op, 0, 0xFFFF, 0, 0), Ok(()), "the ladder does not read a plain send");
    }
}

/// Silent success would suppress the send's own completion while the
/// notification still arrived, leaving the caller one completion it could not
/// match to anything.
#[test]
fn silent_success_is_refused_because_the_notification_would_still_arrive() {
    for op in [IORING_OP_SEND_ZC, IORING_OP_SENDMSG_ZC] {
        assert_eq!(admit(op, IOSQE_CQE_SKIP_SUCCESS, 0, 0, 0), Err(Errno::Einval), "op {op}");
        assert_eq!(admit(op, IOSQE_ASYNC, 0, 0, 0), Ok(()), "op {op}");
    }
}

/// A message-carrying send names its destination inside the header, so an
/// address or a descriptor slot beside it is a second answer.
#[test]
fn the_message_carrying_form_refuses_a_second_destination() {
    assert_eq!(admit(IORING_OP_SENDMSG_ZC, 0, 0, 0x1000, 0), Err(Errno::Einval));
    assert_eq!(admit(IORING_OP_SENDMSG_ZC, 0, 0, 0, 7), Err(Errno::Einval));
    // The plain form addresses its destination exactly that way.
    assert_eq!(admit(IORING_OP_SEND_ZC, 0, 0, 0x1000, 0), Ok(()));
}

/// The notification is routable on its own when the caller names it, so a
/// receive loop can tell "the send finished" from "the memory is free" without
/// tracking both against one identity.
#[test]
fn the_notification_takes_the_identity_the_entry_gives_it() {
    assert_eq!(notif(0xAA, 0xBB, 0), Notif { user_data: 0xBB, report_usage: false });
    assert_eq!(notif(0xAA, 0, 0), Notif { user_data: 0xAA, report_usage: false });
    assert!(notif(0xAA, 0, SEND_ZC_REPORT_USAGE).report_usage);
}

/// The usage word is silent unless it was asked for, so a caller that did not
/// ask can read the notification's result as a plain zero.
#[test]
fn the_usage_word_is_zero_unless_the_caller_asked_to_be_told() {
    assert_eq!(notif_res(false, true), 0);
    assert_eq!(notif_res(false, false), 0);
    assert_eq!(notif_res(true, false), 0);
    assert_eq!(notif_res(true, true), IORING_NOTIF_USAGE_ZC_COPIED as i32);
    // The report rides the sign bit: a caller reading it as a signed result
    // must not mistake it for an errno.
    assert!(notif_res(true, true) < 0);
}
