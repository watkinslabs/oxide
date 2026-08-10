use super::*;

use crate::io_uring_abi::ops::{IORING_OP_RECVMSG, IORING_OP_SENDMSG};
use crate::io_uring_abi::recvsend::{admit as recvsend_admit, POLL_FIRST};

const BASE: u64 = 0x7f00_0000;
const LEN: u64 = 4096;

#[test]
fn the_window_is_addressed_by_the_registered_address_not_by_an_offset() {
    assert_eq!(window(BASE, LEN, BASE, 128), Ok(Window { off: 0, len: 128 }));
    assert_eq!(window(BASE, LEN, BASE + 1024, 128), Ok(Window { off: 1024, len: 128 }));
}

#[test]
fn a_window_outside_the_registration_moves_no_bytes() {
    // Before it.
    assert_eq!(window(BASE, LEN, BASE - 1, 8), Err(Errno::Efault));
    // Running past its end by one byte.
    assert_eq!(window(BASE, LEN, BASE + LEN - 8, 9), Err(Errno::Efault));
    // Starting past its end.
    assert_eq!(window(BASE, LEN, BASE + LEN, 1), Err(Errno::Efault));
    // Wrapping.
    assert_eq!(window(BASE, LEN, u64::MAX, 2), Err(Errno::Efault));
}

/// The whole registration, and the empty window at its end, are both legal:
/// a zero-length transfer touches nothing but is not malformed.
#[test]
fn the_whole_registration_and_an_empty_window_are_both_placed() {
    assert_eq!(window(BASE, LEN, BASE, LEN as u32), Ok(Window { off: 0, len: LEN }));
    assert_eq!(window(BASE, LEN, BASE + LEN, 0), Ok(Window { off: LEN, len: 0 }));
}

/// The sparse slot names no frames at all, so nothing can be transferred
/// through it however small the window.
#[test]
fn an_empty_registration_slot_is_never_a_destination() {
    assert_eq!(window(0, 0, 0, 0), Err(Errno::Efault));
}

#[test]
fn a_registered_buffer_is_refused_on_a_message_carrying_opcode() {
    for op in [IORING_OP_SENDMSG, IORING_OP_RECVMSG] {
        assert_eq!(recvsend_admit(op, 0, FIXED_BUF, 0), Err(Errno::Einval), "op {op}");
    }
}

/// Two answers to "where do the bytes go" is a malformed entry, not a
/// precedence question.
#[test]
fn a_registered_buffer_and_a_second_destination_are_refused_together() {
    for (op, second) in [(IORING_OP_SEND, IORING_RECVSEND_BUNDLE),
                         (IORING_OP_SEND, SEND_VECTORIZED),
                         (IORING_OP_RECV, IORING_RECVSEND_BUNDLE),
                         (IORING_OP_RECV, MULTISHOT)] {
        assert_eq!(recvsend_admit(op, IOSQE_BUFFER_SELECT, FIXED_BUF | second, 0),
                   Err(Errno::Einval), "op {op} with {second:#x}");
        assert_eq!(recvsend_admit(op, 0, FIXED_BUF | second, 0),
                   Err(Errno::Einval), "op {op} with {second:#x}, no group");
    }
    for op in [IORING_OP_SEND, IORING_OP_RECV] {
        assert_eq!(recvsend_admit(op, IOSQE_BUFFER_SELECT, FIXED_BUF, 0), Err(Errno::Einval));
    }
}

/// Multishot is not a receive-only refusal by accident: the send side's
/// second destination is the vector, and each family refuses its own.
#[test]
fn each_family_refuses_the_pairing_its_own_flag_word_defines() {
    assert_eq!(admit(IORING_OP_SEND, 0, FIXED_BUF | SEND_VECTORIZED), Err(Errno::Einval));
    assert_eq!(admit(IORING_OP_RECV, 0, FIXED_BUF | MULTISHOT), Err(Errno::Einval));
}

#[test]
fn a_plain_registered_buffer_transfer_is_admitted() {
    for op in [IORING_OP_SEND, IORING_OP_RECV] {
        assert_eq!(recvsend_admit(op, 0, FIXED_BUF, 0), Ok(()), "op {op}");
        assert_eq!(recvsend_admit(op, 0, FIXED_BUF | POLL_FIRST, 0), Ok(()), "op {op} poll-first");
    }
}

#[test]
fn the_ladder_does_nothing_when_the_bit_is_absent() {
    assert_eq!(admit(IORING_OP_SENDMSG, IOSQE_BUFFER_SELECT, 0), Ok(()));
}
