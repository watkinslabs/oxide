use super::*;
use crate::io_uring_abi::ops::{IORING_OP_SPLICE, IORING_OP_TEE};

fn sqe(op: u8) -> Sqe { Sqe { opcode: op, ..Sqe::default() } }

/// The io_uring-only bit must not reach the transfer: it is not one of the
/// flags the splice machinery defines, so a transfer handed the raw word
/// refuses the whole request and the caller sees `EINVAL` for a submission
/// that was correct.
#[test]
fn the_registered_file_bit_is_stripped_before_the_transfer_sees_the_flags() {
    let mut s = sqe(IORING_OP_SPLICE);
    s.op_flags = SPLICE_F_FD_IN_FIXED | 0x2;
    let sp = prep(&s).expect("valid");
    assert!(sp.fd_in_fixed);
    assert_eq!(sp.flags, 0x2);
    assert_eq!(sp.flags & SPLICE_F_FD_IN_FIXED, 0);
}

#[test]
fn an_ordinary_input_descriptor_is_not_marked_registered() {
    let mut s = sqe(IORING_OP_SPLICE);
    s.op_flags = SPLICE_F_ALL;
    s.splice_fd_in = 7;
    let sp = prep(&s).expect("valid");
    assert!(!sp.fd_in_fixed);
    assert_eq!(sp.fd_in, 7);
    assert_eq!(sp.flags, SPLICE_F_ALL);
}

#[test]
fn a_flag_bit_neither_side_defines_is_refused() {
    let mut s = sqe(IORING_OP_SPLICE);
    s.op_flags = 1 << 16;
    assert_eq!(prep(&s), Err(Errno::Einval));
    let mut t = sqe(IORING_OP_TEE);
    t.op_flags = 1 << 16;
    assert_eq!(prep(&t), Err(Errno::Einval));
}

/// A tee duplicates: neither description moves, so neither has a position an
/// offset could name. Accepting one and dropping it would answer a request the
/// caller did not make.
#[test]
fn a_tee_carrying_either_offset_is_refused() {
    let mut a = sqe(IORING_OP_TEE);
    a.addr = 1;
    assert_eq!(prep(&a), Err(Errno::Einval));
    let mut b = sqe(IORING_OP_TEE);
    b.off = 1;
    assert_eq!(prep(&b), Err(Errno::Einval));
    // Both zero is the only shape a tee has.
    assert!(prep(&sqe(IORING_OP_TEE)).is_ok());
}

/// A tee never reads an offset, so it must not report one either: a handler
/// that took `off_in`/`off_out` from the entry would be reading fields the
/// admission above just proved are zero, but a later change to that admission
/// must not silently give a tee positional behaviour.
#[test]
fn a_tee_reports_no_offsets() {
    let sp = prep(&sqe(IORING_OP_TEE)).expect("valid");
    assert_eq!(sp.off_in, None);
    assert_eq!(sp.off_out, None);
}

/// Only the sentinel means "the description's own position"; every other
/// value, zero included, is a real offset.
#[test]
fn the_offset_sentinel_is_distinguished_from_offset_zero() {
    let mut s = sqe(IORING_OP_SPLICE);
    s.addr = NO_OFFSET;
    s.off = 0;
    let sp = prep(&s).expect("valid");
    assert_eq!(sp.off_in, None);
    assert_eq!(sp.off_out, Some(0));

    s.addr = 4096;
    s.off = NO_OFFSET;
    let sp = prep(&s).expect("valid");
    assert_eq!(sp.off_in, Some(4096));
    assert_eq!(sp.off_out, None);
}

#[test]
fn the_length_and_input_descriptor_come_from_their_own_fields() {
    let mut s = sqe(IORING_OP_SPLICE);
    s.len = 8192;
    s.splice_fd_in = 3;
    s.fd = 9;
    let sp = prep(&s).expect("valid");
    assert_eq!(sp.len, 8192);
    // The entry's own `fd` is the OUTPUT and must not be read as the input.
    assert_eq!(sp.fd_in, 3);
}

#[test]
fn the_family_predicate_names_both_and_nothing_else() {
    assert!(is_splice_family(IORING_OP_SPLICE));
    assert!(is_splice_family(IORING_OP_TEE));
    assert!(!is_splice_family(crate::io_uring_abi::ops::IORING_OP_READ));
}

#[test]
fn the_valid_mask_is_the_transfer_flags_plus_the_one_ring_flag() {
    assert_eq!(SPLICE_VALID_FLAGS, 0xf | (1u32 << 31));
    assert_eq!(SPLICE_F_ALL, 0xf);
    assert_eq!(SPLICE_F_FD_IN_FIXED, 1 << 31);
}
