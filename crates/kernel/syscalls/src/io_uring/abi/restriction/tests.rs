use super::*;
use crate::io_uring_abi::ops::{IORING_OP_NOP, IORING_OP_READ, IOSQE_ASYNC, IOSQE_FIXED_FILE};
use crate::io_uring_abi::register_op::{IORING_REGISTER_BUFFERS, IORING_REGISTER_FILES};

#[test]
fn nothing_registered_permits_everything() {
    let r = Restrictions::default();
    assert!(!r.registered());
    assert!(r.allows_register(IORING_REGISTER_BUFFERS));
    assert!(r.allows_sqe(IORING_OP_READ, IOSQE_FIXED_FILE));
}

#[test]
fn an_empty_registration_forbids_everything() {
    // The dangerous misreading: "no entries" is not "no restrictions".
    let mut r = Restrictions::default();
    r.arm_empty();
    assert!(r.registered());
    assert!(!r.allows_register(IORING_REGISTER_BUFFERS));
    assert!(!r.allows_sqe(IORING_OP_NOP, 0));
}

#[test]
fn register_allow_list_admits_only_the_named_opcodes() {
    let mut r = Restrictions::default();
    r.apply(IORING_RESTRICTION_REGISTER_OP, IORING_REGISTER_FILES as u8).unwrap();
    assert!(r.allows_register(IORING_REGISTER_FILES));
    assert!(!r.allows_register(IORING_REGISTER_BUFFERS));
    // The SQE ladder is a separate arming: a register-only registration does
    // not silently forbid every submission.
    assert!(r.allows_sqe(IORING_OP_READ, 0));
}

#[test]
fn sqe_allow_list_admits_only_the_named_opcodes() {
    let mut r = Restrictions::default();
    r.apply(IORING_RESTRICTION_SQE_OP, IORING_OP_NOP).unwrap();
    assert!(r.allows_sqe(IORING_OP_NOP, 0));
    assert!(!r.allows_sqe(IORING_OP_READ, 0));
    assert!(r.allows_register(IORING_REGISTER_FILES));
}

#[test]
fn sqe_flag_rules_are_required_and_allowed_together() {
    let mut r = Restrictions::default();
    r.apply(IORING_RESTRICTION_SQE_OP, IORING_OP_READ).unwrap();
    r.apply(IORING_RESTRICTION_SQE_FLAGS_REQUIRED, IOSQE_FIXED_FILE).unwrap();
    // Required flag missing.
    assert!(!r.allows_sqe(IORING_OP_READ, 0));
    // Required flag present, and a required flag is implicitly allowed.
    assert!(r.allows_sqe(IORING_OP_READ, IOSQE_FIXED_FILE));
    // A flag outside allowed|required.
    assert!(!r.allows_sqe(IORING_OP_READ, IOSQE_FIXED_FILE | IOSQE_ASYNC));
    r.apply(IORING_RESTRICTION_SQE_FLAGS_ALLOWED, IOSQE_ASYNC).unwrap();
    assert!(r.allows_sqe(IORING_OP_READ, IOSQE_FIXED_FILE | IOSQE_ASYNC));
}

#[test]
fn out_of_range_and_unknown_restrictions_are_refused() {
    let mut r = Restrictions::default();
    assert_eq!(r.apply(IORING_RESTRICTION_REGISTER_OP, 200), Err(Errno::Einval));
    assert_eq!(r.apply(IORING_RESTRICTION_SQE_OP, 250), Err(Errno::Einval));
    assert_eq!(r.apply(IORING_RESTRICTION_LAST, 0), Err(Errno::Einval));
    // A refused entry leaves nothing armed, so a failed registration cannot
    // half-restrict a ring.
    assert!(!r.registered());
}

#[test]
fn restriction_wire_record_decodes_opcode_and_value() {
    let mut b = [0u8; RESTRICTION_BYTES as usize];
    b[0..2].copy_from_slice(&IORING_RESTRICTION_SQE_OP.to_le_bytes());
    b[2] = IORING_OP_READ;
    assert_eq!(decode_one(&b), Some((IORING_RESTRICTION_SQE_OP, IORING_OP_READ)));
    assert_eq!(decode_one(&b[..4]), None);
}
