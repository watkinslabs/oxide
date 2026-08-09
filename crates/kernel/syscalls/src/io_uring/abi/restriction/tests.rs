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

// --- the task form's wire record ----------------------------------------

fn task_hdr(flags: u16, nr: u16) -> [u8; TASK_RESTRICTION_HDR as usize] {
    let mut b = [0u8; TASK_RESTRICTION_HDR as usize];
    b[0..2].copy_from_slice(&flags.to_le_bytes());
    b[2..4].copy_from_slice(&nr.to_le_bytes());
    b
}

#[test]
fn the_task_record_header_carries_the_rule_count_not_nr_args() {
    // `nr_args` is always 1 for the task form; the number of rules is INSIDE
    // the record, which is the whole reason the record exists.
    assert_eq!(admit_task_header(&task_hdr(0, 0)), Ok(0));
    assert_eq!(admit_task_header(&task_hdr(0, 7)), Ok(7));
    assert_eq!(admit_task_header(&task_hdr(0, u16::MAX)), Ok(u16::MAX as u32));
}

#[test]
fn an_undefined_task_record_flag_is_refused() {
    // No flag is defined, so every bit set is a caller asking for a
    // confinement this kernel would not apply.
    for bit in 0..16 {
        assert_eq!(admit_task_header(&task_hdr(1 << bit, 1)), Err(Errno::Einval),
            "flag bit {bit} must not be accepted-and-ignored", bit = bit);
    }
}

#[test]
fn a_non_zero_reserved_word_in_the_task_record_is_refused() {
    for i in 4..TASK_RESTRICTION_HDR as usize {
        let mut b = task_hdr(0, 1);
        b[i] = 0xAA;
        assert_eq!(admit_task_header(&b), Err(Errno::Einval),
            "reserved byte {i} must be checked", i = i);
    }
}

#[test]
fn the_task_record_header_is_sixteen_bytes_and_the_rules_follow_it() {
    // {u16 flags, u16 nr_res, u32 resv[3]} = 16, and the flexible array
    // begins immediately after. Getting this wrong reads the first rule out
    // of the reserved words.
    assert_eq!(TASK_RESTRICTION_HDR, 16);
    assert_eq!(RESTRICTION_BYTES, 16);
}

#[test]
fn the_shared_builder_folds_a_whole_registration_in_order() {
    let built = Restrictions::build(&[
        (IORING_RESTRICTION_SQE_OP, IORING_OP_READ),
        (IORING_RESTRICTION_SQE_FLAGS_REQUIRED, IOSQE_FIXED_FILE),
    ]).expect("valid rules");
    assert!(built.allows_sqe(IORING_OP_READ, IOSQE_FIXED_FILE));
    assert!(!built.allows_sqe(IORING_OP_READ, 0));
    assert!(!built.allows_sqe(IORING_OP_NOP, IOSQE_FIXED_FILE));
    // Only the SQE ladder was armed.
    assert!(built.allows_register(IORING_REGISTER_FILES));
}

#[test]
fn the_shared_builder_arms_both_ladders_on_an_empty_registration() {
    // Ring form and task form must agree that no rules means "may do
    // nothing". A permissive answer here would silently unconfine a sandbox
    // that registered an empty allow-list on purpose.
    let built = Restrictions::build(&[]).expect("empty is legal");
    assert!(built.registered());
    assert!(!built.allows_register(IORING_REGISTER_FILES));
    assert!(!built.allows_sqe(IORING_OP_NOP, 0));
}

#[test]
fn the_shared_builder_refuses_a_bad_rule_and_returns_nothing_armed() {
    assert_eq!(Restrictions::build(&[(IORING_RESTRICTION_SQE_OP, 250)]), Err(Errno::Einval));
    assert_eq!(Restrictions::build(&[(IORING_RESTRICTION_LAST, 0)]), Err(Errno::Einval));
}
