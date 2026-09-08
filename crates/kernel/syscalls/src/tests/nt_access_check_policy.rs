//! The access-check argument ladder, in the order a caller can observe.

use super::*;

fn complete() -> Args {
    Args { descriptor: 0x1000, token: 0x40, desired_access: 0x0002_0000, mapping: 0x2000,
        privileges: 0x3000, return_length: 0x4000, granted: 0x5000, access_status: 0x6000 }
}

#[test]
fn a_complete_call_is_not_refused_at_the_argument_boundary() {
    assert_eq!(refusal(complete(), true), None);
}

#[test]
fn the_privilege_set_and_its_length_are_refused_before_anything_else() {
    let mut args = complete();
    args.privileges = 0;
    args.token = 0;
    assert_eq!(refusal(args, false), Some(STATUS_ACCESS_VIOLATION));
    let mut args = complete();
    args.return_length = 0;
    assert_eq!(refusal(args, true), Some(STATUS_ACCESS_VIOLATION));
}

#[test]
fn an_unreadable_descriptor_is_refused_before_the_token_handle() {
    let mut args = complete();
    args.token = 0;
    assert_eq!(refusal(args, false), Some(STATUS_ACCESS_VIOLATION));
}

#[test]
fn an_absent_descriptor_answers_for_the_descriptor_not_the_handle() {
    let mut args = complete();
    args.descriptor = 0;
    assert_eq!(refusal(args, false), Some(STATUS_ACCESS_VIOLATION));
}

#[test]
fn a_token_argument_naming_no_object_answers_for_the_handle() {
    let mut args = complete();
    args.token = 0;
    assert_eq!(refusal(args, true), Some(STATUS_INVALID_HANDLE));
}

#[test]
fn the_result_words_are_refused_after_the_handle() {
    let mut args = complete();
    args.granted = 0;
    assert_eq!(refusal(args, true), Some(STATUS_ACCESS_VIOLATION));
    let mut args = complete();
    args.access_status = 0;
    assert_eq!(refusal(args, true), Some(STATUS_ACCESS_VIOLATION));
}

#[test]
fn each_word_is_read_at_its_declared_position() {
    let record = args([1, 2, 3, 4, 5, 6], [7, 8]);
    assert_eq!(record.descriptor, 1);
    assert_eq!(record.token, 2);
    assert_eq!(record.desired_access, 3);
    assert_eq!(record.mapping, 4);
    assert_eq!(record.privileges, 5);
    assert_eq!(record.return_length, 6);
    assert_eq!(record.granted, 7);
    assert_eq!(record.access_status, 8);
}

#[test]
fn the_access_mask_is_the_low_half_of_its_slot() {
    let record = args([0, 0, 0x7fff_0000_0002_0000, 0, 0, 0], [0, 0]);
    assert_eq!(record.desired_access, 0x0002_0000);
}
