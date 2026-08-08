use super::*;

use crate::io_uring_abi::ops::IOSQE_CQE_SKIP_SUCCESS;

#[test]
fn poll_flag_values_are_the_uapi_bit_positions() {
    assert_eq!(IORING_POLL_ADD_MULTI, 0x1);
    assert_eq!(IORING_POLL_UPDATE_EVENTS, 0x2);
    assert_eq!(IORING_POLL_UPDATE_USER_DATA, 0x4);
    assert_eq!(IORING_POLL_ADD_LEVEL, 0x8);
    assert_eq!(POLL_NVAL, 0x20);
}

#[test]
fn the_event_mask_comes_from_the_flags_word_and_the_poll_flags_from_len() {
    // Reading these the other way round arms a poll for `IORING_POLL_*` bit
    // values and mistakes a readiness mask for poll flags.
    let mut s = Sqe::default();
    s.op_flags = vfs::POLL_IN;
    s.len = IORING_POLL_ADD_MULTI;
    let p = prep_poll_add(&s).unwrap();
    assert_eq!(p.events & vfs::POLL_IN, vfs::POLL_IN);
    assert!(p.multishot);
    assert_eq!(p.events & vfs::POLL_OUT, 0);
}

#[test]
fn an_error_a_hangup_and_an_invalid_description_are_always_reported() {
    let mut s = Sqe::default();
    s.op_flags = vfs::POLL_IN;
    let p = prep_poll_add(&s).unwrap();
    for bit in [vfs::POLL_ERR, vfs::POLL_HUP, POLL_NVAL, vfs::POLL_RDHUP] {
        assert_ne!(p.events & bit, 0, "bit {:#x} must be armed unasked", bit);
    }
}

#[test]
fn a_poll_takes_no_buffer_no_offset_and_no_address() {
    for f in [|s: &mut Sqe| s.buf_index = 1, |s: &mut Sqe| s.off = 1, |s: &mut Sqe| s.addr = 1] {
        let mut s = Sqe::default(); f(&mut s);
        assert_eq!(prep_poll_add(&s), Err(Errno::Einval));
    }
}

#[test]
fn an_unknown_poll_flag_is_refused() {
    let mut s = Sqe::default();
    s.len = 1 << 4;
    assert_eq!(prep_poll_add(&s), Err(Errno::Einval));
}

#[test]
fn a_repeating_poll_cannot_also_ask_for_silence_on_success() {
    let mut s = Sqe::default();
    s.len = IORING_POLL_ADD_MULTI;
    s.flags = IOSQE_CQE_SKIP_SUCCESS;
    assert_eq!(prep_poll_add(&s), Err(Errno::Einval));
    s.len = 0;
    assert!(prep_poll_add(&s).is_ok(), "a one-shot poll may be silent");
}

#[test]
fn a_removal_with_no_replacement_is_a_cancellation() {
    let s = Sqe { addr: 0xF00D, ..Sqe::default() };
    let u = prep_poll_remove(&s).unwrap();
    assert!(u.is_removal());
    assert_eq!(u.target, 0xF00D);
}

#[test]
fn staying_armed_says_nothing_without_a_replacement_to_apply_it_to() {
    let mut s = Sqe::default();
    s.len = IORING_POLL_ADD_MULTI;
    assert_eq!(prep_poll_remove(&s), Err(Errno::Einval));
    s.len = IORING_POLL_ADD_MULTI | IORING_POLL_UPDATE_EVENTS;
    assert!(prep_poll_remove(&s).unwrap().multishot);
}

#[test]
fn a_replacement_word_the_caller_did_not_ask_to_apply_is_refused() {
    // Silently ignoring these would tell a caller its update landed.
    let mut s = Sqe { off: 7, ..Sqe::default() };
    s.len = IORING_POLL_UPDATE_EVENTS;
    s.op_flags = vfs::POLL_IN;
    assert_eq!(prep_poll_remove(&s), Err(Errno::Einval), "off without UPDATE_USER_DATA");
    let mut s = Sqe::default();
    s.len = IORING_POLL_UPDATE_USER_DATA;
    s.op_flags = vfs::POLL_IN;
    assert_eq!(prep_poll_remove(&s), Err(Errno::Einval), "events without UPDATE_EVENTS");
}

#[test]
fn both_replacements_decode_together() {
    let mut s = Sqe { addr: 1, off: 2, ..Sqe::default() };
    s.len = IORING_POLL_UPDATE_EVENTS | IORING_POLL_UPDATE_USER_DATA;
    s.op_flags = vfs::POLL_OUT;
    let u = prep_poll_remove(&s).unwrap();
    assert_eq!(u.target, 1);
    assert_eq!(u.user_data, Some(2));
    assert_eq!(u.events.unwrap() & vfs::POLL_OUT, vfs::POLL_OUT);
    assert!(!u.is_removal());
}

#[test]
fn a_removal_takes_no_buffer_and_no_splice_descriptor() {
    for f in [|s: &mut Sqe| s.buf_index = 1, |s: &mut Sqe| s.splice_fd_in = 1] {
        let mut s = Sqe::default(); f(&mut s);
        assert_eq!(prep_poll_remove(&s), Err(Errno::Einval));
    }
}

#[test]
fn only_the_asked_for_readiness_is_reported() {
    assert_eq!(poll_hit(vfs::POLL_OUT, vfs::POLL_IN | POLL_ALWAYS), None);
    assert_eq!(poll_hit(vfs::POLL_IN | vfs::POLL_OUT, vfs::POLL_IN | POLL_ALWAYS), Some(vfs::POLL_IN));
    assert_eq!(poll_hit(vfs::POLL_HUP, vfs::POLL_IN | POLL_ALWAYS), Some(vfs::POLL_HUP));
}

#[test]
fn a_repeating_poll_stops_at_a_hangup_rather_than_spinning_on_it() {
    assert!(poll_rearms(true, vfs::POLL_IN));
    assert!(!poll_rearms(true, vfs::POLL_HUP), "a hangup never goes away");
    assert!(!poll_rearms(true, vfs::POLL_ERR));
    assert!(!poll_rearms(false, vfs::POLL_IN), "a one-shot poll never re-arms");
}

#[test]
fn a_retry_waits_for_the_direction_the_operation_needs() {
    assert_ne!(retry_mask(true) & vfs::POLL_IN, 0);
    assert_eq!(retry_mask(true) & vfs::POLL_OUT, 0);
    assert_ne!(retry_mask(false) & vfs::POLL_OUT, 0);
    assert_eq!(retry_mask(false) & vfs::POLL_IN, 0);
    // Both must wake on a hangup, or a retry against a closed peer waits
    // for a readiness that can never arrive.
    for reads in [true, false] { assert_ne!(retry_mask(reads) & vfs::POLL_HUP, 0); }
}
