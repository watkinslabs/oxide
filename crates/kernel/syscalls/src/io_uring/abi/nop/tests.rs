use super::*;

#[test]
fn a_bare_nop_reports_zero_and_asks_for_nothing() {
    let n = prep(0, 99, 3, 7, 8, false).unwrap();
    assert_eq!(n, Nop::default());
    assert_eq!(n.result, 0, "len is ignored unless a result was injected");
}

#[test]
fn an_injected_result_is_reported_verbatim() {
    assert_eq!(prep(IORING_NOP_INJECT_RESULT, 42, -1, 0, 0, false).unwrap().result, 42);
    // Including a negative one: the entry chooses the whole 32-bit value.
    assert_eq!(prep(IORING_NOP_INJECT_RESULT, u32::MAX, -1, 0, 0, false).unwrap().result, -1);
}

#[test]
fn an_unknown_nop_flag_is_einval() {
    assert_eq!(prep(1 << 6, 0, -1, 0, 0, true), Err(Errno::Einval));
    assert_eq!(prep(1 << 31, 0, -1, 0, 0, true), Err(Errno::Einval));
    // And the whole defined set together is fine.
    assert!(prep(NOP_FLAGS, 0, -1, 0, 0, true).is_ok());
}

/// The check that keeps a 32-byte request off a ring with nowhere to put the
/// second half — the caller would otherwise read whatever the next CQ slot
/// held as its payload.
#[test]
fn a_32_byte_completion_is_refused_on_a_ring_that_cannot_carry_one() {
    assert_eq!(prep(IORING_NOP_CQE32, 0, -1, 1, 2, false), Err(Errno::Einval));
    let n = prep(IORING_NOP_CQE32, 0, -1, 1, 2, true).unwrap();
    assert!(n.cqe32);
    assert_eq!(n.extra, [1, 2], "the payload is the entry's own two words");
}

#[test]
fn the_payload_words_are_only_read_when_a_32_byte_completion_was_asked_for() {
    let n = prep(0, 0, -1, 0xdead, 0xbeef, true).unwrap();
    assert!(!n.cqe32);
    assert_eq!(n.extra, [0, 0]);
}

#[test]
fn each_resolution_flag_sets_exactly_its_own_request() {
    let n = prep(IORING_NOP_FILE, 0, 4, 0, 0, false).unwrap();
    assert!(n.check_file && !n.fixed_file && !n.check_buffer);
    let n = prep(IORING_NOP_FIXED_FILE, 0, 4, 0, 0, false).unwrap();
    assert!(n.fixed_file && !n.check_file);
    let n = prep(IORING_NOP_FIXED_BUFFER, 0, 4, 0, 0, false).unwrap();
    assert!(n.check_buffer && !n.check_file);
}

/// Deferred completion is accepted and changes nothing about the record: an
/// entry that completes inline and one that completes through deferred work
/// post the same completion, so the flag names a scheduling preference the
/// caller cannot observe in the result.
#[test]
fn deferred_completion_is_accepted_and_leaves_the_record_alone() {
    assert_eq!(prep(IORING_NOP_TW, 0, -1, 0, 0, false).unwrap(), Nop::default());
}
