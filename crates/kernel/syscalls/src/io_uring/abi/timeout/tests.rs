use super::*;

/// A well-formed arming timeout: one timespec, nothing else set.
fn plain() -> Sqe {
    let mut s = Sqe::default();
    s.len = TIMEOUT_LEN;
    s.addr = 0x1000;
    s
}

#[test]
fn timeout_flag_values_are_the_uapi_bit_positions() {
    assert_eq!(IORING_TIMEOUT_ABS, 0x01);
    assert_eq!(IORING_TIMEOUT_UPDATE, 0x02);
    assert_eq!(IORING_TIMEOUT_BOOTTIME, 0x04);
    assert_eq!(IORING_TIMEOUT_REALTIME, 0x08);
    assert_eq!(IORING_LINK_TIMEOUT_UPDATE, 0x10);
    assert_eq!(IORING_TIMEOUT_ETIME_SUCCESS, 0x20);
    assert_eq!(IORING_TIMEOUT_MULTISHOT, 0x40);
    assert_eq!(IORING_TIMEOUT_IMMEDIATE_ARG, 0x80);
    assert_eq!(IORING_TIMEOUT_CLOCK_MASK, 0x0c);
    assert_eq!(IORING_TIMEOUT_UPDATE_MASK, 0x12);
}

#[test]
fn a_timeout_must_carry_exactly_one_timespec() {
    // `len` is a count of timespecs, not a byte length: 0 and 16 are both wrong.
    for len in [0u32, 2, 16] {
        let mut s = plain(); s.len = len;
        assert_eq!(prep_timeout(&s, false), Err(Errno::Einval), "len={}", len);
    }
    assert!(prep_timeout(&plain(), false).is_ok());
}

#[test]
fn the_reserved_words_must_be_zero() {
    for f in [|s: &mut Sqe| s.addr3 = 1, |s: &mut Sqe| s.pad2 = 1,
              |s: &mut Sqe| s.buf_index = 1, |s: &mut Sqe| s.splice_fd_in = 1] {
        let mut s = plain(); f(&mut s);
        assert_eq!(prep_timeout(&s, false), Err(Errno::Einval));
    }
}

#[test]
fn an_unknown_timeout_flag_is_refused_and_the_removal_bits_are_unknown_here() {
    let mut s = plain(); s.op_flags = 1 << 8;
    assert_eq!(prep_timeout(&s, false), Err(Errno::Einval));
    // UPDATE / LINK_TIMEOUT_UPDATE describe a removal, so an ARMING timeout
    // carrying them is malformed rather than quietly ignored.
    for f in [IORING_TIMEOUT_UPDATE, IORING_LINK_TIMEOUT_UPDATE] {
        let mut s = plain(); s.op_flags = f;
        assert_eq!(prep_timeout(&s, false), Err(Errno::Einval));
    }
}

#[test]
fn two_clocks_at_once_is_refused_and_one_selects_that_clock() {
    let mut s = plain(); s.op_flags = IORING_TIMEOUT_CLOCK_MASK;
    assert_eq!(prep_timeout(&s, false), Err(Errno::Einval));
    assert_eq!(clock_of(0), CLOCK_MONOTONIC);
    assert_eq!(clock_of(IORING_TIMEOUT_BOOTTIME), CLOCK_BOOTTIME);
    assert_eq!(clock_of(IORING_TIMEOUT_REALTIME), CLOCK_REALTIME);
}

#[test]
fn a_repeating_timeout_cannot_also_be_an_absolute_deadline() {
    let mut s = plain(); s.op_flags = IORING_TIMEOUT_MULTISHOT | IORING_TIMEOUT_ABS;
    assert_eq!(prep_timeout(&s, false), Err(Errno::Einval));
    let mut s = plain(); s.op_flags = IORING_TIMEOUT_MULTISHOT;
    assert!(prep_timeout(&s, false).is_ok());
}

#[test]
fn the_immediate_argument_is_the_nanosecond_count_itself() {
    let mut s = plain(); s.addr = 5_000_000;
    assert_eq!(prep_timeout(&s, false).unwrap().time, TimeArg::UserTimespec(5_000_000));
    s.op_flags = IORING_TIMEOUT_IMMEDIATE_ARG;
    assert_eq!(prep_timeout(&s, false).unwrap().time, TimeArg::Nanos(5_000_000));
}

#[test]
fn a_link_timeout_takes_no_completion_count() {
    let mut s = plain(); s.off = 3;
    assert!(prep_timeout(&s, false).is_ok(), "a plain timeout counts completions");
    assert_eq!(prep_timeout(&s, true), Err(Errno::Einval));
}

#[test]
fn a_bounded_multishot_stops_after_its_repeat_count_and_an_unbounded_one_does_not() {
    let mut s = plain(); s.op_flags = IORING_TIMEOUT_MULTISHOT; s.off = 3;
    let p = prep_timeout(&s, false).unwrap();
    assert_eq!((p.multishot, p.repeats, p.count), (true, 3, 3));
    let mut r = p.repeats;
    assert!(multishot_continues(p.count, &mut r));   // 3 -> 2
    assert!(multishot_continues(p.count, &mut r));   // 2 -> 1
    assert!(!multishot_continues(p.count, &mut r));  // 1 -> 0, done
    let mut r = 0;
    assert!(multishot_continues(0, &mut r), "count 0 repeats forever");
}

#[test]
fn a_single_shot_timeout_reports_no_repeats() {
    let mut s = plain(); s.off = 4;
    let p = prep_timeout(&s, false).unwrap();
    assert_eq!((p.multishot, p.repeats, p.count), (false, 0, 4));
}

#[test]
fn removal_carries_no_flags_at_all() {
    let s = Sqe { addr: 0xF00D, ..Sqe::default() };
    let p = prep_timeout_remove(&s).unwrap();
    assert_eq!((p.kind, p.target), (RemoveKind::Remove, 0xF00D));
    let mut s = s; s.op_flags = IORING_TIMEOUT_ABS;
    assert_eq!(prep_timeout_remove(&s), Err(Errno::Einval));
}

#[test]
fn the_update_form_selects_plain_or_link_and_bounds_its_own_flags() {
    let mut s = Sqe { addr: 1, ..Sqe::default() };
    s.op_flags = IORING_TIMEOUT_UPDATE;
    assert_eq!(prep_timeout_remove(&s).unwrap().kind, RemoveKind::Update);
    s.op_flags = IORING_LINK_TIMEOUT_UPDATE;
    assert_eq!(prep_timeout_remove(&s).unwrap().kind, RemoveKind::UpdateLink);
    s.op_flags = IORING_TIMEOUT_UPDATE | IORING_TIMEOUT_ABS | IORING_TIMEOUT_IMMEDIATE_ARG;
    let p = prep_timeout_remove(&s).unwrap();
    assert!(p.abs);
    assert_eq!(p.time, TimeArg::Nanos(0));
    // ETIME_SUCCESS / MULTISHOT describe an arming timeout, not an update.
    s.op_flags = IORING_TIMEOUT_UPDATE | IORING_TIMEOUT_MULTISHOT;
    assert_eq!(prep_timeout_remove(&s), Err(Errno::Einval));
    s.op_flags = IORING_TIMEOUT_UPDATE | IORING_TIMEOUT_CLOCK_MASK;
    assert_eq!(prep_timeout_remove(&s), Err(Errno::Einval));
}

#[test]
fn removal_reads_its_new_time_from_addr2_not_from_addr() {
    // `addr` names the timeout; `addr2` (the `off` word) carries the new time.
    // Reading the time from `addr` would re-arm against the user_data.
    let mut s = Sqe { addr: 0xAAAA, off: 0xBBBB, ..Sqe::default() };
    s.op_flags = IORING_TIMEOUT_UPDATE;
    let p = prep_timeout_remove(&s).unwrap();
    assert_eq!(p.target, 0xAAAA);
    assert_eq!(p.time, TimeArg::UserTimespec(0xBBBB));
}

#[test]
fn a_removal_cannot_name_a_registered_file_or_a_provided_buffer() {
    use crate::io_uring_abi::ops::{IOSQE_BUFFER_SELECT, IOSQE_FIXED_FILE};
    for f in [IOSQE_FIXED_FILE, IOSQE_BUFFER_SELECT] {
        let s = Sqe { addr: 1, flags: f, ..Sqe::default() };
        assert_eq!(prep_timeout_remove(&s), Err(Errno::Einval));
    }
}
