use super::*;
use crate::limits::DEFAULT_KMSG_BYTES;

#[test]
fn a_shutdown_is_not_recorded_by_default_but_a_panic_is() {
    let d = DEFAULT_MAX_REASON;
    assert!(should_capture(DumpReason::Panic, d));
    assert!(should_capture(DumpReason::Oops, d));
    assert!(!should_capture(DumpReason::Emerg, d));
    assert!(!should_capture(DumpReason::Shutdown, d));
}

#[test]
fn raising_the_ceiling_admits_the_quieter_reasons() {
    let all = DumpReason::Shutdown as u8;
    assert!(should_capture(DumpReason::Shutdown, all));
    assert!(should_capture(DumpReason::Panic, all));
}

#[test]
fn an_undefined_reason_is_never_recorded() {
    assert!(!should_capture(DumpReason::Undef, DumpReason::Shutdown as u8));
}

fn log() -> Vec<u8> { (0..200u32).map(|i| b'a' + (i % 26) as u8).collect() }

#[test]
fn a_record_leads_with_the_reason_then_the_log_tail() {
    let l = log();
    let out = compose(DumpReason::Panic, 3, &l, l.len(), DEFAULT_KMSG_BYTES, 1 << 20);
    assert!(out.starts_with(b"Panic#3 Part1\n"));
    assert_eq!(&out[14..], &l[..]);
}

#[test]
fn a_smaller_kmsg_bytes_really_does_shrink_the_record() {
    // The parameter is only worth publishing if it changes what a record
    // CONTAINS. Two captures over the same log, one bound at 32 bytes.
    let l = log();
    let big = compose(DumpReason::Panic, 1, &l, l.len(), 1024, 1 << 20);
    let small = compose(DumpReason::Panic, 1, &l, l.len(), 32, 1 << 20);
    assert_eq!(big.len(), 14 + l.len());
    assert_eq!(small.len(), 14 + 32);
    assert!(small.len() < big.len());
    // …and what survives is the NEWEST 32 bytes, not the oldest.
    assert_eq!(&small[14..], &l[l.len() - 32..]);
}

#[test]
fn the_zone_bounds_the_record_when_it_is_smaller_than_the_option() {
    let l = log();
    let out = compose(DumpReason::Oops, 1, &l, l.len(), DEFAULT_KMSG_BYTES, 80);
    // 80 bytes of room, 14 spent on the header line.
    assert_eq!(out.len(), 14 + (80 - 14));
}

#[test]
fn a_log_longer_than_what_is_still_resident_takes_what_is_there() {
    // The ring has wrapped: 10_000 bytes were logged, 200 survive.
    let l = log();
    let out = compose(DumpReason::Panic, 1, &l, 10_000, 1024, 1 << 20);
    assert_eq!(&out[14..], &l[..]);
}

#[test]
fn a_zero_bound_records_only_the_header() {
    let l = log();
    let out = compose(DumpReason::Panic, 1, &l, l.len(), 0, 1 << 20);
    assert_eq!(out, b"Panic#1 Part1\n".to_vec());
}

#[test]
fn no_backend_means_no_records_rather_than_a_failure() {
    // `capture` on a kernel with nothing registered must be a no-op, not a
    // fault on the crash path.
    capture(DumpReason::Panic, (1, 0), b"anything", 8);
    // Whether a backend was registered by another test in this process is
    // not this test's business; the call above completing is.
}
