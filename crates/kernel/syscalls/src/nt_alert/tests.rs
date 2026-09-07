//! Alert-by-thread-id status and argument admission.

use super::*;

#[test]
fn a_satisfied_alert_wait_reports_alerted_rather_than_success() {
    // The caller distinguishes a wake from an expiry by this status, and
    // folds it to success itself; plain success here would be a wake the
    // address-wait layer could not tell from "the value already changed".
    assert_eq!(wait_status(sched::WaitOutcome::Ready), STATUS_ALERTED);
    assert_ne!(STATUS_ALERTED, STATUS_SUCCESS);
}

#[test]
fn an_expired_alert_wait_reports_a_timeout() {
    assert_eq!(wait_status(sched::WaitOutcome::TimedOut), STATUS_TIMEOUT);
}

#[test]
fn a_signal_wakeup_still_reports_alerted() {
    // The flag is consumed by the predicate, so an interruption that races a
    // real alert must not be reported as an expiry.
    assert_eq!(wait_status(sched::WaitOutcome::Interrupted), STATUS_ALERTED);
}

#[test]
fn a_zero_or_oversized_thread_id_names_no_thread() {
    assert!(!plausible_thread_id(0));
    assert!(!plausible_thread_id(0x1_0000_0000));
    assert!(plausible_thread_id(1));
    assert!(plausible_thread_id(u32::MAX as u64));
}

#[test]
fn the_alert_status_values_match_the_published_codes() {
    assert_eq!(STATUS_ALERTED, 0x0000_0101);
    assert_eq!(STATUS_TIMEOUT, 0x0000_0102);
    assert_eq!(STATUS_INVALID_CID, 0xc000_000b);
}
