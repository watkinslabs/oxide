//! Thread alert-flag contract: raise, absorb, consume, and expiry.

use super::NtAlert;

#[test]
fn a_cleared_flag_reports_no_alert_and_consumes_nothing() {
    let alert = NtAlert::new();
    assert!(!alert.is_alerted());
    assert!(!alert.consume());
}

#[test]
fn an_alert_raised_before_the_wait_is_not_lost() {
    let alert = NtAlert::new();
    assert!(alert.alert());
    // A deadline already in the past must still report the pending alert:
    // the flag outranks expiry, which is what makes the primitive lossless.
    assert!(matches!(unsafe { alert.wait(10, || 10) }, crate::WaitOutcome::Ready));
    assert!(!alert.is_alerted());
}

#[test]
fn a_second_alert_is_absorbed_and_one_wait_consumes_one_flag() {
    let alert = NtAlert::new();
    assert!(alert.alert());
    assert!(!alert.alert());
    assert!(alert.consume());
    assert!(!alert.consume());
}

#[test]
fn an_unalerted_wait_reports_the_expired_deadline() {
    let alert = NtAlert::new();
    assert!(matches!(unsafe { alert.wait(10, || 10) }, crate::WaitOutcome::TimedOut));
}
