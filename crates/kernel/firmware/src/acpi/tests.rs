use super::{RsdpStatus, try_log_rsdp};

#[test]
fn absent_returns_absent() {
    // SAFETY: rsdp_va=0 path returns immediately; pointer is never dereferenced.
    assert_eq!(unsafe { try_log_rsdp(0) }, RsdpStatus::Absent);
}

#[test]
fn rsdp_status_distinct() {
    assert_ne!(RsdpStatus::Absent, RsdpStatus::BadSignature);
    assert_ne!(RsdpStatus::Logged, RsdpStatus::BadSignature);
}
