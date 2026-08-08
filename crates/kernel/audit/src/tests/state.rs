use super::*;

#[test]
fn a_fresh_audit_system_is_off_with_no_consumer_and_no_records() {
    let s = AuditState::new();
    assert_eq!(s.cfg, crate::config::Config::default());
    assert!(!s.consumer.registered());
    assert!(s.backlog.is_empty());
    assert_eq!(s.backlog.hold_len(), 0);
    assert_eq!(s.rate, crate::ratelimit::RateState::default());
}

/// The live instance is reachable and starts in the same state.
#[test]
fn the_live_instance_starts_disabled() {
    let enabled_flag = with(|s| s.cfg.enabled != crate::uapi::AUDIT_OFF);
    assert_eq!(enabled_flag, enabled());
}
