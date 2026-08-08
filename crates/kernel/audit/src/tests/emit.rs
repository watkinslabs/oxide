use super::*;
use crate::config::Field;
use crate::consumer::Consumer;
use crate::record::Record;
use crate::state::AuditState;
use alloc::vec::Vec;

fn rec() -> Record { Record { ty: 1331, text: Vec::from(*b"resp=2") } }

fn with_consumer() -> AuditState {
    let mut s = AuditState::new();
    s.consumer = Consumer { pid: 5, port_id: 9, route: 0 };
    s
}

#[test]
fn a_record_reaches_the_queue_when_a_consumer_is_registered() {
    let mut s = with_consumer();
    assert_eq!(admit(&mut s, rec(), 0), Ok(Admitted::Queued));
    assert_eq!(s.backlog.len(), 1);
    assert_eq!(s.backlog.hold_len(), 0);
    assert_eq!(s.cfg.lost, 0);
}

/// Without a consumer the record is parked, not dropped: a daemon that starts
/// after the kernel still needs to see what happened before it.
#[test]
fn a_record_is_held_when_nobody_is_registered() {
    let mut s = AuditState::new();
    assert_eq!(admit(&mut s, rec(), 0), Ok(Admitted::Held));
    assert_eq!(s.backlog.hold_len(), 1);
    assert_eq!(s.backlog.len(), 0);
}

/// A refused record is COUNTED. An uncounted drop is worse than no log: the
/// consumer would believe it had seen everything.
#[test]
fn a_backlog_refusal_is_counted_lost() {
    let mut s = with_consumer();
    crate::config::set(&mut s.cfg, Field::BacklogLimit, 2).unwrap();
    for _ in 0..3 { assert_eq!(admit(&mut s, rec(), 0), Ok(Admitted::Queued)); }
    assert_eq!(admit(&mut s, rec(), 0), Err(Refusal::BacklogFull));
    assert_eq!(s.backlog.len(), 3, "the refused record was not queued");
    assert_eq!(s.cfg.lost, 1);
    assert_eq!(admit(&mut s, rec(), 0), Err(Refusal::BacklogFull));
    assert_eq!(s.cfg.lost, 2);
}

#[test]
fn the_hold_queue_is_bounded_and_its_refusals_are_counted_too() {
    let mut s = AuditState::new();
    crate::config::set(&mut s.cfg, Field::BacklogLimit, 1).unwrap();
    assert_eq!(admit(&mut s, rec(), 0), Ok(Admitted::Held));
    assert_eq!(admit(&mut s, rec(), 0), Ok(Admitted::Held));
    assert_eq!(admit(&mut s, rec(), 0), Err(Refusal::BacklogFull));
    assert_eq!(s.cfg.lost, 1);
    assert_eq!(s.backlog.hold_len(), 2);
}

/// A flood cannot exhaust memory: the rate limit refuses before the queue even
/// sees the record, and every refusal is counted.
#[test]
fn a_flood_is_bounded_by_the_rate_limit_and_fully_accounted() {
    let mut s = with_consumer();
    crate::config::set(&mut s.cfg, Field::RateLimit, 4).unwrap();
    crate::config::set(&mut s.cfg, Field::BacklogLimit, 0).unwrap();
    let mut queued = 0;
    for _ in 0..1_000 {
        if admit(&mut s, rec(), 500) == Ok(Admitted::Queued) { queued += 1; }
    }
    assert_eq!(queued, 3, "three records fit the window");
    assert_eq!(s.backlog.len(), 3);
    assert_eq!(s.cfg.lost, 997, "every refusal is counted");
}

#[test]
fn a_rate_limited_record_is_refused_before_the_queue() {
    let mut s = with_consumer();
    crate::config::set(&mut s.cfg, Field::RateLimit, 1).unwrap();
    assert_eq!(admit(&mut s, rec(), 0), Err(Refusal::RateLimited));
    assert_eq!(s.backlog.len(), 0);
    assert_eq!(s.cfg.lost, 1);
}

/// An unlimited backlog admits without bound, which is what a zero limit
/// means — the rate limit is then the only ceiling.
#[test]
fn a_zero_backlog_limit_never_refuses() {
    let mut s = with_consumer();
    crate::config::set(&mut s.cfg, Field::BacklogLimit, 0).unwrap();
    for _ in 0..500 { assert_eq!(admit(&mut s, rec(), 0), Ok(Admitted::Queued)); }
    assert_eq!(s.cfg.lost, 0);
    assert_eq!(s.backlog.len(), 500);
}

/// The three failure modes differ only in what a LOSS does; an admitted record
/// never halts anything.
#[test]
fn only_a_lost_record_under_the_panic_mode_is_fatal() {
    use crate::uapi::{AUDIT_FAIL_PANIC, AUDIT_FAIL_PRINTK, AUDIT_FAIL_SILENT};
    let lost: Result<Admitted, Refusal> = Err(Refusal::BacklogFull);
    let kept: Result<Admitted, Refusal> = Ok(Admitted::Queued);
    assert!(fatal_loss(AUDIT_FAIL_PANIC, &lost));
    assert!(!fatal_loss(AUDIT_FAIL_PANIC, &kept));
    assert!(!fatal_loss(AUDIT_FAIL_PRINTK, &lost));
    assert!(!fatal_loss(AUDIT_FAIL_SILENT, &lost));
}

/// The panic failure mode makes losses noisy as well as fatal, so the warning
/// throttle must not swallow the one that matters.
#[test]
fn the_panic_failure_mode_warns_on_every_loss() {
    let mut last = 0u64;
    for now in [10u64, 11, 12] {
        assert!(crate::ratelimit::lost_print_check(&mut last, 100, true, now));
    }
}
