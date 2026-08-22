use super::*;

#[test]
fn an_earlier_registered_timer_shortens_the_driver_park() {
    let now = 1_000_000_000;
    let vivid_tick = now + 1_000_000_000 / 60;
    assert_eq!(park_deadline(now, Some(vivid_tick)), vivid_tick);
}

#[test]
fn an_idle_or_later_registry_keeps_the_bounded_fallback() {
    let now = 7_000_000;
    assert_eq!(park_deadline(now, None), now + super::FALLBACK_NS);
    assert_eq!(park_deadline(now, Some(now + super::FALLBACK_NS * 2)),
               now + super::FALLBACK_NS);
}

#[test]
fn an_overdue_timer_is_immediately_runnable_and_deadlines_saturate() {
    assert_eq!(park_deadline(500, Some(400)), 500);
    assert_eq!(park_deadline(u64::MAX - 4, None), u64::MAX);
}

#[test]
fn the_live_driver_consumes_the_registry_deadline() {
    let source = include_str!("../live/timer_driver.rs");
    assert!(source.contains("timer::next_deadline_ns(now)"));
    assert!(source.contains("timer_driver_policy::park_deadline(now,"));
}
