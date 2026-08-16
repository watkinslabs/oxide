use super::*;

// Every test owns its own counters, so nothing here depends on `SYSTEM` or on
// test execution order.

#[test]
fn fresh_counters_report_nothing() {
    let w = WakeupCounters::new();
    assert_eq!(w.counts(), Counts { registered: 0, in_progress: 0 });
    assert!(!w.wakeup_pending());
    assert_eq!(w.get_wakeup_count(), (0, true));
}

#[test]
fn an_event_moves_from_in_progress_to_registered() {
    let w = WakeupCounters::new();
    w.source_activate();
    assert_eq!(w.counts(), Counts { registered: 0, in_progress: 1 });
    w.source_deactivate();
    assert_eq!(w.counts(), Counts { registered: 1, in_progress: 0 });
}

#[test]
fn deactivate_is_one_atomic_step() {
    // The single add is what makes an event never observable in neither field.
    // Assert the invariant directly: after any number of activate/deactivate
    // pairs the two fields sum to the events that ever started.
    let w = WakeupCounters::new();
    for _ in 0..5 { w.source_activate(); }
    for _ in 0..3 { w.source_deactivate(); }
    let c = w.counts();
    assert_eq!(c.registered + c.in_progress, 5);
    assert_eq!(c, Counts { registered: 3, in_progress: 2 });
}

#[test]
fn arming_against_the_current_count_succeeds() {
    let w = WakeupCounters::new();
    w.source_activate(); w.source_deactivate();
    let (count, quiet) = w.get_wakeup_count();
    assert_eq!((count, quiet), (1, true));
    assert!(w.save_wakeup_count(count));
    assert!(w.check_enabled());
    assert!(!w.wakeup_pending());
}

#[test]
fn arming_against_a_stale_count_fails_and_leaves_it_disarmed() {
    let w = WakeupCounters::new();
    w.source_activate(); w.source_deactivate();
    assert!(!w.save_wakeup_count(0), "stale count armed");
    assert!(!w.check_enabled());
}

#[test]
fn arming_while_an_event_is_in_progress_fails() {
    let w = WakeupCounters::new();
    w.source_activate();
    let (count, quiet) = w.get_wakeup_count();
    assert!(!quiet);
    assert!(!w.save_wakeup_count(count));
    assert!(!w.check_enabled());
}

#[test]
fn an_event_after_arming_makes_the_check_pending_exactly_once() {
    let w = WakeupCounters::new();
    assert!(w.save_wakeup_count(0));
    w.source_activate(); w.source_deactivate();
    assert!(w.wakeup_pending(), "registered movement not reported");
    // Reporting disarms: the same movement must not abort a later transition.
    assert!(!w.check_enabled());
    assert!(!w.wakeup_pending());
}

#[test]
fn an_in_progress_event_is_pending_without_any_registered_movement() {
    let w = WakeupCounters::new();
    assert!(w.save_wakeup_count(0));
    w.source_activate();
    assert_eq!(w.counts().registered, 0);
    assert!(w.wakeup_pending());
}

#[test]
fn an_unarmed_check_ignores_events_but_not_aborts() {
    let w = WakeupCounters::new();
    w.source_activate(); w.source_deactivate();
    assert!(!w.wakeup_pending(), "unarmed check reported an event");
    w.system_wakeup();
    assert!(w.wakeup_pending());
}

#[test]
fn an_abort_stands_until_cleared_and_never_goes_negative() {
    let w = WakeupCounters::new();
    w.system_wakeup();
    assert!(w.wakeup_pending());
    assert!(w.wakeup_pending(), "abort withdrew itself on read");
    w.system_cancel_wakeup();
    assert!(!w.wakeup_pending());
    w.system_cancel_wakeup();
    w.system_cancel_wakeup();
    w.system_wakeup();
    assert!(w.wakeup_pending(), "over-cancelling drove the abort below zero");
}

#[test]
fn irq_wakeup_credits_two_then_stops_posting() {
    let w = WakeupCounters::new();
    w.system_irq_wakeup(4);
    assert_eq!(w.wakeup_irq(), 4);
    w.system_irq_wakeup(9);
    assert_eq!(w.wakeup_irq(), 4);
    // A third has nowhere to be recorded, so it posts no further abort.
    w.system_irq_wakeup(11);
    for _ in 0..2 { w.system_cancel_wakeup(); }
    assert!(!w.wakeup_pending(), "a third IRQ posted an uncredited abort");
}

#[test]
fn clearing_a_named_irq_shifts_the_second_up_and_keeps_the_abort() {
    let w = WakeupCounters::new();
    w.system_irq_wakeup(4);
    w.system_irq_wakeup(9);
    w.wakeup_clear(4);
    assert_eq!(w.wakeup_irq(), 9);
    assert!(w.wakeup_pending(), "clearing one IRQ withdrew the aborts");
}

#[test]
fn clearing_with_zero_drops_everything() {
    let w = WakeupCounters::new();
    w.system_irq_wakeup(4);
    w.wakeup_clear(0);
    assert_eq!(w.wakeup_irq(), 0);
    assert!(!w.wakeup_pending());
}

#[test]
fn the_fields_do_not_bleed_into_each_other() {
    let w = WakeupCounters::new();
    for _ in 0..MAX_IN_PROGRESS.min(4096) { w.source_activate(); }
    assert_eq!(w.counts().registered, 0, "in-progress overflowed into registered");
}
