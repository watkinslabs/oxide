// Hosted tests for the wait-expiry model. This file is deliberately NOT under
// any `target_os = "oxide-kernel"` gate — a `#[cfg(test)]` block inside a
// kernel-gated file compiles out silently while cargo still prints "ok".

use super::model::*;

const MS: u64 = 1_000_000;
const US: u64 = 1_000;
/// Linux default task `.timer_slack_ns = 50000`.
const DEFAULT_SLACK: u64 = 50 * US;

fn q() -> DeadlineQueue<u32> { DeadlineQueue::new() }

#[test]
fn an_empty_queue_reports_no_next_event() {
    assert_eq!(q().earliest_hard_ns(), u64::MAX);
    assert!(q().is_empty());
}

#[test]
fn the_next_event_is_the_earliest_hard_expiry_regardless_of_arm_order() {
    let mut queue = q();
    queue.arm(3, 30 * MS, 30 * MS + DEFAULT_SLACK, 3);
    queue.arm(1, 10 * MS, 10 * MS + DEFAULT_SLACK, 1);
    queue.arm(2, 20 * MS, 20 * MS + DEFAULT_SLACK, 2);
    assert_eq!(queue.earliest_hard_ns(), 10 * MS + DEFAULT_SLACK);
    assert_eq!(queue.len(), 3);
}

/// The regression this branch exists for: a 1 ms wait must put a 1 ms expiry in
/// front of the hardware, not be swallowed by a 100 ms periodic scan.
#[test]
fn a_one_millisecond_wait_is_the_next_event_not_the_hundred_millisecond_tick() {
    let mut queue = q();
    queue.arm(1, MS, MS + DEFAULT_SLACK, 1);
    let hundred_ms_scan = 100 * MS;
    assert_eq!(fold_wait_expiry(0, hundred_ms_scan, queue.earliest_hard_ns()),
        MS + DEFAULT_SLACK,
        "a 1ms wait deadline must reach the one-shot programmer");
}

#[test]
fn pop_yields_expiries_in_soft_order_and_stops_at_the_first_not_due() {
    let mut queue = q();
    queue.arm(1, 10 * MS, 10 * MS, 1);
    queue.arm(2, 20 * MS, 20 * MS, 2);
    assert!(queue.pop_soft_due(5 * MS).is_none(), "nothing is due yet");
    assert_eq!(queue.pop_soft_due(10 * MS).map(|a| a.tid), Some(1));
    assert!(queue.pop_soft_due(10 * MS).is_none(), "the 20ms entry is not due");
    assert_eq!(queue.pop_soft_due(25 * MS).map(|a| a.tid), Some(2));
    assert!(queue.is_empty());
}

/// The reference's sweep fires everything already SOFT-due at the
/// interrupt raised by the earliest HARD expiry. That is the coalescing — one
/// interrupt, N wakeups.
#[test]
fn one_interrupt_sweeps_every_wait_whose_soft_time_has_passed() {
    let mut queue = q();
    // Three waits inside one 100us window, each with 50us of slack.
    queue.arm(1, MS, MS + 50 * US, 1);
    queue.arm(2, MS + 20 * US, MS + 70 * US, 2);
    queue.arm(3, MS + 40 * US, MS + 90 * US, 3);
    // The device is armed at the EARLIEST hard time.
    let fire_at = queue.earliest_hard_ns();
    assert_eq!(fire_at, MS + 50 * US);
    // At that instant all three soft times have passed, so one interrupt
    // drains all three rather than each buying its own.
    let mut swept = 0;
    while queue.pop_soft_due(fire_at).is_some() { swept += 1; }
    assert_eq!(swept, 3, "slack ranges overlap — one interrupt must sweep all three");
}

/// The opposite direction, and the reason slack is not a free win to enlarge: a
/// wait may never end BEFORE its soft time, however convenient the coalescing.
#[test]
fn a_wait_never_fires_before_its_soft_expiry() {
    let mut queue = q();
    queue.arm(1, 10 * MS, 10 * MS + MAX_SLACK_NS, 1);
    assert!(queue.pop_soft_due(10 * MS - 1).is_none(),
        "fired a nanosecond early — nanosleep(2) would return short");
    assert!(queue.pop_soft_due(10 * MS).is_some());
}

#[test]
fn re_arming_a_task_replaces_its_expiry_instead_of_queueing_a_second() {
    let mut queue = q();
    queue.arm(1, 50 * MS, 50 * MS, 1);
    assert!(queue.arm(1, 5 * MS, 5 * MS, 1).is_some(), "the stale entry is returned");
    assert_eq!(queue.len(), 1, "a task parks on at most one wait at a time");
    assert_eq!(queue.earliest_hard_ns(), 5 * MS);
}

#[test]
fn disarm_removes_only_the_named_task_and_reports_a_miss() {
    let mut queue = q();
    queue.arm(1, 10 * MS, 10 * MS, 1);
    queue.arm(2, 20 * MS, 20 * MS, 2);
    assert!(queue.disarm(1).is_some());
    assert!(queue.disarm(1).is_none());
    assert_eq!(queue.earliest_hard_ns(), 20 * MS);
    assert_eq!(queue.len(), 1);
}

#[test]
fn hard_expiry_saturates_like_ktime_add_safe() {
    assert_eq!(hard_expiry(MS, DEFAULT_SLACK), MS + DEFAULT_SLACK);
    assert_eq!(hard_expiry(u64::MAX - 1, DEFAULT_SLACK), u64::MAX);
}

/// Linux `select_estimate_accuracy` — 0.1% of the remaining timeout, floored at
/// the task's own slack, capped at 100 ms.
#[test]
fn poll_slack_is_a_tenth_of_a_percent_floored_at_task_slack_capped_at_100ms() {
    // 1 ms timeout: 0.1% is 1us, below the 50us floor.
    assert_eq!(estimate_accuracy(MS, DEFAULT_SLACK, false), DEFAULT_SLACK);
    // 1 s timeout: 0.1% is 1 ms, above the floor.
    assert_eq!(estimate_accuracy(1000 * MS, DEFAULT_SLACK, false), MS);
    // 1000 s timeout: 0.1% is 1 s, above the 100 ms cap.
    assert_eq!(estimate_accuracy(1_000_000 * MS, DEFAULT_SLACK, false), MAX_SLACK_NS);
    // `nice > 0` spends 0.5% instead.
    assert_eq!(estimate_accuracy(1000 * MS, DEFAULT_SLACK, true), 5 * MS);
}

/// A task with zero slack (SCHED_FIFO/RR/DEADLINE) gets an
/// exact wait, never a coalesced one.
#[test]
fn a_realtime_task_gets_zero_slack_at_every_timeout_length() {
    assert_eq!(estimate_accuracy(MS, 0, false), 0);
    assert_eq!(estimate_accuracy(1_000_000 * MS, 0, false), 0);
    assert_eq!(estimate_accuracy(1_000_000 * MS, 0, true), 0);
}

/// An expiry already in the past must not be programmed: re-arming at the
/// minimal delta for an already-expired timer is
/// "Lather, rinse and repeat", i.e. an interrupt storm.
#[test]
fn an_already_due_expiry_does_not_reprogram_the_hardware() {
    let now = 100 * MS;
    let tick = now + 10 * MS;
    assert_eq!(fold_wait_expiry(now, tick, now - MS), tick);
    assert_eq!(fold_wait_expiry(now, tick, now), tick);
    assert_eq!(fold_wait_expiry(now, tick, now + MS), now + MS);
}

/// Nothing armed leaves the accounting tick in charge — the fold must not
/// shorten the interrupt period on an idle system.
#[test]
fn no_armed_wait_leaves_the_accounting_tick_untouched() {
    let now = 100 * MS;
    let tick = now + 10 * MS;
    assert_eq!(fold_wait_expiry(now, tick, DeadlineQueue::<u32>::new().earliest_hard_ns()), tick);
}

/// A wait LATER than the tick must not push the tick out — the B1455 class of
/// bug, where a reprogram from an unrelated caller postponed CPU accounting.
#[test]
fn a_distant_wait_does_not_postpone_the_accounting_tick() {
    let now = 100 * MS;
    let tick = now + 10 * MS;
    assert_eq!(fold_wait_expiry(now, tick, now + 5000 * MS), tick);
}
