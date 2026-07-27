// End-to-end POSIX timer lifecycle over the real slot table + state machine,
// driven hosted: create -> settime -> gettime -> expiry -> getoverrun -> delete.
// The `k_itimer` behaviour these assert is `common_timer_set` /
// `common_timer_get` / `posix_timer_fn` / `sys_timer_getoverrun`.

use alloc::vec::Vec;

use crate::posix_clock::ClockSpec;
use crate::timer_model::{arm_domain, Expiration, Notify, PosixTimer, TimerSetting};

use super::sigevent::{notify_for, SIGALRM};
use super::slots::{allocate_id, slot_index};

const SIGRTMIN: u32 = 34;

fn table() -> Vec<PosixTimer> { alloc::vec![PosixTimer::default(); PosixTimer::SLOTS] }

/// `timer_create` with a NULL sigevent.
fn create(slots: &mut Vec<PosixTimer>, clock: ClockSpec) -> usize {
    let id = allocate_id(slots).expect("free slot");
    let notify = notify_for(None, id, |_| None).expect("NULL sigevent always validates");
    slots[id] = PosixTimer::allocate(clock, notify);
    id
}

fn create_rt(slots: &mut Vec<PosixTimer>, clock: ClockSpec, signo: u32) -> usize {
    let id = allocate_id(slots).expect("free slot");
    slots[id] = PosixTimer::allocate(clock,
        Notify::Signal { signo, value: 0xabc, target_tid: 0 });
    id
}

/// `timer_settime`: returns the previous setting, then arms.
fn settime(timer: &mut PosixTimer, now: u64, absolute: bool, value_ns: u64, interval_ns: u64)
    -> TimerSetting
{
    let old = timer.setting(now, false);
    let domain = arm_domain(timer.clock, absolute);
    let deadline = if value_ns == 0 { 0 }
        else if absolute { value_ns.max(1) }
        else { now.saturating_add(value_ns).max(1) };
    timer.set(domain, deadline, interval_ns);
    old
}

#[test]
fn full_lifecycle_create_settime_gettime_expire_getoverrun_delete() {
    let mut slots = table();
    let id = create(&mut slots, ClockSpec::Monotonic);
    assert_eq!(slot_index(&slots, id as i64), Some(id));
    assert_eq!(slots[id].notify,
        Notify::Signal { signo: SIGALRM, value: id as u64, target_tid: 0 },
        "a NULL sigevent delivers SIGALRM with the timer id as si_value");

    // Disarmed timer reads back all zeroes.
    assert_eq!(slots[id].setting(1_000, false), TimerSetting::default());

    // Arm one-shot, 500ns out.
    let old = settime(&mut slots[id], 1_000, false, 500, 0);
    assert_eq!(old, TimerSetting::default(), "old_value of a never-armed timer is zero");
    assert_eq!(slots[id].setting(1_100, false),
        TimerSetting { interval_ns: 0, value_ns: 400 }, "gettime counts down");

    // Not due yet, then due.
    assert_eq!(slots[id].expire(1_499, false), None);
    assert_eq!(slots[id].expire(1_500, false),
        Some(Expiration { signo: SIGALRM, value: id as u64, target_tid: 0 }));
    // A one-shot with a signal still pending reports a non-zero remainder,
    // exactly like `common_timer_get`'s `it_value.tv_nsec = 1`.
    assert_eq!(slots[id].setting(1_600, true), TimerSetting { interval_ns: 0, value_ns: 1 });
    // Once delivered it is fully disarmed.
    slots[id].reconcile_delivery(1_600, false);
    assert_eq!(slots[id].setting(1_600, false), TimerSetting::default());
    assert_eq!(slots[id].overrun_last(1_600, false), 0, "a one-shot never overruns");

    // timer_delete frees the id for reuse.
    slots[id] = PosixTimer::default();
    assert_eq!(slot_index(&slots, id as i64), None);
    assert_eq!(allocate_id(&mut slots), Some(id));
}

#[test]
fn timer_abstime_arms_at_the_absolute_deadline_not_now_plus_value() {
    let mut slots = table();
    let id = create(&mut slots, ClockSpec::Monotonic);
    settime(&mut slots[id], 1_000, true, 1_400, 0);
    assert_eq!(slots[id].armed_deadline(), 1_400, "ABSTIME takes the value verbatim");
    assert_eq!(slots[id].setting(1_000, false).value_ns, 400);
    assert_eq!(slots[id].expire(1_399, false), None);
    assert!(slots[id].expire(1_400, false).is_some());

    // The same value RELATIVE lands 1_400ns after now instead.
    let other = create(&mut slots, ClockSpec::Monotonic);
    settime(&mut slots[other], 1_000, false, 1_400, 0);
    assert_eq!(slots[other].armed_deadline(), 2_400);
}

#[test]
fn an_absolute_deadline_already_in_the_past_fires_at_once() {
    let mut slots = table();
    let id = create(&mut slots, ClockSpec::Monotonic);
    settime(&mut slots[id], 5_000, true, 1, 0);
    assert!(slots[id].expire(5_000, false).is_some(),
        "an expired ABSTIME timer queues its signal immediately");
}

#[test]
fn zero_it_value_disarms_and_drops_the_interval() {
    let mut slots = table();
    let id = create(&mut slots, ClockSpec::Monotonic);
    settime(&mut slots[id], 0, false, 100, 25);
    assert_eq!(slots[id].setting(0, false), TimerSetting { interval_ns: 25, value_ns: 100 });

    // A zero it_value disarms even with a non-zero it_interval.
    let old = settime(&mut slots[id], 10, false, 0, 999);
    assert_eq!(old, TimerSetting { interval_ns: 25, value_ns: 90 },
        "old_value reports the setting that was in force");
    assert_eq!(slots[id].armed_deadline(), 0);
    assert_eq!(slots[id].setting(10, false), TimerSetting::default(),
        "a disarmed timer reports a zero interval too");
    assert_eq!(slots[id].expire(1_000_000, false), None, "a disarmed timer never fires");
}

#[test]
fn periodic_overrun_counts_the_intervals_missed_before_delivery() {
    let mut slots = table();
    let id = create_rt(&mut slots, ClockSpec::Monotonic, SIGRTMIN);
    settime(&mut slots[id], 0, false, 100, 10);

    // First expiry queues the signal at t=100.
    assert_eq!(slots[id].expire(100, false),
        Some(Expiration { signo: SIGRTMIN, value: 0xabc, target_tid: 0 }));
    // The signal is still pending through t=100..145: four more periods elapse
    // (110, 120, 130, 140) without queueing another signal.
    for now in [110u64, 125, 140, 145] {
        assert_eq!(slots[id].expire(now, true), None, "no second signal while one is pending");
    }
    assert_eq!(slots[id].overrun_last(145, true), 0,
        "the overrun count is only meaningful once the signal is delivered");

    // Delivery at t=145 caches (145 - 100) / 10 == 4 missed intervals.
    slots[id].reconcile_delivery(145, false);
    assert_eq!(slots[id].overrun_last(145, false), 4);
    assert_eq!(slots[id].overrun_last(145, false), 4, "getoverrun is a cached, repeatable read");

    // Rearming resets the cached count, matching `it_overrun` reinitialisation.
    settime(&mut slots[id], 145, false, 100, 10);
    assert_eq!(slots[id].overrun_last(145, false), 0);
}

#[test]
fn overrun_is_zero_when_the_signal_is_taken_before_the_next_period() {
    let mut slots = table();
    let id = create_rt(&mut slots, ClockSpec::Monotonic, SIGRTMIN);
    settime(&mut slots[id], 0, false, 100, 50);
    assert!(slots[id].expire(100, false).is_some());
    slots[id].reconcile_delivery(120, false);
    assert_eq!(slots[id].overrun_last(120, false), 0, "delivered inside the first period");
    assert_eq!(slots[id].armed_deadline(), 150, "the periodic timer rearmed one interval on");
}

#[test]
fn a_periodic_timer_rearms_itself_and_keeps_firing() {
    let mut slots = table();
    let id = create_rt(&mut slots, ClockSpec::Monotonic, SIGRTMIN);
    settime(&mut slots[id], 0, false, 10, 10);
    for tick in 1..=5u64 {
        let now = tick * 10;
        assert!(slots[id].expire(now, false).is_some(), "period {tick} must fire");
        slots[id].reconcile_delivery(now, false);
    }
    assert_eq!(slots[id].armed_deadline(), 60);
}

#[test]
fn sigev_none_timers_never_deliver_but_still_track_time() {
    let mut slots = table();
    let id = allocate_id(&mut slots).unwrap();
    slots[id] = PosixTimer::allocate(ClockSpec::Boottime, Notify::None);
    settime(&mut slots[id], 0, false, 50, 0);
    assert_eq!(slots[id].expire(60, false), None, "SIGEV_NONE queues no signal");
    assert_eq!(slots[id].setting(60, false), TimerSetting::default(),
        "an expired one-shot SIGEV_NONE timer reads back zero, not a stale remainder");
}

#[test]
fn timers_are_per_process_and_a_fresh_table_owns_no_timers() {
    let mut parent = table();
    create(&mut parent, ClockSpec::Monotonic);
    create(&mut parent, ClockSpec::Realtime);
    // `copy_signal()` gives the child an empty `posix_timers` list: fork does
    // not inherit timers, and exit/exec clear them.
    let child = table();
    for id in 0..PosixTimer::SLOTS as i64 {
        assert_eq!(slot_index(&child, id), None, "a forked process starts with no timers");
    }
    assert_eq!(slot_index(&parent, 0), Some(0));
    for timer in parent.iter_mut() { *timer = PosixTimer::default(); }
    assert_eq!(slot_index(&parent, 0), None, "exit_itimers leaves nothing behind");
}

#[test]
fn relative_realtime_timers_are_immune_to_a_wall_clock_step() {
    let mut slots = table();
    let id = create(&mut slots, ClockSpec::Realtime);
    settime(&mut slots[id], 1_000, false, 500, 0);
    assert_eq!(slots[id].domain, ClockSpec::Monotonic,
        "a relative CLOCK_REALTIME timer is armed on CLOCK_MONOTONIC");
    let abs = create(&mut slots, ClockSpec::Realtime);
    settime(&mut slots[abs], 1_000, true, 5_000, 0);
    assert_eq!(slots[abs].domain, ClockSpec::Realtime,
        "an absolute CLOCK_REALTIME timer stays on the wall clock and is reprojected");
}
