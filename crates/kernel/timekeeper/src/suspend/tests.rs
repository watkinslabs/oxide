// Sleep-time arithmetic (`32a§7`). A wrong answer here makes every timeout in
// the system wrong after one suspend and nothing faults, so every case is
// pinned: the wrap, the backwards counter, the wide multiply, and which clock
// moves by how much.

use super::arith::*;

/// A narrow counter, the case the mask exists for.
const NARROW: Clocksource = Clocksource { mask: 0xFFFF_FFFF, mult: 1, shift: 0 };
/// Counter ticking at 24 MHz, expressed the way a real clocksource is.
const SCALED: Clocksource = Clocksource { mask: 0xFFFF_FFFF_FFFF_FFFF, mult: 125, shift: 1 };

#[test]
fn a_plain_forward_delta_is_the_difference() {
    assert_eq!(cycle_delta(&NARROW, 1_000, 4_500), 3_500);
    assert_eq!(sleep_ns(&Clocksource::nanoseconds(), 10, 90), 80);
}

#[test]
fn a_counter_that_wrapped_still_yields_the_true_distance() {
    // 100 cycles before the wrap to 50 cycles after it.
    let start = 0xFFFF_FFFFu64 - 99;
    let now = 50u64;
    assert_eq!(cycle_delta(&NARROW, start, now), 150);
    assert_eq!(sleep_ns(&NARROW, start, now), 150);
}

#[test]
fn a_wrap_of_a_full_width_counter_also_works() {
    let cs = Clocksource::nanoseconds();
    let start = u64::MAX - 9;
    let now = 5u64;
    assert_eq!(cycle_delta(&cs, start, now), 15);
}

#[test]
fn a_counter_that_went_backwards_reports_no_elapsed_time() {
    // Past seven eighths of the range reads as backwards motion, not as an
    // enormous sleep.
    let d = cycle_delta(&NARROW, 0, NARROW.max_raw_delta() + 1);
    assert_eq!(d, 0);
    assert_eq!(cycle_delta(&NARROW, 0, NARROW.max_raw_delta()), NARROW.max_raw_delta());
}

#[test]
fn the_backwards_threshold_is_seven_eighths_of_the_counter() {
    // The sum of three shifts, not a divide: each shift truncates separately,
    // so it lands four counts ABOVE `mask/8*7` on this mask.
    let mask = 0xFFFF_FFFFu64;
    assert_eq!(NARROW.max_raw_delta(), (mask >> 1) + (mask >> 2) + (mask >> 3));
    assert_eq!(NARROW.max_raw_delta(), mask / 8 * 7 + 4);
    let cs = Clocksource::nanoseconds();
    assert!(cs.max_raw_delta() > u64::MAX / 2, "half a period must still be a valid sleep");
}

#[test]
fn scaling_converts_cycles_to_nanoseconds() {
    // mult 125, shift 1 => 62.5 ns per cycle.
    assert_eq!(cycles_to_ns(&SCALED, 8), 500);
    assert_eq!(cycles_to_ns(&SCALED, 1), 62);
}

#[test]
fn the_wide_multiply_agrees_with_the_narrow_one_at_the_boundary() {
    // Straddling `max_cycles` is where a reimplementation silently switches
    // arithmetic; both sides must produce the same number.
    let boundary = SCALED.max_cycles();
    let narrow_side = boundary - 1;
    assert_eq!(cycles_to_ns(&SCALED, narrow_side),
               ((narrow_side as u128 * SCALED.mult as u128) >> SCALED.shift) as u64);
    assert_eq!(cycles_to_ns(&SCALED, boundary),
               ((boundary as u128 * SCALED.mult as u128) >> SCALED.shift) as u64);
}

#[test]
fn a_conversion_that_cannot_fit_saturates_rather_than_wrapping() {
    let cs = Clocksource { mask: u64::MAX, mult: u32::MAX, shift: 0 };
    assert_eq!(cycles_to_ns(&cs, u64::MAX), u64::MAX);
}

#[test]
fn a_nanosecond_counter_needs_no_scaling() {
    let cs = Clocksource::nanoseconds();
    assert_eq!(cs.mult, 1);
    assert_eq!(cs.shift, 0);
    assert_eq!(cycles_to_ns(&cs, 123_456_789), 123_456_789);
}

#[test]
fn only_boottime_and_realtime_move_across_a_sleep() {
    let a = account(5_000);
    assert_eq!(a, SleepAccount { monotonic_ns: 0, boottime_ns: 5_000, realtime_ns: 5_000 });
}

#[test]
fn a_counter_that_did_not_move_injects_nothing() {
    assert!(!should_inject(0));
    assert!(should_inject(1));
    assert_eq!(sleep_ns(&Clocksource::nanoseconds(), 777, 777), 0);
}

#[test]
fn ordinary_suspend_prefers_a_working_nonstop_counter() {
    assert_eq!(select_sleep_ns(SleepMeasure::Suspend, 7_000,
        Some(1_000_000), Some(1_100_000)), 7_000);
}

#[test]
fn original_hibernate_unwind_still_uses_the_nonstop_counter() {
    // Until the restored architecture continuation explicitly discriminates
    // itself, hibernate failure/thaw is an ordinary in-process resume.
    let measure = resume_measure(false);
    assert_eq!(measure, SleepMeasure::Suspend);
    assert_eq!(select_sleep_ns(measure, 42_000,
        Some(1_000_000), Some(9_000_000)), 42_000);
}

#[test]
fn reset_or_backwards_monotonic_uses_the_persistent_delta() {
    let reset_delta = sleep_ns(&Clocksource::nanoseconds(), 50_000, 10);
    assert_eq!(reset_delta, 0, "a new counter epoch must be rejected");
    assert_eq!(select_sleep_ns(SleepMeasure::Suspend, reset_delta,
        Some(2_000_000_000), Some(7_000_000_000)), 5_000_000_000);
}

#[test]
fn hibernate_never_trusts_the_new_boots_monotonic_epoch() {
    let measure = resume_measure(true);
    assert_eq!(measure, SleepMeasure::Hibernate);
    assert_eq!(select_sleep_ns(measure, 123_456,
        Some(10_000), Some(90_000)), 80_000);
    assert_eq!(persistent_delta_ns(Some(90_000), Some(10_000)), 0,
        "a backwards persistent clock must not wrap");
}

#[test]
fn the_platform_clocksource_is_the_full_width_nanosecond_shape() {
    assert_eq!(super::PLATFORM_CLOCKSOURCE, Clocksource::nanoseconds());
}

// ---- the state machine ------------------------------------------------

#[test]
fn suspend_freezes_the_reader_and_resume_releases_it() {
    // Runs against the real statics, so it also proves the flag is observable
    // through the accessor the clock providers consult.
    assert!(!super::timekeeping_suspended());
    super::timekeeping_suspend();
    assert!(super::timekeeping_suspended());
    let frozen = super::frozen_monotonic_ns();
    assert_eq!(super::frozen_monotonic_ns(), frozen, "the frozen reading must not move");
    let injected = super::timekeeping_resume();
    assert!(!super::timekeeping_suspended());
    // Hosted, the platform counter does not advance, so nothing is injected.
    assert_eq!(injected, 0);
}
