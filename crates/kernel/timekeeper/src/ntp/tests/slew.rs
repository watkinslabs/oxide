use super::fixture::{nominal, query};
use super::super::uapi::*;

// ---- the slew applicator ---------------------------------------------

#[test]
fn an_untouched_clock_slews_by_exactly_nothing() {
    // The property that makes the per-tick hook free on a system no NTP client
    // has spoken to: nominal tick_length is NTP_INTERVAL_LENGTH_SCALED, so the
    // correction term is identically zero.
    let mut n = nominal();
    assert_eq!(n.tick_length, NTP_INTERVAL_LENGTH_SCALED);
    assert_eq!(n.advance(1_000_000, 100), 0, "first call only arms the baseline");
    for i in 1..1_000u64 {
        assert_eq!(n.advance(1_000_000 + i * 10_000_000, 100), 0);
    }
}

#[test]
fn a_frequency_offset_slews_the_wall_clock_at_the_requested_rate() {
    let mut n = nominal();
    let mut t = query();
    t.modes = ADJ_FREQUENCY;
    t.freq = 100 * 65_536; // +100 ppm
    let mut tai = 0i32;
    n.adjtimex(&mut t, 0, 0, &mut tai);

    n.advance(0, 0);
    // One second of monotonic time, delivered as 100 irregular ticks.
    let mut total = 0i64;
    for i in 1..=100u64 { total += n.advance(i * 10_000_000, 0); }
    // 100 ppm of a second is 100_000 ns; allow one ns of fixed-point rounding.
    assert!((total - 100_000).abs() <= 1, "slewed {total} ns, wanted ~100000");
}

#[test]
fn a_negative_frequency_offset_slews_backwards_by_the_same_magnitude() {
    let mut n = nominal();
    let mut t = query();
    t.modes = ADJ_FREQUENCY;
    t.freq = -100 * 65_536;
    let mut tai = 0i32;
    n.adjtimex(&mut t, 0, 0, &mut tai);
    n.advance(0, 0);
    let mut total = 0i64;
    for i in 1..=100u64 { total += n.advance(i * 10_000_000, 0); }
    assert!((total + 100_000).abs() <= 1, "slewed {total} ns, wanted ~-100000");
}

#[test]
fn irregular_ticks_slew_by_elapsed_time_not_tick_count() {
    // This kernel programs a one-shot timer, so ticks are not evenly spaced.
    // One long tick must produce the same correction as many short ones.
    let mut a = nominal();
    let mut b = nominal();
    let mut tai = 0i32;
    for n in [&mut a, &mut b] {
        let mut t = query();
        t.modes = ADJ_FREQUENCY;
        t.freq = 500 * 65_536;
        n.adjtimex(&mut t, 0, 0, &mut tai);
        n.advance(0, 0);
    }
    let dense: i64 = (1..=1_000u64).map(|i| a.advance(i * 1_000_000, 0)).sum();
    let sparse = b.advance(1_000_000_000, 0);
    assert_eq!(dense, sparse);
}

#[test]
fn a_wall_step_resynchronises_the_second_counter_instead_of_replaying() {
    let mut n = nominal();
    n.time_status = STA_PLL;
    n.advance(0, 1_000);
    // settimeofday jumps the wall clock a decade forward.
    n.advance(10_000_000, 1_000 + 400_000_000);
    assert_eq!(n.last_wall_sec, 1_000 + 400_000_000);
    // And backwards.
    n.advance(20_000_000, 5);
    assert_eq!(n.last_wall_sec, 5);
}

#[test]
fn each_elapsed_wall_second_runs_the_leap_machine_exactly_once() {
    let mut n = nominal();
    n.time_status = STA_PLL | STA_INS;
    n.advance(0, 3 * SECS_PER_DAY);
    n.advance(10_000_000, 3 * SECS_PER_DAY + 1);
    assert_eq!(n.time_state, TIME_INS);
    assert_eq!(n.ntp_next_leap_sec, 4 * SECS_PER_DAY);
}

#[test]
fn a_leap_insert_returns_a_whole_second_of_step_from_advance() {
    let mut n = nominal();
    n.time_status = STA_PLL | STA_INS;
    n.time_state = TIME_INS;
    n.ntp_next_leap_sec = 4 * SECS_PER_DAY;
    n.advance(0, 4 * SECS_PER_DAY - 1);
    let delta = n.advance(10_000_000, 4 * SECS_PER_DAY);
    assert_eq!(delta, -NSEC_PER_SEC, "the inserted second sets the clock back");
}

#[test]
fn the_slew_carry_makes_a_sub_nanosecond_rate_accumulate_rather_than_vanish() {
    // 1 ppb over 10 ms is 0.01 ns — truncation alone would report 0 forever.
    let mut n = nominal();
    let mut t = query();
    t.modes = ADJ_FREQUENCY;
    t.freq = 65; // ~0.001 ppm
    let mut tai = 0i32;
    n.adjtimex(&mut t, 0, 0, &mut tai);
    n.advance(0, 0);
    let total: i64 = (1..=100_000u64).map(|i| n.advance(i * 10_000_000, 0)).sum();
    assert!(total > 0, "a sub-ns-per-tick rate must still accumulate");
}
