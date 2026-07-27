use super::fixture::{nominal, query};
use super::super::uapi::*;

// ---- leap seconds -----------------------------------------------------

#[test]
fn sta_ins_schedules_a_leap_at_the_next_day_boundary() {
    let mut n = nominal();
    n.time_status = STA_PLL | STA_INS;
    let now = 3 * SECS_PER_DAY + 1_000;
    n.second_overflow(now);
    assert_eq!(n.time_state, TIME_INS);
    assert_eq!(n.ntp_next_leap_sec, 4 * SECS_PER_DAY);
}

#[test]
fn a_leap_insert_steps_the_clock_back_one_second_and_reports_time_oop() {
    let mut n = nominal();
    n.time_status = STA_PLL | STA_INS;
    n.time_state = TIME_INS;
    n.ntp_next_leap_sec = 4 * SECS_PER_DAY;
    assert_eq!(n.second_overflow(4 * SECS_PER_DAY), -1);
    assert_eq!(n.time_state, TIME_OOP);
    // The query path adjusts the reported time and TAI across the leap.
    let mut t = query();
    let mut tai = 37i32;
    let r = n.adjtimex(&mut t, 4 * SECS_PER_DAY, 0, &mut tai);
    assert_eq!(r, TIME_WAIT, "TIME_OOP at the leap second itself reads as TIME_WAIT");
}

#[test]
fn a_leap_delete_steps_the_clock_forward_and_lands_in_time_wait() {
    let mut n = nominal();
    n.time_status = STA_PLL | STA_DEL;
    n.time_state = TIME_DEL;
    n.ntp_next_leap_sec = 2 * SECS_PER_DAY;
    assert_eq!(n.second_overflow(2 * SECS_PER_DAY), 1);
    assert_eq!(n.time_state, TIME_WAIT);
    assert_eq!(n.ntp_next_leap_sec, TIME64_MAX);
}

#[test]
fn withdrawing_the_leap_request_returns_the_state_machine_to_time_ok() {
    let mut n = nominal();
    n.time_status = STA_PLL;
    n.time_state = TIME_INS;
    n.ntp_next_leap_sec = 100;
    n.second_overflow(50);
    assert_eq!(n.time_state, TIME_OK);
    assert_eq!(n.ntp_next_leap_sec, TIME64_MAX);
}

#[test]
fn a_pending_insert_reports_time_oop_and_rewrites_time_and_tai() {
    let mut n = nominal();
    n.time_status = STA_PLL | STA_INS;
    n.time_state = TIME_INS;
    n.ntp_next_leap_sec = 1_000;
    let mut t = query();
    let mut tai = 37i32;
    let r = n.adjtimex(&mut t, 1_000, 0, &mut tai);
    assert_eq!(r, TIME_OOP);
    assert_eq!(t.tai, 38, "TAI gains the inserted second");
    assert_eq!(t.time_sec, 999, "UTC repeats 23:59:59");
}

#[test]
fn dispersion_grows_each_second_and_desynchronises_at_the_phase_limit() {
    let mut n = nominal();
    n.time_status = STA_PLL;
    n.time_maxerror = NTP_PHASE_LIMIT - 1;
    n.second_overflow(1);
    assert_eq!(n.time_maxerror, NTP_PHASE_LIMIT);
    assert_ne!(n.time_status & STA_UNSYNC, 0, "an unfed clock declares itself unsynced");
}
