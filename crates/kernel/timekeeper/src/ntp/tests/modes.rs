use super::fixture::{nominal, query};
use super::super::uapi::*;

// ---- query semantics --------------------------------------------------

#[test]
fn an_undisciplined_clock_reports_time_error_and_sta_unsync() {
    let mut n = nominal();
    let mut t = query();
    let mut tai = 0i32;
    let r = n.adjtimex(&mut t, 1_700_000_000, 123_456_789, &mut tai);
    assert_eq!(r, TIME_ERROR, "STA_UNSYNC maps the TIME_OK state to TIME_ERROR");
    assert_eq!(t.status, STA_UNSYNC);
    assert_eq!(t.tick, USER_TICK_USEC);
    assert_eq!(t.precision, 1);
    assert_eq!(t.tolerance, MAXFREQ_SCALED / PPM_SCALE);
    assert_eq!(t.maxerror, NTP_PHASE_LIMIT);
    assert_eq!(t.esterror, NTP_PHASE_LIMIT);
    assert_eq!(t.time_sec, 1_700_000_000);
    assert_eq!(t.time_usec, 123_456, "microseconds while STA_NANO is clear");
    assert_eq!(t.constant, 2);
    assert_eq!(t.freq, 0);
}

#[test]
fn a_query_does_not_disturb_the_state() {
    let mut n = nominal();
    let before = n;
    let mut t = query();
    let mut tai = 7i32;
    n.adjtimex(&mut t, 100, 0, &mut tai);
    assert_eq!(n, before, "modes == 0 must be side-effect free");
    assert_eq!(tai, 7, "and must not move the TAI offset");
    assert_eq!(t.tai, 7, "but does report it");
    assert!(!n.armed);
}

#[test]
fn sta_nano_switches_the_reported_sub_second_unit() {
    let mut n = nominal();
    n.time_status |= STA_NANO;
    let mut t = query();
    let mut tai = 0i32;
    n.adjtimex(&mut t, 5, 123_456_789, &mut tai);
    assert_eq!(t.time_usec, 123_456_789);
}

// ---- ADJ_TAI ----------------------------------------------------------

#[test]
fn adj_tai_writes_the_offset_and_is_echoed_back() {
    let mut n = nominal();
    let mut t = query();
    t.modes = ADJ_TAI;
    t.constant = 37;
    let mut tai = 0i32;
    n.adjtimex(&mut t, 100, 0, &mut tai);
    assert_eq!(tai, 37, "CLOCK_TAI's offset is settable only through here");
    assert_eq!(t.tai, 37);
    assert!(n.armed);
}

#[test]
fn adj_tai_out_of_range_is_ignored_rather_than_rejected() {
    // Linux gates on `txc->constant >= 0 && <= MAX_TAI_OFFSET` inside
    // process_adjtimex_modes and simply skips the assignment; there is no
    // EINVAL for it, and the call still succeeds.
    let mut n = nominal();
    let mut tai = 10i32;
    for bad in [-1, MAX_TAI_OFFSET + 1] {
        let mut t = query();
        t.modes = ADJ_TAI;
        t.constant = bad;
        n.adjtimex(&mut t, 100, 0, &mut tai);
        assert_eq!(tai, 10, "constant {bad} must be ignored");
        assert_eq!(t.tai, 10);
    }
    let mut t = query();
    t.modes = ADJ_TAI;
    t.constant = MAX_TAI_OFFSET;
    n.adjtimex(&mut t, 100, 0, &mut tai);
    assert_eq!(tai, MAX_TAI_OFFSET as i32, "the boundary itself is accepted");
}

#[test]
fn adj_tai_shares_the_constant_field_with_adj_timeconst() {
    // Both read txc.constant; TIMECONST is applied first, so a call setting
    // both lands the same number in two places, exactly as Linux does.
    let mut n = nominal();
    let mut t = query();
    t.modes = ADJ_TAI | ADJ_TIMECONST;
    t.constant = 5;
    let mut tai = 0i32;
    n.adjtimex(&mut t, 100, 0, &mut tai);
    assert_eq!(tai, 5);
    assert_eq!(n.time_constant, 9, "clamp(5,0,MAXTC) + 4 while STA_NANO is clear");
    assert_eq!(t.constant, 9, "the readback reports the PLL constant, not the TAI offset");
}

// ---- status / mode application ---------------------------------------

#[test]
fn adj_status_cannot_write_the_read_only_bits() {
    let mut n = nominal();
    let mut t = query();
    t.modes = ADJ_STATUS;
    t.status = STA_PLL | STA_RONLY;
    let mut tai = 0i32;
    n.adjtimex(&mut t, 100, 0, &mut tai);
    assert_eq!(n.time_status & STA_RONLY, 0, "STA_RONLY bits are kernel-owned");
    assert_eq!(n.time_status, STA_PLL);
    assert_eq!(t.status, STA_PLL);
}

#[test]
fn clearing_sta_pll_cancels_the_pending_leap_and_resets_the_state() {
    // process_adj_status assigns STA_UNSYNC on the PLL-off edge, but the very
    // next lines (`&= STA_RONLY; |= txc->status & ~STA_RONLY`) overwrite the
    // whole writable half with what the caller asked for — STA_UNSYNC is not
    // an STA_RONLY bit, so it does NOT survive. Only time_state and the leap
    // cancellation persist. Asserting the intuitive-but-wrong STA_UNSYNC here
    // would have encoded a divergence from Linux as a requirement.
    let mut n = nominal();
    n.time_status = STA_PLL;
    n.time_state = TIME_INS;
    n.ntp_next_leap_sec = 1_000;
    let mut t = query();
    t.modes = ADJ_STATUS;
    t.status = 0;
    let mut tai = 0i32;
    let r = n.adjtimex(&mut t, 100, 0, &mut tai);
    assert_eq!(n.time_state, TIME_OK);
    assert_eq!(n.time_status, 0);
    assert_eq!(n.ntp_next_leap_sec, TIME64_MAX);
    assert_eq!(r, TIME_OK);
}

#[test]
fn enabling_sta_pll_reseeds_the_reference_time() {
    let mut n = nominal();
    n.time_reftime = 0;
    let mut t = query();
    t.modes = ADJ_STATUS;
    t.status = STA_PLL;
    let mut tai = 0i32;
    n.adjtimex(&mut t, 1_700_000_000, 0, &mut tai);
    assert_eq!(n.time_reftime, 1_700_000_000);
    assert_eq!(n.time_status & STA_UNSYNC, 0, "a synchronised client clears UNSYNC");
}

#[test]
fn a_synchronised_clock_reports_time_ok() {
    let mut n = nominal();
    let mut t = query();
    t.modes = ADJ_STATUS;
    t.status = STA_PLL;
    let mut tai = 0i32;
    assert_eq!(n.adjtimex(&mut t, 100, 0, &mut tai), TIME_OK);
}

#[test]
fn adj_nano_and_adj_micro_toggle_the_resolution_bit() {
    let mut n = nominal();
    let mut tai = 0i32;
    let mut t = query();
    t.modes = ADJ_NANO;
    n.adjtimex(&mut t, 100, 0, &mut tai);
    assert_ne!(n.time_status & STA_NANO, 0);
    let mut t = query();
    t.modes = ADJ_MICRO;
    n.adjtimex(&mut t, 100, 0, &mut tai);
    assert_eq!(n.time_status & STA_NANO, 0);
}

#[test]
fn maxerror_and_esterror_are_clamped_into_the_dispersion_range() {
    let mut n = nominal();
    let mut t = query();
    t.modes = ADJ_MAXERROR | ADJ_ESTERROR;
    t.maxerror = -5;
    t.esterror = NTP_PHASE_LIMIT * 4;
    let mut tai = 0i32;
    n.adjtimex(&mut t, 100, 0, &mut tai);
    assert_eq!(n.time_maxerror, 0);
    assert_eq!(n.time_esterror, NTP_PHASE_LIMIT);
    assert_eq!(t.maxerror, 0);
    assert_eq!(t.esterror, NTP_PHASE_LIMIT);
}

#[test]
fn adj_frequency_round_trips_through_the_ppm_scaling() {
    let mut n = nominal();
    let mut t = query();
    t.modes = ADJ_FREQUENCY;
    t.freq = 6_553_600; // 100 ppm in scaled-ppm (65536 units per ppm)
    let mut tai = 0i32;
    n.adjtimex(&mut t, 100, 0, &mut tai);
    assert_eq!(n.time_freq, 6_553_600 * PPM_SCALE);
    assert_eq!(t.freq, 6_553_600, "the readback reproduces the value written");
}

#[test]
fn adj_frequency_is_clamped_to_maxfreq() {
    let mut n = nominal();
    let mut t = query();
    t.modes = ADJ_FREQUENCY;
    t.freq = i64::MAX / PPM_SCALE;
    let mut tai = 0i32;
    n.adjtimex(&mut t, 100, 0, &mut tai);
    assert_eq!(n.time_freq, MAXFREQ_SCALED);
    t.modes = ADJ_FREQUENCY;
    t.freq = i64::MIN / PPM_SCALE;
    n.adjtimex(&mut t, 100, 0, &mut tai);
    assert_eq!(n.time_freq, -MAXFREQ_SCALED);
}

#[test]
fn adj_tick_changes_the_tick_length_base() {
    let mut n = nominal();
    let base = n.tick_length_base;
    let mut t = query();
    t.modes = ADJ_TICK;
    t.tick = USER_TICK_USEC + 100;
    let mut tai = 0i32;
    n.adjtimex(&mut t, 100, 0, &mut tai);
    assert_eq!(n.tick_usec, USER_TICK_USEC + 100);
    assert!(n.tick_length_base > base, "a longer tick lengthens the interval");
    assert_eq!(t.tick, USER_TICK_USEC + 100);
}

#[test]
fn adj_offset_is_ignored_while_the_pll_is_off() {
    let mut n = nominal();
    let mut t = query();
    t.modes = ADJ_OFFSET;
    t.offset = 1_000;
    let mut tai = 0i32;
    n.adjtimex(&mut t, 100, 0, &mut tai);
    assert_eq!(n.time_offset, 0, "ntp_update_offset returns early without STA_PLL");
    assert_eq!(n.time_freq, 0);
}

#[test]
fn adj_offset_feeds_the_pll_and_is_reported_back_in_microseconds() {
    let mut n = nominal();
    n.time_status = STA_PLL;
    n.time_reftime = 100;
    let mut t = query();
    t.modes = ADJ_OFFSET;
    t.offset = 1_000; // us
    let mut tai = 0i32;
    n.adjtimex(&mut t, 132, 0, &mut tai);
    assert!(n.time_offset > 0, "a positive phase sample is queued");
    assert!(n.time_freq > 0, "and steers the frequency");
    // The readback is the queued offset converted back to us.
    assert!(t.offset > 0 && t.offset <= 1_000, "reported {}", t.offset);
}

#[test]
fn the_phase_sample_is_clamped_to_maxphase() {
    let mut n = nominal();
    n.time_status = STA_PLL | STA_NANO;
    let mut t = query();
    t.modes = ADJ_OFFSET;
    t.offset = MAXPHASE * 100;
    let mut tai = 0i32;
    n.adjtimex(&mut t, 1, 0, &mut tai);
    assert_eq!(n.time_offset, (MAXPHASE << NTP_SCALE_SHIFT) / NTP_INTERVAL_FREQ);
}

// ---- legacy adjtime(3) channel ----------------------------------------

#[test]
fn adj_adjtime_sets_the_slew_and_returns_the_previous_residual() {
    let mut n = nominal();
    let mut tai = 0i32;
    let mut t = query();
    t.modes = ADJ_ADJTIME | ADJ_OFFSET_SINGLESHOT;
    t.offset = 250_000; // us
    n.adjtimex(&mut t, 100, 0, &mut tai);
    assert_eq!(t.offset, 0, "no adjustment was in flight");
    assert_eq!(n.time_adjust, 250_000);
    assert!(n.armed);

    let mut t = query();
    t.modes = ADJ_ADJTIME | ADJ_OFFSET_SINGLESHOT;
    t.offset = 0;
    n.adjtimex(&mut t, 100, 0, &mut tai);
    assert_eq!(t.offset, 250_000, "the outstanding residual is handed back");
    assert_eq!(n.time_adjust, 0);
}

#[test]
fn the_read_only_adjtime_form_reports_without_writing() {
    let mut n = nominal();
    n.time_adjust = 4_242;
    let mut tai = 0i32;
    let mut t = query();
    t.modes = ADJ_ADJTIME | ADJ_OFFSET_READONLY | ADJ_OFFSET_SINGLESHOT;
    t.offset = 999;
    n.adjtimex(&mut t, 100, 0, &mut tai);
    assert_eq!(t.offset, 4_242);
    assert_eq!(n.time_adjust, 4_242, "a read-only query must not overwrite it");
    assert!(!n.armed);
}

#[test]
fn adjtime_slew_drains_at_most_max_tickadj_per_second() {
    let mut n = nominal();
    n.time_adjust = MAX_TICKADJ * 3;
    let base = n.tick_length_base;
    n.second_overflow(1);
    assert_eq!(n.time_adjust, MAX_TICKADJ * 2);
    assert_eq!(n.tick_length, base + MAX_TICKADJ_SCALED);
    n.second_overflow(2);
    assert_eq!(n.time_adjust, MAX_TICKADJ);
    n.second_overflow(3);
    assert_eq!(n.time_adjust, 0, "the final partial second consumes the remainder");
}
