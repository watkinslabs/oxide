use super::fixture::query;
use super::super::model::{validate, AdjError};
use super::super::uapi::*;

// ---- validation ladder ------------------------------------------------

#[test]
fn a_read_only_query_needs_no_privilege() {
    // The whole point: `modes == 0` is how every NTP client opens, and Linux
    // lets it through unprivileged. Answering it with EPERM is what makes
    // timesyncd conclude the kernel has no clock discipline at all.
    assert_eq!(validate(&query(), false), Ok(()));
}

#[test]
fn any_mutating_mode_without_cap_sys_time_is_eperm() {
    for m in [ADJ_OFFSET, ADJ_FREQUENCY, ADJ_MAXERROR, ADJ_ESTERROR, ADJ_STATUS,
        ADJ_TIMECONST, ADJ_TAI, ADJ_SETOFFSET, ADJ_MICRO, ADJ_NANO, ADJ_TICK]
    {
        let mut t = query();
        t.modes = m;
        t.tick = USER_TICK_USEC;
        assert_eq!(validate(&t, false), Err(AdjError::Perm), "mode {m:#x}");
    }
}

#[test]
fn the_read_only_single_shot_adjtime_needs_no_privilege() {
    // ADJ_OFFSET_SS_READ == ADJ_ADJTIME | ADJ_OFFSET_READONLY | ADJ_OFFSET_SINGLESHOT.
    let mut t = query();
    t.modes = ADJ_ADJTIME | ADJ_OFFSET_READONLY | ADJ_OFFSET_SINGLESHOT;
    assert_eq!(validate(&t, false), Ok(()));
    // The writing form does need it.
    t.modes = ADJ_ADJTIME | ADJ_OFFSET_SINGLESHOT;
    assert_eq!(validate(&t, false), Err(AdjError::Perm));
    assert_eq!(validate(&t, true), Ok(()));
}

#[test]
fn adj_adjtime_without_single_shot_is_einval_even_for_root() {
    let mut t = query();
    t.modes = ADJ_ADJTIME;
    assert_eq!(validate(&t, true), Err(AdjError::Inval));
    assert_eq!(validate(&t, false), Err(AdjError::Inval), "EINVAL precedes the EPERM test");
}

#[test]
fn adj_tick_accepts_only_within_ten_percent_of_nominal() {
    let mut t = query();
    t.modes = ADJ_TICK;
    for tick in [MIN_TICK_USEC, USER_TICK_USEC, MAX_TICK_USEC] {
        t.tick = tick;
        assert_eq!(validate(&t, true), Ok(()), "tick {tick}");
    }
    for tick in [MIN_TICK_USEC - 1, MAX_TICK_USEC + 1, 0, -1, 1_000_000] {
        t.tick = tick;
        assert_eq!(validate(&t, true), Err(AdjError::Inval), "tick {tick}");
    }
}

#[test]
fn adj_tick_eperm_precedes_its_range_check() {
    let mut t = query();
    t.modes = ADJ_TICK;
    t.tick = -1;
    assert_eq!(validate(&t, false), Err(AdjError::Perm));
}

#[test]
fn adj_setoffset_validates_the_sub_second_field_against_the_nano_bit() {
    let mut t = query();
    t.modes = ADJ_SETOFFSET;
    t.time_usec = USEC_PER_SEC - 1;
    assert_eq!(validate(&t, true), Ok(()));
    t.time_usec = USEC_PER_SEC;
    assert_eq!(validate(&t, true), Err(AdjError::Inval));
    t.modes = ADJ_SETOFFSET | ADJ_NANO;
    assert_eq!(validate(&t, true), Ok(()), "microseconds are in range once NANO widens it");
    t.time_usec = NSEC_PER_SEC;
    assert_eq!(validate(&t, true), Err(AdjError::Inval));
    t.time_usec = -1;
    assert_eq!(validate(&t, true), Err(AdjError::Inval), "tv_usec is never negative");
    // Seconds may be negative — the offset is a signed sum.
    t.time_usec = 0; t.time_sec = -10;
    assert_eq!(validate(&t, true), Ok(()));
}

#[test]
fn adj_frequency_rejects_a_value_that_would_overflow_the_ppm_scaling() {
    let mut t = query();
    t.modes = ADJ_FREQUENCY;
    t.freq = i64::MAX / PPM_SCALE;
    assert_eq!(validate(&t, true), Ok(()));
    t.freq = i64::MAX / PPM_SCALE + 1;
    assert_eq!(validate(&t, true), Err(AdjError::Inval));
    t.freq = i64::MIN / PPM_SCALE - 1;
    assert_eq!(validate(&t, true), Err(AdjError::Inval));
}
