// `__checkparam_dl` ladder + the bandwidth fixed point.

use super::super::params::*;

const MS: u64 = 1_000_000;

fn ok(r: u64, d: u64, p: u64) -> bool { checkparam_dl(r, d, p, 0) }

#[test]
fn a_full_cpu_reservation_is_bandwidth_one() {
    assert_eq!(to_ratio(1_000_000_000, 1_000_000_000), BW_UNIT);
}

#[test]
fn bandwidth_truncates_rather_than_rounds_up() {
    // 1/3 of a period must not be recorded as more than 1/3 of a CPU.
    let bw = to_ratio(3, 1);
    assert_eq!(bw, (1u64 << BW_SHIFT) / 3);
    assert!(bw * 3 <= BW_UNIT);
}

#[test]
fn a_zero_period_carries_no_bandwidth() {
    assert_eq!(to_ratio(0, 5), 0);
}

#[test]
fn an_omitted_period_defaults_to_the_deadline_before_bandwidth_is_derived() {
    // The defaulting order is load-bearing: deriving bw against period 0 first
    // would book every implicit-deadline task at bandwidth zero and admit an
    // unbounded number of them.
    let p = DlParams::from_request(5 * MS, 10 * MS, 0, 0);
    assert_eq!(p.period, 10 * MS);
    assert_eq!(p.bw, to_ratio(10 * MS, 5 * MS));
    assert_ne!(p.bw, 0);
}

#[test]
fn density_uses_the_deadline_and_bandwidth_uses_the_period() {
    let p = DlParams::from_request(1 * MS, 2 * MS, 10 * MS, 0);
    assert_eq!(p.bw, to_ratio(10 * MS, 1 * MS));
    assert_eq!(p.density, to_ratio(2 * MS, 1 * MS));
    assert!(p.density > p.bw);
}

#[test]
fn implicit_deadline_is_deadline_equals_period() {
    assert!(DlParams::from_request(MS, 10 * MS, 10 * MS, 0).is_implicit());
    assert!(DlParams::from_request(MS, 5 * MS, 10 * MS, 0).is_implicit() == false);
    // An omitted period makes the entity implicit by construction.
    assert!(DlParams::from_request(MS, 10 * MS, 0, 0).is_implicit());
}

#[test]
fn a_zero_deadline_is_rejected() {
    assert!(!ok(MS, 0, 10 * MS));
}

#[test]
fn a_runtime_below_the_truncation_floor_is_rejected() {
    // Under `1 << DL_SCALE` the overflow arithmetic reads the runtime as zero,
    // so such a reservation would be admitted at no cost at all.
    assert!(!ok((1 << DL_SCALE) - 1, MS, 10 * MS));
    assert!(!ok(0, MS, 10 * MS));
    assert!(ok(1 << DL_SCALE, MS, 10 * MS));
}

#[test]
fn the_reserved_high_bit_is_rejected_in_deadline_and_period() {
    assert!(!ok(MS, 1u64 << 63, 10 * MS));
    assert!(!ok(MS, MS, 1u64 << 63));
}

#[test]
fn runtime_must_not_exceed_deadline_and_deadline_must_not_exceed_period() {
    assert!(!ok(3 * MS, 2 * MS, 10 * MS));
    assert!(!ok(MS, 20 * MS, 10 * MS));
    assert!(ok(2 * MS, 2 * MS, 10 * MS));
}

#[test]
fn the_period_window_is_enforced_at_both_ends() {
    assert!(!ok(2048, 2048, DL_PERIOD_MIN_NS - 1));
    assert!(ok(2048, DL_PERIOD_MIN_NS, DL_PERIOD_MIN_NS));
    assert!(ok(2048, 2048, DL_PERIOD_MAX_NS));
    assert!(!ok(2048, 2048, DL_PERIOD_MAX_NS + 1));
}

#[test]
fn an_omitted_period_is_validated_as_the_deadline() {
    // period = 0 means "period == deadline", so the window applies to the
    // deadline instead of silently passing a zero period.
    assert!(!ok(2048, DL_PERIOD_MIN_NS - 1, 0));
    assert!(ok(2048, 10 * MS, 0));
}

#[test]
fn a_governor_entity_skips_the_whole_ladder() {
    // The kernel-internal entity carries no parameters at all; every syscall
    // path refuses the flag separately.
    assert!(checkparam_dl(0, 0, 0, FLAG_SUGOV));
    assert!(DlParams::from_request(0, 0, 0, FLAG_SUGOV).is_special());
}

#[test]
fn only_the_deadline_flag_subset_is_stored_on_the_entity() {
    let p = DlParams::from_request(MS, 10 * MS, 10 * MS,
        FLAG_RECLAIM | FLAG_DL_OVERRUN | 0x01 /* reset-on-fork, not ours */);
    assert_eq!(p.flags, FLAG_RECLAIM | FLAG_DL_OVERRUN);
    assert!(p.reclaims());
    assert!(p.wants_overrun_signal());
}

#[test]
fn max_bandwidth_bounds_the_shift() {
    // `runtime << BW_SHIFT` must stay inside 64 bits.
    assert_eq!(MAX_BW, (1u64 << 44) - 1);
    assert!(MAX_BW.checked_shl(BW_SHIFT).is_none() || MAX_BW << BW_SHIFT != 0);
}
