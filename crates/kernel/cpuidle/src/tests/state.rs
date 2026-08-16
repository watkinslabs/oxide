use super::*;
use crate::uapi::{FLAG_OFF, FLAG_POLLING, FLAG_UNUSABLE};

fn state(name: &str, latency_us: u64, residency_us: u64) -> IdleState {
    IdleState::from_us(name, "", latency_us, residency_us, Entry::Halt)
}

fn ladder() -> alloc::vec::Vec<IdleState> {
    alloc::vec![state("POLL", 0, 0), state("C1", 1, 1), state("C2", 40, 100)]
}

#[test]
fn a_microsecond_declaration_becomes_nanoseconds_internally() {
    let c2 = state("C2", 40, 100);
    assert_eq!(c2.exit_latency_ns, 40_000);
    assert_eq!(c2.target_residency_ns, 100_000);
    assert_eq!(c2.exit_latency_us(), 40, "the attribute reports back what was declared");
    assert_eq!(c2.target_residency_us(), 100);
}

#[test]
fn a_sub_microsecond_nanosecond_figure_reports_as_zero_microseconds() {
    let mut fast = state("C1", 0, 0);
    fast.exit_latency_ns = 900;
    assert_eq!(fast.exit_latency_us(), 0, "truncation, not rounding, matching the reference");
}

#[test]
fn a_well_ordered_ladder_is_accepted() {
    assert_eq!(validate(&ladder()), Ok(()));
}

#[test]
fn an_empty_or_over_long_table_is_refused() {
    assert_eq!(validate(&[]), Err(TableError::Empty));
    let long: alloc::vec::Vec<IdleState> =
        (0..crate::limits::MAX_STATES + 1).map(|i| state("C", i as u64, i as u64)).collect();
    assert_eq!(validate(&long), Err(TableError::TooMany));
}

#[test]
fn a_table_whose_depth_order_is_wrong_is_refused_not_silently_sorted() {
    let mut bad = ladder();
    bad[2].target_residency_ns = 500;
    assert_eq!(validate(&bad), Err(TableError::ResidencyOutOfOrder),
               "a governor walks the table as a ladder; an unsorted one misleads it");

    let mut bad = ladder();
    bad[2].exit_latency_ns = 0;
    assert_eq!(validate(&bad), Err(TableError::LatencyOutOfOrder));
}

#[test]
fn a_spin_state_that_is_not_the_shallowest_is_refused() {
    let mut bad = ladder();
    bad[2].flags |= FLAG_POLLING;
    assert_eq!(validate(&bad), Err(TableError::PollingNotFirst));

    let mut good = ladder();
    good[0].flags |= FLAG_POLLING;
    assert_eq!(validate(&good), Ok(()));
    assert!(good[0].polling() && !good[1].polling());
}

#[test]
fn the_two_ways_a_driver_ships_a_state_off_map_to_different_bits() {
    let mut unusable = state("C6", 100, 400);
    unusable.flags |= FLAG_UNUSABLE;
    assert_eq!(unusable.initial_disable(), crate::uapi::DISABLED_BY_DRIVER);

    let mut off = state("C6", 100, 400);
    off.flags |= FLAG_OFF;
    assert_eq!(off.initial_disable(), crate::uapi::DISABLED_BY_USER,
               "shipped off but re-enableable, unlike unusable");

    assert_eq!(state("C1", 1, 1).initial_disable(), 0);
}
