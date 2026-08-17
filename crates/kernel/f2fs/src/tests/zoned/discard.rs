//! What a freed run becomes on a drive with zones.

use super::{action, zone_of, Action};

/// This fixture's zone, in volume blocks.
const PER: u32 = 512;

#[test]
fn a_member_with_no_zones_takes_the_ordinary_discard() {
    assert_eq!(zone_of(0, 0), None);
    assert_eq!(action(false, 0, 8, 0), Action::Discard);
    // Even a member that reports a zone size answers `Discard` for a zone the
    // drive does not require sequential writes in.
    assert_eq!(action(false, 0, u64::from(PER), PER), Action::Discard);
}

#[test]
fn a_whole_sequential_zone_becomes_a_reset() {
    // The one case the drive can act on: the run is exactly the zone, so the
    // pointer can go back to its start.
    assert_eq!(action(true, 0, u64::from(PER), PER), Action::Reset);
    assert_eq!(action(true, u64::from(PER) * 9, u64::from(PER), PER), Action::Reset);
}

#[test]
fn part_of_a_sequential_zone_is_sent_nothing() {
    // An ordinary discard would leave the write pointer where it is, so the
    // space would come back in the accounting and not on the drive; a reset
    // would take blocks the run does not name.
    assert_eq!(action(true, 0, u64::from(PER) - 1, PER), Action::Unaligned);
    assert_eq!(action(true, 1, u64::from(PER), PER), Action::Unaligned);
    assert_eq!(action(true, u64::from(PER) / 2, u64::from(PER) / 2, PER), Action::Unaligned);
}

#[test]
fn a_run_longer_than_one_zone_is_sent_nothing() {
    // A reset addresses ONE zone. A two-zone run issued as one reset would
    // free the second zone on the drive while the filesystem still counted it,
    // and the drive would refuse the length anyway.
    assert_eq!(action(true, 0, u64::from(PER) * 2, PER), Action::Unaligned);
}

#[test]
fn the_zone_a_run_starts_in_is_its_block_over_the_zone_size() {
    assert_eq!(zone_of(0, PER), Some(0));
    assert_eq!(zone_of(u64::from(PER) - 1, PER), Some(0));
    assert_eq!(zone_of(u64::from(PER), PER), Some(1));
    assert_eq!(zone_of(u64::from(PER) * 7 + 3, PER), Some(7));
}
