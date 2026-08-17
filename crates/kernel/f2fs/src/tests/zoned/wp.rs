//! Reconciling a drive's write pointers with the segment tables.

use super::{check_zone, curseg_agrees, needs_new_section, new_zone_needs_reset,
            CursegFacts, Fix, ZoneFacts};
use crate::zoned::report::ZoneCond;

/// Every condition a zone can report. # C: O(1)
const CONDS: [ZoneCond; 8] = [
    ZoneCond::NotWp, ZoneCond::Empty, ZoneCond::ImplicitOpen, ZoneCond::ExplicitOpen,
    ZoneCond::Closed, ZoneCond::Full, ZoneCond::ReadOnly, ZoneCond::Offline,
];

/// A sequential zone in the main area that no log stands in. # C: O(1)
fn zone(valid_blocks: u32, cond: ZoneCond) -> ZoneFacts {
    ZoneFacts { seq_required: true, in_main: true, is_cursec: false, valid_blocks, cond }
}

#[test]
fn an_empty_zone_holding_nothing_is_consistent() {
    assert_eq!(check_zone(zone(0, ZoneCond::Empty)), Fix::Nothing);
}

#[test]
fn a_full_zone_holding_something_is_consistent() {
    assert_eq!(check_zone(zone(1, ZoneCond::Full)), Fix::Nothing);
    assert_eq!(check_zone(zone(4096, ZoneCond::Full)), Fix::Nothing);
}

#[test]
fn a_zone_with_nothing_live_and_a_pointer_that_moved_is_reset() {
    // Nothing in it is wanted, so the drive is told to forget the whole zone
    // rather than being asked to accept a write it would refuse.
    for cond in CONDS {
        if cond == ZoneCond::Empty { continue; }
        assert_eq!(check_zone(zone(0, cond)), Fix::Reset, "{cond:?}");
    }
}

#[test]
fn a_zone_with_live_blocks_and_the_wrong_pointer_is_finished() {
    // The blocks are wanted, so nothing is discarded: the zone is filled to
    // its end and stops being a candidate for allocation.
    for cond in CONDS {
        if cond == ZoneCond::Full { continue; }
        assert_eq!(check_zone(zone(7, cond)), Fix::Finish, "{cond:?}");
    }
}

#[test]
fn a_zone_the_drive_does_not_require_sequential_writes_in_is_left_alone() {
    // A conventional or host-aware zone takes a write anywhere, so its
    // pointer says nothing about what this filesystem may do — and resetting
    // one would discard live blocks for no reason at all.
    for cond in CONDS {
        for valid in [0u32, 9] {
            let f = ZoneFacts { seq_required: false, ..zone(valid, cond) };
            assert_eq!(check_zone(f), Fix::Nothing, "{cond:?} {valid}");
        }
    }
}

#[test]
fn a_zone_outside_the_main_area_is_not_this_checks_to_reconcile() {
    for cond in CONDS {
        let f = ZoneFacts { in_main: false, ..zone(0, cond) };
        assert_eq!(check_zone(f), Fix::Nothing, "{cond:?}");
    }
}

#[test]
fn a_zone_a_current_log_stands_in_is_left_to_the_log() {
    // Repairing it from both sides would have the zone reset out from under
    // a log that is about to write into it.
    for cond in CONDS {
        for valid in [0u32, 3] {
            let f = ZoneFacts { is_cursec: true, ..zone(valid, cond) };
            assert_eq!(check_zone(f), Fix::Nothing, "{cond:?} {valid}");
        }
    }
}

// ------------------------------------------------------------ the log's zone

/// A log whose recorded position matches the drive's pointer exactly.
/// # C: O(1)
fn log_at(segno: u32, blkoff: u16) -> CursegFacts {
    CursegFacts {
        seq_required: true,
        clean_umount: true,
        cs_segno: segno,
        cs_next_blkoff: blkoff,
        wp_segno: segno,
        wp_blkoff: blkoff,
        wp_partial: false,
        zone_first_segno: segno,
    }
}

#[test]
fn a_log_matching_the_drive_after_a_clean_unmount_is_left_where_it_is() {
    assert!(curseg_agrees(log_at(64, 17)));
}

#[test]
fn a_log_in_a_zone_the_drive_writes_freely_is_left_where_it_is() {
    let f = CursegFacts { seq_required: false, clean_umount: false, wp_segno: 9, ..log_at(64, 17) };
    assert!(curseg_agrees(f));
}

#[test]
fn after_a_crash_the_recorded_position_is_not_trusted_even_when_it_matches() {
    // It was written by an OLDER checkpoint; the writes since are exactly
    // what is unaccounted for, and a match proves only that nothing after
    // that checkpoint reached this zone as far as this record knows.
    assert!(!curseg_agrees(CursegFacts { clean_umount: false, ..log_at(64, 17) }));
}

#[test]
fn a_log_in_a_different_segment_or_at_a_different_block_disagrees() {
    assert!(!curseg_agrees(CursegFacts { wp_segno: 65, ..log_at(64, 17) }));
    assert!(!curseg_agrees(CursegFacts { wp_blkoff: 18, ..log_at(64, 17) }));
}

#[test]
fn a_pointer_part_way_into_a_block_is_not_the_same_block() {
    // The drive has taken bytes the log does not know about; appending at
    // that block would write over them.
    assert!(!curseg_agrees(CursegFacts { wp_partial: true, ..log_at(64, 17) }));
}

#[test]
fn only_a_log_at_the_head_of_its_own_zone_needs_no_new_section() {
    assert!(!needs_new_section(log_at(64, 0)));
    assert!(needs_new_section(log_at(64, 1)));
    assert!(needs_new_section(CursegFacts { zone_first_segno: 60, ..log_at(64, 0) }));
}

#[test]
fn a_freshly_chosen_section_is_reset_unless_the_drive_agrees_it_is_fresh() {
    // Free to the FILESYSTEM says nothing about the DRIVE: a zone whose
    // blocks were released without the drive being told still has its
    // pointer part way along, and the log's first write there is refused.
    assert!(new_zone_needs_reset(true, false));
    assert!(!new_zone_needs_reset(true, true));
    assert!(!new_zone_needs_reset(false, false));
}
