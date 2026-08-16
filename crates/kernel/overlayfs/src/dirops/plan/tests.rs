//! The decisions behind create, remove and rename.

use crate::config::{Config, RedirectMode};
use crate::layers::PathType;

use super::{can_move, needs_whiteout, new_dir_opaque, rename_flags_ok, rename_plan, RenamePlan,
            RENAME_EXCHANGE, RENAME_NOREPLACE};

/// A merged directory: upper half plus lower halves.
const MERGED: PathType = PathType { upper: true, merge: true, origin: true };
/// A directory that exists only in the writable layer.
const PURE_UPPER: PathType = PathType { upper: true, merge: false, origin: false };
/// A directory that exists only below.
const LOWER_ONLY: PathType = PathType { upper: false, merge: false, origin: false };

#[test]
fn a_cover_is_left_exactly_when_something_is_below() {
    assert!(needs_whiteout(true));
    assert!(!needs_whiteout(false));
}

#[test]
fn a_file_always_moves() {
    let c = Config::default();
    assert!(can_move(&c, false, MERGED));
    assert!(can_move(&c, false, LOWER_ONLY));
}

#[test]
fn a_merged_directory_cannot_move_without_the_record() {
    // Its lower half stays where it is; without a record of where, the moved
    // directory would silently lose everything below.
    let off = Config::default();
    assert!(!can_move(&off, true, MERGED));
    assert!(!can_move(&off, true, LOWER_ONLY));
    let on = Config { redirect_mode: RedirectMode::On, ..Config::default() };
    assert!(can_move(&on, true, MERGED));
}

#[test]
fn a_directory_only_in_the_writable_layer_moves_freely() {
    assert!(can_move(&Config::default(), true, PURE_UPPER));
}

#[test]
fn a_plain_move_needs_nothing_extra() {
    assert_eq!(rename_plan(false, false, false, false), RenamePlan::default());
}

#[test]
fn a_source_that_still_exists_below_leaves_a_cover() {
    assert_eq!(rename_plan(false, true, false, false),
               RenamePlan { whiteout: true, exchange: false, cleanup: false });
}

#[test]
fn a_cover_already_at_the_destination_is_swapped_rather_than_replaced() {
    // One step that both puts the object in place and leaves a cover behind,
    // where two steps could be interrupted between them.
    assert_eq!(rename_plan(false, true, true, false),
               RenamePlan { whiteout: false, exchange: true, cleanup: false });
}

#[test]
fn a_directory_moving_onto_a_cover_swaps_and_then_tidies_up() {
    assert_eq!(rename_plan(false, false, true, true),
               RenamePlan { whiteout: false, exchange: true, cleanup: true });
}

#[test]
fn an_explicit_swap_stays_a_swap() {
    assert_eq!(rename_plan(true, true, true, true),
               RenamePlan { whiteout: false, exchange: true, cleanup: false });
}

#[test]
fn a_new_directory_over_a_cover_is_opaque() {
    // The cover was hiding a lower directory of the same name; without this
    // the lower one would merge into the new one.
    assert!(new_dir_opaque(&Config::default(), true, false));
}

#[test]
fn a_new_directory_in_a_merged_parent_is_opaque_only_where_layers_may_not_change() {
    let plain = Config::default();
    assert!(!new_dir_opaque(&plain, false, true));
    let strict = Config { index: true, ..Config::default() };
    assert!(new_dir_opaque(&strict, false, true));
    assert!(!new_dir_opaque(&strict, false, false));
}

#[test]
fn only_the_two_flags_this_filesystem_can_carry_out_are_accepted() {
    assert!(rename_flags_ok(0));
    assert!(rename_flags_ok(RENAME_NOREPLACE));
    assert!(rename_flags_ok(RENAME_EXCHANGE));
    assert!(!rename_flags_ok(1 << 5));
}
