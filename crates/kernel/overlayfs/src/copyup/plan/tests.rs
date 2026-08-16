//! The shape of a copy-up, and the order of its steps.

extern crate alloc;

use vfs::types::FileType;

use crate::config::{Config, VerityMode};

use super::{need_index, need_meta_copy_up, needs_copy_up, steps, Kind, Step, O_RDONLY, O_TRUNC};

/// Position of a step in a plan, or `None` when it does not run.
fn at(plan: &[Step], s: Step) -> Option<usize> { plan.iter().position(|&x| x == s) }

#[test]
fn a_read_only_open_needs_no_copy() {
    // This is what keeps starting a container from copying its whole image.
    assert!(!needs_copy_up(O_RDONLY));
    assert!(!needs_copy_up(0));
}

#[test]
fn a_write_or_a_truncate_needs_one() {
    assert!(needs_copy_up(1));
    assert!(needs_copy_up(2));
    assert!(needs_copy_up(O_RDONLY | O_TRUNC));
}

#[test]
fn the_data_is_copied_before_the_attributes() {
    // Writing a file's contents clears its capabilities, so attributes copied
    // first would be silently dropped by the data copy that follows.
    let plan = steps(Kind::File, true, false);
    assert!(at(&plan, Step::CopyData) < at(&plan, Step::CopyXattrs));
}

#[test]
fn the_move_into_place_is_last_but_one() {
    // Nothing incomplete may ever appear under the destination name; only the
    // parent's timestamps are restored afterwards, and they are on the
    // directory, not on the object.
    for kind in [Kind::File, Kind::MetaOnly, Kind::Dir, Kind::Symlink, Kind::Special] {
        let plan = steps(kind, true, true);
        assert_eq!(plan[plan.len() - 2], Step::MoveIntoPlace, "{kind:?}");
        assert_eq!(plan[plan.len() - 1], Step::RestoreParentTimes, "{kind:?}");
    }
}

#[test]
fn every_content_step_runs_before_the_move() {
    for kind in [Kind::File, Kind::MetaOnly, Kind::Dir, Kind::Symlink, Kind::Special] {
        let plan = steps(kind, true, true);
        let mv = at(&plan, Step::MoveIntoPlace).unwrap();
        for s in [Step::CreateTemp, Step::CopyXattrs, Step::SetOrigin, Step::SetAttrs] {
            if let Some(i) = at(&plan, s) { assert!(i < mv, "{kind:?} {s:?}"); }
        }
    }
}

#[test]
fn the_size_is_set_before_the_timestamps() {
    // Truncating afterwards would move the modification time that was just
    // restored from the lower object.
    let plan = steps(Kind::File, true, false);
    assert!(at(&plan, Step::SetSize) < at(&plan, Step::SetAttrs));
}

#[test]
fn only_a_whole_file_copy_carries_data() {
    assert!(at(&steps(Kind::File, true, false), Step::CopyData).is_some());
    for kind in [Kind::MetaOnly, Kind::Dir, Kind::Symlink, Kind::Special] {
        assert!(at(&steps(kind, true, false), Step::CopyData).is_none(), "{kind:?}");
    }
}

#[test]
fn only_a_metadata_only_copy_records_one() {
    assert!(at(&steps(Kind::MetaOnly, true, false), Step::SetMetacopy).is_some());
    assert!(at(&steps(Kind::File, true, false), Step::SetMetacopy).is_none());
}

#[test]
fn the_origin_record_is_skipped_when_a_hardlink_is_being_broken() {
    assert!(at(&steps(Kind::File, false, false), Step::SetOrigin).is_none());
}

#[test]
fn the_flush_runs_only_when_the_mount_asked_for_it_and_before_the_move() {
    let plan = steps(Kind::File, true, true);
    assert!(at(&plan, Step::Fsync).unwrap() < at(&plan, Step::MoveIntoPlace).unwrap());
    assert!(at(&steps(Kind::File, true, false), Step::Fsync).is_none());
}

#[test]
fn the_kind_follows_the_object_type() {
    assert_eq!(Kind::of(FileType::Regular, false), Kind::File);
    assert_eq!(Kind::of(FileType::Regular, true), Kind::MetaOnly);
    assert_eq!(Kind::of(FileType::Directory, true), Kind::Dir);
    assert_eq!(Kind::of(FileType::Symlink, false), Kind::Symlink);
    assert_eq!(Kind::of(FileType::CharDev, false), Kind::Special);
    assert_eq!(Kind::of(FileType::Fifo, false), Kind::Special);
}

#[test]
fn metadata_only_needs_the_feature_a_regular_file_and_no_pending_write() {
    let on = Config { metacopy: true, ..Config::default() };
    assert!(need_meta_copy_up(&on, FileType::Regular, 0, false));
    assert!(!need_meta_copy_up(&Config::default(), FileType::Regular, 0, false));
    assert!(!need_meta_copy_up(&on, FileType::Directory, 0, false));
    assert!(!need_meta_copy_up(&on, FileType::Regular, 1, false));
    assert!(!need_meta_copy_up(&on, FileType::Regular, O_TRUNC, false));
}

#[test]
fn required_verification_forces_a_full_copy_when_the_lower_data_cannot_be_verified() {
    // The alternative is an object whose contents the mount promised to verify
    // and cannot.
    let c = Config { metacopy: true, verity_mode: VerityMode::Require, ..Config::default() };
    assert!(!need_meta_copy_up(&c, FileType::Regular, 0, false));
    assert!(need_meta_copy_up(&c, FileType::Regular, 0, true));
}

#[test]
fn only_a_lower_hardlink_is_indexed_unless_everything_is() {
    assert!(!need_index(false, false, false, 5));
    assert!(!need_index(true, false, false, 1));
    assert!(need_index(true, false, false, 2));
    assert!(!need_index(true, false, true, 2), "a directory is not a hardlink");
    assert!(need_index(true, true, true, 1));
}
