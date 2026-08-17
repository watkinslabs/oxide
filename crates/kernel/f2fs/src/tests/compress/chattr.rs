//! Turning a file's compression mark on and off after it exists.

use syscall::errno::Errno;

use crate::compress::chattr::{check, FileState, FlagChange};
use crate::flags::{FEATURE_COMPRESSION, F2FS_COMPR_FL, F2FS_NODUMP_FL, F2FS_NOCOMP_FL};

const ON: u32 = FEATURE_COMPRESSION;
const OFF: u32 = 0;

/// An empty regular file, which is the only shape the mark may be added to.
/// # C: O(1)
fn reg() -> FileState { FileState { is_reg: true, ..FileState::default() } }

#[test]
fn a_volume_that_cannot_record_the_settings_refuses_either_mark() {
    for bit in [F2FS_COMPR_FL, F2FS_NOCOMP_FL] {
        assert_eq!(check(OFF, 0, bit, &reg()), Err(Errno::Eopnotsupp), "{bit:#x}");
    }
    // An unrelated flag on such a volume is nobody's business here.
    assert_eq!(check(OFF, 0, F2FS_NODUMP_FL, &reg()), Ok(FlagChange::None));
}

#[test]
fn the_two_marks_may_not_both_be_asked_for() {
    assert_eq!(check(ON, 0, F2FS_COMPR_FL | F2FS_NOCOMP_FL, &reg()), Err(Errno::Einval));
}

#[test]
fn adding_the_mark_to_an_empty_regular_file_stamps_the_settings_with_it() {
    assert_eq!(check(ON, 0, F2FS_COMPR_FL, &reg()), Ok(FlagChange::Set));
    // A directory takes it too: it hands the mark on to what is made inside.
    let dir = FileState { is_dir: true, ..FileState::default() };
    assert_eq!(check(ON, 0, F2FS_COMPR_FL, &dir), Ok(FlagChange::Set));
    // A directory holding entries is still empty of DATA blocks, so the
    // block clause does not reach it.
    let dir = FileState { is_dir: true, has_blocks: true, ..FileState::default() };
    assert_eq!(check(ON, 0, F2FS_COMPR_FL, &dir), Ok(FlagChange::Set));
}

#[test]
fn a_file_that_already_holds_blocks_may_not_change_how_they_are_grouped() {
    let held = FileState { has_blocks: true, ..reg() };
    assert_eq!(check(ON, 0, F2FS_COMPR_FL, &held), Err(Errno::Einval));
    // And the mirror: the blocks already written ARE clusters.
    assert_eq!(check(ON, F2FS_COMPR_FL, 0, &held), Err(Errno::Einval));
    // Empty, either direction is fine.
    assert_eq!(check(ON, F2FS_COMPR_FL, 0, &reg()), Ok(FlagChange::Clear));
}

#[test]
fn nothing_that_is_neither_a_file_nor_a_directory_takes_the_mark() {
    let other = FileState::default();
    assert_eq!(check(ON, 0, F2FS_COMPR_FL, &other), Err(Errno::Einval));
}

#[test]
fn a_file_whose_layout_is_already_spoken_for_refuses_it() {
    for st in [FileState { pinned: true, ..reg() }, FileState { atomic: true, ..reg() }] {
        assert_eq!(check(ON, 0, F2FS_COMPR_FL, &st), Err(Errno::Einval), "{st:?}");
    }
}

#[test]
fn a_word_that_leaves_the_mark_where_it_was_changes_nothing() {
    assert_eq!(check(ON, F2FS_COMPR_FL, F2FS_COMPR_FL | F2FS_NODUMP_FL,
                     &FileState { has_blocks: true, ..reg() }),
               Ok(FlagChange::None));
    assert_eq!(check(ON, 0, F2FS_NODUMP_FL, &FileState { has_blocks: true, ..reg() }),
               Ok(FlagChange::None));
    // The refusing mark alone moves nothing about the compressing one.
    assert_eq!(check(ON, 0, F2FS_NOCOMP_FL, &reg()), Ok(FlagChange::None));
}
