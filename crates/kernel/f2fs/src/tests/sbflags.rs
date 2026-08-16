//! The status word: one bit per condition, at the position a reader decodes.
//!
//! The bit numbers are asserted literally rather than through the constants
//! that name them. A test written in terms of the constant cannot fail when
//! the constant moves, and the constant IS the ABI a monitoring tool reads.

use super::*;
use crate::flags::*;
use crate::sbflags::bits::*;

/// Every stored condition, its bit, and a word with only it raised.
fn only(pos: u32) -> u64 {
    let mut f = SbFlags::new();
    f.set(pos);
    f.word(Derived::default())
}

#[test]
fn each_condition_owns_the_bit_its_reader_decodes() {
    assert_eq!(only(IS_CLOSE), 1 << 1);
    assert_eq!(only(NEED_FSCK), 1 << 2);
    assert_eq!(only(NEED_SB_WRITE), 1 << 4);
    assert_eq!(only(NEED_CP), 1 << 5);
    assert_eq!(only(IS_SHUTDOWN), 1 << 6);
    assert_eq!(only(IS_RECOVERED), 1 << 7);
    assert_eq!(only(CP_DISABLED), 1 << 8);
    assert_eq!(only(CP_DISABLED_QUICK), 1 << 9);
    assert_eq!(only(QUOTA_SKIP_FLUSH), 1 << 11);
    assert_eq!(only(QUOTA_NEED_REPAIR), 1 << 12);
    assert_eq!(only(IS_RESIZEFS), 1 << 13);
    assert_eq!(only(IS_FREEZING), 1 << 14);
    assert_eq!(only(IS_WRITABLE), 1 << 15);
    assert_eq!(only(ENABLE_CHECKPOINT), 1 << 16);
}

#[test]
fn the_derived_conditions_own_their_bits_too() {
    let f = SbFlags::new();
    let none = Derived::default();
    assert_eq!(f.word(Derived { dirty: true, ..none }), 1 << 0);
    assert_eq!(f.word(Derived { recovering: true, ..none }), 1 << 3);
    assert_eq!(f.word(Derived { quota_dirty: true, ..none }), 1 << QUOTA_NEED_FLUSH);
    // Asserted through the constant here ONLY because the literal above
    // already pins it: the position is 10 and the derived path must use it.
    assert_eq!(QUOTA_NEED_FLUSH, 10);
}

#[test]
fn the_word_covers_every_condition_the_format_names() {
    let mut f = SbFlags::new();
    for pos in 0..MAX_SBI_FLAG { f.set(pos); }
    let all = f.word(Derived { dirty: true, recovering: true, quota_dirty: true });
    assert_eq!(all, (1u64 << MAX_SBI_FLAG) - 1, "a gap is a condition nothing can raise");
}

#[test]
fn a_derived_condition_is_not_stored_twice() {
    let mut f = SbFlags::new();
    f.set(IS_DIRTY);
    f.set(POR_DOING);
    f.set(QUOTA_NEED_FLUSH);
    assert_eq!(f.stored(), 0, "the volume's own state is the one copy");
    assert!(!f.is_set(IS_DIRTY));
    assert!(!f.is_set(QUOTA_NEED_FLUSH));
    assert_eq!(f.word(Derived { dirty: true, recovering: true, quota_dirty: true }),
               (1 << 0) | (1 << 3) | (1 << 10));
}

#[test]
fn raising_and_lowering_leave_the_rest_alone() {
    let mut f = SbFlags::new();
    f.set(NEED_CP);
    f.set(IS_SHUTDOWN);
    f.clear(NEED_CP);
    assert!(!f.is_set(NEED_CP));
    assert!(f.is_set(IS_SHUTDOWN));
}

// ------------------------------------------------- what the medium seeds

#[test]
fn a_checkpoint_marked_for_fsck_makes_the_mount_say_so() {
    let f = SbFlags::at_mount(CP_FSCK_FLAG);
    assert!(f.is_set(NEED_FSCK));
    assert!(!f.is_set(QUOTA_NEED_REPAIR));
}

#[test]
fn a_checkpoint_that_doubted_the_quota_files_makes_the_mount_doubt_them() {
    assert!(SbFlags::at_mount(CP_QUOTA_NEED_FSCK_FLAG).is_set(QUOTA_NEED_REPAIR));
}

#[test]
fn a_checkpoint_disabled_on_the_short_timer_says_which_timer() {
    assert!(SbFlags::at_mount(CP_DISABLED_QUICK_FLAG).is_set(CP_DISABLED_QUICK));
}

#[test]
fn a_clean_checkpoint_seeds_nothing() {
    assert_eq!(SbFlags::at_mount(CP_UMOUNT_FLAG).stored(), 0);
}

// ------------------------------------------------ what the medium is told

#[test]
fn the_fsck_mark_goes_into_the_checkpoint_and_is_never_taken_out() {
    let mut f = SbFlags::new();
    f.set(NEED_FSCK);
    assert_ne!(f.cp_flags(0) & CP_FSCK_FLAG, 0);
    // Even once nothing in memory says so: the volume stays suspect until a
    // checker clears it, and a checkpoint that dropped the mark would retire
    // it silently.
    let clean = SbFlags::new();
    assert_ne!(clean.cp_flags(CP_FSCK_FLAG) & CP_FSCK_FLAG, 0);
}

#[test]
fn a_resize_in_progress_is_recorded_and_a_finished_one_is_cleared() {
    let mut f = SbFlags::new();
    f.set(IS_RESIZEFS);
    assert_ne!(f.cp_flags(0) & CP_RESIZEFS_FLAG, 0);
    f.clear(IS_RESIZEFS);
    assert_eq!(f.cp_flags(CP_RESIZEFS_FLAG) & CP_RESIZEFS_FLAG, 0);
}

#[test]
fn disabled_checkpointing_is_recorded_and_re_enabling_clears_both_marks() {
    let mut f = SbFlags::new();
    f.disable_checkpoint(true);
    let w = f.cp_flags(0);
    assert_ne!(w & CP_DISABLED_FLAG, 0);
    assert_ne!(w & CP_DISABLED_QUICK_FLAG, 0);
    f.begin_enable_checkpoint();
    assert!(f.is_set(ENABLE_CHECKPOINT));
    f.end_enable_checkpoint();
    assert!(!f.is_set(ENABLE_CHECKPOINT));
    let w = f.cp_flags(CP_DISABLED_FLAG | CP_DISABLED_QUICK_FLAG);
    assert_eq!(w & (CP_DISABLED_FLAG | CP_DISABLED_QUICK_FLAG), 0);
}

#[test]
fn a_skipped_quota_flush_marks_the_checkpoint_and_a_taken_one_clears_it() {
    let mut f = SbFlags::new();
    f.set(QUOTA_SKIP_FLUSH);
    assert_ne!(f.cp_flags(0) & CP_QUOTA_NEED_FSCK_FLAG, 0);
    f.clear(QUOTA_SKIP_FLUSH);
    assert_eq!(f.cp_flags(CP_QUOTA_NEED_FSCK_FLAG) & CP_QUOTA_NEED_FSCK_FLAG, 0);
}

#[test]
fn a_quota_file_needing_repair_keeps_the_mark_a_taken_flush_would_clear() {
    let mut f = SbFlags::new();
    f.set(QUOTA_NEED_REPAIR);
    assert_ne!(f.cp_flags(CP_QUOTA_NEED_FSCK_FLAG) & CP_QUOTA_NEED_FSCK_FLAG, 0,
               "repair outranks a flush that was taken");
}

#[test]
fn a_checkpoint_retires_what_it_satisfied_and_nothing_else() {
    let mut f = SbFlags::new();
    f.set(NEED_CP);
    f.set(QUOTA_SKIP_FLUSH);
    f.set(NEED_FSCK);
    f.set(NEED_SB_WRITE);
    f.checkpointed();
    assert!(!f.need_cp());
    assert!(!f.is_set(QUOTA_SKIP_FLUSH));
    assert!(f.is_set(NEED_FSCK), "a checkpoint is not a repair");
    assert!(f.is_set(NEED_SB_WRITE), "a checkpoint is not a superblock write");
}

#[test]
fn a_flag_word_the_checkpoint_already_carries_is_left_as_it_is() {
    let f = SbFlags::new();
    let other = CP_UMOUNT_FLAG | CP_ORPHAN_PRESENT_FLAG | CP_LARGE_NAT_BITMAP_FLAG;
    assert_eq!(f.cp_flags(other), other);
}
