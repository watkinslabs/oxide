//! The ladder deciding whether one `fsync` may take the chain, with nothing
//! but the state it reads.

use super::*;

/// A state in which the chain is available, which every case below breaks in
/// exactly one place.
fn ok() -> SyncState {
    SyncState {
        regular: true,
        compressed: false,
        links: 1,
        pino_ok: true,
        space_for_roll_forward: true,
        parent_checkpointed: true,
        fastboot: false,
        active_logs: 6,
        strict: false,
        need_dentry_mark: false,
        parent_dir_written: false,
        parent_xattr_written: false,
    }
}

#[test]
fn the_ordinary_state_takes_the_chain() {
    assert_eq!(need_checkpoint(&ok()), CpReason::None);
    assert!(!need_checkpoint(&ok()).needed());
}

#[test]
fn a_directory_takes_the_checkpoint() {
    let s = SyncState { regular: false, ..ok() };
    assert_eq!(need_checkpoint(&s), CpReason::NonRegular);
    assert!(need_checkpoint(&s).needed());
}

#[test]
fn a_compressed_file_takes_the_checkpoint() {
    assert_eq!(need_checkpoint(&SyncState { compressed: true, ..ok() }), CpReason::Compressed);
}

#[test]
fn a_second_name_takes_the_checkpoint() {
    assert_eq!(need_checkpoint(&SyncState { links: 2, ..ok() }), CpReason::Hardlink);
}

#[test]
fn no_name_at_all_takes_the_checkpoint() {
    assert_eq!(need_checkpoint(&SyncState { links: 0, ..ok() }), CpReason::Hardlink);
}

#[test]
fn a_stale_parent_number_takes_the_checkpoint() {
    assert_eq!(need_checkpoint(&SyncState { pino_ok: false, ..ok() }), CpReason::WrongPino);
}

#[test]
fn a_full_volume_takes_the_checkpoint() {
    let s = SyncState { space_for_roll_forward: false, ..ok() };
    assert_eq!(need_checkpoint(&s), CpReason::NoSpaceRollForward);
}

#[test]
fn a_parent_that_is_not_yet_durable_takes_the_checkpoint() {
    let s = SyncState { parent_checkpointed: false, ..ok() };
    assert_eq!(need_checkpoint(&s), CpReason::ParentNotCheckpointed);
}

#[test]
fn fastboot_takes_the_checkpoint() {
    let s = SyncState { fastboot: true, ..ok() };
    assert_eq!(need_checkpoint(&s), CpReason::Fastboot);
    assert!(need_checkpoint(&s).needed());
}

#[test]
fn fastboot_is_read_before_the_log_count() {
    // The rung sits between the parent's durability and the log count, so a
    // state that trips both reports the earlier one.
    let s = SyncState { fastboot: true, active_logs: 2, ..ok() };
    assert_eq!(need_checkpoint(&s), CpReason::Fastboot);
    assert_eq!(need_checkpoint(&SyncState { fastboot: false, ..s }), CpReason::SpecLogNum);
}

#[test]
fn a_parent_not_yet_durable_is_read_before_fastboot() {
    let s = SyncState { fastboot: true, parent_checkpointed: false, ..ok() };
    assert_eq!(need_checkpoint(&s), CpReason::ParentNotCheckpointed);
}

#[test]
fn two_logs_take_the_checkpoint() {
    assert_eq!(need_checkpoint(&SyncState { active_logs: 2, ..ok() }), CpReason::SpecLogNum);
}

#[test]
fn four_logs_do_not() {
    assert_eq!(need_checkpoint(&SyncState { active_logs: 4, ..ok() }), CpReason::None);
}

#[test]
fn strict_mode_alone_does_not_force_a_checkpoint() {
    assert_eq!(need_checkpoint(&SyncState { strict: true, ..ok() }), CpReason::None);
}

#[test]
fn strict_mode_with_an_entry_still_in_the_chain_does() {
    let s = SyncState { strict: true, need_dentry_mark: true, parent_dir_written: true, ..ok() };
    assert_eq!(need_checkpoint(&s), CpReason::RecoverDir);
}

#[test]
fn the_same_state_without_strict_mode_does_not() {
    let s = SyncState { need_dentry_mark: true, parent_dir_written: true, ..ok() };
    assert_eq!(need_checkpoint(&s), CpReason::None);
}

#[test]
fn a_parents_attributes_still_in_the_chain_take_the_checkpoint() {
    let s = SyncState { parent_xattr_written: true, ..ok() };
    assert_eq!(need_checkpoint(&s), CpReason::XattrDir);
}

#[test]
fn the_first_reason_is_the_one_reported() {
    let s = SyncState {
        regular: false, compressed: true, links: 4, pino_ok: false,
        space_for_roll_forward: false, parent_checkpointed: false, active_logs: 2,
        ..ok()
    };
    assert_eq!(need_checkpoint(&s), CpReason::NonRegular);
}

#[test]
fn dropping_the_first_reason_uncovers_the_second() {
    let s = SyncState {
        compressed: true, links: 4, pino_ok: false, space_for_roll_forward: false,
        parent_checkpointed: false, active_logs: 2, ..ok()
    };
    assert_eq!(need_checkpoint(&s), CpReason::Compressed);
    let s = SyncState { compressed: false, ..s };
    assert_eq!(need_checkpoint(&s), CpReason::Hardlink);
    let s = SyncState { links: 1, ..s };
    assert_eq!(need_checkpoint(&s), CpReason::WrongPino);
    let s = SyncState { pino_ok: true, ..s };
    assert_eq!(need_checkpoint(&s), CpReason::NoSpaceRollForward);
    let s = SyncState { space_for_roll_forward: true, ..s };
    assert_eq!(need_checkpoint(&s), CpReason::ParentNotCheckpointed);
    let s = SyncState { parent_checkpointed: true, ..s };
    assert_eq!(need_checkpoint(&s), CpReason::SpecLogNum);
    let s = SyncState { fastboot: true, ..s };
    assert_eq!(need_checkpoint(&s), CpReason::Fastboot);
    let s = SyncState { fastboot: false, ..s };
    assert_eq!(need_checkpoint(&s), CpReason::SpecLogNum);
    let s = SyncState { active_logs: 6, ..s };
    assert_eq!(need_checkpoint(&s), CpReason::None);
}

#[test]
fn only_the_no_reason_case_reports_no_need() {
    let all = [
        CpReason::NonRegular, CpReason::Compressed, CpReason::Hardlink,
        CpReason::WrongPino, CpReason::NoSpaceRollForward,
        CpReason::ParentNotCheckpointed, CpReason::Fastboot, CpReason::SpecLogNum,
        CpReason::RecoverDir, CpReason::XattrDir,
    ];
    for r in all { assert!(r.needed(), "{r:?} must force a checkpoint"); }
    assert!(!CpReason::None.needed());
}
