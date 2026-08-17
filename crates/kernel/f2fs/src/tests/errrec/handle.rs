//! What a mount does when it finds something wrong, and that the record it
//! leaves is on the medium rather than only in memory.

use super::*;
use crate::errrec::handle::{decide, Outcome, Situation};
use crate::opts::{Errors, Options};
use crate::test_image;
use crate::uapi::BLKSIZE;
use crate::volume::Volume;
use sectors::MemImage;

fn plain(reason: StopReason) -> Situation {
    Situation { reason, errors: Errors::Continue, hw_ro: false, mount_ro: false,
                already_shutdown: false, going_down: false }
}

// ------------------------------------------------------------- the decision

#[test]
fn errors_continue_keeps_serving_and_still_records() {
    let o = decide(&plain(StopReason::WriteFail));
    assert_eq!(o, Outcome { record: true, halt: false, shutdown: false, go_readonly: false });
}

#[test]
fn errors_remount_ro_stops_serving_writes() {
    let s = Situation { errors: Errors::RemountRo, ..plain(StopReason::WriteFail) };
    assert!(decide(&s).go_readonly);
    assert!(!decide(&s).halt);
}

#[test]
fn errors_panic_halts() {
    let s = Situation { errors: Errors::Panic, ..plain(StopReason::WriteFail) };
    assert!(decide(&s).halt);
}

#[test]
fn a_machine_on_its_way_down_does_not_halt_whatever_the_option_said() {
    // The device may already be gone, so a halt then is a crash with no
    // diagnosis rather than one with a cause.
    let s = Situation { errors: Errors::Panic, going_down: true, ..plain(StopReason::WriteFail) };
    assert!(!decide(&s).halt);
    let s = Situation { errors: Errors::Panic, already_shutdown: true,
                        ..plain(StopReason::WriteFail) };
    assert!(!decide(&s).halt);
}

#[test]
fn a_deliberate_shutdown_never_halts_and_never_goes_read_only() {
    // Read-only is reached through the remount path, which a shutdown is past;
    // taking it here blocks on a freeze nothing will thaw.
    for e in [Errors::Continue, Errors::RemountRo, Errors::Panic] {
        let s = Situation { errors: e, ..plain(StopReason::Shutdown) };
        let o = decide(&s);
        assert!(!o.halt, "{e:?}");
        assert!(!o.go_readonly, "{e:?}");
        assert!(o.shutdown, "{e:?}");
    }
}

#[test]
fn a_mount_that_is_already_read_only_is_not_made_read_only_again() {
    let s = Situation { errors: Errors::RemountRo, mount_ro: true,
                        ..plain(StopReason::WriteFail) };
    assert!(!decide(&s).go_readonly);
}

#[test]
fn a_medium_that_refuses_writes_records_nothing() {
    // Counting a stop in memory that no later mount can see is worse than not
    // counting it: the array would claim a history it cannot show.
    let s = Situation { hw_ro: true, ..plain(StopReason::WriteFail) };
    assert!(!decide(&s).record);
    assert!(decide(&plain(StopReason::WriteFail)).record);
}

// ------------------------------------------------- against a live volume

#[test]
fn a_recorded_error_survives_a_remount_of_the_image_bytes() {
    let mut v = test_image::with_root().mount_rw().expect("mount");
    assert!(v.handle_error(Error::InconsistentNat));
    assert!(!v.handle_error(Error::InconsistentNat), "the second is not news");
    let bytes = v.into_source().snapshot();
    let img = MemImage::from_bytes(BLKSIZE as u32, bytes);
    let v = Volume::mount_with(img, Options::defaults(), true).expect("remount");
    assert!(v.error_record().has_error(Error::InconsistentNat));
    assert!(!v.error_record().has_error(Error::CorruptedXattr));
}

#[test]
fn a_stop_reason_survives_a_remount_and_accumulates_across_them() {
    let mut v = test_image::with_root().mount_rw().expect("mount");
    v.stop_checkpoint(StopReason::WriteFail, false);
    let bytes = v.into_source().snapshot();
    let img = MemImage::from_bytes(BLKSIZE as u32, bytes);
    let mut v = Volume::mount_with(img, Options::defaults(), true).expect("remount");
    assert_eq!(v.error_record().stops(StopReason::WriteFail), 1);
    v.stop_checkpoint(StopReason::WriteFail, false);
    let bytes = v.into_source().snapshot();
    let img = MemImage::from_bytes(BLKSIZE as u32, bytes);
    let v = Volume::mount_with(img, Options::defaults(), true).expect("remount");
    assert_eq!(v.error_record().stops(StopReason::WriteFail), 2,
               "the arrays are cumulative, not per-mount");
}

#[test]
fn a_later_mount_does_not_erase_what_an_earlier_one_recorded() {
    let mut v = test_image::with_root().mount_rw().expect("mount");
    v.handle_error(Error::CorruptedDirent);
    let bytes = v.into_source().snapshot();
    let img = MemImage::from_bytes(BLKSIZE as u32, bytes);
    let mut v = Volume::mount_with(img, Options::defaults(), true).expect("remount");
    v.handle_error(Error::CorruptedXattr);
    let bytes = v.into_source().snapshot();
    let img = MemImage::from_bytes(BLKSIZE as u32, bytes);
    let v = Volume::mount_with(img, Options::defaults(), true).expect("remount");
    assert!(v.error_record().has_error(Error::CorruptedDirent), "the first mount's kind");
    assert!(v.error_record().has_error(Error::CorruptedXattr), "and the second's");
}

#[test]
fn stopping_marks_the_checkpoint_as_failed() {
    let mut v = test_image::with_root().mount_rw().expect("mount");
    assert_eq!(v.checkpoint().flags & crate::flags::CP_ERROR_FLAG, 0);
    v.stop_checkpoint(StopReason::CorruptedNid, false);
    assert_ne!(v.checkpoint().flags & crate::flags::CP_ERROR_FLAG, 0);
}

#[test]
fn errors_remount_ro_actually_stops_the_writes() {
    let opts = Options { errors: Errors::RemountRo, ..Options::defaults() };
    let mut v = test_image::with_root().mount_opts(opts).expect("mount");
    assert!(v.writable());
    let out = v.stop_checkpoint(StopReason::CorruptedSummary, false);
    assert!(out.go_readonly);
    assert!(!v.writable(), "the mount must have stopped serving writes");
}

#[test]
fn a_shutdown_marks_the_volume_shut_down() {
    let mut v = test_image::with_root().mount_rw().expect("mount");
    assert!(!v.sbi_flags().shutdown());
    v.stop_checkpoint(StopReason::Shutdown, false);
    assert!(v.sbi_flags().shutdown());
    assert!(v.writable(), "a shutdown does not take the read-only path");
}

#[test]
fn a_read_only_mount_still_records_what_it_found() {
    // The record is the one thing a read-only mount writes. A checker's whole
    // reason to read the array is a volume that has been mounted read-only
    // BECAUSE something was wrong with it, and a mount that held the finding
    // in memory would leave that volume looking untouched.
    let v = test_image::with_root().mount_rw().expect("mount");
    let bytes = v.into_source().snapshot();
    let img = MemImage::from_bytes(BLKSIZE as u32, bytes);
    let mut v = Volume::mount_with(img, Options::defaults(), false).expect("mount ro");
    assert!(!v.writable());
    assert!(v.handle_error(Error::InvalidBlkaddr));
    assert!(!v.error_record().dirty(), "the finding reached the medium");
    let bytes = v.into_source().snapshot();
    let img = MemImage::from_bytes(BLKSIZE as u32, bytes);
    let v = Volume::mount_with(img, Options::defaults(), true).expect("remount");
    assert!(v.error_record().has_error(Error::InvalidBlkaddr));
}
