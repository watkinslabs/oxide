//! The volume's own metadata: its name, and whether it needs a check.
//!
//! Driven end to end against an image in memory, because the proof that a
//! rename worked is a fresh mount reading the new name back.

use crate::test_image;
use crate::uapi::*;
use crate::volume::Volume;
use sectors::MemImage;
use syscall::errno::Errno;

/// Renaming a volume replaces one attribute of one record, so the proof is a
/// fresh mount reading the name back: a remove-and-insert that damaged the
/// record would still leave the writing mount's cached name correct.
#[test]
fn a_renamed_volume_keeps_its_new_name_across_a_remount() {
    let image = {
        let mut v = test_image::empty();
        v.set_label("WORK DISK").unwrap();
        assert_eq!(v.label(), "WORK DISK");
        // The rest of the volume record has to survive the replacement: the
        // version and the flags live in a sibling attribute of the same one.
        assert_ne!(v.version(), (0, 0));
        v.into_source()
    };
    let mut opts = crate::opts::Options::defaults();
    opts.settle();
    let v = Volume::mount_with(image, opts).unwrap();
    assert_eq!(v.label(), "WORK DISK");
    assert_ne!(v.version(), (0, 0), "the volume information attribute is still readable");
}

/// A name too long for the on-disk field is refused, and the volume keeps the
/// name it had — a truncated name is a volume answering to something nobody
/// asked for.
#[test]
fn an_oversized_label_is_refused_and_changes_nothing() {
    let mut v = test_image::empty();
    let before = v.label();
    let long: alloc::string::String = core::iter::repeat('x').take(NTFS_LABEL_MAX + 1).collect();
    assert_eq!(v.set_label(&long), Err(Errno::Efbig));
    assert_eq!(v.label(), before);
}

/// A read-only mount refuses the rename rather than reporting a name the
/// medium never took.
#[test]
fn a_read_only_volume_refuses_a_rename() {
    let mut v = test_image::empty();
    v.set_read_only();
    assert_eq!(v.set_label("NOPE"), Err(Errno::Erofs));
}

/// A volume found dirty needs a check whatever its flag reads later, so the
/// fact is recorded when it is loaded. A mount that only kept the flag would
/// call the volume clean the moment it cleared it at unmount.
#[test]
fn a_volume_found_dirty_reports_that_it_needs_a_check() {
    let clean = test_image::empty();
    assert!(!clean.real_dirty(), "a clean image needs no check");
    let image = {
        let mut v = test_image::empty();
        v.set_dirty(true).unwrap();
        v.into_source()
    };
    let mut opts = crate::opts::Options::defaults();
    opts.settle();
    let v = Volume::mount_with(image, opts).unwrap();
    assert!(v.real_dirty(), "the volume was found dirty");
    assert!(v.was_dirty(), "and its flag says so too");
}
