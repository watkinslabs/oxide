//! The defaults a volume's shape dictates, one fact at a time.

use super::*;
use crate::flags::{FEATURE_BLKZONED, FEATURE_RO};
use crate::opts::{AllocMode, BackgroundGc, DiscardUnit, Errors, FsyncMode, MemoryMode, Mode,
                  Options};
use crate::uapi::DEFAULT_INLINE_XATTR_ADDRS;

/// A big, plain, writable volume on a device that cannot be discarded.
fn plain() -> Facts { Facts::plain(0, SMALL_VOLUME_SEGMENTS + 1) }

// ------------------------------------------------------- the three that were
// ------------------------------------------------------- wrong on their own

#[test]
fn the_build_wide_defaults_match_the_format() {
    let o = Options::defaults();
    assert!(o.checkpoint_merge, "the checkpoint thread is on by default");
    assert!(o.lazytime, "timestamps may lag by default");
    assert!(!o.nat_bits, "the free-node bitmap is asked for, never assumed");
}

#[test]
fn an_unnamed_inline_attribute_reservation_resolves_to_the_formats_own() {
    let o = Options::defaults();
    assert_eq!(o.inline_xattr_size, None, "nothing was named");
    assert_eq!(o.inline_xattr_addrs(), DEFAULT_INLINE_XATTR_ADDRS as u16);
    let o = Options { inline_xattr_size: Some(40), ..o };
    assert_eq!(o.inline_xattr_addrs(), 40);
}

// ------------------------------------------------------------ derived at mount

#[test]
fn a_read_only_volume_opens_two_logs_and_a_writable_one_six() {
    assert_eq!(Options::defaults_for(&plain()).active_logs, 6);
    let ro = Facts { feature: FEATURE_RO, ..plain() };
    assert_eq!(Options::defaults_for(&ro).active_logs, 2);
}

#[test]
fn discard_follows_the_device_and_not_the_build() {
    assert!(!Options::defaults_for(&plain()).discard, "a plain device is not told");
    let can = Facts { hw_support_discard: true, ..plain() };
    assert!(Options::defaults_for(&can).discard);
}

#[test]
fn a_zoned_volume_must_be_told_whatever_the_device_says() {
    let z = Facts { feature: FEATURE_BLKZONED, ..plain() };
    assert!(z.hw_should_discard());
    assert!(Options::defaults_for(&z).discard);
    assert_eq!(Options::defaults_for(&z).discard_unit, DiscardUnit::Section);
    assert_eq!(Options::defaults_for(&z).mode, Mode::Lfs);
}

#[test]
fn an_unzoned_volume_discards_by_the_block_and_writes_adaptively() {
    assert_eq!(Options::defaults_for(&plain()).discard_unit, DiscardUnit::Block);
    assert_eq!(Options::defaults_for(&plain()).mode, Mode::Adaptive);
}

#[test]
fn a_small_volume_reuses_space_inside_a_segment() {
    let small = Facts::plain(0, SMALL_VOLUME_SEGMENTS);
    assert_eq!(Options::defaults_for(&small).alloc_mode, AllocMode::Reuse);
    let big = Facts::plain(0, SMALL_VOLUME_SEGMENTS + 1);
    assert_eq!(Options::defaults_for(&big).alloc_mode, AllocMode::Default);
}

#[test]
fn flush_merge_is_on_unless_nothing_may_be_written() {
    assert!(Options::defaults_for(&plain()).flush_merge);
    assert!(!Options::defaults_for(&Facts { mount_ro: true, ..plain() }).flush_merge);
    assert!(!Options::defaults_for(&Facts { feature: FEATURE_RO, ..plain() }).flush_merge);
}

#[test]
fn the_rest_of_the_derived_set_is_what_the_format_states() {
    let o = Options::defaults_for(&plain());
    assert_eq!(o.fsync_mode, FsyncMode::Posix);
    assert_eq!(o.background_gc, BackgroundGc::On);
    assert_eq!(o.memory, MemoryMode::Normal);
    assert_eq!(o.errors, Errors::Continue);
    assert!(o.inline_xattr && o.inline_data && o.inline_dentry);
    assert!(o.extent_cache && !o.checkpoint_disabled);
    assert!(o.user_xattr && o.acl);
    assert_eq!((o.resuid, o.resgid), (0, 0));
}

// ------------------------------------------------------------ across a remount

#[test]
fn a_remount_keeps_the_four_settings_it_may_not_re_derive() {
    // Mounted with the extent cache off, the checkpoint off, discard on and by
    // the section — none of which a remount is allowed to undo behind the
    // caller's back.
    let mounted = Options { extent_cache: false, checkpoint_disabled: true, discard: true,
                            discard_unit: DiscardUnit::Section, ..Options::defaults_for(&plain()) };
    let again = Options::redefault(mounted, &plain(), true);
    assert!(!again.extent_cache);
    assert!(again.checkpoint_disabled);
    assert!(again.discard);
    assert_eq!(again.discard_unit, DiscardUnit::Section);
}

#[test]
fn a_fresh_mount_re_derives_all_four() {
    let mounted = Options { extent_cache: false, checkpoint_disabled: true, discard: true,
                            discard_unit: DiscardUnit::Section, ..Options::defaults_for(&plain()) };
    let fresh = Options::redefault(mounted, &plain(), false);
    assert!(fresh.extent_cache);
    assert!(!fresh.checkpoint_disabled);
    assert!(!fresh.discard);
    assert_eq!(fresh.discard_unit, DiscardUnit::Block);
}

#[test]
fn a_remount_resets_what_the_line_did_not_carry_over() {
    // Everything outside the four is reset, so a remount that stops naming an
    // option gets the default back rather than keeping the old value.
    let mounted = Options { background_gc: BackgroundGc::Off, lazytime: false,
                            active_logs: 2, ..Options::defaults_for(&plain()) };
    let again = Options::redefault(mounted, &plain(), true);
    assert_eq!(again.background_gc, BackgroundGc::On);
    assert!(again.lazytime);
    assert_eq!(again.active_logs, 6);
}

#[test]
fn a_remount_keeps_what_no_default_names() {
    // The options `default_options` never touches survive, which is what makes
    // a remount able to refuse a change to one of them: it can still see what
    // the mount had.
    let mounted = Options { atgc: true, nat_bits: true, age_extent_cache: true,
                            ..Options::defaults_for(&plain()) };
    let again = Options::redefault(mounted, &plain(), true);
    assert!(again.atgc && again.nat_bits && again.age_extent_cache);
}

// --------------------------------------- the reservation reaches a new inode

#[test]
fn a_new_inode_reserves_what_the_mount_line_asked_for() {
    // The wiring, not the value: an option parsed, bounded and reported that
    // no inode ever read would be a number with no effect.
    use crate::mode::S_IFREG;
    use crate::test_image::{self, ROOT_INO};
    use crate::volume::NewInode;
    let spec = NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: (1, 0) };
    let mut v = test_image::with_root()
        .mount_opts(Options { inline_xattr_size: Some(40), ..Options::defaults() })
        .expect("mount");
    let ino = v.create(ROOT_INO, b"f", &spec, None).expect("create");
    let sized = v.read_inode(ino).expect("inode").inline_xattr_addrs;

    let mut v = test_image::with_root().mount_rw().expect("mount");
    let ino = v.create(ROOT_INO, b"f", &spec, None).expect("create");
    let unsized_ = v.read_inode(ino).expect("inode").inline_xattr_addrs;

    // The fixture volume decides whether the reservation is per-inode at all.
    // Where it is, the option must be what lands; where it is not, both are
    // the same and the test says so rather than passing vacuously.
    if unsized_ == 0 {
        assert_eq!(sized, 0, "a volume without the flexible bit reserves nothing per inode");
    } else {
        assert_eq!(unsized_, DEFAULT_INLINE_XATTR_ADDRS, "unnamed takes the format's own");
        assert_eq!(sized, 40, "and a named size is what the inode records");
    }
}
