// Every quota mount-option combination ext4 refuses, with its errno.
// `LOADED`/`FRESH` is the remount vs first-mount distinction.

use crate::mount_opts::check_quota_consistency;
use crate::mount_opts::flags::*;
use super::{hidden, live, parsed, plain, project};

use vfs::VfsError;

const LOADED: bool = true;
const FRESH: bool = false;
const NO_NAMES: [Option<&str>; 3] = [None, None, None];

#[test]
fn prjquota_requires_the_project_feature() {
    let mut o = parsed("prjquota").expect("parses");
    assert_eq!(
        check_quota_consistency(&mut o, &plain(), &live(NO_NAMES, 0, 0), FRESH).err(),
        Some(VfsError::Einval),
    );
    let mut o = parsed("prjquota").expect("parses");
    check_quota_consistency(&mut o, &project(), &live(NO_NAMES, 0, 0), FRESH)
        .expect("project feature present");
}

#[test]
fn user_and_group_quota_need_no_feature_bit() {
    // Legacy quotas living in quota files predate the on-disk feature.
    let mut o = parsed("usrquota,grpquota").expect("parses");
    check_quota_consistency(&mut o, &plain(), &live(NO_NAMES, 0, 0), FRESH)
        .expect("usr/grp quota allowed without any quota feature");
}

#[test]
fn turning_quota_options_off_while_quota_is_loaded_is_einval() {
    let mut o = parsed("noquota").expect("parses");
    assert_eq!(
        check_quota_consistency(&mut o, &plain(), &live(NO_NAMES, 0, EXT4_MOUNT_QUOTA), LOADED).err(),
        Some(VfsError::Einval),
    );
    // Same option on a mount with no quota loaded is fine.
    let mut o = parsed("noquota").expect("parses");
    check_quota_consistency(&mut o, &plain(), &live(NO_NAMES, 0, 0), FRESH)
        .expect("noquota on a quota-less mount");
}

#[test]
fn setting_a_quota_option_while_quota_is_loaded_is_allowed() {
    let mut o = parsed("usrquota").expect("parses");
    check_quota_consistency(&mut o, &plain(), &live(NO_NAMES, 0, EXT4_MOUNT_QUOTA), LOADED)
        .expect("adding a quota option while loaded");
}

#[test]
fn adding_a_journalled_quota_file_while_quota_is_loaded_is_einval() {
    let mut o = parsed("usrjquota=aquota.user,jqfmt=vfsv1").expect("parses");
    assert_eq!(
        check_quota_consistency(&mut o, &plain(), &live(NO_NAMES, vfs::QFMT_VFS_V1, 0), LOADED).err(),
        Some(VfsError::Einval),
    );
}

#[test]
fn removing_a_journalled_quota_file_while_quota_is_loaded_is_einval() {
    let mut o = parsed("usrjquota=").expect("parses");
    let sb = live([Some("aquota.user"), None, None], vfs::QFMT_VFS_V1, EXT4_MOUNT_QUOTA);
    assert_eq!(
        check_quota_consistency(&mut o, &plain(), &sb, LOADED).err(),
        Some(VfsError::Einval),
    );
}

#[test]
fn renaming_a_journalled_quota_file_is_einval_even_before_quota_loads() {
    let mut o = parsed("usrjquota=other.user,jqfmt=vfsv1").expect("parses");
    let sb = live([Some("aquota.user"), None, None], vfs::QFMT_VFS_V1, EXT4_MOUNT_QUOTA);
    assert_eq!(
        check_quota_consistency(&mut o, &plain(), &sb, FRESH).err(),
        Some(VfsError::Einval),
    );
}

#[test]
fn restating_the_same_journalled_quota_file_is_accepted() {
    let mut o = parsed("usrjquota=aquota.user,jqfmt=vfsv1").expect("parses");
    let sb = live([Some("aquota.user"), None, None], vfs::QFMT_VFS_V1, EXT4_MOUNT_QUOTA);
    check_quota_consistency(&mut o, &plain(), &sb, LOADED).expect("identical restatement");
}

#[test]
fn changing_jqfmt_while_quota_is_loaded_is_einval() {
    let mut o = parsed("jqfmt=vfsv0").expect("parses");
    let sb = live(NO_NAMES, vfs::QFMT_VFS_V1, EXT4_MOUNT_QUOTA);
    assert_eq!(
        check_quota_consistency(&mut o, &plain(), &sb, LOADED).err(),
        Some(VfsError::Einval),
    );
    // Restating the format already in force changes nothing and is accepted.
    let mut o = parsed("jqfmt=vfsv1").expect("parses");
    check_quota_consistency(&mut o, &plain(), &sb, LOADED).expect("same format restated");
}

#[test]
fn a_journalled_quota_file_without_a_format_is_einval() {
    let mut o = parsed("usrjquota=aquota.user").expect("parses");
    assert_eq!(
        check_quota_consistency(&mut o, &plain(), &live(NO_NAMES, 0, 0), FRESH).err(),
        Some(VfsError::Einval),
    );
    // A format already in force on the superblock satisfies the requirement.
    let mut o = parsed("usrjquota=aquota.user").expect("parses");
    check_quota_consistency(&mut o, &plain(), &live(NO_NAMES, vfs::QFMT_VFS_V1, 0), FRESH)
        .expect("superblock already carries a quota format");
}

#[test]
fn mixing_a_quota_file_with_the_superblock_plain_quota_option_is_einval() {
    // The superblock already enforces group quota the old way; the mount now
    // names a user quota file. Old and new form must not coexist.
    let mut o = parsed("usrjquota=aquota.user,jqfmt=vfsv1").expect("parses");
    let sb = live(NO_NAMES, 0, EXT4_MOUNT_QUOTA | EXT4_MOUNT_GRPQUOTA);
    assert_eq!(
        check_quota_consistency(&mut o, &plain(), &sb, FRESH).err(),
        Some(VfsError::Einval),
    );
}

#[test]
fn a_quota_file_clears_that_class_plain_option_off_the_superblock() {
    let mut o = parsed("usrjquota=aquota.user,jqfmt=vfsv1").expect("parses");
    let sb = live(NO_NAMES, 0, EXT4_MOUNT_QUOTA | EXT4_MOUNT_USRQUOTA);
    check_quota_consistency(&mut o, &plain(), &sb, FRESH).expect("quota file supersedes");
    assert!(o.mask & EXT4_MOUNT_USRQUOTA != 0, "the plain user-quota bit is masked off");
    assert!(!o.test_opt(EXT4_MOUNT_USRQUOTA));
}

#[test]
fn journalled_options_are_inert_when_hidden_quota_inodes_exist() {
    // With kernel-owned quota inodes the journalled options cannot take
    // effect, so they are accepted and ignored rather than failing the mount.
    let mut o = parsed("usrjquota=aquota.user").expect("parses");
    check_quota_consistency(&mut o, &hidden(), &live(NO_NAMES, 0, 0), FRESH)
        .expect("journalled options ignored, mount still succeeds");

    let mut o = parsed("jqfmt=vfsv0").expect("parses");
    check_quota_consistency(&mut o, &hidden(), &live(NO_NAMES, vfs::QFMT_VFS_V1, 0), FRESH)
        .expect("format option ignored");
}

#[test]
fn a_jqfmt_change_while_loaded_is_still_rejected_under_hidden_quota() {
    // The loaded-change guard runs before the feature short-circuit.
    let mut o = parsed("jqfmt=vfsv0").expect("parses");
    let sb = live(NO_NAMES, vfs::QFMT_VFS_V1, EXT4_MOUNT_QUOTA);
    assert_eq!(
        check_quota_consistency(&mut o, &hidden(), &sb, LOADED).err(),
        Some(VfsError::Einval),
    );
}

#[test]
fn plain_quota_options_still_apply_under_hidden_quota() {
    let mut o = parsed("usrquota,prjquota").expect("parses");
    check_quota_consistency(&mut o, &hidden(), &live(NO_NAMES, 0, 0), FRESH)
        .expect("plain options accepted");
    assert!(o.test_opt(EXT4_MOUNT_USRQUOTA));
    assert!(o.test_opt(EXT4_MOUNT_PRJQUOTA));
}
