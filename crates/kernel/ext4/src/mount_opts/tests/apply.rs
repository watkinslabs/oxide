// How an accepted mount-data string lands on a superblock's quota option
// state — the state the mount path then turns into live quota accounting.

use crate::mount_opts::{SbQuotaOpts, configure};
use crate::mount_opts::flags::*;
use super::{hidden, live, plain, project};

use vfs::{QuotaType, VfsError};

const NO_NAMES: [Option<&str>; 3] = [None, None, None];
const FRESH: bool = false;
const LOADED: bool = true;

#[test]
fn usrquota_requests_user_limits_only() {
    let mut sb = SbQuotaOpts::default();
    configure("rw,usrquota", &plain(), &mut sb, FRESH).expect("configure");
    assert!(sb.test_opt(EXT4_MOUNT_QUOTA));
    assert!(sb.limits_requested(QuotaType::User));
    assert!(!sb.limits_requested(QuotaType::Group));
    assert!(!sb.limits_requested(QuotaType::Project));
}

#[test]
fn quota_is_the_user_quota_spelling() {
    let mut a = SbQuotaOpts::default();
    let mut b = SbQuotaOpts::default();
    configure("quota", &plain(), &mut a, FRESH).expect("configure quota");
    configure("usrquota", &plain(), &mut b, FRESH).expect("configure usrquota");
    assert_eq!(a, b);
}

#[test]
fn prjquota_requests_project_limits_on_a_project_filesystem() {
    let mut sb = SbQuotaOpts::default();
    configure("prjquota", &project(), &mut sb, FRESH).expect("configure");
    assert!(sb.limits_requested(QuotaType::Project));
    assert!(!sb.limits_requested(QuotaType::User));
}

#[test]
fn noquota_clears_options_already_on_the_superblock() {
    let mut sb = live(NO_NAMES, 0, EXT4_MOUNT_QUOTA | EXT4_MOUNT_USRQUOTA | EXT4_MOUNT_GRPQUOTA);
    configure("noquota", &plain(), &mut sb, FRESH).expect("configure");
    assert_eq!(sb.mount_opt & EXT4_MOUNT_QUOTA_MASK, 0);
    assert!(!sb.limits_requested(QuotaType::User));
}

#[test]
fn a_journalled_quota_file_records_its_name_format_and_implies_accounting() {
    let mut sb = SbQuotaOpts::default();
    configure("usrjquota=aquota.user,jqfmt=vfsv1", &plain(), &mut sb, FRESH).expect("configure");
    assert_eq!(sb.journalled_file(QuotaType::User), Some("aquota.user"));
    assert_eq!(sb.journalled_file(QuotaType::Group), None);
    assert_eq!(sb.jquota_fmt, vfs::QFMT_VFS_V1);
    assert!(sb.test_opt(EXT4_MOUNT_QUOTA), "a named quota file implies accounting");
    assert!(!sb.limits_requested(QuotaType::User), "the plain user-quota bit is not implied");
    assert!(sb.has_journalled_files());
}

#[test]
fn both_journalled_quota_files_can_be_named_at_once() {
    let mut sb = SbQuotaOpts::default();
    configure("usrjquota=aquota.user,grpjquota=aquota.group,jqfmt=vfsv0", &plain(), &mut sb, FRESH)
        .expect("configure");
    assert_eq!(sb.journalled_file(QuotaType::User), Some("aquota.user"));
    assert_eq!(sb.journalled_file(QuotaType::Group), Some("aquota.group"));
    assert_eq!(sb.jquota_fmt, vfs::QFMT_VFS_V0);
}

#[test]
fn an_empty_journalled_name_removes_the_file_from_the_superblock() {
    let mut sb = live([Some("aquota.user"), None, None], vfs::QFMT_VFS_V1, EXT4_MOUNT_QUOTA);
    configure("usrjquota=", &plain(), &mut sb, FRESH).expect("configure");
    assert_eq!(sb.journalled_file(QuotaType::User), None);
    assert!(!sb.has_journalled_files());
}

#[test]
fn hidden_quota_inodes_suppress_journalled_names_and_format() {
    let mut sb = SbQuotaOpts::default();
    configure("usrjquota=aquota.user,jqfmt=vfsv1,prjquota", &hidden(), &mut sb, FRESH)
        .expect("configure");
    assert_eq!(sb.journalled_file(QuotaType::User), None, "kernel-owned quota inodes win");
    assert_eq!(sb.jquota_fmt, 0);
    // The plain quota options still apply — they select limit enforcement.
    assert!(sb.limits_requested(QuotaType::Project));
}

#[test]
fn unknown_options_do_not_disturb_quota_state() {
    let mut sb = SbQuotaOpts::default();
    configure("rw,relatime,errors=remount-ro,data=ordered,nobarrier", &plain(), &mut sb, FRESH)
        .expect("unknown options never fail an ext4 mount");
    assert_eq!(sb, SbQuotaOpts::default());
}

#[test]
fn a_rejected_data_string_leaves_the_superblock_untouched() {
    let before = live([Some("aquota.user"), None, None], vfs::QFMT_VFS_V1, EXT4_MOUNT_QUOTA);
    let mut sb = before.clone();
    assert_eq!(
        configure("usrjquota=other.user", &plain(), &mut sb, LOADED).err(),
        Some(VfsError::Einval),
    );
    assert_eq!(sb, before);
}

#[test]
fn remount_restating_the_current_options_is_a_no_op() {
    let before = live([Some("aquota.user"), None, None], vfs::QFMT_VFS_V1, EXT4_MOUNT_QUOTA);
    let mut sb = before.clone();
    configure("usrjquota=aquota.user,jqfmt=vfsv1", &plain(), &mut sb, LOADED)
        .expect("restating the live options");
    assert_eq!(sb, before);
}
