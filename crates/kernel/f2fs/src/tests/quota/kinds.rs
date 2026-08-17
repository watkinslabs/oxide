//! Which kinds of accounting a volume offers this mount.

use crate::flags::{CP_QUOTA_NEED_FSCK_FLAG, FEATURE_PRJQUOTA, FEATURE_QUOTA_INO};
use crate::opts::Options;
use crate::quota::types::{self, Enforcement};
use crate::quota::uapi::*;
use crate::quota::QuotaError;

fn opts(usr: bool, grp: bool, prj: bool) -> Options {
    Options { usrquota: usr, grpquota: grp, prjquota: prj, ..Options::defaults() }
}

const INOS: [u32; MAX_QUOTAS] = [4, 5, 6];

#[test]
fn a_volume_with_the_files_tracks_every_kind_it_has_unasked() {
    let s = types::resolve(&INOS, FEATURE_QUOTA_INO, 0, &opts(false, false, false)).unwrap();
    for t in 0..MAX_QUOTAS {
        assert_eq!(s[t].ino, INOS[t]);
        assert_eq!(s[t].enforcement, Enforcement::Usage);
        assert!(types::accounted(&s[t]), "counts stay current for the next mount");
        assert!(!types::enforced(&s[t]), "but nothing is refused");
    }
}

#[test]
fn the_mount_option_adds_enforcement_only_to_the_kind_it_names() {
    let feature = FEATURE_QUOTA_INO | FEATURE_PRJQUOTA;
    let s = types::resolve(&INOS, feature, 0, &opts(true, false, false)).unwrap();
    assert_eq!(s[USRQUOTA].enforcement, Enforcement::UsageAndLimits);
    assert_eq!(s[GRPQUOTA].enforcement, Enforcement::Usage);
    assert_eq!(s[PRJQUOTA].enforcement, Enforcement::Usage);
    let all = types::resolve(&INOS, feature, 0, &opts(true, true, true)).unwrap();
    for t in 0..MAX_QUOTAS {
        assert_eq!(all[t].enforcement, Enforcement::UsageAndLimits);
    }
}

#[test]
fn a_kind_the_volume_has_no_file_for_stays_off_however_it_is_asked_for() {
    let inos = [4, 0, 0];
    let s = types::resolve(&inos, FEATURE_QUOTA_INO, 0, &opts(true, true, false)).unwrap();
    assert_eq!(s[USRQUOTA].enforcement, Enforcement::UsageAndLimits);
    assert_eq!(s[GRPQUOTA].enforcement, Enforcement::Off);
    assert_eq!(s[GRPQUOTA].ino, 0);
    assert!(!types::accounted(&s[GRPQUOTA]));
    assert_eq!(s[PRJQUOTA].enforcement, Enforcement::Off);
}

#[test]
fn project_accounting_needs_the_volume_to_store_project_identities() {
    // Without the bit each inode has no project of its own, so the request is
    // refused at mount rather than accounting everything to one identity.
    let e = types::resolve(&INOS, FEATURE_QUOTA_INO, 0, &opts(false, false, true));
    assert_eq!(e, Err(QuotaError::NoProjectQuota));
    let ok = types::resolve(&INOS, FEATURE_QUOTA_INO | FEATURE_PRJQUOTA, 0, &opts(false, false, true));
    assert_eq!(ok.unwrap()[PRJQUOTA].enforcement, Enforcement::UsageAndLimits);
    // The other two kinds carry no such requirement.
    assert!(types::resolve(&INOS, FEATURE_QUOTA_INO, 0, &opts(true, true, false)).is_ok());
}

#[test]
fn a_volume_that_does_not_keep_its_files_as_inodes_offers_nothing_here() {
    // The inode numbers in the superblock mean nothing without the bit, so
    // following them would account against whatever inode four happens to be.
    let s = types::resolve(&INOS, 0, 0, &opts(true, true, false)).unwrap();
    for t in 0..MAX_QUOTAS {
        assert_eq!(s[t].enforcement, Enforcement::Off);
        assert_eq!(s[t].ino, 0);
    }
}

#[test]
fn a_checkpoint_that_marked_the_files_for_repair_suppresses_all_three() {
    let feature = FEATURE_QUOTA_INO | FEATURE_PRJQUOTA;
    let s = types::resolve(&INOS, feature, CP_QUOTA_NEED_FSCK_FLAG, &opts(true, true, true)).unwrap();
    for t in 0..MAX_QUOTAS {
        assert_eq!(s[t].enforcement, Enforcement::Off);
    }
    // The refusal of an impossible request still comes first.
    assert_eq!(
        types::resolve(&INOS, FEATURE_QUOTA_INO, CP_QUOTA_NEED_FSCK_FLAG, &opts(false, false, true)),
        Err(QuotaError::NoProjectQuota)
    );
}

#[test]
fn the_quota_files_themselves_are_not_accounted() {
    // Charging a quota file's growth to the identity it records is recursion.
    assert!(types::is_quota_inode(&INOS, FEATURE_QUOTA_INO, 4));
    assert!(types::is_quota_inode(&INOS, FEATURE_QUOTA_INO, 6));
    assert!(!types::is_quota_inode(&INOS, FEATURE_QUOTA_INO, 7));
    // A zero slot must not make inode zero a quota file.
    assert!(!types::is_quota_inode(&[0, 0, 0], FEATURE_QUOTA_INO, 0));
    // And without the bit the numbers are not inode numbers at all.
    assert!(!types::is_quota_inode(&INOS, 0, 4));
}

#[test]
fn a_quota_file_carries_the_attributes_that_keep_it_out_of_reach() {
    assert_eq!(QUOTA_DEFAULT_FL, crate::flags::F2FS_NOATIME_FL | crate::flags::F2FS_IMMUTABLE_FL);
    assert!(QUOTA_DEFAULT_FL & crate::flags::F2FS_IMMUTABLE_FL != 0);
}

#[test]
fn has_quota_ino_reads_the_one_bit_it_names() {
    assert!(types::has_quota_ino(FEATURE_QUOTA_INO));
    assert!(types::has_quota_ino(FEATURE_QUOTA_INO | FEATURE_PRJQUOTA));
    assert!(!types::has_quota_ino(FEATURE_PRJQUOTA));
    assert!(!types::has_quota_ino(0));
}

// ------------------------------------- files the mount names, not the volume

use crate::opts::jquota::{JqFmt, Jquota, QKind, QfName};

/// A mount naming one file per kind in `kinds`, in the format `fmt`.
fn named(kinds: &[QKind], fmt: Option<JqFmt>) -> Options {
    let mut j = Jquota { names: core::array::from_fn(|_| None), fmt };
    for k in kinds { j.names[*k as usize] = Some(QfName::new("aquota.file").unwrap()); }
    Options { jquota: j, ..Options::defaults() }
}

#[test]
fn a_volume_with_no_quota_inodes_accounts_the_kinds_the_mount_named() {
    let o = named(&[QKind::User, QKind::Group], Some(JqFmt::VfsV1));
    let s = types::resolve(&[0; MAX_QUOTAS], 0, 0, &o).unwrap();
    for t in [USRQUOTA, GRPQUOTA] {
        assert_eq!(s[t].enforcement, Enforcement::UsageAndLimits,
            "a named file was asked for by name, so it enforces");
        assert!(s[t].named, "the caller must resolve the name to an inode");
        assert_eq!(s[t].ino, 0, "and until it does there is no inode");
        assert_eq!(s[t].fmt, JqFmt::VfsV1 as u32);
        assert!(types::accounted(&s[t]));
        assert!(types::enforced(&s[t]));
    }
    assert_eq!(s[PRJQUOTA].enforcement, Enforcement::Off, "no name, no accounting");
    assert!(!s[PRJQUOTA].named);
}

#[test]
fn the_format_the_mount_named_is_the_one_the_kind_carries() {
    for fmt in [JqFmt::VfsOld, JqFmt::VfsV0, JqFmt::VfsV1] {
        let s = types::resolve(&[0; MAX_QUOTAS], 0, 0, &named(&[QKind::User], Some(fmt))).unwrap();
        assert_eq!(s[USRQUOTA].fmt, fmt as u32);
    }
}

#[test]
fn a_volume_that_keeps_its_own_quota_inodes_ignores_the_names() {
    // The superblock already answers the question the names were asking, and
    // opening both would keep two records for one identity.
    let o = named(&[QKind::User], Some(JqFmt::VfsV1));
    let s = types::resolve(&INOS, FEATURE_QUOTA_INO, 0, &o).unwrap();
    assert_eq!(s[USRQUOTA].ino, INOS[USRQUOTA]);
    assert!(!s[USRQUOTA].named);
    assert_eq!(s[USRQUOTA].fmt, types::SYSFILE_FORMAT);
    assert_eq!(s[USRQUOTA].enforcement, Enforcement::Usage, "the name is not an enforcement ask");
}

#[test]
fn a_named_file_with_no_format_is_unreadable_and_so_accounts_nothing() {
    let s = types::resolve(&[0; MAX_QUOTAS], 0, 0, &named(&[QKind::User], None)).unwrap();
    assert_eq!(s[USRQUOTA].enforcement, Enforcement::Off);
}

#[test]
fn a_checkpoint_that_marked_the_files_for_repair_suppresses_the_named_ones_too() {
    let o = named(&[QKind::User], Some(JqFmt::VfsV1));
    let s = types::resolve(&[0; MAX_QUOTAS], 0, CP_QUOTA_NEED_FSCK_FLAG, &o).unwrap();
    assert_eq!(s[USRQUOTA].enforcement, Enforcement::Off);
}

#[test]
fn every_kind_a_volume_offers_carries_the_format_it_is_read_with() {
    let s = types::resolve(&INOS, FEATURE_QUOTA_INO, 0, &opts(true, false, false)).unwrap();
    for t in 0..MAX_QUOTAS { assert_eq!(s[t].fmt, types::SYSFILE_FORMAT); }
    // A kind that is off carries no format at all, so nothing can read a file
    // for it by accident.
    let none = types::resolve(&[0; MAX_QUOTAS], FEATURE_QUOTA_INO, 0, &opts(true, true, false))
        .unwrap();
    for t in 0..MAX_QUOTAS { assert_eq!(none[t].fmt, 0); }
}
