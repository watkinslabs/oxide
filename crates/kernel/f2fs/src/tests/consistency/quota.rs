//! The two accounting arrangements, at a mount and across a remount.

use super::*;
use crate::consistency::{resolve_remount, Sbi};
use crate::flags::{FEATURE_PRJQUOTA, FEATURE_QUOTA_INO};
use crate::opts::{QKind, QfName};

/// A mount running with `line` already applied, ready to be reconfigured.
fn running(facts: &Facts, line: &str) -> Sbi {
    let cur = at_mount(facts, line).expect("the mount itself must be legal");
    Sbi { facts: *facts, cur, remount: true, quota_on: false, casefold_loadable: true }
}

fn name(s: &str) -> Option<QfName> { Some(QfName::new(s).expect("name")) }

// ------------------------------------------------------------ project quota

#[test]
fn project_enforcement_needs_the_field_to_enforce_against() {
    assert_eq!(at_mount(&plain(), "prjquota"), Err(Errno::Einval));
    let p = Facts { feature: FEATURE_PRJQUOTA, ..plain() };
    assert!(at_mount(&p, "prjquota").expect("accepted").prjquota);
}

// ---------------------------------------------------------------- mixing

#[test]
fn a_named_file_and_the_modern_flag_for_the_same_kind_settle_to_the_file() {
    let o = at_mount(&plain(), "usrquota,usrjquota=aq,jqfmt=vfsv1").expect("accepted");
    assert!(!o.usrquota, "the file wins");
    assert_eq!(o.jquota.names[QKind::User as usize], name("aq"));
}

#[test]
fn a_named_file_for_one_kind_and_the_flag_for_another_is_refused() {
    assert_eq!(at_mount(&plain(), "grpquota,usrjquota=aq,jqfmt=vfsv1"), Err(Errno::Einval));
}

#[test]
fn a_named_file_with_no_format_is_refused() {
    assert_eq!(at_mount(&plain(), "usrjquota=aq"), Err(Errno::Einval));
    assert!(at_mount(&plain(), "usrjquota=aq,jqfmt=vfsold").is_ok());
}

// ---------------------------------------------------------------- remount

#[test]
fn a_remount_may_restate_the_same_name() {
    let sbi = running(&plain(), "usrjquota=aq,jqfmt=vfsv1");
    let (o, spec) = resolve_remount(&sbi, "usrjquota=aq").expect("accepted");
    assert_eq!(o.jquota.names[QKind::User as usize], name("aq"));
    assert!(!spec.qname[QKind::User as usize], "restating is not a change");
}

#[test]
fn a_remount_may_not_name_a_different_file_for_a_kind_that_has_one() {
    let sbi = running(&plain(), "usrjquota=aq,jqfmt=vfsv1");
    assert_eq!(resolve_remount(&sbi, "usrjquota=bq"), Err(Errno::Einval));
}

#[test]
fn a_remount_may_take_a_name_back_out() {
    let sbi = running(&plain(), "usrjquota=aq,jqfmt=vfsv1");
    let o = resolve_remount(&sbi, "usrjquota").expect("accepted").0;
    assert_eq!(o.jquota.names[QKind::User as usize], None);
}

#[test]
fn a_remount_may_not_add_or_remove_a_name_while_accounting_runs() {
    let mut sbi = running(&plain(), "usrjquota=aq,jqfmt=vfsv1");
    sbi.quota_on = true;
    assert_eq!(resolve_remount(&sbi, "usrjquota"), Err(Errno::Einval));
    let mut fresh = running(&plain(), "");
    fresh.quota_on = true;
    assert_eq!(resolve_remount(&fresh, "usrjquota=aq,jqfmt=vfsv1"), Err(Errno::Einval));
    // With accounting off, both are ordinary changes.
    sbi.quota_on = false;
    assert!(resolve_remount(&sbi, "usrjquota").is_ok());
}

#[test]
fn a_remount_inherits_the_format_the_mount_already_has() {
    // The line names a file and no format; the running mount's format covers
    // it, so refusing would refuse a legal reconfiguration.
    let sbi = running(&plain(), "usrjquota=aq,jqfmt=vfsv1");
    assert!(resolve_remount(&sbi, "grpjquota=bq").is_ok());
}

#[test]
fn a_volume_that_names_its_own_quota_inodes_ignores_the_line_rather_than_refusing() {
    let q = Facts { feature: FEATURE_QUOTA_INO, ..plain() };
    let sbi = running(&q, "");
    let (o, spec) = resolve_remount(&sbi, "usrjquota=aq,jqfmt=vfsv1").expect("accepted");
    assert_eq!(o.jquota.names[QKind::User as usize], None, "the name is dropped");
    assert!(!spec.qname[QKind::User as usize]);
}

#[test]
fn the_mixture_is_judged_over_both_sides() {
    // The mount already names a user file; the line asks for group accounting
    // the modern way. Neither side alone is a mixture and the pair is.
    let sbi = running(&plain(), "usrjquota=aq,jqfmt=vfsv1");
    assert_eq!(resolve_remount(&sbi, "grpquota"), Err(Errno::Einval));
}
