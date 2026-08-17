//! Quota files named on the mount line, and the two arrangements that may not
//! be mixed.

use syscall::errno::Errno;

use crate::opts::jquota::{JqFmt, QKind};
use crate::opts::{parse, show, Options};

fn p(s: &str) -> Result<Options, Errno> { parse(Options::defaults(), s) }

fn named(o: &Options, k: QKind) -> Option<&str> {
    o.jquota.names[k as usize].as_ref().map(|n| n.as_str())
}

#[test]
fn each_kind_names_its_own_file() {
    let o = p("jqfmt=vfsv1,usrjquota=aquota.user,grpjquota=aquota.group,\
               prjjquota=aquota.project").unwrap();
    assert_eq!(named(&o, QKind::User), Some("aquota.user"));
    assert_eq!(named(&o, QKind::Group), Some("aquota.group"));
    assert_eq!(named(&o, QKind::Project), Some("aquota.project"));
}

#[test]
fn every_format_the_interface_defines_is_taken() {
    for (spelling, want) in [("vfsold", JqFmt::VfsOld), ("vfsv0", JqFmt::VfsV0),
                             ("vfsv1", JqFmt::VfsV1)] {
        let o = p(&alloc::format!("jqfmt={spelling}")).unwrap();
        assert_eq!(o.jquota.fmt, Some(want));
    }
    assert_eq!(p("jqfmt=vfsv2"), Err(Errno::Einval));
    assert_eq!(p("jqfmt"), Err(Errno::Einval));
}

#[test]
fn a_name_carrying_a_separator_is_refused_rather_than_resolved() {
    // Resolving it would let a mount point its accounting at a file on
    // another filesystem, which is not a place this volume can account to.
    for name in ["/aquota.user", "sub/aquota.user", "../aquota.user"] {
        assert_eq!(p(&alloc::format!("jqfmt=vfsv1,usrjquota={name}")), Err(Errno::Einval),
                   "{name}");
    }
}

#[test]
fn a_name_longer_than_a_directory_entry_can_hold_is_refused() {
    let long = "a".repeat(crate::uapi::NAME_LEN + 1);
    assert_eq!(p(&alloc::format!("jqfmt=vfsv1,usrjquota={long}")), Err(Errno::Enametoolong));
    let at_the_limit = "a".repeat(crate::uapi::NAME_LEN);
    assert!(p(&alloc::format!("jqfmt=vfsv1,usrjquota={at_the_limit}")).is_ok());
}

#[test]
fn a_bare_spelling_takes_the_file_back_out() {
    // That is how a remount stops accounting to a named file; refusing the
    // bare form would leave no way to undo the naming.
    let o = p("jqfmt=vfsv1,usrjquota=aquota.user,usrjquota").unwrap();
    assert_eq!(named(&o, QKind::User), None);
}

#[test]
fn naming_the_same_file_twice_agrees_and_naming_two_conflicts() {
    let o = p("jqfmt=vfsv1,usrjquota=q.user,usrjquota=q.user").unwrap();
    assert_eq!(named(&o, QKind::User), Some("q.user"));
    assert_eq!(p("jqfmt=vfsv1,usrjquota=q.user,usrjquota=other"), Err(Errno::Einval));
}

#[test]
fn a_named_file_with_no_format_is_refused() {
    // Nothing in the file says which parser it wants, so guessing reads the
    // wrong structure out of a real file and reports limits nobody set.
    assert_eq!(p("usrjquota=aquota.user"), Err(Errno::Einval));
    assert!(p("usrjquota=aquota.user,jqfmt=vfsv0").is_ok());
}

#[test]
fn a_format_with_no_named_file_is_harmless() {
    let o = p("jqfmt=vfsv0").unwrap();
    assert_eq!(o.jquota.fmt, Some(JqFmt::VfsV0));
    assert!(!o.jquota.any_named());
}

#[test]
fn naming_a_file_for_a_kind_supersedes_that_kinds_enforcement_flag() {
    // The file and the flag are two spellings of the same request for that
    // kind, so the file wins and the flag goes quiet rather than the pair
    // being refused.
    let o = p("jqfmt=vfsv1,usrquota,usrjquota=aquota.user").unwrap();
    assert!(!o.usrquota);
    assert_eq!(named(&o, QKind::User), Some("aquota.user"));
}

#[test]
fn the_order_the_two_spellings_arrive_in_does_not_matter() {
    let a = p("jqfmt=vfsv1,usrquota,usrjquota=aquota.user").unwrap();
    let b = p("jqfmt=vfsv1,usrjquota=aquota.user,usrquota").unwrap();
    assert_eq!(a, b);
}

#[test]
fn accounting_one_kind_each_way_is_refused() {
    // One kind in a hidden inode and another in a root file is a genuine
    // mixture: two arrangements, and no mount can be running both.
    assert_eq!(p("jqfmt=vfsv1,usrjquota=aquota.user,grpquota"), Err(Errno::Einval));
    assert_eq!(p("jqfmt=vfsv1,grpjquota=aquota.group,prjquota"), Err(Errno::Einval));
}

#[test]
fn the_legacy_arrangement_round_trips_through_its_own_rendering() {
    let o = p("jqfmt=vfsv1,usrjquota=aquota.user,grpjquota=aquota.group").unwrap();
    let line = show(&o, 0);
    assert!(line.contains(",jqfmt=vfsv1"), "{line}");
    assert!(line.contains(",usrjquota=aquota.user"), "{line}");
    assert!(line.contains(",grpjquota=aquota.group"), "{line}");
    assert_eq!(parse(Options::defaults(), &line).unwrap(), o);
}
