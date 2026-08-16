//! The option grammar and the combinations that are refused.
//!
//! Every case here is the behaviour a container runtime depends on, encoded so
//! the contract is re-checkable without a mount.

extern crate alloc;

use alloc::string::ToString;
use alloc::vec;
use syscall::errno::Errno;

use crate::config::{Config, FsyncMode, LowerName, OptSet, RedirectMode, UuidMode, VerityMode,
                    XinoMode};

use super::split::{next_opt, options, split_lowerdirs, unescape};
use super::parse::parse;
use super::show::show;
use super::verify::verify;

// ---- splitting ---------------------------------------------------------

#[test]
fn option_split_honours_escaped_comma() {
    assert_eq!(options("lowerdir=/a\\,b,upperdir=/u"), vec!["lowerdir=/a\\,b", "upperdir=/u"]);
}

#[test]
fn option_split_plain() {
    assert_eq!(options("a,b,c"), vec!["a", "b", "c"]);
}

#[test]
fn next_opt_stops_at_end() {
    assert_eq!(next_opt("only"), Some(("only", "")));
    assert_eq!(next_opt(""), None);
}

#[test]
fn trailing_backslash_does_not_run_off_the_end() {
    assert_eq!(options("a\\"), vec!["a\\"]);
}

#[test]
fn unescape_removes_one_level() {
    assert_eq!(unescape("/a\\,b\\:c"), "/a,b:c".to_string());
    assert_eq!(unescape("/plain"), "/plain".to_string());
}

#[test]
fn single_colon_separates_merged_layers() {
    let l = split_lowerdirs("/a:/b:/c").unwrap();
    assert_eq!(l.len(), 3);
    assert!(l.iter().all(|x| !x.data_only));
    assert_eq!(l[2].raw, "/c");
}

#[test]
fn double_colon_starts_data_layers() {
    let l = split_lowerdirs("/l1:/l2::/d1::/d2").unwrap();
    assert_eq!(l.len(), 4);
    assert_eq!(l.iter().map(|x| x.data_only).collect::<alloc::vec::Vec<_>>(),
               vec![false, false, true, true]);
}

#[test]
fn escaped_colon_stays_in_the_path() {
    let l = split_lowerdirs("/a\\:b:/c").unwrap();
    assert_eq!(l.len(), 2);
    assert_eq!(unescape(&l[0].raw), "/a:b");
}

#[test]
fn three_colons_name_nothing() {
    assert_eq!(split_lowerdirs("/a:::/b"), Err(Errno::Einval));
}

#[test]
fn trailing_colon_is_refused() {
    assert_eq!(split_lowerdirs("/a:"), Err(Errno::Einval));
    assert_eq!(split_lowerdirs("/a::"), Err(Errno::Einval));
}

#[test]
fn leading_colon_is_refused() {
    assert_eq!(split_lowerdirs(":/a"), Err(Errno::Einval));
}

#[test]
fn merged_layer_may_not_follow_a_data_layer() {
    assert_eq!(split_lowerdirs("/l::/d:/l2"), Err(Errno::Einval));
}

// ---- parsing -----------------------------------------------------------

#[test]
fn the_option_string_a_runtime_writes() {
    let p = parse("lowerdir=/lo,upperdir=/up,workdir=/wk").unwrap();
    assert_eq!(p.config.upperdir.as_deref(), Some("/up"));
    assert_eq!(p.config.workdir.as_deref(), Some("/wk"));
    assert_eq!(p.config.lowerdirs, vec![LowerName { name: "/lo".to_string(), data_only: false }]);
    assert_eq!(p.config.lowerdir_all.as_deref(), Some("/lo"));
}

#[test]
fn lowerdir_replaces_every_earlier_layer() {
    let p = parse("lowerdir=/a:/b,lowerdir=/c").unwrap();
    assert_eq!(p.config.lowerdirs.len(), 1);
    assert_eq!(p.config.lowerdirs[0].name, "/c");
}

#[test]
fn empty_lowerdir_clears_the_stack() {
    let p = parse("lowerdir=/a,lowerdir=").unwrap();
    assert!(p.config.lowerdirs.is_empty());
    assert!(p.config.lowerdir_all.is_none());
}

#[test]
fn append_form_builds_the_stack() {
    let p = parse("lowerdir+=/a,lowerdir+=/b,datadir+=/d").unwrap();
    assert_eq!(p.config.lowerdirs.len(), 3);
    assert_eq!(p.config.nr_data(), 1);
    assert_eq!(p.config.nr_merged_lower(), 2);
}

#[test]
fn append_may_not_follow_the_list_form() {
    assert_eq!(parse("lowerdir=/a,lowerdir+=/b"), Err(Errno::Einval));
}

#[test]
fn merged_append_may_not_follow_a_data_append() {
    assert_eq!(parse("datadir+=/d,lowerdir+=/l"), Err(Errno::Einval));
}

#[test]
fn append_takes_the_path_verbatim() {
    let p = parse("lowerdir+=/a\\b").unwrap();
    assert_eq!(p.config.lowerdirs[0].name, "/a\\b");
}

#[test]
fn list_form_unescapes_each_layer() {
    let p = parse("lowerdir=/a\\:b").unwrap();
    assert_eq!(p.config.lowerdirs[0].name, "/a:b");
}

#[test]
fn every_enumerated_option_parses() {
    let p = parse("lowerdir=/l,upperdir=/u,workdir=/w,default_permissions,redirect_dir=on,\
                   index=on,uuid=null,nfs_export=off,userxattr,xino=on,metacopy=off,\
                   verity=require,fsync=strict")
        .unwrap();
    assert!(p.config.default_permissions);
    assert_eq!(p.config.redirect_mode, RedirectMode::On);
    assert!(p.config.index);
    assert_eq!(p.config.uuid, UuidMode::Null);
    assert!(!p.config.nfs_export);
    assert!(p.config.userxattr);
    assert_eq!(p.config.xino, XinoMode::On);
    assert!(!p.config.metacopy);
    assert_eq!(p.config.verity_mode, VerityMode::Require);
    assert_eq!(p.config.fsync_mode, FsyncMode::Strict);
    assert_eq!(p.set, OptSet { metacopy: true, redirect: true, nfs_export: true, index: true });
}

#[test]
fn volatile_is_the_same_as_fsync_volatile() {
    assert_eq!(parse("volatile").unwrap().config.fsync_mode, FsyncMode::Volatile);
}

#[test]
fn override_creds_negates() {
    assert!(parse("").unwrap().config.override_creds);
    assert!(!parse("nooverride_creds").unwrap().config.override_creds);
    assert!(parse("nooverride_creds,override_creds").unwrap().config.override_creds);
}

#[test]
fn redirect_off_still_follows() {
    // "off" means do not WRITE one; a layer that already carries one keeps
    // working. Turning it into nofollow here would break every upper layer
    // built by a mount that had redirects on.
    assert_eq!(parse("redirect_dir=off").unwrap().config.redirect_mode, RedirectMode::Follow);
}

#[test]
fn an_unknown_option_is_refused() {
    assert_eq!(parse("lowerdir=/l,nosuchthing"), Err(Errno::Einval));
}

#[test]
fn a_flag_may_not_carry_a_value_and_a_value_may_not_be_missing() {
    assert_eq!(parse("userxattr=on"), Err(Errno::Einval));
    assert_eq!(parse("xino"), Err(Errno::Einval));
    assert_eq!(parse("index=maybe"), Err(Errno::Einval));
}

// ---- verification ------------------------------------------------------

/// An upper-layer configuration with nothing else named.
fn upper() -> Config {
    let mut c = Config::default();
    c.upperdir = Some("/u".to_string());
    c.workdir = Some("/w".to_string());
    c
}

#[test]
fn a_read_only_mount_drops_the_write_only_options() {
    let mut c = Config::default();
    c.workdir = Some("/w".to_string());
    c.index = true;
    c.fsync_mode = FsyncMode::Volatile;
    c.uuid = UuidMode::On;
    verify(&mut c, OptSet { index: true, ..OptSet::default() }, true).unwrap();
    assert!(c.workdir.is_none());
    assert!(!c.index);
    assert_eq!(c.fsync_mode, FsyncMode::Auto);
    assert_eq!(c.uuid, UuidMode::Null);
}

#[test]
fn metacopy_turns_redirects_on_by_itself() {
    let mut c = upper();
    c.metacopy = true;
    verify(&mut c, OptSet { metacopy: true, ..OptSet::default() }, true).unwrap();
    assert!(c.metacopy);
    assert_eq!(c.redirect_mode, RedirectMode::On);
}

#[test]
fn metacopy_against_a_named_redirect_mode_is_refused() {
    let mut c = upper();
    c.metacopy = true;
    c.redirect_mode = RedirectMode::NoFollow;
    let named = OptSet { metacopy: true, redirect: true, ..OptSet::default() };
    assert_eq!(verify(&mut c, named, true), Err(Errno::Einval));
}

#[test]
fn a_named_redirect_mode_disables_a_defaulted_metacopy() {
    let mut c = upper();
    c.metacopy = true;
    c.redirect_mode = RedirectMode::NoFollow;
    verify(&mut c, OptSet { redirect: true, ..OptSet::default() }, true).unwrap();
    assert!(!c.metacopy);
    assert_eq!(c.redirect_mode, RedirectMode::NoFollow);
}

#[test]
fn nfs_export_turns_the_index_on() {
    let mut c = upper();
    c.nfs_export = true;
    verify(&mut c, OptSet { nfs_export: true, ..OptSet::default() }, true).unwrap();
    assert!(c.index);
}

#[test]
fn nfs_export_against_a_named_index_off_is_refused() {
    let mut c = upper();
    c.nfs_export = true;
    let named = OptSet { nfs_export: true, index: true, ..OptSet::default() };
    assert_eq!(verify(&mut c, named, true), Err(Errno::Einval));
}

#[test]
fn nfs_export_and_metacopy_cannot_both_be_named() {
    let mut c = upper();
    c.nfs_export = true;
    c.metacopy = true;
    c.index = true;
    let named = OptSet { nfs_export: true, metacopy: true, ..OptSet::default() };
    assert_eq!(verify(&mut c, named, true), Err(Errno::Einval));
}

#[test]
fn a_named_metacopy_disables_a_defaulted_nfs_export() {
    let mut c = upper();
    c.nfs_export = true;
    c.metacopy = true;
    c.index = true;
    verify(&mut c, OptSet { metacopy: true, ..OptSet::default() }, true).unwrap();
    assert!(!c.nfs_export);
    assert!(c.metacopy);
}

#[test]
fn verity_keeps_metacopy_and_drops_nfs_export() {
    let mut c = upper();
    c.nfs_export = true;
    c.metacopy = true;
    c.index = true;
    c.verity_mode = VerityMode::On;
    verify(&mut c, OptSet::default(), true).unwrap();
    assert!(!c.nfs_export);
    assert!(c.metacopy);
}

#[test]
fn userxattr_silently_disables_the_two_forgeable_features() {
    let mut c = upper();
    c.userxattr = true;
    c.metacopy = true;
    verify(&mut c, OptSet::default(), true).unwrap();
    assert!(!c.metacopy);
    assert_eq!(c.redirect_mode, RedirectMode::NoFollow);
}

#[test]
fn userxattr_refuses_them_when_they_were_named() {
    let mut c = upper();
    c.userxattr = true;
    c.redirect_mode = RedirectMode::On;
    let named = OptSet { redirect: true, ..OptSet::default() };
    assert_eq!(verify(&mut c, named, true), Err(Errno::Einval));

    let mut c = upper();
    c.userxattr = true;
    c.metacopy = true;
    c.redirect_mode = RedirectMode::On;
    let named = OptSet { metacopy: true, ..OptSet::default() };
    assert_eq!(verify(&mut c, named, true), Err(Errno::Einval));
}

#[test]
fn without_privilege_the_trusted_features_are_refused() {
    let mut c = upper();
    c.redirect_mode = RedirectMode::On;
    let named = OptSet { redirect: true, ..OptSet::default() };
    assert_eq!(verify(&mut c, named, false), Err(Errno::Eperm));

    let mut c = upper();
    c.verity_mode = VerityMode::On;
    assert_eq!(verify(&mut c, OptSet::default(), false), Err(Errno::Eperm));

    let mut c = upper();
    c.lowerdirs = vec![LowerName { name: "/d".to_string(), data_only: true }];
    assert_eq!(verify(&mut c, OptSet::default(), false), Err(Errno::Eperm));
}

#[test]
fn an_unprivileged_default_mount_is_fine() {
    let mut c = upper();
    c.lowerdirs = vec![LowerName { name: "/l".to_string(), data_only: false }];
    verify(&mut c, OptSet::default(), false).unwrap();
}

// ---- showing -----------------------------------------------------------

#[test]
fn the_line_round_trips_through_the_parser() {
    let src = "lowerdir=/l1:/l2,upperdir=/u,workdir=/w,redirect_dir=on,index=on";
    let a = parse(src).unwrap();
    let line = show(&a.config, false);
    let b = parse(line.trim_start_matches(',')).unwrap();
    assert_eq!(a.config, b.config);
}

#[test]
fn a_comma_in_a_layer_path_comes_back_escaped() {
    let mut c = Config::default();
    c.lowerdirs = vec![LowerName { name: "/a,b".to_string(), data_only: false }];
    let line = show(&c, false);
    assert!(line.contains("lowerdir+=/a\\,b"), "{line}");
}

#[test]
fn the_list_form_unescapes_a_comma_but_the_append_form_does_not() {
    // `lowerdir=` unescapes its value, so a comma reaches the layer path. The
    // append forms take their value verbatim — they exist for the
    // one-parameter-per-layer interface, where nothing ever splits on a comma,
    // and unescaping there would corrupt a path containing a real backslash.
    let a = parse("lowerdir=/a\\,b").unwrap();
    assert_eq!(a.config.lowerdirs[0].name, "/a,b");

    let b = parse("lowerdir+=/a\\,b").unwrap();
    assert_eq!(b.config.lowerdirs[0].name, "/a\\,b");
}

#[test]
fn the_shown_list_form_keeps_the_escape_the_mount_was_given() {
    // The verbatim `lowerdir=` string is what is shown back, so an escape in
    // it is escaped again on the way out. Re-parsing the line therefore leaves
    // one level of backslash behind — the same as the reference, and left that
    // way deliberately: rendering the unescaped paths instead would change
    // which line every existing tool reads out of `/proc/mounts`.
    let a = parse("lowerdir=/a\\,b").unwrap();
    let line = show(&a.config, false);
    assert!(line.contains("lowerdir=/a\\\\\\,b"), "{line}");
    let back = parse(line.trim_start_matches(',')).unwrap();
    assert_eq!(back.config.lowerdirs[0].name, "/a\\,b");
}

#[test]
fn defaulted_options_are_omitted() {
    let mut c = Config::default();
    c.lowerdirs = vec![LowerName { name: "/l".to_string(), data_only: false }];
    let line = show(&c, false);
    assert!(!line.contains("index="), "{line}");
    assert!(!line.contains("metacopy="), "{line}");
    assert!(!line.contains("fsync="), "{line}");
}

#[test]
fn inode_remapping_is_not_shown_when_the_layers_are_one_filesystem() {
    let mut c = Config::default();
    c.xino = XinoMode::On;
    assert!(!show(&c, true).contains("xino"));
    assert!(show(&c, false).contains("xino=on"));
}

#[test]
fn the_data_layer_form_is_shown_as_datadir() {
    let mut c = Config::default();
    c.lowerdirs = vec![
        LowerName { name: "/l".to_string(), data_only: false },
        LowerName { name: "/d".to_string(), data_only: true },
    ];
    let line = show(&c, false);
    assert!(line.contains(",lowerdir+=/l"), "{line}");
    assert!(line.contains(",datadir+=/d"), "{line}");
}
