//! The option tail, and whether the parser accepts what it renders.
//!
//! The round trip is the contract: a remount reads this string back, so an
//! option shown in a form the parser refuses breaks a mount that was working.

use super::*;
use crate::opts::{parse, AllocMode, BackgroundGc, Errors, Fragment, FsyncMode, Mode, Options};

fn shown(o: &Options) -> alloc::string::String { show(o) }

#[test]
fn every_rendered_option_carries_its_own_leading_comma() {
    let s = shown(&Options::defaults());
    assert!(s.starts_with(','));
    assert!(!s.contains(",,"));
}

#[test]
fn the_default_tail_round_trips_to_the_defaults() {
    let d = Options::defaults();
    assert_eq!(parse(Options::defaults(), &shown(&d)).unwrap(), d);
}

#[test]
fn an_option_set_round_trips_through_its_own_rendering() {
    let mut o = Options::defaults();
    o.background_gc = BackgroundGc::Sync;
    o.recovery = false;
    o.discard = false;
    o.user_xattr = false;
    o.acl = false;
    o.active_logs = 2;
    o.ext_identify = false;
    o.inline_xattr = false;
    o.inline_xattr_size = Some(44);
    o.inline_data = false;
    o.inline_dentry = false;
    o.flush_merge = true;
    o.barrier = false;
    o.data_flush = true;
    o.extent_cache = false;
    o.age_extent_cache = true;
    o.reserve_root = 99;
    o.resuid = 1000;
    o.resgid = 1001;
    o.mode = Mode::Lfs;
    o.alloc_mode = AllocMode::Reuse;
    o.fsync_mode = FsyncMode::Strict;
    o.errors = Errors::Panic;
    o.checkpoint_merge = true;
    o.lazytime = true;
    o.gc_merge = true;
    o.atgc = true;
    o.usrquota = true;
    o.grpquota = true;
    o.prjquota = true;
    assert_eq!(parse(Options::defaults(), &shown(&o)).unwrap(), o);
}

#[test]
fn every_placement_mode_round_trips() {
    for m in [Mode::Adaptive, Mode::Lfs, Mode::Fragment(Fragment::Segment),
              Mode::Fragment(Fragment::Block)] {
        let mut o = Options::defaults();
        o.mode = m;
        assert_eq!(parse(Options::defaults(), &shown(&o)).unwrap().mode, m);
    }
}

#[test]
fn every_error_policy_round_trips() {
    for e in [Errors::Continue, Errors::Panic, Errors::RemountRo] {
        let mut o = Options::defaults();
        o.errors = e;
        assert_eq!(parse(Options::defaults(), &shown(&o)).unwrap().errors, e);
    }
}

#[test]
fn every_cleaner_setting_round_trips() {
    for g in [BackgroundGc::On, BackgroundGc::Off, BackgroundGc::Sync] {
        let mut o = Options::defaults();
        o.background_gc = g;
        assert_eq!(parse(Options::defaults(), &shown(&o)).unwrap().background_gc, g);
    }
}

#[test]
fn a_default_valued_option_is_not_shown() {
    // A short line for an untouched mount is what makes the table readable.
    let s = shown(&Options::defaults());
    assert!(!s.contains("background_gc"));
    assert!(!s.contains("active_logs"));
    assert!(!s.contains("errors="));
    assert!(!s.contains("reserve_root"));
}

#[test]
fn the_options_a_mount_always_states_are_always_shown() {
    let s = shown(&Options::defaults());
    for name in [",discard", ",user_xattr", ",acl", ",inline_data", ",inline_dentry",
                 ",extent_cache", ",mode=adaptive", ",fsync_mode=posix"] {
        assert!(s.contains(name), "{name} missing from {s}");
    }
}

#[test]
fn a_negated_option_shows_its_negated_spelling() {
    let mut o = Options::defaults();
    o.discard = false;
    o.acl = false;
    let s = shown(&o);
    assert!(s.contains(",nodiscard"));
    assert!(s.contains(",noacl"));
    assert!(!s.contains(",discard"));
}

#[test]
fn a_disabled_checkpoint_is_shown() {
    let mut o = Options::defaults();
    o.checkpoint_disabled = true;
    assert!(shown(&o).contains(",checkpoint=disable"));
}

#[test]
fn the_identity_options_are_shown_only_when_set() {
    let mut o = Options::defaults();
    assert!(!shown(&o).contains("resuid"));
    o.resuid = 5;
    assert!(shown(&o).contains(",resuid=5"));
}

#[test]
fn the_inline_attribute_size_is_shown_only_when_stated() {
    let mut o = Options::defaults();
    assert!(!shown(&o).contains("inline_xattr_size"));
    o.inline_xattr_size = Some(40);
    assert!(shown(&o).contains(",inline_xattr_size=40"));
}

#[test]
fn no_rendered_name_is_one_the_parser_refuses() {
    // Every name in the tail must be a name `parse` knows; an unknown one
    // would be silently dropped on remount, and a refused one would fail it.
    let mut o = Options::defaults();
    o.checkpoint_disabled = true;
    o.usrquota = true;
    let s = shown(&o);
    assert!(parse(Options::defaults(), &s).is_ok());
}
