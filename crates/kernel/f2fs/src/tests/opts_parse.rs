//! One `-o` string into an option set.

use super::*;
use crate::opts::{BackgroundGc, Options};

fn p(s: &str) -> Result<Options, Errno> { parse(Options::defaults(), s) }

#[test]
fn an_empty_string_leaves_the_defaults() {
    assert_eq!(p("").unwrap(), Options::defaults());
}

#[test]
fn whitespace_and_empty_tokens_are_ignored() {
    assert_eq!(p(" , , ").unwrap(), Options::defaults());
}

#[test]
fn the_defaults_are_what_a_fresh_mount_gets() {
    let d = Options::defaults();
    assert_eq!(d.background_gc, BackgroundGc::On);
    assert!(d.recovery);
    assert!(d.discard);
    assert!(d.user_xattr);
    assert!(d.acl);
    assert_eq!(d.active_logs, 6);
    assert!(d.inline_data);
    assert!(d.inline_dentry);
    assert!(d.extent_cache);
    assert!(d.barrier);
    assert!(!d.checkpoint_disabled);
}

#[test]
fn the_cleaner_setting_takes_its_three_spellings() {
    assert_eq!(p("background_gc=on").unwrap().background_gc, BackgroundGc::On);
    assert_eq!(p("background_gc=off").unwrap().background_gc, BackgroundGc::Off);
    assert_eq!(p("background_gc=sync").unwrap().background_gc, BackgroundGc::Sync);
    assert_eq!(p("background_gc=maybe"), Err(Errno::Einval));
}

#[test]
fn the_negating_spellings_turn_their_option_off() {
    assert!(!p("nodiscard").unwrap().discard);
    assert!(!p("nouser_xattr").unwrap().user_xattr);
    assert!(!p("noacl").unwrap().acl);
    assert!(!p("noinline_data").unwrap().inline_data);
    assert!(!p("noinline_dentry").unwrap().inline_dentry);
    assert!(!p("noinline_xattr").unwrap().inline_xattr);
    assert!(!p("noextent_cache").unwrap().extent_cache);
    assert!(!p("nobarrier").unwrap().barrier);
}

#[test]
fn later_tokens_win_over_earlier_ones() {
    assert!(p("nodiscard,discard").unwrap().discard);
    assert!(!p("discard,nodiscard").unwrap().discard);
}

#[test]
fn both_recovery_spellings_disable_it() {
    assert!(!p("norecovery").unwrap().recovery);
    assert!(!p("disable_roll_forward").unwrap().recovery);
}

#[test]
fn only_the_three_log_counts_the_format_admits_are_accepted() {
    for n in [2u8, 4, 6] {
        assert_eq!(p(&alloc::format!("active_logs={n}")).unwrap().active_logs, n);
    }
    for n in [0u8, 1, 3, 5, 7, 16] {
        assert_eq!(p(&alloc::format!("active_logs={n}")), Err(Errno::Einval),
                   "active_logs={n} should be refused");
    }
}

#[test]
fn the_placement_mode_takes_its_four_spellings() {
    use crate::opts::{Fragment, Mode};
    assert_eq!(p("mode=adaptive").unwrap().mode, Mode::Adaptive);
    assert_eq!(p("mode=lfs").unwrap().mode, Mode::Lfs);
    assert_eq!(p("mode=fragment:segment").unwrap().mode, Mode::Fragment(Fragment::Segment));
    assert_eq!(p("mode=fragment:block").unwrap().mode, Mode::Fragment(Fragment::Block));
    assert_eq!(p("mode=nonsense"), Err(Errno::Einval));
}

#[test]
fn the_allocation_and_sync_modes_take_their_spellings() {
    use crate::opts::{AllocMode, FsyncMode};
    assert_eq!(p("alloc_mode=reuse").unwrap().alloc_mode, AllocMode::Reuse);
    assert_eq!(p("alloc_mode=default").unwrap().alloc_mode, AllocMode::Default);
    assert_eq!(p("alloc_mode=other"), Err(Errno::Einval));
    assert_eq!(p("fsync_mode=strict").unwrap().fsync_mode, FsyncMode::Strict);
    assert_eq!(p("fsync_mode=nobarrier").unwrap().fsync_mode, FsyncMode::Nobarrier);
    assert_eq!(p("fsync_mode=other"), Err(Errno::Einval));
}

#[test]
fn the_error_policy_takes_its_three_spellings() {
    use crate::opts::Errors;
    assert_eq!(p("errors=continue").unwrap().errors, Errors::Continue);
    assert_eq!(p("errors=panic").unwrap().errors, Errors::Panic);
    assert_eq!(p("errors=remount-ro").unwrap().errors, Errors::RemountRo);
    assert_eq!(p("errors=other"), Err(Errno::Einval));
}

#[test]
fn the_checkpoint_setting_takes_a_percentage_form() {
    assert!(p("checkpoint=enable").unwrap().checkpoint_disabled == false);
    assert!(p("checkpoint=disable").unwrap().checkpoint_disabled);
    assert!(p("checkpoint=disable:50").unwrap().checkpoint_disabled);
    assert_eq!(p("checkpoint=disable:101"), Err(Errno::Einval));
    assert_eq!(p("checkpoint=disable:x"), Err(Errno::Einval));
    assert_eq!(p("checkpoint=maybe"), Err(Errno::Einval));
}

#[test]
fn the_numeric_options_read_decimal() {
    let o = p("reserve_root=128,resuid=1000,resgid=1001,inline_xattr_size=40").unwrap();
    assert_eq!(o.reserve_root, 128);
    assert_eq!(o.resuid, 1000);
    assert_eq!(o.resgid, 1001);
    assert_eq!(o.inline_xattr_size, Some(40));
}

#[test]
fn a_numeric_option_with_no_value_is_refused() {
    assert_eq!(p("reserve_root"), Err(Errno::Einval));
}

#[test]
fn a_numeric_option_with_a_non_numeric_value_is_refused() {
    assert_eq!(p("resuid=root"), Err(Errno::Einval));
}

#[test]
fn a_bare_flag_carrying_a_value_is_refused() {
    assert_eq!(p("discard=1"), Err(Errno::Einval));
    assert_eq!(p("acl=yes"), Err(Errno::Einval));
}

#[test]
fn a_valued_option_with_no_value_is_refused() {
    assert_eq!(p("mode"), Err(Errno::Einval));
    assert_eq!(p("errors"), Err(Errno::Einval));
}

#[test]
fn the_quota_options_set_their_own_kind() {
    let o = p("usrquota,grpquota,prjquota").unwrap();
    assert!(o.usrquota && o.grpquota && o.prjquota);
    let o = p("usrquota,grpquota,noquota").unwrap();
    assert!(!o.usrquota && !o.grpquota && !o.prjquota);
}

#[test]
fn a_name_this_build_cannot_deliver_is_refused_rather_than_dropped() {
    // Accepting one silently would be a promise nothing keeps.
    for name in [
        "compress_algorithm=lz4",
        "compress_log_size=14",
        "compress_extension=so",
        "nocompress_extension=txt",
        "compress_chksum",
        "compress_mode=fs",
        "compress_cache",
        "test_dummy_encryption",
        "inlinecrypt",
        "fault_injection=1",
        "fault_type=1",
        "memory=low",
        "discard_unit=block",
        "lookup_mode=perf",
        "usrjquota=aquota.user",
        "grpjquota=aquota.group",
        "prjjquota=aquota.project",
        "jqfmt=vfsv1",
    ] {
        assert_eq!(p(name), Err(Errno::Eopnotsupp), "{name} should be refused");
    }
}

#[test]
fn a_name_this_filesystem_does_not_own_is_skipped() {
    // The generic per-mount words travel in the same string; refusing them
    // would break every ordinary read-only mount.
    assert_eq!(p("ro,rw,relatime,nosuid,nodev,noexec").unwrap(), Options::defaults());
}

#[test]
fn a_refusal_stops_the_whole_string() {
    assert_eq!(p("discard,compress_cache,noacl"), Err(Errno::Eopnotsupp));
}

#[test]
fn several_options_apply_together() {
    let o = p("background_gc=off,nodiscard,mode=lfs,active_logs=2,atgc,lazytime").unwrap();
    assert_eq!(o.background_gc, BackgroundGc::Off);
    assert!(!o.discard);
    assert_eq!(o.mode, crate::opts::Mode::Lfs);
    assert_eq!(o.active_logs, 2);
    assert!(o.atgc);
    assert!(o.lazytime);
}
