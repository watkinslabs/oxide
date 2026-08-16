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
    assert_eq!(p("checkpoint=disable:x"), Err(Errno::Einval));
    assert_eq!(p("checkpoint=maybe"), Err(Errno::Einval));
}

#[test]
fn the_cap_is_blocks_without_a_sign_and_a_percentage_with_one() {
    // The two spellings differ by one character and mean entirely different
    // quantities: reading `disable:5` as five percent caps a small volume at
    // nothing, and reading `disable:5%` as five blocks caps a large one at
    // five. Neither reports anything when it is wrong.
    let o = p("checkpoint=disable:5").unwrap();
    assert_eq!((o.unusable_cap, o.unusable_cap_perc), (5, 0));
    let o = p("checkpoint=disable:5%").unwrap();
    assert_eq!((o.unusable_cap, o.unusable_cap_perc), (0, 5));
    // A block count has no upper bound; a percentage does.
    assert!(p("checkpoint=disable:100000").is_ok());
    assert_eq!(p("checkpoint=disable:101%"), Err(Errno::Einval));
    assert!(p("checkpoint=disable:100%").is_ok());
}

#[test]
fn re_enabling_checkpoints_clears_the_cap_it_was_disabled_under() {
    let o = p("checkpoint=disable:40%,checkpoint=enable").unwrap();
    assert!(!o.checkpoint_disabled);
    assert_eq!((o.unusable_cap, o.unusable_cap_perc), (0, 0));
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
        "compress_cache",
    ] {
        assert_eq!(p(name), Err(Errno::Eopnotsupp), "{name} should be refused");
    }
}

#[test]
fn which_side_compresses_is_honoured_and_survives_being_shown() {
    // Refusing it would leave this build unable to be asked for caller-driven
    // compression at all, and the two rewrite commands mean nothing without
    // it. A remount reads the shown string back, so both spellings have to
    // come out of `show` in a form `parse` accepts.
    use crate::opts::CompressMode;
    assert_eq!(Options::defaults().compress_mode, CompressMode::Fs);
    assert_eq!(p("compress_mode=fs").unwrap().compress_mode, CompressMode::Fs);
    let user = p("compress_mode=user").unwrap();
    assert_eq!(user.compress_mode, CompressMode::User);
    assert_eq!(p("compress_mode=maybe").map(|_| ()), Err(Errno::Einval));
    assert_eq!(p("compress_mode").map(|_| ()), Err(Errno::Einval));
    let shown = crate::opts::show(&user);
    assert!(shown.contains(",compress_mode=user"), "{shown}");
    assert_eq!(crate::opts::parse(Options::defaults(), &shown).unwrap().compress_mode,
               CompressMode::User);
}

#[test]
fn the_two_policy_knobs_this_build_honours_are_accepted() {
    // Both change what the mount actually does — which granularity freed
    // space is announced at, and how much memory it may spend — so they are
    // honoured rather than refused.
    use crate::opts::{DiscardUnit, MemoryMode};
    assert_eq!(p("discard_unit=segment").unwrap().discard_unit, DiscardUnit::Segment);
    assert_eq!(p("memory=low").unwrap().memory, MemoryMode::Low);
    assert_eq!(p("memory=huge"), Err(Errno::Einval));
    assert_eq!(p("lookup_mode=perf").unwrap().lookup_mode, crate::casefold::LookupMode::Perf);
    assert_eq!(p("lookup_mode=compat").unwrap().lookup_mode,
               crate::casefold::LookupMode::Compat);
    assert_eq!(p("lookup_mode=auto").unwrap().lookup_mode, crate::casefold::LookupMode::Auto);
    assert_eq!(p("lookup_mode=fast"), Err(Errno::Einval));
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

#[test]
fn the_second_reserve_axis_is_taken_as_well_as_the_first() {
    // A volume can exhaust either axis. Reserving only blocks leaves the
    // privileged caller unable to create the file it needed the reserve for.
    let o = p("reserve_root=128,reserve_node=64").unwrap();
    assert_eq!(o.reserve_root, 128);
    assert_eq!(o.reserve_node, 64);
    assert_eq!(p("reserve_node"), Err(Errno::Einval));
}

#[test]
fn skipping_the_work_that_only_helps_later_mounts_is_taken() {
    assert!(p("fastboot").unwrap().fastboot);
    assert!(!Options::defaults().fastboot);
    assert_eq!(p("fastboot=1"), Err(Errno::Einval));
}

#[test]
fn the_two_names_the_format_no_longer_acts_on_are_still_accepted() {
    // Refusing them would break a mount line that has carried them for years.
    // Letting them fall through as unknown would accept a value they never
    // took, which is the difference between accepting a name and ignoring one.
    assert_eq!(p("heap").unwrap(), Options::defaults());
    assert_eq!(p("no_heap").unwrap(), Options::defaults());
    assert_eq!(p("heap=3"), Err(Errno::Einval));
    assert_eq!(p("no_heap=off"), Err(Errno::Einval));
}

#[test]
fn the_new_options_round_trip_through_their_own_rendering() {
    let o = p("fastboot,reserve_root=8,reserve_node=4,checkpoint=disable:12%").unwrap();
    assert_eq!(parse(Options::defaults(), &crate::opts::show(&o)).unwrap(), o);
}
