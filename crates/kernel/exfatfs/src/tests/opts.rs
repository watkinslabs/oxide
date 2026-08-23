use super::*;
use crate::opts::{parse, Errors, Options};
use syscall::errno::Errno;

fn base() -> Options { Options::defaults() }

#[test]
fn a_mount_that_named_nothing_gets_the_defaults() {
    let o = parse(base(), "").unwrap();
    assert_eq!(o.uid, 0);
    assert_eq!(o.fmask, 0);
    assert_eq!(o.errors, Errors::RemountRo);
    assert!(o.utf8);
    assert!(!o.keep_last_dots);
}

#[test]
fn the_masks_are_octal_and_umask_sets_both() {
    let o = parse(base(), "umask=0077").unwrap();
    assert_eq!(o.fmask, 0o77);
    assert_eq!(o.dmask, 0o77);
    let o = parse(base(), "fmask=0133,dmask=0022").unwrap();
    assert_eq!(o.fmask, 0o133);
    assert_eq!(o.dmask, 0o22);
}

#[test]
fn identity_is_decimal() {
    let o = parse(base(), "uid=1000,gid=1000").unwrap();
    assert_eq!((o.uid, o.gid), (1000, 1000));
}

#[test]
fn allow_utime_keeps_only_the_group_and_other_write_bits() {
    let o = parse(base(), "allow_utime=0777").unwrap();
    assert_eq!(o.allow_utime, Some(0o22));
}

#[test]
fn allow_utime_defaults_to_the_directory_masks_write_bits() {
    let o = parse(base(), "dmask=0022").unwrap();
    assert_eq!(o.utime_bits(), 0o0);
    let o = parse(base(), "dmask=0000").unwrap();
    assert_eq!(o.utime_bits(), 0o22);
}

#[test]
fn allow_utime_matches_linux_owner_and_group_exception() {
    let mut o = base();
    o.settle();
    assert!(!o.allows_non_owner_utime(true, false));
    assert!(o.allows_non_owner_utime(false, false));
    assert!(o.allows_non_owner_utime(false, true));
    o.allow_utime = Some(0);
    assert!(!o.allows_non_owner_utime(false, false));
}

#[test]
fn a_charset_this_build_cannot_honour_is_refused_rather_than_ignored() {
    assert!(parse(base(), "iocharset=utf8").is_ok());
    assert_eq!(parse(base(), "iocharset=iso8859-1").unwrap_err(), Errno::Einval);
}

#[test]
fn the_error_policy_has_three_spellings() {
    assert_eq!(parse(base(), "errors=continue").unwrap().errors, Errors::Continue);
    assert_eq!(parse(base(), "errors=panic").unwrap().errors, Errors::Panic);
    assert_eq!(parse(base(), "errors=remount-ro").unwrap().errors, Errors::RemountRo);
    assert_eq!(parse(base(), "errors=nonsense").unwrap_err(), Errno::Einval);
}

#[test]
fn the_time_offset_is_bounded() {
    assert_eq!(parse(base(), "time_offset=-330").unwrap().time.offset_minutes, -330);
    assert_eq!(parse(base(), "time_offset=1441").unwrap_err(), Errno::Einval);
    assert_eq!(parse(base(), "time_offset=x").unwrap_err(), Errno::Einval);
}

#[test]
fn the_negatable_flags_can_be_turned_off_again() {
    assert!(parse(base(), "discard").unwrap().discard);
    assert!(!parse(base(), "discard,nodiscard").unwrap().discard);
    assert!(parse(base(), "zero_size_dir").unwrap().zero_size_dir);
    assert!(!parse(base(), "zero_size_dir,nozero_size_dir").unwrap().zero_size_dir);
}

#[test]
fn a_flag_given_a_value_is_refused() {
    assert_eq!(parse(base(), "discard=1").unwrap_err(), Errno::Einval);
}

#[test]
fn a_key_this_filesystem_does_not_know_is_skipped() {
    // The generic per-mount words travel in the same string; failing on one
    // would make every ordinary `mount -o ro` fail.
    assert!(parse(base(), "ro,noatime,nodev").is_ok());
}

#[test]
fn what_is_rendered_parses_back_to_the_same_options() {
    let asked = "uid=1000,gid=100,fmask=0133,dmask=0022,errors=continue,discard,keep_last_dots,time_offset=-330";
    let o = parse(base(), asked).unwrap();
    let shown = show(&o);
    let round = parse(base(), shown.trim_start_matches(',')).unwrap();
    assert_eq!(o, round, "rendered as {shown}");
}

#[test]
fn an_untouched_mount_renders_a_short_line() {
    let o = parse(base(), "").unwrap();
    let shown = show(&o);
    assert!(!shown.contains("uid="), "{shown}");
    assert!(shown.contains(",fmask=0000"), "{shown}");
    assert!(shown.contains(",errors=remount-ro"), "{shown}");
}
