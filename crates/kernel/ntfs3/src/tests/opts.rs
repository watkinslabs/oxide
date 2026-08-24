use super::*;
use syscall::errno::Errno;

fn base() -> Options { Options::defaults() }

#[test]
fn a_mount_that_named_nothing_gets_the_defaults() {
    let o = parse(base(), "").unwrap();
    assert_eq!(o.uid, 0);
    assert!(!o.acl);
    assert_eq!(o.streams, StreamInterface::Xattr);
    assert!(!o.case_sensitive);
}

#[test]
fn the_masks_are_octal_and_umask_sets_both() {
    let o = parse(base(), "umask=0027").unwrap();
    assert_eq!((o.fmask, o.dmask), (0o27, 0o27));
    let o = parse(base(), "fmask=0133,dmask=0022").unwrap();
    assert_eq!((o.fmask, o.dmask), (0o133, 0o22));
}

#[test]
fn identity_is_decimal() {
    let o = parse(base(), "uid=1000,gid=100").unwrap();
    assert_eq!((o.uid, o.gid), (1000, 100));
}

#[test]
fn allow_utime_keeps_only_the_group_and_other_write_bits() {
    assert_eq!(parse(base(), "allow_utime=0777").unwrap().allow_utime, Some(0o22));
}

#[test]
fn the_negatable_flags_can_be_turned_off_again() {
    assert!(parse(base(), "acl").unwrap().acl);
    assert!(!parse(base(), "acl,noacl").unwrap().acl);
    assert!(parse(base(), "discard").unwrap().discard);
    assert!(!parse(base(), "discard,nodiscard").unwrap().discard);
    assert!(parse(base(), "case_sensitive").unwrap().case_sensitive);
    assert!(!parse(base(), "case_sensitive,nocase_sensitive").unwrap().case_sensitive);
    assert!(parse(base(), "sparse").unwrap().sparse);
    assert!(!parse(base(), "sparse,nosparse").unwrap().sparse);
    assert!(parse(base(), "compress").unwrap().compress);
    assert!(!parse(base(), "compress,nocompress").unwrap().compress);
}

#[test]
fn the_stream_interface_has_three_spellings() {
    assert_eq!(parse(base(), "streams_interface=none").unwrap().streams, StreamInterface::None);
    assert_eq!(parse(base(), "streams_interface=xattr").unwrap().streams, StreamInterface::Xattr);
    assert_eq!(parse(base(), "streams_interface=windows").unwrap().streams, StreamInterface::Windows);
    assert_eq!(parse(base(), "streams_interface=other").unwrap_err(), Errno::Einval);
}

#[test]
fn a_charset_this_build_cannot_honour_is_refused_rather_than_ignored() {
    assert!(parse(base(), "iocharset=utf8").is_ok());
    assert_eq!(parse(base(), "iocharset=cp1252").unwrap_err(), Errno::Einval);
}

#[test]
fn a_flag_given_a_value_is_refused() {
    assert_eq!(parse(base(), "acl=1").unwrap_err(), Errno::Einval);
}

#[test]
fn a_key_this_filesystem_does_not_know_is_skipped() {
    assert!(parse(base(), "ro,noatime,nodev,relatime").is_ok());
}

#[test]
fn what_is_rendered_parses_back_to_the_same_options() {
    let asked = "uid=1000,gid=100,fmask=0133,dmask=0022,acl,discard,case_sensitive,\
                 streams_interface=none,compress,force";
    let o = parse(base(), asked).unwrap();
    let shown = show(&o);
    let round = parse(base(), shown.trim_start_matches(',')).unwrap();
    assert_eq!(o, round, "rendered as {shown}");
}
