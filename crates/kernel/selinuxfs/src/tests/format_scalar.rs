// Flags, counts and the trimming every write depends on.

use crate::format::scalar::{parse_class, parse_flag, parse_u32, render_flag, render_u32,
                            request_text};
use vfs::VfsError;

#[test]
fn a_shell_redirection_terminator_is_not_part_of_the_request() {
    assert_eq!(request_text(b"1\n").unwrap(), "1");
    assert_eq!(request_text(b"1\0").unwrap(), "1");
    assert_eq!(request_text(b"  1 \n\0").unwrap(), "1");
}

#[test]
fn any_non_zero_is_on_and_zero_is_off() {
    assert!(parse_flag("1").unwrap());
    assert!(parse_flag("2").unwrap());
    assert!(parse_flag("-1").unwrap());
    assert!(!parse_flag("0").unwrap());
}

#[test]
fn a_written_word_is_refused_rather_than_read_as_zero() {
    for text in ["on", "", "1x", "yes", " "] {
        assert_eq!(parse_flag(text), Err(VfsError::Einval), "{text}");
    }
}

#[test]
fn class_zero_and_a_non_number_are_refused() {
    assert_eq!(parse_class("6").unwrap(), 6);
    assert_eq!(parse_class("0"), Err(VfsError::Einval));
    assert_eq!(parse_class("file"), Err(VfsError::Einval));
    assert_eq!(parse_class("65536"), Err(VfsError::Einval));
    assert_eq!(parse_class("-1"), Err(VfsError::Einval));
}

#[test]
fn counts_and_flags_render_as_plain_decimals() {
    assert_eq!(render_flag(true), "1");
    assert_eq!(render_flag(false), "0");
    assert_eq!(render_u32(512), "512");
    assert_eq!(parse_u32("512").unwrap(), 512);
}
