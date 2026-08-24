//! Which two names are one name, and which names may be stored at all.

use crate::name::compare::{eq, eq_insensitive, eq_insensitive_with, eq_sensitive, fold_byte,
                           IoCharset, striptail,
                          striptail_len, validate};

use syscall::errno::Errno;

/// A trailing run of dots is not part of a name. The format cannot store it,
/// so a mount that accepted the name would then fail to find it again.
#[test]
fn trailing_dots_are_not_part_of_a_name() {
    assert_eq!(striptail("readme..."), "readme");
    assert_eq!(striptail("readme.txt"), "readme.txt");
    assert_eq!(striptail_len("..."), 0);
    assert_eq!(striptail("readme"), "readme");
    assert!(eq_sensitive("readme", "readme..."));
}

/// A leading or interior dot is a character, not padding.
#[test]
fn only_the_trailing_dots_go() {
    assert_eq!(striptail(".profile"), ".profile");
    assert_eq!(striptail("a.b.c"), "a.b.c");
    assert_eq!(striptail(".."), "");
}

/// The default is case-insensitive, which is why a directory cannot hold both
/// spellings of one name.
#[test]
fn the_default_comparison_ignores_case() {
    assert!(eq_insensitive("Makefile", "MAKEFILE"));
    assert!(eq_insensitive("readme.TXT", "README.txt"));
    assert!(!eq_insensitive("readme", "read"));
    assert!(!eq_sensitive("Makefile", "MAKEFILE"));
    assert!(eq("Makefile", "MAKEFILE", false));
    assert!(!eq("Makefile", "MAKEFILE", true));
}

/// Folding is over BYTES of the IO charset, which reaches the Latin-1 letters
/// and stops there. A name differing only in the case of a character outside
/// that range is two names — the reference's behaviour, and the reason this
/// is pinned rather than left to a Unicode fold.
#[test]
fn folding_covers_the_latin_range_and_no_further() {
    assert_eq!(fold_byte(b'A'), b'a');
    assert_eq!(fold_byte(0xc0), 0xe0, "capital A with grave");
    assert_eq!(fold_byte(0xde), 0xfe, "capital thorn");
    assert_eq!(fold_byte(0xd7), 0xd7, "the multiplication sign is not a letter");
    assert_eq!(fold_byte(0xdf), 0xdf, "and sharp s has no uppercase");
    // Two spellings of one Greek letter are two names, because their UTF-8
    // bytes fall outside the range the fold covers.
    assert!(!eq_insensitive("\u{3a3}", "\u{3c3}"));
}

#[test]
fn iocharset_selects_the_long_name_fold_table() {
    assert!(eq_insensitive_with("Ä", "ä", IoCharset::Iso88591));
    assert!(!eq_insensitive_with("Ä", "ä", IoCharset::Utf8));
}

/// A character the format forbids, or a trailing space that a reader would
/// strip as padding, is refused before anything is written.
#[test]
fn a_name_the_format_cannot_hold_is_refused() {
    assert_eq!(validate("a/b"), Err(Errno::Einval));
    assert_eq!(validate("a:b"), Err(Errno::Einval));
    assert_eq!(validate("a*b"), Err(Errno::Einval));
    assert_eq!(validate("a\u{1}b"), Err(Errno::Einval));
    assert_eq!(validate("trailing "), Err(Errno::Einval));
    assert_eq!(validate(""), Err(Errno::Enoent));
    assert_eq!(validate("ok name.txt"), Ok(()), "an interior space is fine");
}

/// The limit is code units, not characters: a name of characters outside the
/// basic plane reaches it at half as many.
#[test]
fn a_name_past_what_the_slots_address_is_refused() {
    let at_limit: alloc::string::String = core::iter::repeat('x').take(255).collect();
    assert_eq!(validate(&at_limit), Ok(()));
    let over: alloc::string::String = core::iter::repeat('x').take(256).collect();
    assert_eq!(validate(&over), Err(Errno::Enametoolong));
}
