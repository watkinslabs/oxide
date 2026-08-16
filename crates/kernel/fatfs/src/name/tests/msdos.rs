//! The 8.3-only rules: a name either fits in eleven bytes or it does not
//! exist. Nothing generates an alias here, which is the whole difference from
//! the long-name side.

use crate::name::msdos::{eq, format_name, NameCheck, Options};

use syscall::errno::Errno;

fn normal() -> Options { Options::default() }
fn strict() -> Options { Options { check: NameCheck::Strict, ..Options::default() } }
fn relaxed() -> Options { Options { check: NameCheck::Relaxed, ..Options::default() } }

fn fmt(name: &str) -> Result<[u8; 11], Errno> { format_name(name.as_bytes(), &normal()) }

#[test]
fn a_name_is_split_at_the_dot_and_padded_to_both_widths() {
    assert_eq!(fmt("readme.txt"), Ok(*b"README  TXT"));
    assert_eq!(fmt("makefile"), Ok(*b"MAKEFILE   "));
    assert_eq!(fmt("a.b"), Ok(*b"A       B  "));
    assert_eq!(fmt("readme."), Ok(*b"README     "), "a dot with nothing after it");
}

/// The eight and the three are hard limits, and what does not fit is dropped
/// rather than making the name an alias — there are no aliases here.
#[test]
fn what_does_not_fit_is_dropped() {
    assert_eq!(fmt("averylongname.txt"), Ok(*b"AVERYLONTXT"));
    assert_eq!(fmt("archive.tarball"), Ok(*b"ARCHIVE TAR"),
               "the extension is cut at three");
}

/// The name is folded up unless the mount asked otherwise, which is what
/// makes an 8.3 mount case-insensitive without storing any case bits.
#[test]
fn case_folds_up_unless_the_mount_says_not_to() {
    assert_eq!(fmt("ReadMe.TxT"), Ok(*b"README  TXT"));
    let keep = Options { nocase: true, ..Options::default() };
    assert_eq!(format_name(b"ReadMe.TxT", &keep), Ok(*b"ReadMe  TxT"));
}

/// A name may legitimately begin with the deleted marker's own value. Stored
/// as it stands the entry would read as a free slot and the file would
/// vanish, so the first byte — and only the first — is escaped.
#[test]
fn a_leading_deleted_marker_is_escaped() {
    let escaped = format_name(b"\xe5ile.txt", &normal()).expect("legal");
    assert_eq!(escaped[0], 0x05);
    assert_eq!(&escaped[1..], b"ILE    TXT");

    let interior = format_name(b"f\xe5le.txt", &normal()).expect("legal");
    assert_eq!(interior[1], 0xe5, "and a later one is left alone");
}

/// The characters the format cannot store are refused, not replaced.
#[test]
fn a_character_the_format_forbids_is_refused() {
    for name in ["a*b", "a?b", "a<b", "a>b", "a|b", "a\"b"] {
        assert_eq!(fmt(name), Err(Errno::Einval), "{name}");
    }
    assert_eq!(fmt("a:b"), Err(Errno::Einval));
    assert_eq!(fmt("a\\b"), Err(Errno::Einval));
    assert_eq!(format_name(b"a\x01b", &normal()), Err(Errno::Einval));
}

/// The relaxed rule stores what the normal one refuses; the strict rule
/// refuses what the normal one stores.
#[test]
fn the_three_rules_draw_three_different_lines() {
    assert_eq!(format_name(b"a*b", &relaxed()), Ok(*b"A*B        "));
    assert_eq!(format_name(b"a+b", &normal()), Ok(*b"A+B        "));
    assert_eq!(format_name(b"a+b", &strict()), Err(Errno::Einval));
    assert_eq!(format_name(b"README", &strict()), Err(Errno::Einval),
               "the strict rule predates lowercase names being typed at all");
    assert_eq!(format_name(b"readme", &strict()), Ok(*b"README     "));
}

/// A name ending in a space is refused: a reader strips the padding, so the
/// name it found would not be the name that was stored.
#[test]
fn a_name_ending_in_a_space_is_refused() {
    assert_eq!(fmt("readme "), Err(Errno::Einval));
    assert_eq!(fmt("readme. txt"), Ok(*b"README   TX"), "an interior one is a character");
    assert_eq!(fmt("readme.tx "), Err(Errno::Einval));
    assert_eq!(fmt(""), Err(Errno::Einval));
}

/// A leading dot is not a character here: without the option that stores it
/// as the hidden attribute, such a name cannot exist at all.
#[test]
fn a_dotfile_needs_the_option_that_stores_it() {
    assert_eq!(fmt(".profile"), Err(Errno::Einval));
    let dots = Options { dots_ok: true, ..Options::default() };
    assert_eq!(format_name(b".profile", &dots), Ok(*b"PROFILE    "));
}

/// Two names are one name when they format to the same eleven bytes; two that
/// cannot be formatted fall back to comparing the bytes, so a lookup of an
/// impossible name fails rather than matching something else.
#[test]
fn names_match_through_the_same_formatting() {
    assert!(eq(b"readme.txt", b"README.TXT", &normal()));
    assert!(!eq(b"readme.txt", b"readme.txr", &normal()));
    assert!(eq(b"a*b", b"a*b", &normal()), "neither formats, so the bytes decide");
    assert!(!eq(b"a*b", b"A*B", &normal()));
}
