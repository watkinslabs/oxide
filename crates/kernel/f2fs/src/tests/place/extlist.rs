//! The written form of an extension-list change.

use super::*;
use syscall::errno::Errno;

#[test]
fn a_marker_names_the_list_and_the_bang_names_a_removal() {
    let c = parse("[c]iso").unwrap();
    assert_eq!((c.name, c.hot, c.set), ("iso", false, true));
    let c = parse("[h]db").unwrap();
    assert_eq!((c.name, c.hot, c.set), ("db", true, true));
    let c = parse("[c]!iso").unwrap();
    assert_eq!((c.name, c.hot, c.set), ("iso", false, false));
    let c = parse("[h]!db").unwrap();
    assert_eq!((c.name, c.hot, c.set), ("db", true, false));
}

/// A write arrives with the newline a shell adds, and a tool may pad it.
#[test]
fn the_line_is_trimmed_before_it_is_read() {
    assert_eq!(parse("  [c]iso\n").unwrap().name, "iso");
}

/// An unmarked line names no list. Guessing one would place a file in the wrong
/// log for the life of the filesystem, so it is refused.
#[test]
fn a_line_that_names_no_list_is_refused() {
    for line in ["iso", "!iso", "[x]iso", "", "\n", "[c", "c]iso"] {
        assert_eq!(parse(line).map(|c| c.name), Err(Errno::Einval), "{line:?}");
    }
}

/// A marker with nothing after it names no extension.
#[test]
fn a_line_with_no_name_is_refused() {
    for line in ["[c]", "[h]", "[c]!", "[h]!"] {
        assert_eq!(parse(line).map(|c| c.name), Err(Errno::Einval), "{line:?}");
    }
}
