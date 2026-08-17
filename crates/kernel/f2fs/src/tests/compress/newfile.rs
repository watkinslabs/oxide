//! Whether a file being created is created compressed.

use crate::compress::newfile::{decide, NewFile};
use crate::flags::{F2FS_COMPR_FL, F2FS_NOCOMP_FL};
use crate::opts::ExtList;

/// A list holding these entries. # C: O(entries)
fn list(entries: &[&[u8]]) -> ExtList {
    let mut l = ExtList::empty();
    for e in entries { l.push(e).expect("fits"); }
    l
}

/// A regular file created by the operation that hands over its name.
/// # C: O(entries)
fn file(name: &[u8], allow: &[&[u8]], refuse: &[&[u8]], dir_flags: u32) -> NewFile {
    decide(false, Some(name), &[], dir_flags, &list(allow), &list(refuse))
}

#[test]
fn a_name_on_the_allowing_list_is_compressed() {
    assert_eq!(file(b"a.txt", &[b"txt"], &[], 0), NewFile::Compress);
    assert_eq!(file(b"a.bin", &[b"txt"], &[], 0), NewFile::Plain);
}

#[test]
fn the_refusing_list_wins_and_stops_the_walk() {
    // On both lists: refused. And refused HARD — the directory's own mark is
    // never reached, which is what makes `compress_extension=*` plus a few
    // refusals a pair that can be relied on.
    assert_eq!(file(b"a.log", &[b"txt", b"log"], &[b"log"], 0), NewFile::Plain);
    assert_eq!(file(b"a.log", &[b"*"], &[b"log"], F2FS_COMPR_FL), NewFile::Plain);
    assert_eq!(file(b"a.bin", &[b"*"], &[b"log"], 0), NewFile::Compress);
}

#[test]
fn a_hot_name_is_left_alone_whatever_the_lists_say() {
    let allow = list(&[b"*"]);
    let hot: [&[u8]; 1] = [b"db"];
    assert_eq!(decide(false, Some(b"x.db"), &hot, 0, &allow, &ExtList::empty()),
               NewFile::Plain);
    // And it stops the walk too: the directory's mark does not rescue it.
    assert_eq!(decide(false, Some(b"x.db"), &hot, F2FS_COMPR_FL, &allow, &ExtList::empty()),
               NewFile::Plain);
    assert_eq!(decide(false, Some(b"x.txt"), &hot, 0, &allow, &ExtList::empty()),
               NewFile::Compress);
}

#[test]
fn the_hot_list_matches_more_loosely_than_the_compression_lists() {
    // A dotted component that merely BEGINS with the entry is hot; the same
    // name is not a match for compression, which wants the real extension.
    let hot: [&[u8]; 1] = [b"mp4"];
    let allow = list(&[b"mp4"]);
    let none = ExtList::empty();
    assert_eq!(decide(false, Some(b"clip.mp4x"), &hot, 0, &allow, &none), NewFile::Plain);
    assert_eq!(decide(false, Some(b"clip.mp4x"), &[], 0, &allow, &none), NewFile::Plain);
    assert_eq!(decide(false, Some(b"clip.mp4"), &[], 0, &allow, &none), NewFile::Compress);
}

#[test]
fn a_name_no_list_mentions_takes_the_directory_s_mark() {
    let none = ExtList::empty();
    assert_eq!(decide(false, Some(b"a.bin"), &[], F2FS_COMPR_FL, &none, &none),
               NewFile::Compress);
    assert_eq!(decide(false, Some(b"a.bin"), &[], F2FS_NOCOMP_FL, &none, &none),
               NewFile::Refuse);
    assert_eq!(decide(false, Some(b"a.bin"), &[], 0, &none, &none), NewFile::Plain);
    // A directory carrying both marks refuses: the mark that says no is the
    // one someone added to make an exception.
    assert_eq!(decide(false, Some(b"a.bin"), &[], F2FS_COMPR_FL | F2FS_NOCOMP_FL, &none, &none),
               NewFile::Refuse);
}

#[test]
fn a_directory_skips_the_name_entirely_and_only_inherits() {
    let allow = list(&[b"*"]);
    let none = ExtList::empty();
    let hot: [&[u8]; 1] = [b"*"];
    // The wildcard on the allowing list would compress every FILE; a directory
    // holds no data of its own, so it takes only what its parent carries.
    assert_eq!(decide(true, Some(b"d.txt"), &hot, 0, &allow, &none), NewFile::Plain);
    assert_eq!(decide(true, Some(b"d.txt"), &hot, F2FS_COMPR_FL, &allow, &none),
               NewFile::Compress);
    assert_eq!(decide(true, None, &[], F2FS_NOCOMP_FL, &allow, &none), NewFile::Refuse);
}

#[test]
fn an_operation_that_hands_over_no_name_takes_nothing_at_all() {
    // A device node, a symbolic link and an unnamed temporary file: not the
    // lists, and not the directory either.
    let allow = list(&[b"*"]);
    let none = ExtList::empty();
    assert_eq!(decide(false, None, &[], 0, &allow, &none), NewFile::Plain);
    assert_eq!(decide(false, None, &[], F2FS_COMPR_FL, &allow, &none), NewFile::Plain);
    assert_eq!(decide(false, None, &[], F2FS_NOCOMP_FL, &allow, &none), NewFile::Plain);
}
