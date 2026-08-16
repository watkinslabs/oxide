//! What `.` and `..` hold, and what counts against a directory's emptiness.

use super::*;

use crate::dirent::{Record, ATTR_ARCH, ATTR_DIR, ATTR_EXT, ATTR_VOLUME, ENTRY_BYTES};
use crate::namei::{dir_is_empty, dot_records, find_dotdot, DOT, DOTDOT};
use crate::time::FatTime;

fn when() -> FatTime { FatTime { time: 0x4a3c, date: 0x5123, cs: 137 } }

/// `.` names the directory's own cluster and `..` names its parent's.
#[test]
fn the_two_entries_name_this_directory_and_its_parent() {
    let [dot, dotdot] = dot_records(9, 4, when(), true);
    let a = Record::parse(&dot).unwrap();
    let b = Record::parse(&dotdot).unwrap();
    assert_eq!(a.short.raw_name, DOT);
    assert_eq!(b.short.raw_name, DOTDOT);
    assert_eq!(a.short.cluster, 9);
    assert_eq!(b.short.cluster, 4);
    assert_eq!(a.short.attr, ATTR_DIR);
    assert_eq!(b.short.attr, ATTR_DIR);
    assert_eq!(a.short.size, 0);
    assert_eq!(b.short.size, 0);
}

/// `..` in a directory of the ROOT names cluster ZERO, on every width. The
/// root has no first cluster to name, and a FAT32 root's cluster number is
/// deliberately not used — a `..` naming it would be a second, different way
/// to reach the root, which every checker reports.
#[test]
fn dotdot_of_a_directory_in_the_root_names_cluster_zero() {
    let [_, dotdot] = dot_records(9, 0, when(), true);
    assert_eq!(Record::parse(&dotdot).unwrap().short.cluster, 0);
}

/// The 8.3-only type leaves the creation and access fields alone here too.
#[test]
fn the_short_only_type_stamps_only_the_modification_field() {
    let [dot, _] = dot_records(9, 4, when(), false);
    let r = Record::parse(&dot).unwrap();
    assert_eq!(r.times.create, FatTime::default());
    assert_eq!(r.times.access_date, 0);
    assert_eq!(r.times.modify, FatTime { time: when().time, date: when().date, cs: 0 });
    // ...and the long-name type writes all three.
    let [dot, _] = dot_records(9, 4, when(), true);
    assert_eq!(Record::parse(&dot).unwrap().times.create, when());
}

/// A directory holding only its two dot entries is empty.
#[test]
fn a_directory_of_only_dots_is_empty() {
    let mut bytes = blank(16);
    let records = dot_records(9, 4, when(), true);
    for (i, r) in records.iter().enumerate() {
        bytes[i * ENTRY_BYTES..(i + 1) * ENTRY_BYTES].copy_from_slice(r);
    }
    assert!(dir_is_empty(&bytes));
    assert_eq!(find_dotdot(&bytes), Some(ENTRY_BYTES as u64));
}

/// One name is enough to make it not empty.
#[test]
fn one_name_makes_it_not_empty() {
    let mut bytes = blank(16);
    used(&mut bytes, 0, &DOT, ATTR_DIR);
    used(&mut bytes, 1, &DOTDOT, ATTR_DIR);
    used(&mut bytes, 2, b"HELLO   TXT", ATTR_ARCH);
    assert!(!dir_is_empty(&bytes));
}

/// Three kinds of record do NOT count against emptiness: a released entry, a
/// long-name slot, and a volume label. Counting any of them makes a directory
/// that has had a file deleted from it impossible to remove.
#[test]
fn released_entries_long_slots_and_a_label_do_not_count() {
    let mut bytes = blank(16);
    used(&mut bytes, 0, &DOT, ATTR_DIR);
    used(&mut bytes, 1, &DOTDOT, ATTR_DIR);
    used(&mut bytes, 2, b"GONE    TXT", ATTR_ARCH);
    deleted(&mut bytes, 2);
    used(&mut bytes, 3, b"SLOTBYTES  ", ATTR_EXT);
    used(&mut bytes, 4, b"LABEL      ", ATTR_VOLUME);
    assert!(dir_is_empty(&bytes));
}

/// A directory with no `..` at all is one nothing can walk out of, and the
/// caller has to be able to tell.
#[test]
fn a_missing_dotdot_is_reported_as_missing() {
    let mut bytes = blank(16);
    used(&mut bytes, 0, &DOT, ATTR_DIR);
    assert_eq!(find_dotdot(&bytes), None);
}
