//! The per-epoch inode lists a checkpoint retires.

use super::{InoKind, InoLists};

#[test]
fn a_recorded_number_is_found_and_an_unrecorded_one_is_not() {
    let mut l = InoLists::new();
    assert!(!l.exists(InoKind::TransDir, 7));
    l.add(InoKind::TransDir, 7);
    assert!(l.exists(InoKind::TransDir, 7));
    assert!(!l.exists(InoKind::TransDir, 8));
}

#[test]
fn the_two_lists_are_separate() {
    let mut l = InoLists::new();
    l.add(InoKind::TransDir, 7);
    assert!(!l.exists(InoKind::XattrDir, 7), "one reason is not the other");
    l.add(InoKind::XattrDir, 9);
    assert!(!l.exists(InoKind::TransDir, 9));
    assert_eq!((l.len(InoKind::TransDir), l.len(InoKind::XattrDir)), (1, 1));
}

#[test]
fn recording_the_same_number_twice_is_one_entry() {
    let mut l = InoLists::new();
    l.add(InoKind::XattrDir, 3);
    l.add(InoKind::XattrDir, 3);
    assert_eq!(l.len(InoKind::XattrDir), 1);
}

#[test]
fn a_checkpoint_retires_every_list() {
    let mut l = InoLists::new();
    l.add(InoKind::TransDir, 1);
    l.add(InoKind::XattrDir, 2);
    l.release();
    assert!(l.is_empty(InoKind::TransDir) && l.is_empty(InoKind::XattrDir));
    assert!(!l.exists(InoKind::TransDir, 1) && !l.exists(InoKind::XattrDir, 2));
}
