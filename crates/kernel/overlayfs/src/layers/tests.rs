//! The object list, and what it says the object is made of.

extern crate alloc;

use crate::testfs::layer;

use super::{dirs_disjoint, Layer, OvlEntry, OvlPath};

/// An object list with `n` lower objects and optionally an upper one.
fn entry(upper: bool, n: usize) -> OvlEntry {
    let l = Layer::new(layer(2), 1, 1, false);
    let mut e = OvlEntry::default();
    if upper { e.upper = Some(layer(1)); }
    for _ in 0..n { e.lower.push(OvlPath { layer: l.clone(), inode: layer(2) }); }
    e
}

#[test]
fn a_pure_upper_object_needs_no_merge() {
    let t = entry(true, 0).path_type(false);
    assert!(t.upper && !t.merge && !t.origin);
}

#[test]
fn a_copied_up_file_keeps_its_origin_without_merging() {
    // Its data is all in the upper layer; the lower entry is only its
    // identity. Reporting a merge here would make every read consult a layer
    // that has nothing to add.
    let t = entry(true, 1).path_type(false);
    assert!(t.upper && t.origin && !t.merge);
}

#[test]
fn a_metadata_only_file_does_merge() {
    let mut e = entry(true, 1);
    e.metacopy = true;
    let t = e.path_type(false);
    assert!(t.upper && t.origin && t.merge);
}

#[test]
fn a_directory_with_a_lower_half_merges() {
    let t = entry(true, 1).path_type(true);
    assert!(t.upper && t.origin && t.merge);
}

#[test]
fn a_lower_only_object_merges_only_when_several_layers_hold_it() {
    assert!(!entry(false, 1).path_type(true).merge);
    assert!(entry(false, 2).path_type(true).merge);
}

#[test]
fn the_object_reads_go_to_is_the_upper_one_when_there_is_one() {
    let e = entry(true, 1);
    assert!(alloc::sync::Arc::ptr_eq(&e.real().unwrap(), e.upper.as_ref().unwrap()));
    let e = entry(false, 2);
    assert!(alloc::sync::Arc::ptr_eq(&e.real().unwrap(), &e.lower[0].inode));
}

#[test]
fn a_metadata_only_object_reads_its_data_from_the_bottom_of_the_stack() {
    let mut e = entry(true, 2);
    e.metacopy = true;
    assert!(alloc::sync::Arc::ptr_eq(&e.realdata().unwrap(), &e.lower[1].inode));
    e.metacopy = false;
    assert!(alloc::sync::Arc::ptr_eq(&e.realdata().unwrap(), e.upper.as_ref().unwrap()));
}

#[test]
fn a_work_directory_inside_the_upper_layer_is_refused() {
    assert!(!dirs_disjoint("/m/upper", "/m/upper/work"));
    assert!(!dirs_disjoint("/m/upper/work", "/m/upper"));
    assert!(!dirs_disjoint("/m/upper", "/m/upper"));
    assert!(dirs_disjoint("/m/upper", "/m/work"));
}

#[test]
fn a_shared_prefix_that_is_not_a_path_prefix_is_fine() {
    // `/m/upper2` is not inside `/m/upper`, however it sorts.
    assert!(dirs_disjoint("/m/upper", "/m/upper2"));
}

#[test]
fn a_trailing_slash_does_not_change_the_answer() {
    assert!(!dirs_disjoint("/m/upper/", "/m/upper/work"));
}
