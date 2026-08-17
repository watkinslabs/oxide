//! The page-index radix tree (`17§4.1`).

extern crate alloc;
use alloc::vec::Vec;

use crate::pagecache::radix::RadixTree;

#[test]
fn an_empty_tree_finds_nothing() {
    let t: RadixTree<u32> = RadixTree::new();
    assert_eq!(t.len(), 0);
    assert!(t.is_empty());
    assert!(t.get(0).is_none());
    assert!(t.get(u64::MAX).is_none());
}

#[test]
fn an_inserted_index_reads_back_and_replaces() {
    let mut t = RadixTree::new();
    assert!(t.insert(7, 70u32).is_none());
    assert_eq!(t.get(7), Some(&70));
    assert_eq!(t.len(), 1);
    assert_eq!(t.insert(7, 71), Some(70));
    assert_eq!(t.get(7), Some(&71));
    assert_eq!(t.len(), 1, "a replace is not a second entry");
}

#[test]
fn the_root_grows_to_hold_a_far_index() {
    let mut t = RadixTree::new();
    t.insert(0, 1u32);
    t.insert(1 << 40, 2u32);
    t.insert(u64::MAX, 3u32);
    assert_eq!(t.get(0), Some(&1));
    assert_eq!(t.get(1 << 40), Some(&2));
    assert_eq!(t.get(u64::MAX), Some(&3));
    assert_eq!(t.len(), 3);
}

#[test]
fn removing_the_last_entry_empties_the_tree() {
    let mut t = RadixTree::new();
    for i in 0..300u64 { t.insert(i, i); }
    for i in 0..300u64 { assert_eq!(t.remove(i), Some(i)); }
    assert!(t.is_empty());
    assert!(t.get(5).is_none());
    // Usable again after the root was dropped.
    t.insert(9, 9);
    assert_eq!(t.get(9), Some(&9));
}

#[test]
fn removing_an_absent_index_changes_nothing() {
    let mut t = RadixTree::new();
    t.insert(1, 1u64);
    assert_eq!(t.remove(2), None);
    assert_eq!(t.remove(1 << 50), None);
    assert_eq!(t.len(), 1);
    assert_eq!(t.get(1), Some(&1));
}

#[test]
fn a_walk_is_ascending_and_complete() {
    let mut t = RadixTree::new();
    let keys: Vec<u64> = alloc::vec![0, 1, 63, 64, 65, 4095, 4096, 1 << 30];
    for k in &keys { t.insert(*k, *k); }
    let mut seen = Vec::new();
    t.for_each(|k, v| { assert_eq!(k, *v); seen.push(k); });
    assert_eq!(seen, keys);
}

#[test]
fn a_range_walk_returns_only_the_window() {
    let mut t = RadixTree::new();
    for i in 0..200u64 { t.insert(i, i); }
    assert_eq!(t.keys_in_range(64, 68), alloc::vec![64, 65, 66, 67]);
    assert!(t.keys_in_range(10, 10).is_empty());
    assert!(t.keys_in_range(10, 5).is_empty());
    assert_eq!(t.keys_in_range(198, 1 << 20), alloc::vec![198, 199]);
}

#[test]
fn a_sparse_tree_reads_back_every_index_it_was_given() {
    let mut t = RadixTree::new();
    let mut expect = Vec::new();
    let mut k = 1u64;
    while k < (1u64 << 62) { t.insert(k, k); expect.push(k); k = k.saturating_mul(7).wrapping_add(3); }
    expect.sort_unstable();
    let mut seen = Vec::new();
    t.for_each(|key, _| seen.push(key));
    assert_eq!(seen, expect);
    for key in &expect { assert_eq!(t.get(*key), Some(key)); }
}
