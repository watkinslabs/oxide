//! The order a deletion writes in.
//!
//! These are the tests that matter for deletion: nothing here makes the set of
//! writes atomic, so what a reader sees between them is decided entirely by
//! the order, and the order is the only thing worth pinning.

use super::*;

use crate::dirent::ENTRY_BYTES;
use crate::namei::deletion_order;

/// The SHORT entry is freed first. It is the file: once its slot is free the
/// name is gone, and the slots still on the medium are an orphaned run every
/// reader discards. The reverse order leaves a live short entry preceded by
/// freed slots, which reads as a file that silently lost its long name.
#[test]
fn the_short_entry_is_freed_before_its_slots() {
    let order = deletion_order(0, 4);
    assert_eq!(order[0], (3 * ENTRY_BYTES) as u64);
}

/// After the short entry the run shortens from its tail, so it never has a
/// hole in the middle.
#[test]
fn the_slots_are_freed_backwards_from_the_short_entry() {
    let e = ENTRY_BYTES as u64;
    assert_eq!(deletion_order(0, 4), ::alloc::vec![3 * e, 2 * e, e, 0]);
}

/// Every record of the group is freed and none twice. A slot left behind is a
/// slot the next name that needs a run of that length skips past forever.
#[test]
fn every_record_is_freed_exactly_once() {
    let at = 7 * ENTRY_BYTES as u64;
    let order = deletion_order(at, 5);
    assert_eq!(order.len(), 5);
    let mut sorted = order.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), 5);
    assert_eq!(sorted[0], at);
    assert_eq!(sorted[4], at + 4 * ENTRY_BYTES as u64);
}

/// A name with no long-name slots is one record, freed where it is.
#[test]
fn a_short_only_name_is_one_write() {
    let at = 3 * ENTRY_BYTES as u64;
    assert_eq!(deletion_order(at, 1), ::alloc::vec![at]);
}
