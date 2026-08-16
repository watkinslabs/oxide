//! The offsets one deletion writes, in the order it writes them.
//!
//! The ORDER is the whole content of this module. A name's records are marked
//! free one at a time and nothing makes the set of writes atomic, so what a
//! reader sees between them is decided here.
//!
//! The SHORT entry goes first. It is the file: once its slot is free the name
//! is gone, and the long-name slots still on the medium are an orphaned run,
//! which every reader — this one included — discards when the entry it names
//! does not follow. The reverse order leaves a live short entry preceded by
//! slots that have been freed, which reads as a file that has lost its long
//! name and kept its alias: a rename nobody asked for, and a name that cannot
//! be deleted again because it is no longer the name that was there.
//!
//! The slots after it are marked from the short entry BACKWARDS, so the run
//! shortens from its tail and never has a hole in the middle.

use alloc::vec::Vec;

use crate::dirent::ENTRY_BYTES;

/// Offsets to mark free, in write order, for a group of `nr_slots` records
/// beginning at `at`.
///
/// `at` is the FIRST record of the group — the long-name slot with the highest
/// ordinal — not the short entry.
/// # C: O(nr_slots)
pub fn deletion_order(at: u64, nr_slots: usize) -> Vec<u64> {
    let mut out = Vec::with_capacity(nr_slots);
    for back in 0..nr_slots {
        out.push(at + ((nr_slots - 1 - back) * ENTRY_BYTES) as u64);
    }
    out
}
