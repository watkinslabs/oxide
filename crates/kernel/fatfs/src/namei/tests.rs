//! Test manifest for name creation, deletion and the dot entries.
//!
//! Module manifest:
//! - `find`:   the free-slot run, the damaged-directory refusal, the scan.
//! - `build`:  the records a name becomes, under both naming rules.
//! - `remove`: the order a deletion writes in.
//! - `dots`:   what `.` and `..` hold, and what emptiness counts.

use ::alloc::vec;
use ::alloc::vec::Vec;

use crate::dirent::{DELETED_FLAG, ENTRY_BYTES};

/// A directory image of `entries` records, all never-used.
pub fn blank(entries: usize) -> Vec<u8> { vec![0u8; entries * ENTRY_BYTES] }

/// Put a live short entry at `index`.
pub fn used(bytes: &mut [u8], index: usize, name: &[u8; 11], attr: u8) {
    let at = index * ENTRY_BYTES;
    bytes[at..at + 11].copy_from_slice(name);
    bytes[at + 11] = attr;
}

/// Mark the record at `index` as released.
pub fn deleted(bytes: &mut [u8], index: usize) {
    bytes[index * ENTRY_BYTES] = DELETED_FLAG;
}

#[path = "tests/find.rs"] mod find;
#[path = "tests/build.rs"] mod build;
#[path = "tests/remove.rs"] mod remove;
#[path = "tests/dots.rs"] mod dots;
