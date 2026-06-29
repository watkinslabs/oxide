//! fdtable-D33: `fork_clone` right-sizes the child table to the parent's
//! currently-open fds (Linux `dup_fd` → `sane_fdtable_size`), instead of
//! copying the parent's high-water capacity verbatim. Pre-fix `fork_clone`
//! did `files.clone()` of the full Vec, so a parent that opened then CLOSED a
//! high fd handed the child an over-large table that never shrank. These tests
//! drive the real `FdTable` and assert the child capacity follows the highest
//! OPEN fd (word-aligned), the parent table is untouched, and every open fd is
//! preserved and independent post-fork.

use std::sync::Arc;

use vfs::{InodeBuilder, default_file_ops, default_inode_ops, mk_mode};
use vfs::{Dentry, FdTable, File, FileType, InodeRef, OpenFlags};

const WORD: usize = 64;

fn mk_inode() -> InodeRef {
    InodeBuilder::new(0x1, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops()).build()
}

fn mk_file() -> Arc<File> {
    let ino: InodeRef = mk_inode();
    let dentry = Dentry::new(None, "f".into(), Arc::clone(&ino));
    File::new(ino, dentry, OpenFlags::O_RDWR)
}

/// Parent grows to ~200 slots then closes everything above fd 0 → the child
/// table shrinks to one word (64 slots), while the parent keeps its capacity.
#[test]
fn fork_shrinks_to_open_highwater() {
    let parent = FdTable::new();
    let mut fds = Vec::new();
    for _ in 0..200 { fds.push(parent.alloc(mk_file()).unwrap()); }
    let grown = parent.capacity();
    assert!(grown >= 200, "parent grew to hold 200 fds");
    // Close every fd above 0 (highest open becomes fd 0).
    for &fd in fds.iter().skip(1) { parent.close(fd).unwrap(); }

    let child = parent.fork_clone();
    assert_eq!(child.capacity(), WORD,
        "child right-sized to one word (highest open fd 0 → 64 slots), not the parent high-water");
    assert!(parent.capacity() >= 200, "parent capacity is NOT shrunk by fork");
    // The surviving low fd is present in the child.
    assert!(child.get(fds[0]).is_ok(), "open fd survives the right-sized fork");
}

/// A child of an empty parent gets an empty (zero-capacity) table — no fd open,
/// no words needed (our lazy baseline, consistent with `FdTable::new`).
#[test]
fn fork_of_empty_is_empty() {
    let parent = FdTable::new();
    let child = parent.fork_clone();
    assert_eq!(child.capacity(), 0, "no open fd → child needs no slots");
}

/// Capacity follows the HIGHEST open fd, not the count: one open fd at index 70
/// (word 1) needs two words = 128 slots even though only a single fd is live.
#[test]
fn fork_capacity_tracks_highest_not_count() {
    let parent = FdTable::new();
    let mut fds = Vec::new();
    for _ in 0..100 { fds.push(parent.alloc(mk_file()).unwrap()); }
    // Keep only fd 70 open.
    for &fd in fds.iter() { if fd != 70 { parent.close(fd).unwrap(); } }
    let child = parent.fork_clone();
    assert_eq!(child.capacity(), 2 * WORD,
        "highest open fd 70 lives in word 1 → child holds 2 words (128 slots)");
    assert!(child.get(70).is_ok(), "the single high open fd survives");
    assert_eq!(child.count(), 1, "exactly one fd open in the child");
}

/// Post-fork the child and parent fd tables are independent (closing in the
/// child does not affect the parent), while the open file description is shared.
#[test]
fn fork_tables_independent() {
    let parent = FdTable::new();
    let fd = parent.alloc(mk_file()).unwrap();
    let child = parent.fork_clone();
    assert!(child.get(fd).is_ok() && parent.get(fd).is_ok(), "both see the inherited fd");
    child.close(fd).unwrap();
    assert!(child.get(fd).is_err(), "closed in child");
    assert!(parent.get(fd).is_ok(), "still open in parent — tables are independent");
}
