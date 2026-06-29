//! fdtable: RLIMIT_NOFILE / max-fds enforcement on the alloc path
//! (Linux `__alloc_fd(files, 0, rlimit(RLIMIT_NOFILE), flags)`).
//!
//! Two ceilings:
//!   - the per-process soft limit passed to `alloc_limit` (the task's
//!     `RLIMIT_NOFILE` cur): fds `[0, limit)` allocate; the `limit`-th
//!     → EMFILE. A `limit` of 0 yields EMFILE immediately.
//!   - the hard `FD_TABLE_MAX` table ceiling: `alloc` (no soft limit)
//!     fills `[0, FD_TABLE_MAX)` then the next → EMFILE; a soft limit
//!     above the table ceiling is clamped to it.
//!
//! No global state — each test owns a fresh `FdTable`, so no serial
//! guard is needed.

use std::sync::Arc;

use vfs::{InodeBuilder, default_file_ops, default_inode_ops, mk_mode};
use vfs::{Dentry, FdTable, File, FileType, InodeRef, OpenFlags, VfsError, FD_TABLE_MAX};

/// Minimal regular-file inode; the table never touches its I/O paths.
fn mk_inode() -> InodeRef {
    InodeBuilder::new(0x1, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops()).build()
}

fn mk_file() -> Arc<File> {
    let ino: InodeRef = mk_inode();
    let dentry = Dentry::new(None, "f".into(), Arc::clone(&ino));
    File::new(ino, dentry, OpenFlags::O_RDWR)
}

/// Soft limit boundary: with limit N, fds 0..N allocate, then EMFILE.
#[test]
fn alloc_limit_soft_boundary_emfile() {
    let t = FdTable::new();
    const N: usize = 8;
    for expect in 0..N {
        let fd = t.alloc_limit(mk_file(), N).expect("fd below soft limit must allocate");
        assert_eq!(fd, expect as i32, "first-fit fills 0..N in order");
    }
    assert_eq!(t.alloc_limit(mk_file(), N), Err(VfsError::Emfile),
        "the N-th fd at soft limit N must be EMFILE");
}

/// A soft limit of 0 forbids every fd → EMFILE on the first alloc.
#[test]
fn alloc_limit_zero_is_emfile() {
    let t = FdTable::new();
    assert_eq!(t.alloc_limit(mk_file(), 0), Err(VfsError::Emfile),
        "RLIMIT_NOFILE soft limit 0 must reject all fd allocation");
}

/// A lowered soft limit is honored even when the table has free slots
/// far below FD_TABLE_MAX (the prlimit64 EMFILE contract).
#[test]
fn alloc_limit_below_table_max_enforced() {
    let t = FdTable::new();
    // Fill exactly up to a small soft limit.
    let limit = 3;
    for _ in 0..limit { t.alloc_limit(mk_file(), limit).unwrap(); }
    assert_eq!(t.alloc_limit(mk_file(), limit), Err(VfsError::Emfile),
        "fd allocation past the soft limit must be EMFILE despite a near-empty table");
    // A subsequent alloc with a higher limit succeeds at the freed-up slot.
    let fd = t.alloc_limit(mk_file(), limit + 1).unwrap();
    assert_eq!(fd, limit as i32, "raising the soft limit lets the next slot allocate");
}

/// A soft limit above FD_TABLE_MAX is clamped to the hard table ceiling.
#[test]
fn alloc_limit_clamped_to_table_max() {
    let t = FdTable::new();
    // Fill the whole table via a huge soft limit; all FD_TABLE_MAX ok.
    for expect in 0..FD_TABLE_MAX {
        let fd = t.alloc_limit(mk_file(), usize::MAX).expect("fd below FD_TABLE_MAX must allocate");
        assert_eq!(fd, expect as i32);
    }
    assert_eq!(t.alloc_limit(mk_file(), usize::MAX), Err(VfsError::Emfile),
        "fd FD_TABLE_MAX must be EMFILE even with an unbounded soft limit");
}

/// The default `alloc` (no soft limit) still enforces the hard
/// FD_TABLE_MAX ceiling: 0..FD_TABLE_MAX ok, next → EMFILE.
#[test]
fn alloc_hard_table_max_boundary() {
    let t = FdTable::new();
    for expect in 0..FD_TABLE_MAX {
        let fd = t.alloc(mk_file()).expect("fd below FD_TABLE_MAX must allocate");
        assert_eq!(fd, expect as i32);
    }
    assert_eq!(t.alloc(mk_file()), Err(VfsError::Emfile),
        "the FD_TABLE_MAX-th fd must be EMFILE");
}
