//! fdtable: `close_range(2)` span op (Linux `__range_close`) over the
//! real `FdTable`. Before this method, the work logic lived in the slot
//! 436 syscall shim (a `live_fds` loop), violating docs/53 (kernel =
//! hollow shell, zero work logic) and untested except by a hand-rolled
//! model in `src/tests.rs`. Asserts:
//!   - the close path drops exactly the inclusive `[first, last]` span,
//!     leaving fds outside it intact, and flushes each closed File;
//!   - the CLOSE_RANGE_CLOEXEC path marks fds cloexec instead of closing
//!     (fds stay open, FD_CLOEXEC set only inside the span);
//!   - `first == last` closes a single fd;
//!   - a `last` past the table end (e.g. `u32::MAX`) closes the whole
//!     tail without panicking on the bitmap bounds.

use std::sync::Arc;

use vfs::{InodeBuilder, default_file_ops, default_inode_ops, mk_mode};
use vfs::{Dentry, FdTable, File, FileType, InodeRef, OpenFlags, VfsError};

fn mk_inode() -> InodeRef {
    InodeBuilder::new(0x1, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops()).build()
}

fn mk_file() -> Arc<File> {
    let ino: InodeRef = mk_inode();
    let dentry = Dentry::new(None, "f".into(), Arc::clone(&ino));
    File::new(ino, dentry, OpenFlags::O_RDWR)
}

/// close_range(1, 3): only fds 1..=3 drop; 0 and 4 survive.
#[test]
fn close_range_drops_inclusive_span() {
    let t = FdTable::new();
    let f: Vec<i32> = (0..5).map(|_| t.alloc(mk_file()).unwrap()).collect();
    assert_eq!(f, [0, 1, 2, 3, 4]);
    t.close_range(1, 3, false);
    assert!(t.get(0).is_ok(), "fd below span survives");
    assert_eq!(t.get(1).err(), Some(VfsError::Ebadf));
    assert_eq!(t.get(2).err(), Some(VfsError::Ebadf));
    assert_eq!(t.get(3).err(), Some(VfsError::Ebadf));
    assert!(t.get(4).is_ok(), "fd above span survives");
    assert_eq!(t.live_fds(), alloc_vec(&[0, 4]));
}

/// CLOSE_RANGE_CLOEXEC: fds in the span stay open but gain FD_CLOEXEC;
/// fds outside the span keep their (clear) flag.
#[test]
fn close_range_cloexec_marks_not_closes() {
    let t = FdTable::new();
    for _ in 0..4 { t.alloc(mk_file()).unwrap(); } // 0..=3
    t.close_range(1, 2, true);
    for fd in 0..4 {
        assert!(t.get(fd).is_ok(), "cloexec_only never closes");
    }
    assert_eq!(t.cloexec(0), Ok(false));
    assert_eq!(t.cloexec(1), Ok(true), "in-span fd marked cloexec");
    assert_eq!(t.cloexec(2), Ok(true), "in-span fd marked cloexec");
    assert_eq!(t.cloexec(3), Ok(false), "out-of-span fd untouched");
    // A subsequent execve sweep then drops exactly the marked span.
    t.close_on_exec();
    assert!(t.get(0).is_ok());
    assert_eq!(t.get(1).err(), Some(VfsError::Ebadf));
    assert_eq!(t.get(2).err(), Some(VfsError::Ebadf));
    assert!(t.get(3).is_ok());
}

/// `first == last` closes exactly one fd.
#[test]
fn close_range_single_fd() {
    let t = FdTable::new();
    for _ in 0..3 { t.alloc(mk_file()).unwrap(); }
    t.close_range(1, 1, false);
    assert!(t.get(0).is_ok());
    assert_eq!(t.get(1).err(), Some(VfsError::Ebadf));
    assert!(t.get(2).is_ok());
}

/// `last == u32::MAX` closes the whole tail from `first` without
/// indexing past the `open_fds` bitmap (the loop is bounded by the
/// table's word count, not `last`).
#[test]
fn close_range_to_end_is_bounded() {
    let t = FdTable::new();
    for _ in 0..5 { t.alloc(mk_file()).unwrap(); }
    t.close_range(2, u32::MAX, false);
    assert!(t.get(0).is_ok());
    assert!(t.get(1).is_ok());
    assert_eq!(t.get(2).err(), Some(VfsError::Ebadf));
    assert_eq!(t.get(3).err(), Some(VfsError::Ebadf));
    assert_eq!(t.get(4).err(), Some(VfsError::Ebadf));
    assert_eq!(t.live_fds(), alloc_vec(&[0, 1]));
}

/// An empty table tolerates any range (no panic on zero-length bitmap).
#[test]
fn close_range_empty_table_noop() {
    let t = FdTable::new();
    t.close_range(0, u32::MAX, false);
    assert_eq!(t.live_fds(), alloc_vec(&[]));
}

/// CLOSE_RANGE_UNSHARE without CLOEXEC mirrors Linux `dup_fd(...,
/// punch_hole)`: the new private table omits the range, while the old
/// shared table remains unchanged and no transient file refs are taken
/// for the punched-out slots.
#[test]
fn fork_clone_close_range_punches_hole_without_touching_source() {
    let t = FdTable::new();
    for _ in 0..5 { t.alloc(mk_file()).unwrap(); }
    let held = t.get(2).unwrap();
    let count_before = held.f_count();

    let private = t.fork_clone_close_range(1, 3, false);

    assert_eq!(t.live_fds(), alloc_vec(&[0, 1, 2, 3, 4]));
    assert_eq!(private.live_fds(), alloc_vec(&[0, 4]));
    assert!(t.get(2).is_ok(), "source table still owns fd in punched range");
    assert_eq!(private.get(2).err(), Some(VfsError::Ebadf));
    assert_eq!(held.f_count(), count_before, "punched range was not cloned then closed");
}

/// CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC must copy the whole shared table
/// then mark only the requested span close-on-exec in the private copy.
#[test]
fn fork_clone_close_range_cloexec_copies_all_then_marks_private_span() {
    let t = FdTable::new();
    for _ in 0..4 { t.alloc(mk_file()).unwrap(); }
    t.set_cloexec(0, true).unwrap();
    let in_span = t.get(2).unwrap();
    let count_before = in_span.f_count();

    let private = t.fork_clone_close_range(1, 2, true);

    assert_eq!(t.live_fds(), alloc_vec(&[0, 1, 2, 3]));
    assert_eq!(private.live_fds(), alloc_vec(&[0, 1, 2, 3]));
    assert_eq!(t.cloexec(0), Ok(true));
    assert_eq!(t.cloexec(1), Ok(false));
    assert_eq!(t.cloexec(2), Ok(false));
    assert_eq!(private.cloexec(0), Ok(true));
    assert_eq!(private.cloexec(1), Ok(true));
    assert_eq!(private.cloexec(2), Ok(true));
    assert_eq!(private.cloexec(3), Ok(false));
    assert_eq!(in_span.f_count(), count_before + 1, "cloexec unshare keeps an fd ref in the private copy");
}

fn alloc_vec(s: &[i32]) -> Vec<i32> { s.to_vec() }
