//! fdtable-D17: dup2 / F_DUPFD fd-range validation. Drives the real
//! `FdTable` and asserts the Linux errno contract for out-of-range fds:
//!   - `dup_min` (fcntl F_DUPFD): a requested `min >= FD_TABLE_MAX`
//!     (the RLIMIT_NOFILE ceiling) → EINVAL, NOT EMFILE (the pre-fix
//!     behaviour — `alloc_fd_min` ran the range loop off the end and
//!     surfaced EMFILE) and NOT EBADF. Linux `do_fcntl` F_DUPFD checks
//!     `arg >= rlimit(RLIMIT_NOFILE)` → -EINVAL before allocating.
//!   - bad/negative `oldfd` → EBADF (validated before the `min` range,
//!     matching the syscall-layer fdget which fetches oldfd first).
//!   - `dup2`/`dup3` newfd out of range → EBADF (Linux dup2 returns
//!     EBADF, not EINVAL, for a newfd above RLIMIT_NOFILE).

use std::sync::Arc;

use vfs::inode::Inode;
use vfs::{Dentry, FdTable, File, FileType, InodeRef, KResult, OpenFlags, VfsError, FD_TABLE_MAX};

/// Minimal regular-file inode; the table never touches its I/O paths.
struct Dummy;
impl Inode for Dummy {
    fn ino(&self) -> vfs::Ino { 0x1 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
}

fn mk_file() -> Arc<File> {
    let ino: InodeRef = Arc::new(Dummy);
    let dentry = Dentry::new(None, "f".into(), Arc::clone(&ino));
    File::new(ino, dentry, OpenFlags::O_RDWR)
}

/// F_DUPFD with `min == FD_TABLE_MAX` is out of range → EINVAL.
/// Pre-fix this returned EMFILE (alloc loop hit `fd >= FD_TABLE_MAX`).
#[test]
fn dupfd_min_at_ceiling_is_einval() {
    let t = FdTable::new();
    let fd = t.alloc(mk_file()).unwrap();
    assert_eq!(t.dup_min(fd, FD_TABLE_MAX as i32), Err(VfsError::Einval),
        "F_DUPFD arg == FD_TABLE_MAX must be EINVAL, not EMFILE");
}

/// F_DUPFD with `min` well past the ceiling → EINVAL (not EMFILE/EBADF).
#[test]
fn dupfd_min_above_ceiling_is_einval() {
    let t = FdTable::new();
    let fd = t.alloc(mk_file()).unwrap();
    assert_eq!(t.dup_min(fd, FD_TABLE_MAX as i32 + 99), Err(VfsError::Einval),
        "F_DUPFD arg > FD_TABLE_MAX must be EINVAL");
}

/// Negative `min` → EINVAL.
#[test]
fn dupfd_negative_min_is_einval() {
    let t = FdTable::new();
    let fd = t.alloc(mk_file()).unwrap();
    assert_eq!(t.dup_min(fd, -1), Err(VfsError::Einval),
        "F_DUPFD negative arg must be EINVAL");
}

/// Bad oldfd is rejected with EBADF before the `min` range check —
/// EBADF wins over EINVAL when both oldfd and arg are invalid.
#[test]
fn dupfd_bad_oldfd_is_ebadf_even_with_bad_min() {
    let t = FdTable::new();
    assert_eq!(t.dup_min(99, FD_TABLE_MAX as i32), Err(VfsError::Ebadf),
        "unopened oldfd must be EBADF (precedes the min range check)");
    assert_eq!(t.dup_min(-1, 0), Err(VfsError::Ebadf),
        "negative oldfd must be EBADF");
}

/// In-range F_DUPFD still works: lands at the lowest free fd >= min.
#[test]
fn dupfd_in_range_lands_at_min() {
    let t = FdTable::new();
    let fd = t.alloc(mk_file()).unwrap();
    let n = t.dup_min(fd, 10).unwrap();
    assert_eq!(n, 10, "F_DUPFD(10) on an otherwise-empty table lands at 10");
    // The highest legal fd, FD_TABLE_MAX-1, must allocate (not EINVAL).
    let hi = t.dup_min(fd, FD_TABLE_MAX as i32 - 1).unwrap();
    assert_eq!(hi, FD_TABLE_MAX as i32 - 1, "FD_TABLE_MAX-1 is the last legal fd");
}

/// dup2 newfd out of range → EBADF (Linux dup2 contract — NOT EINVAL),
/// and negative oldfd/newfd → EBADF.
#[test]
fn dup2_out_of_range_newfd_is_ebadf() {
    let t = FdTable::new();
    let fd = t.alloc(mk_file()).unwrap();
    assert_eq!(t.dup2(fd, FD_TABLE_MAX as i32), Err(VfsError::Ebadf),
        "dup2 newfd >= FD_TABLE_MAX must be EBADF");
    assert_eq!(t.dup2(fd, -1), Err(VfsError::Ebadf), "dup2 negative newfd must be EBADF");
    assert_eq!(t.dup2(-1, 5), Err(VfsError::Ebadf), "dup2 negative oldfd must be EBADF");
}
