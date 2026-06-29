//! `File::seek` rejects a resulting offset < 0 with EINVAL (file-D14).
//! The bug: SEEK_SET did `off as u64`, so a negative `off` became a huge
//! positive position; SEEK_CUR/SEEK_END `checked_add` then `as u64` let a
//! negative *result* wrap to a huge value too. Linux `vfs_setpos` returns
//! EINVAL for any resulting offset < 0. Driven over a real `File` with a
//! fixed-size inode so only the seek arithmetic is under test.

use std::sync::Arc;

use vfs::{Dentry, File, FileType, InodeBuilder, InodeRef, OpenFlags, SeekFrom, VfsError,
          default_file_ops, default_inode_ops, mk_mode};

fn file(size: u64) -> Arc<File> {
    let ino: InodeRef = InodeBuilder::new(0x5eec, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops())
        .size(size).build();
    let dentry = Dentry::new(None, "f".into(), Arc::clone(&ino));
    File::new(ino, dentry, OpenFlags::O_RDWR)
}

#[test]
fn seek_set_negative_is_einval() {
    let f = file(100);
    // Pre-fix: -1 became u64::MAX. Linux: EINVAL.
    assert_eq!(f.seek(SeekFrom::Start, -1), Err(VfsError::Einval), "SEEK_SET<0 must be EINVAL");
    assert_eq!(f.pos(), 0, "rejected seek must not move the cursor");
}

#[test]
fn seek_set_zero_and_positive_ok() {
    let f = file(100);
    assert_eq!(f.seek(SeekFrom::Start, 0), Ok(0));
    assert_eq!(f.seek(SeekFrom::Start, 42), Ok(42));
    assert_eq!(f.pos(), 42);
}

#[test]
fn seek_cur_below_zero_is_einval() {
    let f = file(100);
    f.set_pos(10);
    // 10 + (-25) = -15 -> EINVAL, cursor unchanged.
    assert_eq!(f.seek(SeekFrom::Current, -25), Err(VfsError::Einval), "SEEK_CUR result<0 must be EINVAL");
    assert_eq!(f.pos(), 10, "rejected SEEK_CUR must not move the cursor");
    // 10 + (-10) = 0 is the boundary -> allowed.
    assert_eq!(f.seek(SeekFrom::Current, -10), Ok(0));
}

#[test]
fn seek_end_below_zero_is_einval() {
    let f = file(100);
    // size 100 + (-101) = -1 -> EINVAL.
    assert_eq!(f.seek(SeekFrom::End, -101), Err(VfsError::Einval), "SEEK_END result<0 must be EINVAL");
    // size 100 + (-100) = 0 boundary -> allowed; positive past-EOF allowed.
    assert_eq!(f.seek(SeekFrom::End, -100), Ok(0));
    assert_eq!(f.seek(SeekFrom::End, 50), Ok(150), "seeking past EOF is allowed");
}

#[test]
fn seek_overflow_is_einval() {
    let f = file(0);
    f.set_pos(i64::MAX as u64);
    // base (i64::MAX) + i64::MAX overflows -> EINVAL via checked_add.
    assert_eq!(f.seek(SeekFrom::Current, i64::MAX), Err(VfsError::Einval), "overflow must be EINVAL");
}
