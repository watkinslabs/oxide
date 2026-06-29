//! `File::seek` must honor FMODE_LSEEK (Linux `vfs_llseek`): an O_PATH fd
//! carries no llseek and a pipe/socket/fifo is inherently non-seekable, so
//! `lseek(2)` on either returns ESPIPE ("illegal seek"). Pre-fix `seek()`
//! ignored `f_mode` and the inode type entirely — it computed a new cursor
//! and returned `Ok` for an O_PATH or fifo fd, which Linux never does.

use std::sync::Arc;

use vfs::inode::Inode;
use vfs::{Dentry, File, FileOps, FileType, InodeBuilder, InodeRef, KResult, OpenFlags, SeekFrom, VfsError,
          default_inode_ops, mk_mode};

/// `O_PATH` (asm-generic) — not declared in `OpenFlags`; set as a raw bit and
/// preserved via `from_bits_retain`, exactly how the syscall layer hands it in.
const O_PATH: u32 = 0o10000000;

/// `i_fop` that always satisfies read/write, so the only thing that can produce
/// ESPIPE is the seekability gate under test.
struct OkOps;
impl FileOps for OkOps {
    fn read(&self, _inode: &Inode, _off: u64, buf: &mut [u8]) -> KResult<usize> { Ok(buf.len()) }
    fn write(&self, _inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> { Ok(buf.len()) }
}

fn file(ft: FileType, flags: u32) -> Arc<File> {
    let ino: InodeRef = InodeBuilder::new(0x5151, mk_mode(ft, 0o644), default_inode_ops(), Arc::new(OkOps))
        .size(100).build();
    let dentry = Dentry::new(None, "f".into(), Arc::clone(&ino));
    File::new(ino, dentry, OpenFlags::from_bits_retain(flags))
}

/// Crux: an O_PATH fd over a regular file has FMODE_PATH only (no FMODE_LSEEK)
/// — every whence returns ESPIPE. Pre-fix this returned `Ok(..)`.
#[test]
fn o_path_seek_is_espipe() {
    let f = file(FileType::Regular, O_PATH);
    assert_eq!(f.f_mode(), vfs::Fmode::PATH, "O_PATH fd is FMODE_PATH only");
    assert_eq!(f.seek(SeekFrom::Start, 0), Err(VfsError::Espipe), "O_PATH SEEK_SET must be ESPIPE");
    assert_eq!(f.seek(SeekFrom::Current, 4), Err(VfsError::Espipe), "O_PATH SEEK_CUR must be ESPIPE");
    assert_eq!(f.seek(SeekFrom::End, 0), Err(VfsError::Espipe), "O_PATH SEEK_END must be ESPIPE");
}

/// A pipe/fifo is non-seekable: `lseek` is ESPIPE regardless of access mode.
#[test]
fn fifo_seek_is_espipe() {
    let f = file(FileType::Fifo, OpenFlags::O_RDWR.bits());
    assert_eq!(f.seek(SeekFrom::Start, 0), Err(VfsError::Espipe), "fifo lseek must be ESPIPE");
}

/// A socket fd is likewise non-seekable.
#[test]
fn socket_seek_is_espipe() {
    let f = file(FileType::Socket, OpenFlags::O_RDWR.bits());
    assert_eq!(f.seek(SeekFrom::Current, 8), Err(VfsError::Espipe), "socket lseek must be ESPIPE");
}

/// Regression: a normal regular-file fd still seeks (FMODE_LSEEK set). The gate
/// must not over-reject the common seekable case.
#[test]
fn regular_seek_still_works() {
    let f = file(FileType::Regular, OpenFlags::O_RDWR.bits());
    assert_eq!(f.seek(SeekFrom::Start, 10), Ok(10), "regular SEEK_SET should move cursor");
    assert_eq!(f.seek(SeekFrom::Current, 5), Ok(15), "regular SEEK_CUR should advance");
    assert_eq!(f.seek(SeekFrom::End, 0), Ok(100), "regular SEEK_END should land at size");
    // Negative result still EINVAL, not ESPIPE (the existing vfs_setpos gate).
    assert_eq!(f.seek(SeekFrom::Start, -1), Err(VfsError::Einval), "negative offset is EINVAL");
}
