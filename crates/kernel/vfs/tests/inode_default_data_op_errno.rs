//! inode-D44: the default (no-data-op) `Inode::read`/`write` bind to the
//! inode's `S_IFMT` type. A directory rejects read/write with `Eisdir`
//! (Linux `generic_read_dir` / directory-write guard); a NON-directory
//! backend that installs no data op gets `Einval` (Linux `vfs_read`/
//! `vfs_write` when `f_op->read`/`read_iter` are absent) — NOT the old
//! unconditional `Eisdir`. `read_nonblock`/`write_nonblock` delegate to
//! `read`/`write`, so they inherit the same type-keyed errno.
//! Driven over minimal `Inode` impls, no QEMU.

use vfs::inode::Inode;
use vfs::{FileType, InodeRef, KResult, VfsError};

/// Directory backend with NO data op overrides → defaults apply.
struct TDir;
impl Inode for TDir {
    fn ino(&self) -> vfs::Ino { 2 }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
}

/// Regular file backend with NO data op overrides → defaults apply.
struct TReg;
impl Inode for TReg {
    fn ino(&self) -> vfs::Ino { 3 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
}

/// Socket backend with NO data op overrides → defaults apply. The pre-fix
/// code mislabelled this `Eisdir`; Linux returns `Einval`.
struct TSock;
impl Inode for TSock {
    fn ino(&self) -> vfs::Ino { 4 }
    fn file_type(&self) -> FileType { FileType::Socket }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
}

#[test]
fn directory_default_read_write_is_eisdir() {
    let d = TDir;
    let mut buf = [0u8; 4];
    assert_eq!(d.read(0, &mut buf), Err(VfsError::Eisdir));
    assert_eq!(d.write(0, &buf), Err(VfsError::Eisdir));
}

#[test]
fn nondir_default_read_write_is_einval() {
    // Regular file with no installed data op → EINVAL (was wrongly EISDIR).
    let f = TReg;
    let mut buf = [0u8; 4];
    assert_eq!(f.read(0, &mut buf), Err(VfsError::Einval));
    assert_eq!(f.write(0, &buf), Err(VfsError::Einval));

    // Socket with no installed data op → EINVAL, not EISDIR.
    let s = TSock;
    assert_eq!(s.read(0, &mut buf), Err(VfsError::Einval));
    assert_eq!(s.write(0, &buf), Err(VfsError::Einval));
}

#[test]
fn nonblock_variants_inherit_type_keyed_errno() {
    // read_nonblock/write_nonblock delegate to read/write → same errno.
    let d = TDir;
    let s = TSock;
    let mut buf = [0u8; 4];
    assert_eq!(d.read_nonblock(0, &mut buf), Err(VfsError::Eisdir));
    assert_eq!(d.write_nonblock(0, &buf), Err(VfsError::Eisdir));
    assert_eq!(s.read_nonblock(0, &mut buf), Err(VfsError::Einval));
    assert_eq!(s.write_nonblock(0, &buf), Err(VfsError::Einval));
}
