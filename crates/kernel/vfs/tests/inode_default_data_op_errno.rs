//! inode-D44: the default (no-data-op) `Inode::read`/`write` bind to the
//! inode's `S_IFMT` type. A directory rejects read/write with `Eisdir`
//! (Linux `generic_read_dir` / directory-write guard); a NON-directory
//! backend that installs no data op gets `Einval` (Linux `vfs_read`/
//! `vfs_write` when `f_op->read`/`read_iter` are absent) — NOT the old
//! unconditional `Eisdir`. `read_nonblock`/`write_nonblock` delegate to
//! `read`/`write`, so they inherit the same type-keyed errno.
//! Driven over `InodeBuilder` fixtures with the default `i_fop`, no QEMU.

use vfs::inode::InodeBuilder;
use vfs::{default_file_ops, default_inode_ops, mk_mode, FileType, InodeRef, VfsError};

/// Backend with NO data op overrides (the default `i_fop`) of a given type.
fn node(ino: u64, ft: FileType) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(ft, 0o644), default_inode_ops(), default_file_ops()).build()
}

#[test]
fn directory_default_read_write_is_eisdir() {
    let d = node(2, FileType::Directory);
    let mut buf = [0u8; 4];
    assert_eq!(d.read(0, &mut buf), Err(VfsError::Eisdir));
    assert_eq!(d.write(0, &buf), Err(VfsError::Eisdir));
}

#[test]
fn nondir_default_read_write_is_einval() {
    // Regular file with no installed data op → EINVAL (was wrongly EISDIR).
    let f = node(3, FileType::Regular);
    let mut buf = [0u8; 4];
    assert_eq!(f.read(0, &mut buf), Err(VfsError::Einval));
    assert_eq!(f.write(0, &buf), Err(VfsError::Einval));

    // Socket with no installed data op → EINVAL, not EISDIR.
    let s = node(4, FileType::Socket);
    assert_eq!(s.read(0, &mut buf), Err(VfsError::Einval));
    assert_eq!(s.write(0, &buf), Err(VfsError::Einval));
}

#[test]
fn nonblock_variants_inherit_type_keyed_errno() {
    // read_nonblock/write_nonblock delegate to read/write → same errno.
    let d = node(2, FileType::Directory);
    let s = node(4, FileType::Socket);
    let mut buf = [0u8; 4];
    assert_eq!(d.read_nonblock(0, &mut buf), Err(VfsError::Eisdir));
    assert_eq!(d.write_nonblock(0, &buf), Err(VfsError::Eisdir));
    assert_eq!(s.read_nonblock(0, &mut buf), Err(VfsError::Einval));
    assert_eq!(s.write_nonblock(0, &buf), Err(VfsError::Einval));
}
