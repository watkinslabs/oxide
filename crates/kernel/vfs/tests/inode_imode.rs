//! inode-D27 (vfs part): the unified Linux `umode_t` (`i_mode`) view —
//! `Inode::i_mode() == file_type().to_ifmt() | perm`. Proves the single
//! mode-builder (`FileType::to_ifmt`) round-trips type+perm and that a
//! pseudo-fs node stamped with the Linux default perm agrees with `getattr`.
//! Driven over `InodeBuilder` fixtures, no QEMU.

use vfs::inode::InodeBuilder;
use vfs::types::{S_IFCHR, S_IFDIR, S_IFLNK, S_IFMT, S_IFREG};
use vfs::{default_file_ops, default_inode_ops, mk_mode, FileType, InodeRef};

/// Directory with an explicit perm.
fn tdir(perm: u16) -> InodeRef {
    InodeBuilder::new(2, mk_mode(FileType::Directory, perm), default_inode_ops(), default_file_ops()).build()
}

/// Regular file with an explicit perm.
fn treg(perm: u16) -> InodeRef {
    InodeBuilder::new(3, mk_mode(FileType::Regular, perm), default_inode_ops(), default_file_ops()).build()
}

/// Symlink stamped with the Linux default symlink perm (0o777).
fn tlnk() -> InodeRef {
    InodeBuilder::new(4, mk_mode(FileType::Symlink, 0o777), default_inode_ops(), default_file_ops()).build()
}

/// Char device stamped with the Linux default device perm (0o666).
fn tchr() -> InodeRef {
    InodeBuilder::new(5, mk_mode(FileType::CharDev, 0o666), default_inode_ops(), default_file_ops()).build()
}

#[test]
fn dir_imode_is_ifdir_or_perm() {
    let d = tdir(0o755);
    assert_eq!(d.i_mode(), S_IFDIR | 0o755);
    assert_eq!(d.i_mode() & S_IFMT, S_IFDIR);
    assert_eq!(d.i_mode() & !S_IFMT, 0o755, "perm bits == low-12 of i_mode");
}

#[test]
fn reg_imode_is_ifreg_or_perm() {
    let f = treg(0o644);
    assert_eq!(f.i_mode(), S_IFREG | 0o644);
    assert_eq!(f.i_mode() & !S_IFMT, 0o644);
}

#[test]
fn symlink_imode_type_is_iflnk() {
    let l = tlnk();
    assert_eq!(l.i_mode() & S_IFMT, S_IFLNK);
    assert_ne!(l.i_mode() & !S_IFMT, 0, "default perm is nonzero");
}

#[test]
fn chardev_imode_type_is_ifchr() {
    let c = tchr();
    assert_eq!(c.i_mode() & S_IFMT, S_IFCHR);
    assert_ne!(c.i_mode() & !S_IFMT, 0, "default perm is nonzero");
}

#[test]
fn none_perm_matches_getattr_default() {
    // The low-12 mode bits agree with a stat for a symlink stamped with the
    // Linux default perm — `i_mode()` and `generic_fillattr` read the same field.
    use vfs::IDENTITY;
    let l = tlnk();
    let st = vfs::generic_fillattr(&l, &IDENTITY, None);
    assert_eq!(st.mode, u32::from(l.i_mode()),
        "Kstat.mode (no overlay) == i_mode() for the inode");
}
