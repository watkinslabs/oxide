//! inode-D27 (vfs part): the unified Linux `umode_t` (`i_mode`) view —
//! `Inode::i_mode() == file_type().to_ifmt() | perm`. Proves the single
//! mode-builder (`FileType::to_ifmt`) round-trips type+perm and that the
//! `perm() == None` pseudo-fs path falls back to `default_perm_for`.
//! Driven over minimal `Inode` impls, no QEMU.

use std::sync::Arc;

use vfs::inode::Inode;
use vfs::types::{S_IFCHR, S_IFDIR, S_IFLNK, S_IFMT, S_IFREG};
use vfs::{FileType, InodeRef, KResult, VfsError};

/// Directory with an explicit perm.
struct TDir { perm: u16 }
impl Inode for TDir {
    fn ino(&self) -> vfs::Ino { 2 }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn perm(&self) -> Option<u16> { Some(self.perm) }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
}

/// Regular file with an explicit perm.
struct TReg { perm: u16 }
impl Inode for TReg {
    fn ino(&self) -> vfs::Ino { 3 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn perm(&self) -> Option<u16> { Some(self.perm) }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
}

/// Symlink with no per-FS perm override (`perm() == None`).
struct TLnk;
impl Inode for TLnk {
    fn ino(&self) -> vfs::Ino { 4 }
    fn file_type(&self) -> FileType { FileType::Symlink }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
}

/// Char device with no per-FS perm override (`perm() == None`).
struct TChr;
impl Inode for TChr {
    fn ino(&self) -> vfs::Ino { 5 }
    fn file_type(&self) -> FileType { FileType::CharDev }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
}

#[test]
fn dir_imode_is_ifdir_or_perm() {
    let d = TDir { perm: 0o755 };
    assert_eq!(d.i_mode(), S_IFDIR | 0o755);
    assert_eq!(d.i_mode() & S_IFMT, S_IFDIR);
    assert_eq!(d.i_mode() & !S_IFMT, 0o755, "perm bits == low-12 of i_mode");
}

#[test]
fn reg_imode_is_ifreg_or_perm() {
    let f = TReg { perm: 0o644 };
    assert_eq!(f.i_mode(), S_IFREG | 0o644);
    assert_eq!(f.i_mode() & !S_IFMT, 0o644);
}

#[test]
fn symlink_imode_type_is_iflnk() {
    let l: Arc<dyn Inode> = Arc::new(TLnk);
    assert_eq!(l.i_mode() & S_IFMT, S_IFLNK);
    // perm() == None → sane default (type set, nonzero perm).
    assert_eq!(l.i_mode() & S_IFMT, S_IFLNK);
    assert_ne!(l.i_mode() & !S_IFMT, 0, "default perm is nonzero");
}

#[test]
fn chardev_imode_type_is_ifchr() {
    let c = TChr;
    assert_eq!(c.i_mode() & S_IFMT, S_IFCHR);
    assert_ne!(c.i_mode() & !S_IFMT, 0, "default perm is nonzero");
}

#[test]
fn none_perm_matches_getattr_default() {
    // i_mode()'s None-perm fallback uses the same default_perm_for that
    // generic_fillattr does, so the low-12 bits agree with a stat.
    use vfs::IDENTITY;
    let l = TLnk;
    let st = vfs::generic_fillattr(&l, &IDENTITY, None);
    assert_eq!(st.mode, u32::from(l.i_mode()),
        "Kstat.mode (no overlay) == i_mode() for a None-perm inode");
}
