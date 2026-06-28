//! `may_open` (Linux `fs/namei.c`) rejects a SYMLINK final inode with ELOOP.
//! This is the path `open(O_NOFOLLOW)` without `O_PATH` takes: the namei walk
//! returns the symlink as-is (`no_follow_final`), then `may_open`'s `i_mode`
//! switch turns `S_IFLNK` into ELOOP. Companion checks: a regular file opens,
//! and a directory opened for write is EISDIR. No QEMU.

use std::sync::Arc;

use vfs::inode::Inode;
use vfs::{Cred, FileType, InodeRef, KResult, VfsError};

/// Symlink inode (no per-FS perm override).
struct TLnk;
impl Inode for TLnk {
    fn ino(&self) -> vfs::Ino { 4 }
    fn file_type(&self) -> FileType { FileType::Symlink }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
}

/// World-readable regular file.
struct TReg;
impl Inode for TReg {
    fn ino(&self) -> vfs::Ino { 3 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn perm(&self) -> Option<u16> { Some(0o644) }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
}

/// Searchable directory.
struct TDir;
impl Inode for TDir {
    fn ino(&self) -> vfs::Ino { 2 }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn perm(&self) -> Option<u16> { Some(0o755) }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
}

#[test]
fn may_open_symlink_is_eloop() {
    let l: InodeRef = Arc::new(TLnk);
    // open(O_NOFOLLOW) without O_PATH: the final symlink reaches may_open.
    assert_eq!(vfs::may_open(&l, true, false, &Cred::root()).err(), Some(VfsError::Eloop),
        "a symlink final inode is ELOOP (Linux may_open S_IFLNK)");
    // The type rejection precedes the access-mode check: RDWR is still ELOOP.
    assert_eq!(vfs::may_open(&l, true, true, &Cred::root()).err(), Some(VfsError::Eloop));
}

#[test]
fn may_open_regular_ok() {
    let f: InodeRef = Arc::new(TReg);
    assert!(vfs::may_open(&f, true, false, &Cred::root()).is_ok());
    assert!(vfs::may_open(&f, true, true, &Cred::root()).is_ok());
}

#[test]
fn may_open_dir_write_is_eisdir() {
    let d: InodeRef = Arc::new(TDir);
    assert_eq!(vfs::may_open(&d, false, true, &Cred::root()).err(), Some(VfsError::Eisdir),
        "writing to a directory is EISDIR");
    // A read-only open of a directory is allowed (opendir).
    assert!(vfs::may_open(&d, true, false, &Cred::root()).is_ok());
}
