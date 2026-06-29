//! `may_open` (Linux `fs/namei.c`) rejects a SYMLINK final inode with ELOOP.
//! This is the path `open(O_NOFOLLOW)` without `O_PATH` takes: the namei walk
//! returns the symlink as-is (`no_follow_final`), then `may_open`'s `i_mode`
//! switch turns `S_IFLNK` into ELOOP. Companion checks: a regular file opens,
//! and a directory opened for write is EISDIR. No QEMU.

use vfs::{Cred, FileType, InodeBuilder, InodeRef, VfsError, default_file_ops, default_inode_ops, mk_mode};

/// Symlink inode (no per-FS perm override).
fn tlnk() -> InodeRef {
    InodeBuilder::new(4, mk_mode(FileType::Symlink, 0o777), default_inode_ops(), default_file_ops()).build()
}

/// World-readable regular file.
fn treg() -> InodeRef {
    InodeBuilder::new(3, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops()).build()
}

/// Searchable directory.
fn tdir() -> InodeRef {
    InodeBuilder::new(2, mk_mode(FileType::Directory, 0o755), default_inode_ops(), default_file_ops()).build()
}

#[test]
fn may_open_symlink_is_eloop() {
    let l: InodeRef = tlnk();
    // open(O_NOFOLLOW) without O_PATH: the final symlink reaches may_open.
    assert_eq!(vfs::may_open(&l, true, false, &Cred::root()).err(), Some(VfsError::Eloop),
        "a symlink final inode is ELOOP (Linux may_open S_IFLNK)");
    // The type rejection precedes the access-mode check: RDWR is still ELOOP.
    assert_eq!(vfs::may_open(&l, true, true, &Cred::root()).err(), Some(VfsError::Eloop));
}

#[test]
fn may_open_regular_ok() {
    let f: InodeRef = treg();
    assert!(vfs::may_open(&f, true, false, &Cred::root()).is_ok());
    assert!(vfs::may_open(&f, true, true, &Cred::root()).is_ok());
}

#[test]
fn may_open_dir_write_is_eisdir() {
    let d: InodeRef = tdir();
    assert_eq!(vfs::may_open(&d, false, true, &Cred::root()).err(), Some(VfsError::Eisdir),
        "writing to a directory is EISDIR");
    // A read-only open of a directory is allowed (opendir).
    assert!(vfs::may_open(&d, true, false, &Cred::root()).is_ok());
}
