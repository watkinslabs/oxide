//! `may_create_in_sticky` (Linux `fs/namei.c`) gate for `O_CREAT` opens of
//! entries that already exist in sticky directories.

use vfs::namei::may_create_in_sticky;
use vfs::{Cred, FileType, InodeBuilder, InodeRef, VfsError, default_file_ops, default_inode_ops, mk_mode};

fn inode(ft: FileType, perm: u16, uid: u32) -> InodeRef {
    InodeBuilder::new(1, mk_mode(ft, perm), default_inode_ops(), default_file_ops()).owner(uid, 0).build()
}

fn dir(perm: u16, uid: u32) -> InodeRef { inode(FileType::Directory, perm, uid) }
fn reg(perm: u16, uid: u32) -> InodeRef { inode(FileType::Regular, perm, uid) }
fn fifo(perm: u16, uid: u32) -> InodeRef { inode(FileType::Fifo, perm, uid) }
fn chr(perm: u16, uid: u32) -> InodeRef { inode(FileType::CharDev, perm, uid) }

fn user(uid: u32) -> Cred {
    Cred {
        uid, gid: uid,
        cap_dac_override: false, cap_dac_read_search: false,
        cap_fowner: false, cap_chown: false, cap_fsetid: false,
        groups: vfs::GroupList::empty(),
    }
}

#[test]
fn non_sticky_allows_existing_target() {
    assert!(may_create_in_sticky(&dir(0o777, 0), &reg(0o644, 1000), &user(2000)).is_ok());
}

#[test]
fn world_writable_sticky_denies_non_owner_regular_fifo_and_special() {
    let d = dir(0o1777, 0);
    assert_eq!(may_create_in_sticky(&d, &reg(0o644, 1000), &user(2000)).err(), Some(VfsError::Eacces));
    assert_eq!(may_create_in_sticky(&d, &fifo(0o644, 1000), &user(2000)).err(), Some(VfsError::Eacces));
    assert_eq!(may_create_in_sticky(&d, &chr(0o600, 1000), &user(2000)).err(), Some(VfsError::Eacces));
}

#[test]
fn existing_file_owner_and_directory_owner_are_allowed() {
    let root_sticky = dir(0o1777, 0);
    assert!(may_create_in_sticky(&root_sticky, &reg(0o644, 1000), &user(1000)).is_ok());
    let owned_sticky = dir(0o1777, 2000);
    assert!(may_create_in_sticky(&owned_sticky, &reg(0o644, 2000), &user(1000)).is_ok());
}

#[test]
fn group_writable_sticky_uses_linux_sysctl_levels() {
    let d = dir(0o1730, 0);
    assert_eq!(may_create_in_sticky(&d, &reg(0o644, 1000), &user(2000)).err(), Some(VfsError::Eacces));
    assert!(may_create_in_sticky(&d, &fifo(0o644, 1000), &user(2000)).is_ok());
}
