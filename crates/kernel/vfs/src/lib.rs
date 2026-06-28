// Virtual File System — superblock / dentry / inode.
//
// Per docs/16 (FROZEN). Foundation lands here:
//   - shared types + errno (`types.rs`)
//   - `Inode` trait (`inode.rs`, v1 subset)
//   - `Dentry` (`dentry.rs`)
//   - `File` (`file.rs`) with read/write/seek + O_APPEND + O_RDONLY/WRONLY checks
//   - `FdTable` (`fdtable.rs`) with alloc/get/close/dup/dup2/CLOEXEC
//   - lexical path splitting (`path.rs`)
//
// Caches (`16§4` open-addressed hash + RCU), Superblock impls,
// Filesystem trait, mount table (`16§6`), full `Inode` surface, and
// `path_lookup` with symlink + RESOLVE_BENEATH + mount crossing all
// land in subsequent P1-N branches.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
pub mod static_file;
pub use static_file::StaticFileInode;
#[cfg(any(test, feature = "hosted"))]
extern crate std;

pub mod dcache;
pub mod dentry;
pub mod devnode;
pub mod dirent;
pub mod fdtable;
pub mod file;
pub mod getattr;
pub mod idmap;
pub mod inode;
pub mod inode_times;
pub mod mapping;
pub mod setattr;
pub mod namei;
pub mod path;
pub mod fs;
pub mod mount;
pub mod mntns;
pub mod superblock;
pub mod types;
pub mod poll_subs;

pub use dcache::{d_add, d_add_negative, d_alloc, d_drop, d_instantiate, d_invalidate, d_lookup, d_make_root, d_move, d_splice_alias, dget, dput};
pub use dentry::{Dentry, D_HASHED, D_NEGATIVE, D_ROOT};
pub use devnode::{BlockDevOps, CharDevOps, DeviceNodeInode, Devt, lookup_blkdev, lookup_chrdev, register_blkdev, register_chrdev, unregister_blkdev, unregister_chrdev};
pub use superblock::{FileSystemType, SbStatFs, SuperBlock, SuperOps};
pub use namei::{path_lookup, path_lookup_path, path_lookup_cred, resolve_abs, resolve_path_dentry, set_root_dentry_provider, inode_permission, generic_permission, may_open, may_create, may_chmod, may_chown, chmod_sgid_strip, chown_kill_priv, Cred, LookupFlags, Nameidata, VfsPath, CRED_NGROUPS, MAX_SYMLINK_DEPTH, MAY_EXEC, MAY_READ, MAY_WRITE, S_ISUID, S_ISGID, S_IXGRP};
pub use dirent::{dirent64_pack, dirent64_reclen, DIRENT64_HEADER, dirent_pack, dirent_reclen, DIRENT_HEADER};
pub use path::{path_from_bytes, path_into_bytes};
pub use fdtable::{FdTable, FD_TABLE_MAX};
pub use file::{File, Fmode, SeekFrom, fire_clone_hook, fire_dirent_create, fire_dirent_delete, set_clone_hook, set_close_hook, set_dirent_create_hook, set_dirent_delete_hook, set_drop_hook, set_open_hook, set_read_hook, set_write_hook};
pub use inode::{Inode, InodeRef, I_DIRTY, I_NEW, I_FREEING, POLL_IN, POLL_OUT, POLL_HUP, POLL_ERR, POLL_PRI, POLL_RDHUP};
pub use getattr::{generic_fillattr, vfs_getattr, default_perm_for, Kstat, S_IFMT, S_IFSOCK, S_IFLNK, S_IFREG, S_IFBLK, S_IFDIR, S_IFCHR, S_IFIFO};
pub use idmap::{Idmap, IdExtent, IDENTITY};
pub use setattr::{setattr_prepare, simple_setattr, notify_change, apply_kill_priv, Iattr, ATTR_MODE, ATTR_UID, ATTR_GID, ATTR_SIZE, ATTR_ATIME, ATTR_MTIME, ATTR_CTIME, ATTR_ATIME_SET, ATTR_MTIME_SET, ATTR_KILL_SUID, ATTR_KILL_SGID};
pub use mapping::AddressSpaceOps;
pub use types::{FileMode, FileType, Ino, KResult, OpenFlags, PollMask, StatxMask, VfsError};
pub use poll_subs::{EpollNotify, PollSubscribers};

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_d4b;

/// Subsystem-level error per `38`. Kept for the existing skeleton
/// `init` shim; the canonical VFS error is `VfsError` above.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    NotImplemented,
    NoMem,
    Inval,
    Io,
}

#[allow(dead_code)]
pub(crate) type StubResult<T> = core::result::Result<T, Error>;

/// Initialization entry; called by the kernel boot phase per `00§3` /
/// `boot-flow.md`. v1 returns `NotImplemented`; bodies in P1-N.
///
/// # SAFETY: caller is the boot path, runs single-CPU with IRQs off
/// per `boot-flow.md`. Subsystem-specific preconditions documented at
/// the implementation site.
///
/// # C: O(N_pfn) once at boot
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn init() -> StubResult<()> {
    Err(Error::NotImplemented)
}

#[cfg(test)]
mod stub_tests {
    use super::*;

    #[test]
    fn init_returns_not_implemented() {
        // SAFETY: hosted-test entry; nothing else has touched the subsystem; init's preconditions trivially hold.
        let r = unsafe { init() };
        assert_eq!(r, Err(Error::NotImplemented));
    }
}
