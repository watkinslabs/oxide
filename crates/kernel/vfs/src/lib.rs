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
pub use static_file::{StaticFileInode, make_static_file_inode};
#[cfg(any(test, feature = "hosted"))]
extern crate std;

pub mod dcache;
pub mod dentry;
pub mod devnode;
pub mod dirent;
pub mod fdtable;
pub mod file;
pub mod fileattr;
pub mod file_ops;
pub mod getattr;
pub mod idmap;
pub mod inode;
pub mod inode_ops;
pub mod inode_times;
pub mod mapping;
pub mod memory_accounting;
pub mod setattr;
pub mod namei;
pub mod path;
pub mod fs;
pub mod mount;
pub mod mntns;
pub mod superblock;
mod superblock_wb;
pub mod types;
pub mod uapi;
pub mod poll_subs;
pub mod quota;
pub mod xattr;

pub use dcache::{d_add, d_add_negative, d_alloc, d_drop, d_drop_child, d_instantiate, d_invalidate, d_lookup, d_make_root, d_move, d_obtain_alias, d_splice_alias, dget, dput};
pub use dentry::{Dentry, D_HASHED, D_NEGATIVE, D_ROOT};
// D12: RCU grace-period barrier — flush deferred dentry reclaim (`__d_free`
// via `sync::call_rcu`). Umount/teardown and tests that need the deferred
// `iput` to have run call this (Linux `rcu_barrier` in
// `generic_shutdown_super`).
pub use sync::rcu_barrier;
pub use devnode::{BlockDevOps, CharDevOps, Devt, DeviceNodeData, init_special_inode, make_device_node_inode, make_fifo_inode, make_socket_inode, device_inode_open, device_inode_ioctl, device_inode_devt, lookup_blkdev, lookup_chrdev, register_blkdev, register_blkdev_region, register_chrdev, register_chrdev_region, unregister_blkdev, unregister_blkdev_region, unregister_chrdev, unregister_chrdev_region, mkdev, kdev_major, kdev_minor, new_encode_dev, huge_encode_dev, MINORBITS, MINORMASK};
pub use superblock::{FileSystemType, SbStatFs, SimpleSuperOps, SuperBlock, SuperOps};
pub use namei::{path_lookup, path_lookup_path, path_lookup_cred, path_lookup_at_cred, path_lookup_at_root_cred, mountpoint_lookup_at_root_cred, mount_target_from_resolved_path, resolve_abs, resolve_path_dentry, set_root_dentry_provider, inode_permission, generic_permission, may_open, may_create, may_create_in_sticky, may_link, may_link_source, may_chmod, may_chown, chmod_sgid_strip, chown_kill_priv, Cred, LastType, LookupFlags, LinkTarget, MountTarget, Nameidata, VfsPath, GroupList, MAX_SYMLINK_DEPTH, MAY_EXEC, MAY_READ, MAY_WRITE, S_ISUID, S_ISGID, S_IXGRP};
pub use dirent::{dirent64_pack, dirent64_reclen, DIRENT64_HEADER, dirent_pack, dirent_reclen, DIRENT_HEADER};
pub use path::{path_from_bytes, path_into_bytes};
pub use fdtable::{FdTable, FD_TABLE_MAX, set_file_ref_drop_hook};
pub use file::{File, FileCred, FileEpollLink, Fmode, SeekFrom, clear_file_lock_wait_hooks, file_lock_interrupted, file_lock_park, file_lock_schedule, file_lock_wake, fire_clone_hook, fire_dirent_create, fire_dirent_delete, set_clone_hook, set_close_hook, set_dirent_create_hook, set_dirent_delete_hook, set_drop_hook, set_file_lock_wait_hooks, set_open_hook, set_read_hook, set_write_hook};
pub use inode::{Inode, InodeBuilder, InodeRef, SealCarrier, FileAttr, FiemapExtent, FileLockContext, FlockKind, FlockTry, get_next_ino, generic_update_time, inode_unlock, lock_rename, unlock_rename, RenameLockGuard, prepare_create_owner_mode, prepare_symlink_owner, I_DIRTY, I_NEW, I_FREEING, I_LINKABLE, S_IMMUTABLE, S_APPEND, S_NOATIME, S_SYNC, S_ATIME, S_MTIME, S_CTIME, S_VERSION, POLL_IN, POLL_OUT, POLL_HUP, POLL_ERR, POLL_PRI, POLL_RDNORM, POLL_RDHUP};
pub use fileattr::{FileAttrSource, clear_fileattr_hooks, fileattr_get, fileattr_prepare_set, fileattr_set, set_fileattr_hooks};
pub use inode_ops::{InodeOps, DefaultInodeOps, default_inode_ops, mk_mode, CreateCtx};
pub use xattr::{SimpleXattrs, XattrError};
pub use file_ops::{FileOps, DefaultFileOps, default_file_ops, stream_write_iter_file, DirContext, DirEmit, FileIoctlCmd, FileIoctlReply, IoctlIntCmd};
#[cfg(feature = "debug-getdents")]
pub use file_ops::DirDebugBackend;
pub use getattr::{fsid_to_dev, st_dev_for_fsid, generic_fillattr, vfs_getattr, default_perm_for, Kstat, S_IFMT, S_IFSOCK, S_IFLNK, S_IFREG, S_IFBLK, S_IFDIR, S_IFCHR, S_IFIFO};
pub use idmap::{Idmap, IdExtent, IDENTITY};
pub use setattr::{setattr_prepare, simple_setattr, notify_change, notify_change_mnt, apply_kill_priv, setattr_should_drop_suidgid, inode_newsize_ok, set_rlimit_fsize_hook, clear_rlimit_fsize_hook, RlimitFsizeHook, Iattr, ATTR_MODE, ATTR_UID, ATTR_GID, ATTR_SIZE, ATTR_ATIME, ATTR_MTIME, ATTR_CTIME, ATTR_ATIME_SET, ATTR_MTIME_SET, ATTR_KILL_SUID, ATTR_KILL_SGID, ATTR_FORCE};
pub use mapping::{AddressSpaceOps, SharedFrame};
pub use memory_accounting::{MemoryPageSnapshot, memory_page_snapshot};
pub use types::{FileMode, FileType, Ino, KResult, OpenFlags, PollMask, StatxMask, VfsError};
pub use poll_subs::{EpollNotify, PollSubscribers};
pub use quota::{__dquot_transfer, DQB_INO_COUNT, DQB_INO_HARD, DQB_INO_SOFT, DQB_INO_TIMER, DQB_RTB_COUNT, DQB_RTB_HARD, DQB_RTB_SOFT, DQB_RTB_TIMER, DQB_SPACE, DQB_SPC_HARD, DQB_SPC_SOFT, DQB_SPC_TIMER, DQB_VFS_MASK, DQF_GETINFO_MASK, DQF_ROOT_SQUASH, DQF_SETINFO_MASK, DQF_SYS_FILE, Dquot, DquotLimits, DquotOperations, DquotRef, DquotSet, DquotTransferIds, DquotTransferSlot, DquotUsage, IIF_ALL, IIF_BGRACE, IIF_BWARN, IIF_FLAGS, IIF_IGRACE, IIF_IWARN, IIF_RT_BGRACE, IIF_RTBWARN, InodeDquots, Kqid, MemDqblk, MemDqinfo, QuotaCtlCmd, QuotaCtlCred, QuotaFileStat, QuotaId, QuotaInfo, QuotaLimit, QuotaState, QuotaType, QuotaTypeState, QFMT_VFS_OLD, QFMT_VFS_V0, QFMT_VFS_V1, MAXQUOTAS, clear_quota_wait_hooks, dquot_alloc_inode, dquot_charge_usage, dquot_drop, dquot_drop_type, dquot_free_inode, dquot_initialize, dquot_release_usage, dquot_transfer, dquot_transfer_inode, dquot_transfer_owner, dqget, dqput, inode_dquot, quota_check_quotactl_permission, quota_disable_limits, quota_enable_limits, quota_getfmt, quota_getinfo, quota_getnextquota, quota_getquota, quota_off, quota_on, quota_setinfo, quota_setquota, quota_setquota_masked, quota_shutdown, quota_suspend_sysfiles, quota_sync, quota_sync_all, quota_sysfile_active, set_quota_wait_hooks};

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_d4b;
#[cfg(test)]
mod tests_dircontext;

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
