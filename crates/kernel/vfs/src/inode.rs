// Module manifest: `model` owns the concrete inode types/state, `metadata`
// owns field accessors and mutators, `rwsem` owns sleeping exclusion,
// `locking` owns `i_rwsem` helpers,
// `ops` owns the `i_op`/`i_fop` delegators, `builder` owns construction, and
// `helpers`/`flags` own shared utility routines and ABI constants.

mod builder;
mod flags;
mod helpers;
mod locking;
mod metadata;
mod model;
mod ops;
mod rwsem;

pub use builder::InodeBuilder;
pub use flags::{
    FIEMAP_EXTENT_DATA_ENCRYPTED, FIEMAP_EXTENT_DATA_INLINE, FIEMAP_EXTENT_DELALLOC,
    FIEMAP_EXTENT_ENCODED, FIEMAP_EXTENT_LAST, FIEMAP_EXTENT_MERGED, FIEMAP_EXTENT_NOT_ALIGNED,
    FIEMAP_EXTENT_SHARED, FIEMAP_EXTENT_UNKNOWN, FIEMAP_EXTENT_UNWRITTEN, FS_APPEND_FL,
    FS_CASEFOLD_FL,
    FS_COMPR_FL, FS_COMMON_FL, FS_DAX_FL, FS_IMMUTABLE_FL, FS_NODUMP_FL, FS_NOATIME_FL,
    FS_PROJINHERIT_FL, FS_SECRM_FL, FS_SYNC_FL, FS_VERITY_FL,
    FS_UNRM_FL, I_CLEAR, I_DIRTY, I_DIRTY_DATASYNC, I_DIRTY_PAGES, I_DIRTY_SYNC, I_FREEING,
    I_LINKABLE, I_NEW, I_VERSION_INCREMENT, I_VERSION_QUERIED, I_VERSION_QUERIED_SHIFT, I_WILL_FREE,
    FS_XFLAG_APPEND, FS_XFLAG_COMMON, FS_XFLAG_COWEXTSIZE, FS_XFLAG_DAX, FS_XFLAG_EXTSIZE,
    FS_XFLAG_EXTSZINHERIT, FS_XFLAG_IMMUTABLE, FS_XFLAG_NOATIME, FS_XFLAG_NODUMP,
    FS_XFLAG_CASEFOLD, FS_XFLAG_PROJINHERIT, FS_XFLAG_RTINHERIT, FS_XFLAG_SYNC, FS_XFLAG_VERITY,
    POLL_ERR, POLL_HUP, POLL_IN, POLL_OUT, POLL_PRI, POLL_RDNORM, POLL_RDHUP, S_APPEND, S_ATIME, S_CASEFOLD,
    S_CTIME, S_DAX, S_DEAD, S_DIRSYNC, S_ENCRYPTED, S_IMMUTABLE, S_MTIME, S_NOATIME, S_SYNC,
    S_VERITY, S_VERSION,
};
pub use helpers::{
    generic_update_time, get_next_ino, inode_inc_iversion, inode_init_owner,
    inode_init_owner_idmap, inode_maybe_inc_iversion, inode_owner_or_capable,
    inode_peek_iversion_raw, inode_query_iversion, inode_set_iversion_raw,
    is_append, is_immutable, is_noatime, is_sync, prepare_create_owner_mode,
    prepare_symlink_owner,
};
pub(crate) use helpers::no_data_op_errno;
pub use locking::{RenameLockGuard, inode_unlock, lock_rename, unlock_rename};
pub use model::{FileAttr, FiemapExtent, Inode, InodeRef, OwnerPersist, SealCarrier};
pub use rwsem::{clear_inode_rwsem_wait_hooks, set_inode_rwsem_wait_hooks};
