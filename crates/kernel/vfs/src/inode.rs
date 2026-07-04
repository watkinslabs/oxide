// Module manifest: `model` owns the concrete inode types/state, `metadata`
// owns field accessors and mutators, `locking` owns `i_rwsem` helpers,
// `ops` owns the `i_op`/`i_fop` delegators, `builder` owns construction, and
// `helpers`/`flags` own shared utility routines and ABI constants.

mod builder;
mod flags;
mod helpers;
mod locking;
mod metadata;
mod model;
mod ops;

pub use builder::InodeBuilder;
pub use flags::{
    FIEMAP_EXTENT_DATA_ENCRYPTED, FIEMAP_EXTENT_DATA_INLINE, FIEMAP_EXTENT_DELALLOC,
    FIEMAP_EXTENT_ENCODED, FIEMAP_EXTENT_LAST, FIEMAP_EXTENT_MERGED, FIEMAP_EXTENT_NOT_ALIGNED,
    FIEMAP_EXTENT_SHARED, FIEMAP_EXTENT_UNKNOWN, FIEMAP_EXTENT_UNWRITTEN, FS_APPEND_FL,
    FS_COMPR_FL, FS_IMMUTABLE_FL, FS_NODUMP_FL, FS_NOATIME_FL, FS_SECRM_FL, FS_SYNC_FL,
    FS_UNRM_FL, I_CLEAR, I_DIRTY, I_DIRTY_DATASYNC, I_DIRTY_PAGES, I_DIRTY_SYNC, I_FREEING,
    I_NEW, I_VERSION_INCREMENT, I_VERSION_QUERIED, I_VERSION_QUERIED_SHIFT, I_WILL_FREE,
    POLL_ERR, POLL_HUP, POLL_IN, POLL_OUT, POLL_PRI, POLL_RDHUP, S_APPEND, S_ATIME, S_CASEFOLD,
    S_CTIME, S_DAX, S_DEAD, S_DIRSYNC, S_ENCRYPTED, S_IMMUTABLE, S_MTIME, S_NOATIME, S_SYNC,
    S_VERITY, S_VERSION,
};
pub use helpers::{
    generic_update_time, get_next_ino, inode_inc_iversion, inode_init_owner,
    inode_maybe_inc_iversion, inode_owner_or_capable, inode_peek_iversion_raw,
    inode_query_iversion, inode_set_iversion_raw, is_append, is_immutable, is_noatime, is_sync,
};
pub(crate) use helpers::no_data_op_errno;
pub use locking::{RenameLockGuard, inode_unlock, lock_rename, unlock_rename};
pub use model::{FileAttr, FiemapExtent, Inode, InodeRef, SealCarrier};
