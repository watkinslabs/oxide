// `fs/sync.c` work-fns. Module manifest.
//
//   fsync.rs — `vfs_fsync`/`vfs_fsync_range` (fsync(2)/fdatasync(2)): errno
//              shims over `vfs::File`'s durability primitive.
//   range.rs — `sync_file_range` (slot 277): the flag/offset ladder and the
//              DATA-ONLY range writeback. Deliberately does NOT commit metadata
//              (Linux `fs/sync.c:341-346`), so it is not an fsync.
//   dirtytime.rs — the periodic sweep that bounds a `lazytime` mount's deferral.

mod fsync;
mod range;
#[cfg(target_os = "oxide-kernel")]
mod dirtytime;

pub use fsync::{vfs_fsync, vfs_fsync_range};
#[cfg(target_os = "oxide-kernel")]
pub use dirtytime::start_dirtytime_writeback;
pub use range::{sync_file_range, SyncRange, SYNC_FILE_RANGE_VALID_FLAGS,
    SYNC_FILE_RANGE_WAIT_AFTER, SYNC_FILE_RANGE_WAIT_BEFORE, SYNC_FILE_RANGE_WRITE};
