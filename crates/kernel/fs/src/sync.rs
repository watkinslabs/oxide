// `fs/sync.c` work-fns. Module manifest.
//
//   fsync.rs — `vfs_fsync` (fsync(2)/fdatasync(2)): whole-file flush + metadata.
//   range.rs — `sync_file_range` (slot 277): the flag/offset ladder and the
//              DATA-ONLY range writeback. Deliberately does NOT commit metadata
//              (Linux `fs/sync.c:341-346`), so it is not an fsync.

mod fsync;
mod range;

pub use fsync::vfs_fsync;
pub use range::{sync_file_range, SyncRange, SYNC_FILE_RANGE_VALID_FLAGS,
    SYNC_FILE_RANGE_WAIT_AFTER, SYNC_FILE_RANGE_WAIT_BEFORE, SYNC_FILE_RANGE_WRITE};
