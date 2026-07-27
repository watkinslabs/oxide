// Module manifest for Linux `inode->i_flctx` (`fs/locks.c`): `context` owns
// the per-inode BSD-flock + byte-range-record state and its wait key,
// `records` owns the byte-range algebra (conflict rule, split/merge),
// `deadlock` owns the global blocked-owner graph `posix_locks_deadlock` walks.

mod context;
mod deadlock;
mod records;
#[cfg(test)]
mod tests;

pub use context::{FileLockContext, FlockKind, FlockTry};
pub use deadlock::{block_on as record_lock_block_on, unblock as record_lock_unblock};
pub use records::{
    F_RDLCK, F_UNLCK, F_WRLCK, RECORD_END_MAX, RecordLock, RecordOwner, RecordTry,
};
