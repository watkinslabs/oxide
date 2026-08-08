// `fsync(2)` / `fdatasync(2)` work-fns: whole-file and byte-range durability.
// The syscall shim owns only fd resolution.
//
// The mechanism lives on `vfs::File` ([`vfs::File::vfs_fsync_range`]) because
// `generic_write_sync` — the `O_SYNC`/`O_DSYNC` write tail — has to call the
// same code from inside `vfs`'s own write paths, and a durability primitive
// must have exactly one implementation. These are the errno-encoding shims the
// syscall slots call.

use vfs::File;

/// Flush the whole file's data (and metadata unless `datasync`).
///
/// Ordering, which is the entire point, is documented on
/// [`vfs::File::vfs_fsync_range`]: page-cache writeback FIRST, then the
/// backend's journal commit + device barrier, then the deferred-error harvest.
/// The previous implementation ran the backend commit first and the writeback
/// after, so the transaction it made durable did not yet contain the data or
/// the extents describing it — `fsync(2)` returned 0 having fenced nothing.
///
/// A description whose `f_op` has no `fsync` slot is `EINVAL` — pipes, FIFOs,
/// sockets, character devices, and the anon-inode fds (eventfd / epoll /
/// timerfd / signalfd / inotify), exactly as on Linux.
///
/// Returns 0 or `-errno`. # C: O(N_dirty)
pub fn vfs_fsync(file: &File, datasync: bool) -> i64 {
    match file.vfs_fsync(datasync) {
        Ok(()) => 0,
        Err(e) => -(e as i64),
    }
}

/// Byte-range durability form behind the `O_SYNC`/`O_DSYNC` write tail and
/// `msync(MS_SYNC)`. `end_incl` is INCLUSIVE. Returns 0 or `-errno`.
/// # C: O(N_dirty in range)
pub fn vfs_fsync_range(file: &File, start: u64, end_incl: u64, datasync: bool) -> i64 {
    match file.vfs_fsync_range(start, end_incl, datasync) {
        Ok(()) => 0,
        Err(e) => -(e as i64),
    }
}
