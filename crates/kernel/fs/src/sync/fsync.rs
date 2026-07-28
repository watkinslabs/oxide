// `fsync(2)` / `fdatasync(2)` work-fn — Linux `fs/sync.c` (`do_fsync` →
// `vfs_fsync` → `vfs_fsync_range` → `f_op->fsync`). The syscall shim owns only
// fd resolution.

use syscall::errno::Errno;
use vfs::File;

/// `vfs_fsync_range` (Linux `fs/sync.c`): dispatch to the description's
/// `f_op->fsync`, then push the file's dirty page-cache and commit the owning
/// filesystem's metadata so the data is on the backing store when this returns.
///
/// A description whose `f_op` has no `fsync` slot is `EINVAL` — pipes, FIFOs,
/// sockets, and the anon-inode fds (eventfd / epoll / timerfd / signalfd /
/// inotify) all land here, exactly as on Linux. That gate is the trait default
/// in [`vfs::FileOps::fsync`], so a backend states its own answer rather than
/// this function keeping a list.
///
/// The metadata half belongs to the BACKEND'S `f_op->fsync`, NOT to
/// `super_operations->sync_fs`: `sync_fs` is the whole-filesystem pass behind
/// `sync(2)`/`syncfs(2)` (for ext4 it flushes every dirty page on the mount and
/// issues a device flush), whereas `fsync(2)` must commit only the journal
/// transaction carrying THIS inode — Linux `ext4_sync_file`. Calling `sync_fs`
/// here would silently promote every `fsync` to a `syncfs`, which is both wrong
/// and, on a boot that fsyncs constantly, ruinously slow.
///
/// `datasync` is passed to the backend; ext4's journal commit is the same
/// operation either way once the inode has pending metadata, so `fdatasync`
/// differs only in what a backend chooses to skip. # C: O(N_dirty)
pub fn vfs_fsync(file: &File, datasync: bool) -> i64 {
    if let Err(e) = file.f_op().fsync(file, datasync) { return -(e as i64); }
    if let Some(mapping) = file.inode().i_mapping() {
        if mapping.writeback().is_err() { return -(Errno::Eio.as_i32() as i64); }
    }
    0
}
