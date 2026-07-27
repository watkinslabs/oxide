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
/// The metadata half goes through the OWNING superblock's `sync_fs` (Linux
/// `super_operations->sync_fs`, which for ext4 drains the running journal
/// transaction). Reaching it through `i_sb` — not through a rootfs-only
/// helper — is what makes `fsync` durable for files on a non-root mount.
/// `datasync` is passed to the backend; ext4's journal commit is the same
/// operation either way once the inode has pending metadata, so `fdatasync`
/// differs only in what a backend chooses to skip. # C: O(N_dirty)
pub fn vfs_fsync(file: &File, datasync: bool) -> i64 {
    if let Err(e) = file.f_op().fsync(file, datasync) { return -(e as i64); }
    if let Some(mapping) = file.inode().i_mapping() {
        if mapping.writeback().is_err() { return -(Errno::Eio.as_i32() as i64); }
    }
    if let Some(sb) = file.inode().i_sb() {
        if sb.sync_fs(true).is_err() { return -(Errno::Eio.as_i32() as i64); }
    }
    0
}
