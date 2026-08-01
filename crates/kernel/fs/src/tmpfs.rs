// Minimal in-memory filesystem per docs/16. v1 stand-in for a
// real tmpfs:
//   - flat path -> TmpfsFileInode map (no directory structure)
//   - each inode wraps a `Spinlock<Vec<u8>>` body
//   - read/write extend the body; truncate on first write per
//     O_TRUNC behaviour (O_TRUNC handling rides VFS open-flag
//     work)
//   - `open(path, O_CREAT)` lazily registers an empty file
//
// `/tmp/*` paths fall through to this when not found in devfs/
// procfs. v1 uses a global registry; per-mount-tree isolation
// rides the multi-mount work in docs/16.
//
// Module manifest:
// - `limits`: tmpfs sizing, root inode, and inode allocation bounds.
// - `uapi`: tmpfs Linux magic/fallback fsid values.
// - `flags`: memfd seal bits and mode-type masks.
// - `inode`: shared inode-cache and fsid helpers.
// - `accounting`: per-instance tmpfs block/inode accounting.
// - `file`: regular file/memfd data, file ops, and address-space ops.
// - `symlink`: symlink body and inode builder.
// - `special`: socket/FIFO/device special inode builders.
// - `dir`: directory tree state and namespace inode ops.
// - `fs`: mounted tmpfs filesystem and superblock ops.
// - `params`: the tmpfs/ramfs mount-parameter tables mount options are admitted against.
// - `fileattr`: `chattr` flag word (`i_op->fileattr_{get,set}`, Linux shmem).

mod accounting;
mod dir;
mod falloc;
mod file;
mod fileattr;
mod flags;
mod fs;
mod inode;
mod lifetime;
mod limits;
mod mount_opts;
mod migration;
mod params;
mod reclaim;
mod special;
mod symlink;
mod uapi;

#[cfg(test)]
mod tests;

/// `stx_btime` for a newly created tmpfs inode. Linux `shmem_get_inode` sets
/// `info->i_crtime` from the inode's mtime at creation and `shmem_getattr`
/// reports `STATX_BTIME` unconditionally, so `stat -c %w` on a tmpfs file
/// answers with a real birth time. Without it every /tmp, /run and /dev/shm
/// file reported no creation time at all. # C: O(1)
pub(crate) fn birth_time() -> vfs::Timespec64 {
    let ns = vfs::inode_times::realtime_now_ns();
    vfs::Timespec64 { sec: (ns / 1_000_000_000) as i64, nsec: (ns % 1_000_000_000) as u32 }
}

pub use accounting::TmpfsSb;
pub use params::{RAMFS_PARAMS, TMPFS_PARAMS};
pub use uapi::RAMFS_MAGIC;
pub use file::{tmpfs_anon_file, tmpfs_sealable_file, TmpfsFileData};
pub use flags::{F_SEAL_EXEC, F_SEAL_FUTURE_WRITE, F_SEAL_GROW, F_SEAL_SEAL, F_SEAL_SHRINK, F_SEAL_WRITE};
pub use fs::{init, smoke_test, TmpfsFs, TmpfsSuperOps};
