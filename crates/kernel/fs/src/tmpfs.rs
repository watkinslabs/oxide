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

mod accounting;
mod dir;
mod file;
mod flags;
mod fs;
mod inode;
mod limits;
mod mount_opts;
mod migration;
mod reclaim;
mod special;
mod symlink;
mod uapi;

#[cfg(test)]
mod tests;

pub use accounting::TmpfsSb;
pub use file::{tmpfs_anon_file, tmpfs_sealable_file, TmpfsFileData};
pub use flags::{F_SEAL_FUTURE_WRITE, F_SEAL_GROW, F_SEAL_SEAL, F_SEAL_SHRINK, F_SEAL_WRITE};
pub use fs::{init, smoke_test, TmpfsFs, TmpfsSuperOps};
