//! `/proc/fs` — the directory a filesystem publishes its own `/proc` files in.
//!
//! Upstream `/proc/fs` is made by the procfs boot path itself, beside
//! `/proc/driver` and `/proc/bus`, and filesystems then `proc_mkdir("fs/<name>")`
//! under it: `fs/f2fs`, `fs/xfs`, `fs/jfs`, `fs/nfs`, `fs/nfsd`, `fs/cifs`,
//! `fs/ksmbd`, `fs/lockd`, `fs/netfs`, `fs/ntfs3`. A filesystem with per-mount
//! files then makes one directory per mount under its own.
//!
//! This is not `/proc/sys/fs`, which is the sysctl tree and unrelated.
//!
//! What routing every filesystem through one module buys is the same pair as
//! the sysfs side: a name is CLAIMED, so two filesystems cannot write into one
//! directory and an unclaimed name cannot receive files; and registration is
//! SYMMETRIC, so an unmount withdraws exactly the subtree its mount published.
//!
//! Files here are seq files: the body is produced by the filesystem's own
//! renderer, once per open, and every partial read is served from that one
//! result — a paginated read of a segment table must not see the table change
//! under it between pages.
//!
//! Module manifest:
//! - `file`: the seq-file inode built from a filesystem's renderer.
//! - `tree`: the `/proc/fs` directory itself, and claim/publish/withdraw.

pub mod file;
mod tree;

#[cfg(test)]
mod tests;

pub use file::{ShowFn, StoreFn};
pub use tree::{claim, is_claimed, fs_names, names_in, proc_fs_root, proc_fs_inode, publish_dir,
               publish_file, release, withdraw};
