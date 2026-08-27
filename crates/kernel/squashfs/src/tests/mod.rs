//! Manifest for the volume-level tests: mounting a fixture built by
//! [`crate::test_image`] and driving the real [`crate::volume::Volume`]
//! against it, end to end.
//!
//! - `mount`:    superblock/geometry refusals surfaced through `mount_with`.
//! - `lookup`:   name resolution, sorted-listing early exit, `ENOENT`.
//! - `readfile`: whole/partial/sparse reads, and symlink targets.
//! - `vfs_adapter`: the VFS-facing mount, its root inode and its operations.

mod lookup;
mod mount;
mod readfile;
mod vfs_adapter;
