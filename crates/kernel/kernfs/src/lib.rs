//! Generic pseudo-filesystem tree (Linux `fs/kernfs` shape). `PseudoDir`
//! is a real per-component `vfs::Inode`: its `children` BTreeMap IS the
//! directory and resolution is per-component `i_op->lookup`, never a
//! whole-path key. Lifted from devfs's `DevDir` (D1) and given a `Weak<
//! SuperBlock>` (`i_sb`, the tmpfs `TmpfsDir` precedent) so each pseudo-fs
//! (devfs/sysfs/procfs/tracefs/devpts) can OWN its own tree under its
//! SuperBlock instead of a shared global path registry (D1b).
//!
//! `readdir` enumerates its (sorted) BTreeMap children only. D19 removed the
//! last ext4-overlay user (`/etc`); `/dev` lost its overlay at D17. The
//! synthetic dirs no longer merge on-disk rootfs entries — the rootfs ext4
//! mount serves `/etc` (and any other real dir) directly.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[cfg(any(test, feature = "hosted"))]
extern crate std;

mod dir_ops;
mod fs;
mod tree;

pub use fs::{PseudoFs, PSEUDO_ROOT_INO};
pub use tree::{PseudoDir, PseudoSymlink, dir_ino};

#[cfg(test)]
mod tests;
