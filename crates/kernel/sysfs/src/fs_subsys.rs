//! `/sys/fs` — the directory every filesystem hangs its own sysfs surface on.
//!
//! Upstream this is one kobject (`fs_kobj`) created unconditionally while the
//! mount machinery initialises, long before any filesystem registers. A
//! filesystem then adds a kset or kobject named after itself under it
//! (`f2fs`, `ext4`, `btrfs`, `xfs`, `9p`, `ecryptfs`), and per-mount objects
//! under that. Nothing about that arrangement is specific to any one of them,
//! so it lives here rather than in a filesystem.
//!
//! Two properties are the point of routing every filesystem through one
//! module instead of raw `/sys/fs/...` path writes:
//!
//! - **A subsystem is claimed by name.** Two filesystems cannot publish the
//!   same name, and a name that was never claimed cannot receive attributes —
//!   so a typo produces an error instead of a directory nobody meant.
//! - **Registration is symmetric.** What a mount publishes it can withdraw,
//!   as one subtree, which is what an unmount needs and what a per-path write
//!   bus cannot offer.
//!
//! Module manifest:
//! - `attr`: the live attribute file — `show` on every read, `store` on write.
//! - `tree`: the `/sys/fs` directory itself, and claim/publish/withdraw.

pub mod attr;
mod tree;

#[cfg(test)]
mod tests;

pub use attr::{ShowFn, StoreFn};
pub use tree::{claim, fs_root, init, is_claimed, names_in, publish_attr, publish_dir, release,
               subsys_names, withdraw};
