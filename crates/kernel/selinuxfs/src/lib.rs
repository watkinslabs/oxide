// The mandatory-access-control filesystem interface (`docs/62§8`).
//
// `/sys/fs/selinux` is what userspace uses to load a policy, read the
// enforcement state and ask the policy questions. A distribution's early
// userspace probes several of these nodes before it does anything else, so
// the node set and the exact byte formats decide whether a boot works.
//
// The decision engine lives in `selinux` and the one live server in
// `selinux-runtime`; nothing here keeps a second copy of policy state. The
// only bytes this crate owns are the policy image itself, which the engine
// does not retain and the `policy` node must hand back verbatim.
//
// Module manifest:
//   ops         — the policy operations the node handlers act through
//   server      — those operations over the live security server
//   subject     — the SID a write to this filesystem is checked against
//   format      — every read/write byte format, as pure functions
//   nodes       — one module per node group: handlers plus their inodes
//   notify      — what a write announces to the userspace AVC, and when
//   root        — the node tree, its population and its per-load rebuild
//   fs_impl     — the mountable filesystem

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod ops;
pub mod server;
pub mod subject;
pub mod format;
pub mod nodes;
pub mod notify;
pub mod root;
pub mod fs_impl;

pub use fs_impl::SelinuxFs;
pub use ops::PolicyOps;
pub use root::{selinux_root, SELINUXFS_FSID};

/// `SELINUX_MAGIC` — the `statfs` `f_type` of `/sys/fs/selinux`.
///
/// Shares its value with the policy image's leading magic word: userspace
/// identifies the mount by this number, and a different one makes every
/// `statfs`-based probe conclude the interface is absent.
pub const SELINUX_MAGIC: u64 = 0xf97c_ff8c;

/// Build the node tree. # C: O(nodes)
///
/// Idempotent, and also reached lazily the first time the mount root is
/// asked for, so a boot path that has not called it still presents a
/// populated filesystem rather than an empty directory.
pub fn init() { root::populate(); }

/// The stand-in policy the handler tests drive.
#[cfg(test)]
#[path = "tests/fake.rs"]
pub mod fake;
