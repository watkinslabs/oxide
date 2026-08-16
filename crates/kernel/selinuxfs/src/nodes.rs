// The nodes of `/sys/fs/selinux`, one module per group.
//
// Each module holds the group's HANDLERS — pure functions over
// `&mut dyn PolicyOps` — and the inode construction that hangs them off the
// tree. The handler is the part a test drives; the construction is plumbing
// with no decision in it.
//
// Module manifest:
//   plumb       — the inode shape every node is built from
//   enforce     — the enforcement-mode control
//   load        — the policy-load node and the image it hands back
//   booleans    — per-boolean values and the commit node
//   classes     — the loaded policy's classes and permissions
//   caps        — the loaded policy's capability bits
//   initcon     — the contexts of the initial SIDs
//   stats       — decision-cache and SID-table statistics
//   transaction — the write-then-read-back query nodes
//   misc        — version, MLS, unknown-class disposition, compatibility
//                 nodes, `validatetrans`, and the null device

pub mod plumb;
pub mod enforce;
pub mod load;
pub mod booleans;
pub mod classes;
pub mod caps;
pub mod initcon;
pub mod stats;
pub mod transaction;
pub mod misc;
