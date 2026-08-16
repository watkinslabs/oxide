// Object labelling: how a mount decides where its inodes' labels come from,
// what label one inode carries, and what a relabel costs.
//
// Everything here is a function over values — a policy, a filesystem type
// name, a written context, a mode. It holds no inode, no superblock and no
// task, because the objects those describe are owned elsewhere and a copy
// here could disagree with the owner's. The kernel glue reads the object's
// state, calls in, and stores the answer back on the object.
//
// Module manifest:
//   sb      — the per-mount decision: which behaviour, which default label
//   resolve — the per-inode decision: existing label, and a new object's
//   relabel — the three-permission ladder a `security.selinux` write costs
//   xattr   — what a `security.*` attribute operation is allowed to demand
//   perm    — the access-vector one ordinary permission check asks for

pub mod sb;
pub mod resolve;
pub mod relabel;
pub mod xattr;
pub mod perm;

pub use sb::{MountOptions, SuperblockSecurity, sb_plan, superblock_security, SbPlan};
pub use resolve::{LabelPlan, NewInodePlan, existing_inode_plan, existing_inode_sid,
                  genfs_context, new_inode_plan, new_inode_sid};
pub use relabel::{Check, RelabelRequest, relabel_checks, relabel_decision,
                  PERM_ASSOCIATE, PERM_RELABELFROM, PERM_RELABELTO};
pub use xattr::{XattrGate, XattrOp, selinux_xattr_gate};
pub use perm::inode_permission_av;

#[cfg(test)]
#[path = "tests/inode.rs"]
mod tests;
