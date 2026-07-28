// NUMA memory policy (`mm/mempolicy.c`, `include/uapi/linux/mempolicy.h`).
//
// Module manifest:
//   uapi     MPOL_* / MPOL_F_* / MPOL_MF_* numbers, MAX_NUMNODES, nr_node_ids
//   nodemask NodeMask + the get_nodes / copy_nodes_to_user bit conventions
//   policy   struct mempolicy, sanitize_mpol_flags, mpol_new
//   query    do_get_mempolicy's four reporting behaviours
//   scan     queue_pages_range (mbind's hole/EFAULT + STRICT/EIO scan)
//   args     per-syscall argument ladders in Linux's order
//
// None of it is target-gated: the syscall slots are
// `#![cfg(target_os = "oxide-kernel")]`, so any test written inside them
// silently compiles out.
//
// Scope note (honest, not a hedge): oxide's PMM is single-node UMA
// (`uapi::NR_NODE_IDS == 1`). Policy STORAGE, validation, inheritance and
// reporting are complete Linux semantics; page MIGRATION is trivially
// satisfied because the only legal destination node is the one every page
// already occupies. `mpol_set_nodemask`'s intersection with the nodes that
// have memory is what makes that true rather than assumed — a policy naming
// only node 1 is rejected with EINVAL, exactly as Linux rejects it on a
// one-node machine.

pub mod args;
pub mod nodemask;
pub mod policy;
pub mod query;
pub mod scan;
pub mod uapi;

#[cfg(test)]
mod tests;

pub use nodemask::{copy_nodes_to_user_plan, get_nodes, nodes_with_memory, NodeMask, NodemaskOut};
pub use policy::{mpol_equal, mpol_new, sanitize_mpol_flags, MemPolicy};
pub use query::{get_mempolicy_kind, report_policy, GetPolicyKind, PolicyReport};
pub use scan::{queue_pages_range, vma_migratable, MPOL_MF_DISCONTIG_OK, MPOL_MF_INVERT};
