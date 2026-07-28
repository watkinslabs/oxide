// `do_get_mempolicy` (`mm/mempolicy.c:1147`) split into the part that only
// needs the flags (validation, which decides WHICH lookup the slot must do)
// and the part that turns a resolved policy into the two output values.
//
// Four distinct behaviours, all reachable from libnuma:
//   MPOL_F_MEMS_ALLOWED              → mode 0, nodemask = cpuset mems_allowed
//   MPOL_F_ADDR                      → the VMA's policy at `addr`
//   MPOL_F_ADDR | MPOL_F_NODE        → the NODE the page at `addr` lives on
//   MPOL_F_NODE (no ADDR)            → next interleave node; EINVAL otherwise

use super::nodemask::{nodes_with_memory, NodeMask};
use super::policy::MemPolicy;
use super::uapi::*;
use crate::Error;

/// Which lookup `do_get_mempolicy` needs after flag validation.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum GetPolicyKind {
    /// `MPOL_F_MEMS_ALLOWED`: no policy lookup at all.
    MemsAllowed,
    /// `MPOL_F_ADDR`: the VMA policy at `addr` (NOT the task policy — Linux
    /// deliberately reports MPOL_DEFAULT for a VMA with no policy).
    VmaPolicy { node: bool },
    /// No `MPOL_F_ADDR`: the calling thread's own policy.
    TaskPolicy { node: bool },
}

/// `do_get_mempolicy`'s flag ladder (`mm/mempolicy.c:1152..1174`).
/// `addr` matters: without `MPOL_F_ADDR` a non-zero `addr` is `EINVAL`.
/// # C: O(1)
pub fn get_mempolicy_kind(flags: u64, addr: u64) -> Result<GetPolicyKind, Error> {
    if flags & !MPOL_F_GET_VALID != 0 { return Err(Error::Inval); }
    if flags & MPOL_F_MEMS_ALLOWED != 0 {
        if flags & (MPOL_F_NODE | MPOL_F_ADDR) != 0 { return Err(Error::Inval); }
        return Ok(GetPolicyKind::MemsAllowed);
    }
    let node = flags & MPOL_F_NODE != 0;
    if flags & MPOL_F_ADDR != 0 { return Ok(GetPolicyKind::VmaPolicy { node }); }
    if addr != 0 { return Err(Error::Inval); }
    Ok(GetPolicyKind::TaskPolicy { node })
}

/// `current->il_prev` right after `do_set_mempolicy` installs an interleave
/// policy (`mm/mempolicy.c:1095`). oxide's allocator is single-node, so the
/// interleave cursor is never advanced past its seed — `next_node_in` from
/// here is the only value `get_mempolicy(MPOL_F_NODE)` can observe.
pub const IL_PREV_INIT: u16 = (MAX_NUMNODES - 1) as u16;

/// `next_node_in(n, mask)`: first node after `n` in `mask`, wrapping.
/// # C: O(MAX_NUMNODES)
pub fn next_node_in(n: u16, mask: NodeMask) -> u16 {
    if mask.is_empty() { return MAX_NUMNODES as u16; }
    for step in 1..=MAX_NUMNODES {
        let cand = ((n as u64 + step) % MAX_NUMNODES) as u16;
        if mask.is_set(cand) { return cand; }
    }
    MAX_NUMNODES as u16
}

/// The pair `do_get_mempolicy` writes back.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PolicyReport {
    /// `*policy` — the mode word, or a node id under `MPOL_F_NODE`.
    pub policy: i32,
    /// `*nmask`.
    pub nodes: NodeMask,
}

/// Resolve a looked-up policy into the reported pair.
///
/// `pol` is `None` for Linux's `&default_policy` (no policy installed).
/// `node_at_addr` is the `lookup_node()` result, required only for
/// `VmaPolicy { node: true }`; the slot supplies it because it needs the page
/// table.
/// # C: O(MAX_NUMNODES) worst case
pub fn report_policy(kind: GetPolicyKind, pol: Option<MemPolicy>,
                     node_at_addr: Option<u16>) -> Result<PolicyReport, Error> {
    if kind == GetPolicyKind::MemsAllowed {
        // `*policy = 0` "just so it's initialized"; the mask is the cpuset's.
        return Ok(PolicyReport { policy: 0, nodes: nodes_with_memory() });
    }
    let want_node = match kind {
        GetPolicyKind::VmaPolicy { node } | GetPolicyKind::TaskPolicy { node } => node,
        GetPolicyKind::MemsAllowed => false,
    };
    let policy = if want_node {
        match kind {
            GetPolicyKind::VmaPolicy { .. } => node_at_addr.ok_or(Error::Fault)? as i32,
            // Without MPOL_F_ADDR, `pol` IS `current->mempolicy`, so the
            // `pol == current->mempolicy` guard reduces to "a policy exists".
            GetPolicyKind::TaskPolicy { .. } => match pol {
                Some(p) if p.mode == MPOL_INTERLEAVE || p.mode == MPOL_WEIGHTED_INTERLEAVE =>
                    next_node_in(IL_PREV_INIT, p.nodes) as i32,
                // Includes the no-policy case: `&default_policy` is not
                // `current->mempolicy`, so Linux falls through to EINVAL.
                _ => return Err(Error::Inval),
            },
            GetPolicyKind::MemsAllowed => unreachable!(),
        }
    } else {
        match pol { Some(p) => p.reported_mode(), None => MPOL_DEFAULT as i32 }
    };
    let nodes = match pol { Some(p) => p.reported_nodes(), None => NodeMask::EMPTY };
    Ok(PolicyReport { policy, nodes })
}
