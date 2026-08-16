// NUMA / memory-policy keying for futex2 (`FUTEX2_NUMA`, `FUTEX2_MPOL`).
//
// The node a futex is keyed on is resolved by a fixed ladder: the caller's
// node-id word, then the mapping's memory policy, then the node the caller is
// running on. Every step here is a pure decision so the ladder — and the
// write-back that publishes the resolved node to userspace — is hosted-tested;
// the user-memory reads and writes it implies live in `live::futex::numa`,
// which is kernel-gated and holds no policy of its own.
//
// What node keying MEANS on this machine: the PMM is single-node UMA
// (`NR_NODE_IDS == 1`), so the resolved node selects among exactly one queue
// and therefore never separates two futexes that would otherwise match. What
// remains user-visible, and is implemented in full: the doubled operand and
// its natural-alignment requirement, `EFAULT` on an inaccessible node word,
// `EINVAL` on a node id this machine does not have, the memory-policy
// derivation, and the write-back of the resolved node id. Those are the same
// observable answers a single-node reference machine gives.

use vmm::mempolicy::uapi::{MAX_NUMNODES, MPOL_BIND, MPOL_PREFERRED, MPOL_PREFERRED_MANY,
                           NODE_ID_LOCAL, NR_NODE_IDS, NUMA_NO_NODE};
use vmm::mempolicy::MemPolicy;

/// `FUTEX_NO_NODE` — the node-id word value meaning "no preference". Distinct
/// ABI from the mempolicy sentinel even though the two share a value; a test
/// pins that they agree.
pub const FUTEX_NO_NODE: i32 = -1;

/// The node this kernel's CPUs run on. Single-node UMA, so every CPU is on
/// node `NODE_ID_LOCAL` and `numa_node_id()` is a constant.
/// # C: O(1)
pub const fn current_node_id() -> i32 { NODE_ID_LOCAL as i32 }

/// `node_possible()` — whether `node` is a node this machine has.
/// # C: O(1)
pub const fn node_possible(node: i32) -> bool {
    node >= 0 && (node as u64) < NR_NODE_IDS
}

/// Byte offset of the node-id word from the futex word: it sits immediately
/// after it, so at half the doubled operand.
/// # C: O(1)
pub const fn node_word_addr(uaddr: u64, access_bytes: u32) -> u64 {
    uaddr + (access_bytes / 2) as u64
}

/// Natural alignment of the futex operand. A `FUTEX2_NUMA` 32-bit futex
/// therefore needs 8-byte alignment, not 4 — the pair is accessed as one
/// operand and a straddling pair would tear across a page boundary.
/// # C: O(1)
pub const fn addr_aligned(uaddr: u64, access_bytes: u32) -> bool {
    uaddr % access_bytes as u64 == 0
}

/// Node a mapping's memory policy prefers, or `FUTEX_NO_NODE` when it
/// expresses none. `MPOL_PREFERRED` names its node directly; the mask-valued
/// modes only express a node through an explicit home node. Every other mode
/// (interleave, local, default) is a distribution rather than a preference and
/// yields no node.
/// # C: O(1)
pub fn mpol_node(pol: Option<MemPolicy>) -> i32 {
    let Some(p) = pol else { return FUTEX_NO_NODE };
    match p.mode {
        MPOL_PREFERRED => {
            let first = p.nodes.first();
            // An empty `MPOL_PREFERRED` mask is not constructible — `mpol_new`
            // folds that case to `MPOL_LOCAL` — and `first()` reports
            // `MAX_NUMNODES` for it, which is no node.
            if (first as u64) < MAX_NUMNODES { first as i32 } else { FUTEX_NO_NODE }
        }
        MPOL_PREFERRED_MANY | MPOL_BIND => {
            if p.home_node != NUMA_NO_NODE { p.home_node } else { FUTEX_NO_NODE }
        }
        _ => FUTEX_NO_NODE,
    }
}

/// Outcome of the node ladder.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NodeOutcome {
    /// Node the futex is keyed on; `FUTEX_NO_NODE` when nothing selected one.
    pub node: i32,
    /// Node id to publish back into the caller's node-id word. `Some` only
    /// when the kernel resolved a node the caller had not written there —
    /// the caller learns which node its futex landed on.
    pub write_back: Option<i32>,
}

/// Node ladder rejection. Maps to `EINVAL`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NodeReject {
    /// The caller's node-id word named a node this machine does not have.
    NoSuchNode,
}

/// Resolve the node a futex is keyed on.
///
/// * `user_node` — the node-id word, present exactly when `FUTEX2_NUMA` is
///   set (the caller performs the read; this decides what it means).
/// * `policy_node` — [`mpol_node`] of the mapping's policy, consulted only
///   when `FUTEX2_MPOL` is set and the caller expressed no preference.
///
/// Rejection outranks both later steps: a node id this machine does not have
/// is `EINVAL` even when the memory policy would have supplied one, because
/// the caller asked for a specific node and cannot silently be given another.
/// # C: O(1)
pub fn resolve_node(numa: bool, mpol: bool, user_node: Option<i32>, policy_node: i32)
    -> Result<NodeOutcome, NodeReject>
{
    let mut node = FUTEX_NO_NODE;
    if numa {
        node = user_node.unwrap_or(FUTEX_NO_NODE);
        if node != FUTEX_NO_NODE && ((node as u32 as u64) >= MAX_NUMNODES || !node_possible(node)) {
            return Err(NodeReject::NoSuchNode);
        }
    }
    let mut updated = false;
    if node == FUTEX_NO_NODE && mpol {
        node = policy_node;
        updated = true;
    }
    let mut write_back = None;
    if numa {
        if node == FUTEX_NO_NODE {
            node = current_node_id();
            updated = true;
        }
        if updated { write_back = Some(node); }
    }
    Ok(NodeOutcome { node, write_back })
}

#[cfg(test)]
#[path = "futex_numa/tests.rs"]
mod tests;
