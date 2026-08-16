// futex NUMA / memory-policy node ladder. Provenance for the verified
// contract: the operand doubling and its alignment, which node ids a caller
// may name, the order in which the node-id word, the memory policy and the
// running node are consulted, and exactly when the resolved node is written
// back into the caller's word.

use super::*;
use vmm::mempolicy::uapi::{MPOL_DEFAULT, MPOL_INTERLEAVE, MPOL_LOCAL};
use vmm::mempolicy::NodeMask;

fn pol(mode: u16, nodes: u64, home_node: i32) -> Option<MemPolicy> {
    Some(MemPolicy { mode, flags: 0, nodes: NodeMask(nodes), user_nodes: NodeMask::EMPTY, home_node })
}

#[test]
fn the_futex_no_node_sentinel_agrees_with_the_mempolicy_one() {
    // Two separately-specified ABIs that happen to share a value. If one ever
    // moves, the node ladder must not silently start treating a real node as
    // "no preference".
    assert_eq!(FUTEX_NO_NODE, NUMA_NO_NODE);
}

#[test]
fn only_the_nodes_this_machine_has_are_possible() {
    assert!(node_possible(0));
    assert!(!node_possible(-1));
    assert!(!node_possible(1), "single-node UMA: node 1 does not exist");
    assert!(!node_possible(MAX_NUMNODES as i32));
}

#[test]
fn the_node_word_follows_the_futex_word() {
    assert_eq!(node_word_addr(0x1000, 8), 0x1004);
    // Without NUMA there is no second word; the helper is only reached with
    // the doubled operand, and halving it must land on the futex word itself.
    assert_eq!(node_word_addr(0x1000, 4), 0x1002);
}

#[test]
fn a_numa_futex_needs_the_doubled_natural_alignment() {
    assert!(addr_aligned(0x1000, 4));
    assert!(addr_aligned(0x1004, 4));
    assert!(!addr_aligned(0x1002, 4));
    assert!(addr_aligned(0x1000, 8));
    assert!(!addr_aligned(0x1004, 8),
            "a NUMA futex at a 4-aligned address is EINVAL: the pair is one operand");
}

#[test]
fn a_preferred_policy_names_its_node() {
    assert_eq!(mpol_node(pol(MPOL_PREFERRED, 1 << 0, NUMA_NO_NODE)), 0);
}

#[test]
fn mask_valued_policies_only_name_a_node_through_the_home_node() {
    assert_eq!(mpol_node(pol(MPOL_BIND, 1 << 0, NUMA_NO_NODE)), FUTEX_NO_NODE);
    assert_eq!(mpol_node(pol(MPOL_BIND, 1 << 0, 0)), 0);
    assert_eq!(mpol_node(pol(MPOL_PREFERRED_MANY, 1 << 0, NUMA_NO_NODE)), FUTEX_NO_NODE);
    assert_eq!(mpol_node(pol(MPOL_PREFERRED_MANY, 1 << 0, 0)), 0);
}

#[test]
fn distribution_policies_and_no_policy_name_no_node() {
    assert_eq!(mpol_node(None), FUTEX_NO_NODE);
    assert_eq!(mpol_node(pol(MPOL_DEFAULT, 0, NUMA_NO_NODE)), FUTEX_NO_NODE);
    assert_eq!(mpol_node(pol(MPOL_LOCAL, 0, NUMA_NO_NODE)), FUTEX_NO_NODE);
    assert_eq!(mpol_node(pol(MPOL_INTERLEAVE, 1 << 0, NUMA_NO_NODE)), FUTEX_NO_NODE);
    // An empty PREFERRED mask is not constructible; if one were reached it
    // must read as no preference rather than as node MAX_NUMNODES.
    assert_eq!(mpol_node(pol(MPOL_PREFERRED, 0, NUMA_NO_NODE)), FUTEX_NO_NODE);
}

#[test]
fn without_numa_or_mpol_no_node_is_selected_and_nothing_is_written_back() {
    assert_eq!(resolve_node(false, false, None, FUTEX_NO_NODE),
               Ok(NodeOutcome { node: FUTEX_NO_NODE, write_back: None }));
}

#[test]
fn a_numa_caller_naming_a_real_node_keeps_it_and_is_not_written_back() {
    // The caller already knows the answer; overwriting its word would be a
    // gratuitous store into user memory that could fault a read-only mapping.
    assert_eq!(resolve_node(true, false, Some(0), FUTEX_NO_NODE),
               Ok(NodeOutcome { node: 0, write_back: None }));
}

#[test]
fn a_numa_caller_naming_a_node_this_machine_lacks_is_rejected() {
    assert_eq!(resolve_node(true, false, Some(1), FUTEX_NO_NODE), Err(NodeReject::NoSuchNode));
    assert_eq!(resolve_node(true, false, Some(MAX_NUMNODES as i32), FUTEX_NO_NODE),
               Err(NodeReject::NoSuchNode));
    // A negative value that is not the sentinel is a node id of
    // 0xffff_fffe-and-friends, not "no preference".
    assert_eq!(resolve_node(true, false, Some(-2), FUTEX_NO_NODE), Err(NodeReject::NoSuchNode));
}

#[test]
fn rejection_outranks_the_memory_policy() {
    // The caller asked for a specific node. Falling back to the policy's node
    // would silently key the futex somewhere else, so the request fails.
    assert_eq!(resolve_node(true, true, Some(1), 0), Err(NodeReject::NoSuchNode));
}

#[test]
fn no_preference_falls_through_to_the_memory_policy_then_is_written_back() {
    assert_eq!(resolve_node(true, true, Some(FUTEX_NO_NODE), 0),
               Ok(NodeOutcome { node: 0, write_back: Some(0) }));
}

#[test]
fn no_preference_and_no_policy_node_falls_through_to_the_running_node() {
    assert_eq!(resolve_node(true, false, Some(FUTEX_NO_NODE), FUTEX_NO_NODE),
               Ok(NodeOutcome { node: current_node_id(), write_back: Some(current_node_id()) }));
    assert_eq!(resolve_node(true, true, Some(FUTEX_NO_NODE), FUTEX_NO_NODE),
               Ok(NodeOutcome { node: current_node_id(), write_back: Some(current_node_id()) }));
}

#[test]
fn mpol_without_numa_selects_a_node_but_writes_nothing_back() {
    // There is no node-id word to write to: MPOL alone does not double the
    // operand, so a write-back here would scribble past the futex.
    assert_eq!(resolve_node(false, true, None, 0),
               Ok(NodeOutcome { node: 0, write_back: None }));
    assert_eq!(resolve_node(false, true, None, FUTEX_NO_NODE),
               Ok(NodeOutcome { node: FUTEX_NO_NODE, write_back: None }));
}
