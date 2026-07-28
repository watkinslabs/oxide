// `do_get_mempolicy` (`mm/mempolicy.c:1147`).
//
// The pre-F763 slot ignored `flags` and `addr` entirely and always wrote
// MPOL_DEFAULT into `*policy`, so every case below was answered "0".

use crate::mempolicy::nodemask::NodeMask;
use crate::mempolicy::policy::mpol_new;
use crate::mempolicy::query::*;
use crate::mempolicy::uapi::*;
use crate::Error;

const NODE0: NodeMask = NodeMask(1);

fn bind_policy() -> Option<crate::mempolicy::MemPolicy> {
    mpol_new(MPOL_BIND, 0, NODE0).unwrap()
}

#[test]
fn undefined_get_flags_are_einval() {
    assert_eq!(get_mempolicy_kind(1 << 3, 0), Err(Error::Inval));
    assert_eq!(get_mempolicy_kind(u64::MAX, 0), Err(Error::Inval));
}

#[test]
fn mems_allowed_excludes_node_and_addr() {
    assert_eq!(get_mempolicy_kind(MPOL_F_MEMS_ALLOWED, 0), Ok(GetPolicyKind::MemsAllowed));
    assert_eq!(get_mempolicy_kind(MPOL_F_MEMS_ALLOWED | MPOL_F_NODE, 0), Err(Error::Inval));
    assert_eq!(get_mempolicy_kind(MPOL_F_MEMS_ALLOWED | MPOL_F_ADDR, 0x1000), Err(Error::Inval));
}

#[test]
fn a_non_zero_addr_without_mpol_f_addr_is_einval() {
    assert_eq!(get_mempolicy_kind(0, 0x4000_0000), Err(Error::Inval));
    assert_eq!(get_mempolicy_kind(MPOL_F_NODE, 0x4000_0000), Err(Error::Inval));
    // With MPOL_F_ADDR the same address is the whole point.
    assert_eq!(get_mempolicy_kind(MPOL_F_ADDR, 0x4000_0000),
               Ok(GetPolicyKind::VmaPolicy { node: false }));
}

#[test]
fn the_four_reporting_behaviours_are_distinct() {
    assert_eq!(get_mempolicy_kind(MPOL_F_MEMS_ALLOWED, 0), Ok(GetPolicyKind::MemsAllowed));
    assert_eq!(get_mempolicy_kind(MPOL_F_ADDR, 0x1000),
               Ok(GetPolicyKind::VmaPolicy { node: false }));
    assert_eq!(get_mempolicy_kind(MPOL_F_ADDR | MPOL_F_NODE, 0x1000),
               Ok(GetPolicyKind::VmaPolicy { node: true }));
    assert_eq!(get_mempolicy_kind(MPOL_F_NODE, 0),
               Ok(GetPolicyKind::TaskPolicy { node: true }));
}

#[test]
fn mems_allowed_reports_the_cpuset_mask_and_a_zero_mode() {
    let r = report_policy(GetPolicyKind::MemsAllowed, bind_policy(), None).unwrap();
    assert_eq!(r.policy, 0);
    assert_eq!(r.nodes, NODE0, "single-node cpuset mems_allowed is {{0}}");
}

#[test]
fn no_policy_reports_mpol_default_with_an_empty_mask() {
    let r = report_policy(GetPolicyKind::TaskPolicy { node: false }, None, None).unwrap();
    assert_eq!(r.policy, MPOL_DEFAULT as i32);
    assert_eq!(r.nodes, NodeMask::EMPTY);
}

#[test]
fn set_mempolicy_round_trips_through_get_mempolicy() {
    // The property libnuma actually depends on.
    for (mode, mask) in [(MPOL_BIND, NODE0), (MPOL_INTERLEAVE, NODE0),
                         (MPOL_PREFERRED, NODE0), (MPOL_PREFERRED_MANY, NODE0),
                         (MPOL_WEIGHTED_INTERLEAVE, NODE0)] {
        let pol = mpol_new(mode, 0, mask).unwrap();
        let r = report_policy(GetPolicyKind::TaskPolicy { node: false }, pol, None).unwrap();
        assert_eq!(r.policy, mode as i32, "mode {mode} must come back unchanged");
        assert_eq!(r.nodes, mask);
    }
}

#[test]
fn mpol_local_reports_an_empty_nodemask() {
    let pol = mpol_new(MPOL_LOCAL, 0, NodeMask::EMPTY).unwrap();
    let r = report_policy(GetPolicyKind::TaskPolicy { node: false }, pol, None).unwrap();
    assert_eq!(r.policy, MPOL_LOCAL as i32);
    assert_eq!(r.nodes, NodeMask::EMPTY, "MPOL_LOCAL means 'no nodes named'");
}

#[test]
fn mpol_f_node_without_an_interleave_policy_is_einval() {
    assert_eq!(report_policy(GetPolicyKind::TaskPolicy { node: true }, None, None),
               Err(Error::Inval), "no policy installed");
    assert_eq!(report_policy(GetPolicyKind::TaskPolicy { node: true }, bind_policy(), None),
               Err(Error::Inval), "MPOL_BIND is not an interleave policy");
}

#[test]
fn mpol_f_node_on_an_interleave_policy_reports_the_next_node() {
    for mode in [MPOL_INTERLEAVE, MPOL_WEIGHTED_INTERLEAVE] {
        let pol = mpol_new(mode, 0, NODE0).unwrap();
        let r = report_policy(GetPolicyKind::TaskPolicy { node: true }, pol, None).unwrap();
        assert_eq!(r.policy, NODE_ID_LOCAL as i32);
        // The nodemask is still filled on this path.
        assert_eq!(r.nodes, NODE0);
    }
}

#[test]
fn next_node_in_wraps_from_the_interleave_seed() {
    assert_eq!(IL_PREV_INIT, (MAX_NUMNODES - 1) as u16);
    assert_eq!(next_node_in(IL_PREV_INIT, NODE0), 0);
    assert_eq!(next_node_in(0, NodeMask(0b110)), 1);
    assert_eq!(next_node_in(1, NodeMask(0b110)), 2);
    assert_eq!(next_node_in(2, NodeMask(0b110)), 1, "wraps");
    assert_eq!(next_node_in(0, NodeMask::EMPTY), MAX_NUMNODES as u16);
}

#[test]
fn addr_plus_node_reports_the_page_node_not_the_policy() {
    let r = report_policy(GetPolicyKind::VmaPolicy { node: true }, bind_policy(),
                          Some(NODE_ID_LOCAL)).unwrap();
    assert_eq!(r.policy, NODE_ID_LOCAL as i32);
    // An unresolvable page is EFAULT, matching lookup_node()'s gup failure.
    assert_eq!(report_policy(GetPolicyKind::VmaPolicy { node: true }, bind_policy(), None),
               Err(Error::Fault));
}

#[test]
fn addr_without_node_reports_the_vma_policy_and_defaults_when_it_has_none() {
    let r = report_policy(GetPolicyKind::VmaPolicy { node: false }, bind_policy(), None).unwrap();
    assert_eq!(r.policy, MPOL_BIND as i32);
    // Linux deliberately does NOT fall back to the task policy here.
    let r = report_policy(GetPolicyKind::VmaPolicy { node: false }, None, None).unwrap();
    assert_eq!(r.policy, MPOL_DEFAULT as i32);
    assert_eq!(r.nodes, NodeMask::EMPTY);
}
