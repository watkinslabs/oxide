// `sanitize_mpol_flags` (`mm/mempolicy.c:1721`) + `mpol_new`/`mpol_set_nodemask`
// (`:441`, `:404`).
//
// The pre-F763 shims tested `mode > MPOL_LOCAL` and stored nothing, so they
// rejected MPOL_PREFERRED_MANY and MPOL_WEIGHTED_INTERLEAVE (both legal) and
// accepted every mode-flag combination (several illegal).

use crate::mempolicy::nodemask::NodeMask;
use crate::mempolicy::policy::*;
use crate::mempolicy::uapi::*;
use crate::Error;

const NODE0: NodeMask = NodeMask(1);

#[test]
fn every_mode_up_to_mpol_max_is_accepted() {
    for mode in 0..MPOL_MAX {
        assert_eq!(sanitize_mpol_flags(mode as u32), Ok((mode, 0)),
                   "mode {mode} must be legal — MPOL_MAX is {MPOL_MAX}");
    }
    // The old shim's ceiling was MPOL_LOCAL (4), so 5 and 6 were EINVAL.
    assert_eq!(sanitize_mpol_flags(MPOL_PREFERRED_MANY as u32), Ok((MPOL_PREFERRED_MANY, 0)));
    assert_eq!(sanitize_mpol_flags(MPOL_WEIGHTED_INTERLEAVE as u32),
               Ok((MPOL_WEIGHTED_INTERLEAVE, 0)));
    assert_eq!(sanitize_mpol_flags(MPOL_MAX as u32), Err(Error::Inval));
}

#[test]
fn mode_flags_ride_in_the_high_bits_of_the_mode_word() {
    // The old shim compared the WHOLE word against MPOL_LOCAL, so
    // `MPOL_BIND | MPOL_F_STATIC_NODES` was EINVAL. It is legal.
    assert_eq!(sanitize_mpol_flags((MPOL_BIND | MPOL_F_STATIC_NODES) as u32),
               Ok((MPOL_BIND, MPOL_F_STATIC_NODES)));
    assert_eq!(sanitize_mpol_flags((MPOL_INTERLEAVE | MPOL_F_RELATIVE_NODES) as u32),
               Ok((MPOL_INTERLEAVE, MPOL_F_RELATIVE_NODES)));
}

#[test]
fn static_and_relative_nodes_together_are_einval() {
    let w = (MPOL_BIND | MPOL_F_STATIC_NODES | MPOL_F_RELATIVE_NODES) as u32;
    assert_eq!(sanitize_mpol_flags(w), Err(Error::Inval));
}

#[test]
fn numa_balancing_is_only_legal_with_bind_or_preferred_many() {
    for mode in [MPOL_BIND, MPOL_PREFERRED_MANY] {
        let (m, f) = sanitize_mpol_flags((mode | MPOL_F_NUMA_BALANCING) as u32).unwrap();
        assert_eq!(m, mode);
        // The internal MOF|MORON bits are ORed in and must not leak back out
        // of get_mempolicy — `reported_mode` masks with MPOL_MODE_FLAGS.
        assert_eq!(f, MPOL_F_NUMA_BALANCING | MPOL_F_MOF | MPOL_F_MORON);
    }
    for mode in [MPOL_DEFAULT, MPOL_PREFERRED, MPOL_INTERLEAVE, MPOL_LOCAL,
                 MPOL_WEIGHTED_INTERLEAVE] {
        assert_eq!(sanitize_mpol_flags((mode | MPOL_F_NUMA_BALANCING) as u32),
                   Err(Error::Inval), "MPOL_F_NUMA_BALANCING with mode {mode}");
    }
}

#[test]
fn bits_outside_the_mode_flag_window_are_part_of_the_mode() {
    // Only bits 13..15 are mode flags; bit 16 stays in the mode and blows the
    // MPOL_MAX ceiling.
    assert_eq!(sanitize_mpol_flags(1 << 16), Err(Error::Inval));
    assert_eq!(sanitize_mpol_flags(u32::MAX), Err(Error::Inval));
}

#[test]
fn mpol_default_is_the_null_policy_and_rejects_a_nodemask() {
    assert_eq!(mpol_new(MPOL_DEFAULT, 0, NodeMask::EMPTY), Ok(None));
    assert_eq!(mpol_new(MPOL_DEFAULT, 0, NODE0), Err(Error::Inval));
}

#[test]
fn preferred_with_an_empty_mask_becomes_mpol_local() {
    let p = mpol_new(MPOL_PREFERRED, 0, NodeMask::EMPTY).unwrap().unwrap();
    assert_eq!(p.mode, MPOL_LOCAL, "empty MPOL_PREFERRED is rewritten to MPOL_LOCAL");
    assert_eq!(p.reported_nodes(), NodeMask::EMPTY);
    // ... but not when the caller pinned the mask semantics.
    assert_eq!(mpol_new(MPOL_PREFERRED, MPOL_F_STATIC_NODES, NodeMask::EMPTY), Err(Error::Inval));
    assert_eq!(mpol_new(MPOL_PREFERRED, MPOL_F_RELATIVE_NODES, NodeMask::EMPTY),
               Err(Error::Inval));
}

#[test]
fn mpol_local_refuses_a_nodemask_or_a_nodemask_flag() {
    assert!(mpol_new(MPOL_LOCAL, 0, NodeMask::EMPTY).unwrap().is_some());
    assert_eq!(mpol_new(MPOL_LOCAL, 0, NODE0), Err(Error::Inval));
    assert_eq!(mpol_new(MPOL_LOCAL, MPOL_F_STATIC_NODES, NodeMask::EMPTY), Err(Error::Inval));
}

#[test]
fn bind_and_interleave_require_a_non_empty_mask() {
    for mode in [MPOL_BIND, MPOL_INTERLEAVE, MPOL_PREFERRED_MANY, MPOL_WEIGHTED_INTERLEAVE] {
        assert_eq!(mpol_new(mode, 0, NodeMask::EMPTY), Err(Error::Inval), "mode {mode}");
        assert!(mpol_new(mode, 0, NODE0).unwrap().is_some(), "mode {mode}");
    }
}

#[test]
fn a_nodemask_naming_only_a_memoryless_node_is_einval() {
    // The single-node case that actually bites: mpol_set_nodemask intersects
    // with node_states[N_MEMORY] = {0}, and an empty result fails
    // mpol_ops[mode].create. `mbind(MPOL_BIND, nodemask={1})` is EINVAL on a
    // one-node machine — the old shim returned 0.
    assert_eq!(mpol_new(MPOL_BIND, 0, NodeMask::single(1)), Err(Error::Inval));
    assert_eq!(mpol_new(MPOL_BIND, 0, NodeMask(0b110)), Err(Error::Inval));
    // Node 0 anywhere in the mask survives the intersection.
    let p = mpol_new(MPOL_BIND, 0, NodeMask(0b111)).unwrap().unwrap();
    assert_eq!(p.nodes, NODE0);
}

#[test]
fn preferred_keeps_only_the_first_node() {
    let p = mpol_new(MPOL_PREFERRED, 0, NodeMask(0b111)).unwrap().unwrap();
    assert_eq!(p.mode, MPOL_PREFERRED);
    assert_eq!(p.nodes, NODE0);
}

#[test]
fn static_nodes_makes_get_mempolicy_echo_the_raw_mask() {
    // With MPOL_F_STATIC_NODES the raw user mask is retained verbatim, so
    // get_mempolicy reports {0,1,2} even though only node 0 is usable.
    let p = mpol_new(MPOL_BIND, MPOL_F_STATIC_NODES, NodeMask(0b111)).unwrap().unwrap();
    assert_eq!(p.nodes, NODE0, "effective mask is intersected");
    assert_eq!(p.reported_nodes(), NodeMask(0b111), "reported mask is the raw one");
    // Without the flag, the effective mask is what comes back.
    let q = mpol_new(MPOL_BIND, 0, NodeMask(0b111)).unwrap().unwrap();
    assert_eq!(q.reported_nodes(), NODE0);
}

#[test]
fn relative_nodes_remaps_rather_than_intersects() {
    let p = mpol_new(MPOL_BIND, MPOL_F_RELATIVE_NODES, NodeMask::single(1)).unwrap().unwrap();
    // {1} relative to the allowed {0} folds onto node 0 — NOT the EINVAL a
    // plain intersection would give.
    assert_eq!(p.nodes, NODE0);
    assert_eq!(p.reported_nodes(), NodeMask::single(1));
}

#[test]
fn reported_mode_carries_the_mode_flags_but_not_the_internal_bits() {
    let (mode, flags) = sanitize_mpol_flags((MPOL_BIND | MPOL_F_NUMA_BALANCING) as u32).unwrap();
    let p = mpol_new(mode, flags, NODE0).unwrap().unwrap();
    assert_eq!(p.reported_mode(), (MPOL_BIND | MPOL_F_NUMA_BALANCING) as i32);
    assert_eq!(p.reported_mode() & (MPOL_F_MOF | MPOL_F_MORON) as i32, 0);
}

#[test]
fn policy_round_trips_through_its_packed_form() {
    for mode in 1..MPOL_MAX {
        let nodes = if mode == MPOL_LOCAL { NodeMask::EMPTY } else { NODE0 };
        let flags = if mode == MPOL_LOCAL { 0 } else { MPOL_F_STATIC_NODES };
        let mut p = mpol_new(mode, flags, nodes).unwrap().unwrap();
        p.home_node = NUMA_NO_NODE;
        assert_eq!(MemPolicy::from_words(p.to_words()), Some(p), "mode {mode}");
        p.home_node = 0;
        assert_eq!(MemPolicy::from_words(p.to_words()), Some(p), "mode {mode} home 0");
    }
    // Zero word means "no policy", which is what MPOL_DEFAULT collapses to.
    assert_eq!(MemPolicy::from_words([0, 0, 0]), None);
}
