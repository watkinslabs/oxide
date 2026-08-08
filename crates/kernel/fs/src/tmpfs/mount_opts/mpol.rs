// `mpol=` — the NUMA memory policy a tmpfs mount allocates its pages under.
//
// The written form is `<mode>[:<nodelist>][=<flags>]`, and every part of it is
// checked here rather than stored raw: a nodelist naming a node the machine
// does not have, a mode that insists on a nodelist and was not given one, a
// mode that forbids one and was, and an unknown flag word are all refusals.
// This machine is single-node, so the mask a mount may legally name is a small
// set — which makes the refusals the OBSERVABLE half of this option, and the
// reason it cannot be stored unvalidated.
//
// The constructed policy is the same object `set_mempolicy(2)` builds, from the
// same constructor, so a mount policy and a task policy can never disagree
// about what a mode/flags/nodes triple means.

use vfs::{KResult, VfsError};
use vmm::mempolicy::uapi::{MPOL_BIND, MPOL_DEFAULT, MPOL_F_RELATIVE_NODES, MPOL_F_STATIC_NODES,
                           MPOL_INTERLEAVE, MPOL_LOCAL, MPOL_PREFERRED, MPOL_PREFERRED_MANY,
                           MPOL_WEIGHTED_INTERLEAVE};
use vmm::mempolicy::{mpol_new, nodes_with_memory, MemPolicy, NodeMask};

/// Separator between the mode and its node list.
const NODELIST_SEP: char = ':';
/// Separator between the mode (or node list) and the mode flags.
const FLAGS_SEP: char = '=';
/// Separator between node-list elements.
const NODE_SEP: char = ',';
/// Separator of a node-list range.
const NODE_RANGE: char = '-';

const MODE_DEFAULT: &str = "default";
const MODE_PREFER: &str = "prefer";
const MODE_BIND: &str = "bind";
const MODE_INTERLEAVE: &str = "interleave";
const MODE_WEIGHTED_INTERLEAVE: &str = "weighted interleave";
const MODE_LOCAL: &str = "local";
const MODE_PREFER_MANY: &str = "prefer (many)";

const FLAG_STATIC: &str = "static";
const FLAG_RELATIVE: &str = "relative";

/// Mode name → mode number; `None` for a name that is not a policy mode.
/// # C: O(1)
fn mode_from_name(name: &str) -> Option<u16> {
    match name {
        MODE_DEFAULT => Some(MPOL_DEFAULT),
        MODE_PREFER => Some(MPOL_PREFERRED),
        MODE_BIND => Some(MPOL_BIND),
        MODE_INTERLEAVE => Some(MPOL_INTERLEAVE),
        MODE_WEIGHTED_INTERLEAVE => Some(MPOL_WEIGHTED_INTERLEAVE),
        MODE_LOCAL => Some(MPOL_LOCAL),
        MODE_PREFER_MANY => Some(MPOL_PREFERRED_MANY),
        _ => None,
    }
}

/// Parse a node list (`0`, `0-3`, `0,2-4`) into a mask. Any malformed element,
/// a reversed range, or a node number outside the mask width is a refusal.
/// # C: O(len)
fn nodelist_parse(s: &str) -> KResult<NodeMask> {
    if s.is_empty() { return Err(VfsError::Einval); }
    let mut mask = NodeMask::EMPTY;
    for elem in s.split(NODE_SEP) {
        let (lo, hi) = match elem.split_once(NODE_RANGE) {
            Some((a, b)) => (node_num(a)?, node_num(b)?),
            None => { let n = node_num(elem)?; (n, n) }
        };
        if lo > hi { return Err(VfsError::Einval); }
        for n in lo..=hi { mask = NodeMask(mask.0 | NodeMask::single(n).0); }
    }
    Ok(mask)
}

/// One node number: decimal digits only, and within the mask's width.
/// # C: O(len)
fn node_num(s: &str) -> KResult<u16> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) { return Err(VfsError::Einval); }
    let n: u32 = s.parse().map_err(|_| VfsError::Einval)?;
    if n as u64 >= vmm::mempolicy::uapi::MAX_NUMNODES { return Err(VfsError::Einval); }
    Ok(n as u16)
}

/// `mpol_parse_str`: build the policy an `mpol=` value names.
///
/// `Ok(None)` is the DEFAULT policy, which is the absence of a policy rather
/// than a policy object — the same thing `set_mempolicy(MPOL_DEFAULT)` stores.
/// # C: O(len)
pub(crate) fn parse_mpol(value: &str) -> KResult<Option<MemPolicy>> {
    // Split off the flags first: the mode name ends at whichever of `:` or `=`
    // comes first, and a node list sits between them.
    let (head, flags) = match value.split_once(FLAGS_SEP) {
        Some((h, f)) => (h, Some(f)),
        None => (value, None),
    };
    let (mode_name, nodelist) = match head.split_once(NODELIST_SEP) {
        Some((m, n)) => (m, Some(n)),
        None => (head, None),
    };

    let nodes = match nodelist {
        Some(list) => {
            let parsed = nodelist_parse(list)?;
            // A node the machine does not have is a refusal, not a silent
            // narrowing: a mount asking to be bound to node 1 on a one-node
            // machine gets an answer, not a policy it did not ask for.
            if !parsed.subset_of(nodes_with_memory()) { return Err(VfsError::Einval); }
            parsed
        }
        None => NodeMask::EMPTY,
    };

    let mode = mode_from_name(mode_name).ok_or(VfsError::Einval)?;
    let mut nodes = nodes;
    match mode {
        // A preference must name exactly one node when it names any, and the
        // list may not be a range.
        MPOL_PREFERRED => {
            if let Some(list) = nodelist {
                if !list.bytes().all(|b| b.is_ascii_digit()) { return Err(VfsError::Einval); }
                if nodes.is_empty() { return Err(VfsError::Einval); }
            }
        }
        // Interleaving with no list spreads over every node with memory.
        MPOL_INTERLEAVE | MPOL_WEIGHTED_INTERLEAVE => {
            if nodelist.is_none() { nodes = nodes_with_memory(); }
        }
        // Local allocation is defined by having no list at all.
        MPOL_LOCAL => { if nodelist.is_some() { return Err(VfsError::Einval); } }
        // The default policy is the empty one, and insists on an empty list.
        MPOL_DEFAULT => {
            if nodelist.is_some() { return Err(VfsError::Einval); }
            return Ok(None);
        }
        // Binding is meaningless without the set it binds to.
        MPOL_BIND | MPOL_PREFERRED_MANY => {
            if nodelist.is_none() { return Err(VfsError::Einval); }
        }
        _ => {}
    }

    let mode_flags = match flags {
        None => 0,
        Some(FLAG_STATIC) => MPOL_F_STATIC_NODES,
        Some(FLAG_RELATIVE) => MPOL_F_RELATIVE_NODES,
        Some(_) => return Err(VfsError::Einval),
    };

    let mut pol = mpol_new(mode, mode_flags, nodes).map_err(|_| VfsError::Einval)?;
    // The nodes the mount was WRITTEN with are what `/proc/mounts` has to echo
    // back, so they are kept beside the effective mask rather than instead of
    // it. A single-node preference records that node; a preference with no
    // list is local allocation.
    if let Some(p) = pol.as_mut() {
        if mode != MPOL_PREFERRED { p.nodes = nodes; }
        else if nodelist.is_some() { p.nodes = NodeMask::single(nodes.first()); }
        p.user_nodes = nodes;
    }
    Ok(pol)
}
