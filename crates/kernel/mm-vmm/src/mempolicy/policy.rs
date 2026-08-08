// Stored NUMA memory policy and its constructors: mode-flag sanitization,
// policy construction from a nodemask, and the effective-nodemask query used
// by get_mempolicy(2).

use super::nodemask::{nodes_with_memory, relative_nodemask, NodeMask};
use super::uapi::*;
use crate::Error;

/// A stored NUMA memory policy, minus the refcount (we store by value).
///
/// `nodes` is the EFFECTIVE mask after intersection with the nodes that have
/// memory; `user_nodes` is the raw mask the caller passed, kept only when
/// `MPOL_F_STATIC_NODES`/`MPOL_F_RELATIVE_NODES` is set because
/// `get_mempolicy` must then echo the raw mask rather than the effective one.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct MemPolicy {
    pub mode: u16,
    pub flags: u16,
    pub nodes: NodeMask,
    pub user_nodes: NodeMask,
    pub home_node: i32,
}

impl MemPolicy {
    /// Whether this policy's raw user nodemask must be echoed back verbatim
    /// by get_mempolicy(2). # C: O(1)
    pub fn stores_user_nodemask(&self) -> bool { self.flags & MPOL_USER_NODEMASK_FLAGS != 0 }

    /// The nodemask get_mempolicy(2) reports: MPOL_LOCAL reports an
    /// EMPTY mask; every other stored mode reports its effective nodes.
    /// # C: O(1)
    pub fn reported_nodes(&self) -> NodeMask {
        if self.stores_user_nodemask() { return self.user_nodes; }
        if self.mode == MPOL_LOCAL { NodeMask::EMPTY } else { self.nodes }
    }

    /// The mode word `get_mempolicy` writes back: the mode plus the optional
    /// mode flags, with the internal `MPOL_F_SHARED`/`MOF`/`MORON` bits masked
    /// off — those never leak to userspace.
    /// # C: O(1)
    pub fn reported_mode(&self) -> i32 { (self.mode | (self.flags & MPOL_MODE_FLAGS)) as i32 }

    /// Encoded form for lock-free per-task storage: mode, flags and home node
    /// in one word. Never zero for a real policy — `home_node` starts at
    /// `NUMA_NO_NODE`, so word 0 unambiguously means "no policy" (which is
    /// what `mpol_new(MPOL_DEFAULT)` yields anyway).
    /// # C: O(1)
    pub fn to_words(self) -> [u64; 3] {
        [(self.mode as u64) | ((self.flags as u64) << 16) | ((self.home_node as u32 as u64) << 32),
         self.nodes.0, self.user_nodes.0]
    }

    /// Inverse of [`Self::to_words`]; `None` for the all-zero "no policy" word.
    /// # C: O(1)
    pub fn from_words(w: [u64; 3]) -> Option<MemPolicy> {
        if w[0] == 0 { return None; }
        Some(MemPolicy {
            mode: (w[0] & 0xffff) as u16,
            flags: ((w[0] >> 16) & 0xffff) as u16,
            nodes: NodeMask(w[1]),
            user_nodes: NodeMask(w[2]),
            home_node: (w[0] >> 32) as u32 as i32,
        })
    }
}

/// Splits the caller's mode word into (mode, mode-flags) and rejects the
/// three illegal combinations. Runs BEFORE the nodemask is fetched in both
/// `mbind(2)` and `set_mempolicy(2)`, so a bad mode outranks an unreadable
/// `nmask`.
/// # C: O(1)
pub fn sanitize_mpol_flags(mode_arg: u32) -> Result<(u16, u16), Error> {
    let mut flags = (mode_arg & MPOL_MODE_FLAGS as u32) as u16;
    let mode = mode_arg & !(MPOL_MODE_FLAGS as u32);
    if mode >= MPOL_MAX as u32 { return Err(Error::Inval); }
    let mode = mode as u16;
    if flags & MPOL_F_STATIC_NODES != 0 && flags & MPOL_F_RELATIVE_NODES != 0 {
        return Err(Error::Inval);
    }
    if flags & MPOL_F_NUMA_BALANCING != 0 {
        if mode == MPOL_BIND || mode == MPOL_PREFERRED_MANY { flags |= MPOL_F_MOF | MPOL_F_MORON; }
        else { return Err(Error::Inval); }
    }
    Ok((mode, flags))
}

/// Policy construction fused with nodemask population, because oxide stores
/// policies by value and has no separate construct-then-populate step.
///
/// `Ok(None)` is the NULL policy — `MPOL_DEFAULT`, which is "no policy
/// object at all", not "a policy whose mode is DEFAULT".
///
/// The mode rewrite matters: `MPOL_PREFERRED` with an empty nodemask BECOMES
/// `MPOL_LOCAL`, and `get_mempolicy` afterwards reports `MPOL_LOCAL`.
/// # C: O(MAX_NUMNODES) worst case via `relative_nodemask`
pub fn mpol_new(mode: u16, flags: u16, nodes: NodeMask) -> Result<Option<MemPolicy>, Error> {
    let mut mode = mode;
    if mode == MPOL_DEFAULT {
        if !nodes.is_empty() { return Err(Error::Inval); }
        return Ok(None);
    }
    if mode == MPOL_PREFERRED {
        if nodes.is_empty() {
            if flags & MPOL_USER_NODEMASK_FLAGS != 0 { return Err(Error::Inval); }
            mode = MPOL_LOCAL;
        }
    } else if mode == MPOL_LOCAL {
        if !nodes.is_empty() || flags & MPOL_USER_NODEMASK_FLAGS != 0 { return Err(Error::Inval); }
    } else if nodes.is_empty() {
        return Err(Error::Inval);
    }
    let mut pol = MemPolicy {
        mode, flags, nodes: NodeMask::EMPTY, user_nodes: NodeMask::EMPTY,
        home_node: NUMA_NO_NODE,
    };
    // MPOL_LOCAL needs no constructor and is not remapped.
    if mode == MPOL_LOCAL { return Ok(Some(pol)); }
    let allowed = nodes_with_memory();
    let effective = if flags & MPOL_F_RELATIVE_NODES != 0 {
        relative_nodemask(nodes, allowed)
    } else {
        nodes.and(allowed)
    };
    if pol.stores_user_nodemask() { pol.user_nodes = nodes; }
    // Per-mode construction: reject an empty effective mask.
    if effective.is_empty() { return Err(Error::Inval); }
    pol.nodes = if mode == MPOL_PREFERRED {
        // MPOL_PREFERRED keeps only the first node.
        NodeMask::single(effective.first())
    } else {
        effective
    };
    Ok(Some(pol))
}

/// `mpol_equal` — VMA merge/`mbind_range` compares policies before rewriting.
/// # C: O(1)
pub fn mpol_equal(a: &Option<MemPolicy>, b: &Option<MemPolicy>) -> bool { a == b }
