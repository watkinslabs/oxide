// Layer-mask algebra. A request is tracked as a per-layer set of rights that
// are still unfulfilled; walking a hierarchy clears bits, and the request is
// allowed once every layer's set is empty. Pure arithmetic, no VFS: the whole
// decision procedure is reachable from the hosted suite.

use crate::uapi::*;

/// What one layer grants at one hierarchy node, and whether the rule that
/// granted it asked for denials naming that object to stay unreported.
///
/// The two travel together because they are read from the same rule: a rule
/// marked quiet still grants what it grants, and a rule that grants nothing
/// can still mark an object quiet — which is the only reason to add it.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Grant {
    pub access: AccessMask,
    pub quiet: bool,
}

impl Grant {
    /// A grant from a source that carries no quiet marking: a scope, a port
    /// with no rule, an in-domain peer.
    /// # C: O(1)
    pub fn plain(access: AccessMask) -> Self { Self { access, quiet: false } }
}

/// Per-layer unfulfilled-rights matrix. Index = layer level, outermost first.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct LayerMasks {
    pub layers: [AccessMask; MAX_NUM_LAYERS],
    /// Whether a rule marked quiet was met at this layer during the walk.
    /// Accumulated, never cleared: an object is quiet at a layer if ANY rule
    /// of that layer said so.
    pub quiet: [bool; MAX_NUM_LAYERS],
}

impl Default for LayerMasks {
    fn default() -> Self { Self { layers: [0; MAX_NUM_LAYERS], quiet: [false; MAX_NUM_LAYERS] } }
}

impl LayerMasks {
    /// Seed from a request. `handled[i]` is the mask layer `i` filters; a layer
    /// contributes only the requested rights it actually handles. Returns the
    /// union, which is the part of the request any layer cares about — zero
    /// means no layer filters the operation and it is allowed outright.
    /// # C: O(N_layers)
    pub fn init(handled: &[AccessMask], access_request: AccessMask) -> (Self, AccessMask) {
        let mut m = Self::default();
        if access_request == 0 { return (m, 0); }
        let mut union = 0;
        for (i, h) in handled.iter().enumerate().take(MAX_NUM_LAYERS) {
            m.layers[i] = access_request & *h;
            union |= m.layers[i];
        }
        (m, union)
    }

    /// Clear the rights `granted[i]` supplies at layer `i`. Returns true once
    /// nothing is left unfulfilled.
    ///
    /// Rights accumulate by union along a walk: a layer is satisfied when the
    /// rules met anywhere between the object and the root jointly grant the
    /// request, so a right granted high in the hierarchy still covers an object
    /// deep inside it.
    /// # C: O(N_layers)
    pub fn unmask(&mut self, granted: &[Grant]) -> bool {
        for (i, g) in granted.iter().enumerate().take(MAX_NUM_LAYERS) {
            self.layers[i] &= !g.access;
            if g.quiet { self.quiet[i] = true; }
        }
        self.all_clear()
    }

    /// The YOUNGEST layer still refusing part of `request`: its level, the
    /// rights it refuses, and whether it marked the object quiet.
    ///
    /// Youngest rather than outermost because that is the layer whose author
    /// most recently chose to refuse this, and therefore the one whose logging
    /// configuration decides whether the denial is reported at all.
    /// # C: O(N_layers)
    pub fn denied_layer(&self, request: AccessMask) -> Option<(usize, AccessMask, bool)> {
        for i in (0..MAX_NUM_LAYERS).rev() {
            let missing = self.layers[i] & request;
            if missing != 0 { return Some((i, missing, self.quiet[i])); }
        }
        None
    }

    /// # C: O(N_layers)
    pub fn all_clear(&self) -> bool { self.layers.iter().all(|a| *a == 0) }

    /// Narrow every layer to `access_request`, dropping rights that were only
    /// tracked for the wider domain-level comparison. Returns true if nothing
    /// remains unfulfilled afterwards.
    /// # C: O(N_layers)
    pub fn scope_to_request(&mut self, access_request: AccessMask) -> bool {
        let mut unfulfilled = false;
        for a in self.layers.iter_mut() {
            *a &= access_request;
            if *a != 0 { unfulfilled = true; }
        }
        !unfulfilled
    }

    /// Whether a denial should be reported as "not permitted" rather than "not
    /// on this filesystem". An outstanding reparenting right alone means the
    /// hierarchies are incompatible, which is the cross-device answer; any
    /// other outstanding right means the operation is simply forbidden.
    /// # C: O(N_layers)
    pub fn is_eacces(&self, access_request: AccessMask) -> bool {
        self.layers.iter().any(|a| (*a & access_request & !ACCESS_FS_REFER) != 0)
    }
}

/// Whether a child carrying `src_child` rights under `src_parent` would keep at
/// most the same rights under `new_parent`.
///
/// The masks hold *unfulfilled* rights, so a larger mask means a more
/// restricted hierarchy: the destination must be at least as restricted as the
/// source for the move not to be an escalation. A non-directory child can only
/// carry file rights, so directory-shaped restrictions are ignored for it.
/// # C: O(N_layers)
pub fn may_refer(src_parent: &LayerMasks, src_child: &LayerMasks,
                 new_parent: &LayerMasks, child_is_dir: bool) -> bool
{
    for i in 0..MAX_NUM_LAYERS {
        let mut child_access  = src_parent.layers[i] & src_child.layers[i];
        let mut parent_access = new_parent.layers[i];
        if !child_is_dir {
            child_access  &= ACCESS_FILE;
            parent_access &= ACCESS_FILE;
        }
        if (child_access | parent_access) != parent_access { return false; }
    }
    true
}

/// Whether reparenting cannot increase rights in either direction. The second
/// child is present only for an exchange, which moves two hierarchies at once.
/// # C: O(N_layers)
pub fn no_more_access(parent1: &LayerMasks, child1: &LayerMasks, child1_is_dir: bool,
                      parent2: &LayerMasks, child2: Option<&LayerMasks>, child2_is_dir: bool)
    -> bool
{
    if !may_refer(parent1, child1, parent2, child1_is_dir) { return false; }
    match child2 {
        None => true,
        Some(c2) => may_refer(parent2, c2, parent1, child2_is_dir),
    }
}

#[cfg(test)]
#[path = "tests/eval.rs"]
mod tests;
