// The enforced policy: an immutable stack of layers, snapshotted from a
// ruleset at the instant it is enforced and thereafter shared by reference.
//
// Immutability is the security property. A ruleset fd stays writable after
// `landlock_restrict_self`, and if enforcement read through to that live object
// a sandboxed thread could add an allow-rule to widen the sandbox it is already
// inside. Snapshotting means the only way the policy changes is another
// enforcement, and merging can only ever add a layer.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use syscall::errno::Errno;
use vfs::VfsPath;

use crate::abi;
use crate::audit::RequestType;
use crate::eval::{Grant, LayerMasks};
use crate::logging::{DomainDetails, LayerLog, LogConfig, LogStatus};
use crate::ruleset::{FsRule, NetRule, Ruleset};
use crate::uapi::*;
use crate::walk::{self, Node};

/// One enforced policy layer.
pub struct Layer {
    pub handled_fs:  AccessMask,
    pub handled_net: AccessMask,
    pub scoped:      AccessMask,
    /// Rights whose denial this layer asked not to have reported, for objects
    /// one of its rules marked quiet. Never affects an access decision.
    pub quiet_fs:     AccessMask,
    pub quiet_net:    AccessMask,
    /// Scopes whose denial is never reported; needs no object marking.
    pub quiet_scoped: AccessMask,
    pub fs:  Vec<FsRule>,
    pub net: Vec<NetRule>,
    /// Reporting state, SHARED with every domain that inherited this layer.
    pub log: Arc<LayerLog>,
}

impl Layer {
    /// # C: O(1)
    pub fn fs_mask(&self) -> AccessMask { abi::fs_layer_mask(self.handled_fs) }

    /// What this layer grants at one hierarchy node, and whether any rule it
    /// matched there marked the object quiet. A rule that grants nothing still
    /// contributes its quiet marking — carrying that marking is the only
    /// reason such a rule can be added at all.
    /// # C: O(N_rules)
    fn granted_at(&self, node: &Node) -> Grant {
        let key = Arc::as_ptr(&node.inode);
        let mut g = Grant::default();
        for r in self.fs.iter() {
            if Arc::as_ptr(&r.inode) != key { continue; }
            g.access |= r.allowed;
            g.quiet |= r.quiet;
        }
        g
    }

    /// What this layer grants on one port.
    /// # C: O(N_rules)
    fn granted_port(&self, port: u16) -> Grant {
        let mut g = Grant::default();
        for r in self.net.iter() {
            if r.port != port { continue; }
            g.access |= r.allowed;
            g.quiet |= r.quiet;
        }
        g
    }

    /// # C: O(1)
    pub fn count_denial(&self) { self.log.count_denial(); }
    /// # C: O(1)
    pub fn denials(&self) -> u64 { self.log.denials() }
    /// # C: O(1)
    pub fn log_status(&self) -> LogStatus { self.log.status() }
    /// # C: O(1)
    pub fn claim_description(&self) -> LogStatus { self.log.claim_description() }

    /// Clone for a stacked domain: the rules are copied, the reporting state
    /// is SHARED — it describes one layer, however many domains hold it.
    /// # C: O(N_rules)
    fn inherit(&self) -> Self {
        Self {
            handled_fs: self.handled_fs, handled_net: self.handled_net, scoped: self.scoped,
            quiet_fs: self.quiet_fs, quiet_net: self.quiet_net,
            quiet_scoped: self.quiet_scoped,
            fs: self.fs.clone(), net: self.net.clone(), log: Arc::clone(&self.log),
        }
    }
}

static NEXT_DOMAIN_ID: AtomicU64 = AtomicU64::new(1);

/// An enforced Landlock policy.
pub struct Domain {
    pub layers: Vec<Layer>,
    /// Identity of this domain and of each of its ancestors, outermost first.
    /// `ancestry[i]` names the domain that existed when layer `i` was added,
    /// which is what decides whether another thread is inside this domain.
    pub ancestry: Vec<u64>,
}

impl Domain {
    /// Stack `rs` on top of `parent`. The result is always at least as
    /// restrictive as `parent`: layers are only ever appended, never replaced,
    /// so a thread cannot escape a policy by enforcing another one.
    /// # C: O(N_rules)
    pub fn merge(parent: Option<&Arc<Domain>>, rs: &Ruleset) -> Result<Arc<Domain>, Errno> {
        Self::merge_logged(parent, rs, LogConfig::default(), DomainDetails::default())
    }

    /// `merge`, with the reporting configuration the enforcement asked for and
    /// the identity of whoever asked. The two are fixed at enforcement time
    /// because the layer is immutable thereafter — including its logging,
    /// which a sandboxed thread must not be able to turn back on.
    /// # C: O(N_rules)
    pub fn merge_logged(parent: Option<&Arc<Domain>>, rs: &Ruleset, log: LogConfig,
                        details: DomainDetails) -> Result<Arc<Domain>, Errno>
    {
        let mut layers = Vec::new();
        let mut ancestry = Vec::new();
        if let Some(p) = parent {
            abi::may_stack_layer(p.layers.len())?;
            for l in p.layers.iter() { layers.push(l.inherit()); }
            ancestry.extend_from_slice(&p.ancestry);
        }
        let (fs, net) = rs.snapshot();
        layers.push(Layer {
            handled_fs: rs.handled_fs, handled_net: rs.handled_net, scoped: rs.scoped,
            quiet_fs: rs.quiet_fs, quiet_net: rs.quiet_net, quiet_scoped: rs.quiet_scoped,
            fs, net, log: Arc::new(LayerLog::new(log, details)),
        });
        ancestry.push(NEXT_DOMAIN_ID.fetch_add(1, Ordering::AcqRel));
        Ok(Arc::new(Domain { layers, ancestry }))
    }

    /// # C: O(1)
    pub fn num_layers(&self) -> usize { self.layers.len() }

    /// Per-layer filtered-rights masks, in layer order.
    /// # C: O(N_layers)
    pub fn fs_masks(&self) -> Vec<AccessMask> {
        self.layers.iter().map(|l| l.fs_mask()).collect()
    }

    /// # C: O(N_layers)
    pub fn net_masks(&self) -> Vec<AccessMask> {
        self.layers.iter().map(|l| l.handled_net).collect()
    }

    /// Whether any layer filters `access` at all. A domain that filters none of
    /// it must not inspect the address: producing an argument error from a
    /// policy that does not apply would change a program's errno by the mere
    /// presence of an unrelated sandbox.
    /// # C: O(N_layers)
    pub fn handles_net(&self, access: AccessMask) -> bool {
        self.layers.iter().any(|l| (l.handled_net & access) != 0)
    }

    /// Whether any layer filters `access` on the filesystem.
    /// # C: O(N_layers)
    pub fn handles_fs(&self, access: AccessMask) -> bool {
        self.layers.iter().any(|l| (l.fs_mask() & access) != 0)
    }

    /// Union of every layer's filtered filesystem rights.
    /// # C: O(N_layers)
    pub fn union_fs_mask(&self) -> AccessMask {
        self.layers.iter().fold(0, |a, l| a | l.fs_mask())
    }

    /// Per-layer grants at one node.
    /// # C: O(N_layers × N_rules)
    pub(crate) fn granted_at(&self, node: &Node) -> Vec<Grant> {
        self.layers.iter().map(|l| l.granted_at(node)).collect()
    }

    /// Report the denial `m` describes, if the layer that produced it reports.
    ///
    /// Called on every refusal path so a sandboxed program's failure is
    /// explainable: the record names the layer, the domain, and exactly which
    /// rights were still missing when the walk ran out.
    /// # C: O(N_layers)
    pub(crate) fn report_denial_masks(&self, m: &LayerMasks, ty: RequestType, request: AccessMask) {
        let Some((layer, missing, object_quiet)) = m.denied_layer(request) else { return };
        crate::audit::log_denial(self, ty, layer, missing, object_quiet,
                                 crate::audit::same_execution(layer));
    }

    /// Whether `access` is allowed on `path`.
    ///
    /// Every layer must be satisfied independently; within a layer the rights
    /// met anywhere on the walk from the object to the root are unioned.
    /// # C: O(depth × N_layers × N_rules)
    pub fn check_fs(&self, path: &VfsPath, access: AccessMask) -> Result<(), Errno> {
        let chain = walk::ancestors(path);
        self.check_fs_chain(&chain, access)
    }

    /// `check_fs` over an already-collected hierarchy.
    /// # C: O(depth × N_layers × N_rules)
    pub fn check_fs_chain(&self, chain: &[Node], access: AccessMask) -> Result<(), Errno> {
        let masks = self.fs_masks();
        let (mut m, req) = LayerMasks::init(&masks, access);
        if req == 0 { return Ok(()); }
        for n in chain.iter() {
            if m.unmask(&self.granted_at(n)) { return Ok(()); }
        }
        self.report_denial_masks(&m, RequestType::FsAccess, req);
        Err(Errno::Eacces)
    }

    /// Whether this thread may resolve the pathname socket at `path`, whose
    /// server was published from `peer`.
    ///
    /// A socket published inside the domain that scoped resolution stays
    /// reachable without any rule, exactly as a scoped resource does: a layer
    /// is satisfied outright when the peer's ancestry agrees with ours there.
    /// Every other layer still has to be satisfied by a hierarchy rule, which
    /// is why a denial is the filesystem answer and not the scope one.
    /// # C: O(depth × N_layers × N_rules)
    pub fn check_unix_resolve(&self, path: &VfsPath, peer: Option<&Arc<Domain>>)
        -> Result<(), Errno>
    {
        let req = ACCESS_FS_RESOLVE_UNIX;
        let masks = self.fs_masks();
        let (mut m, union) = LayerMasks::init(&masks, req);
        if union == 0 { return Ok(()); }
        let inside: Vec<Grant> = (0..self.layers.len())
            .map(|i| Grant::plain(if self.peer_inside_at(peer, i) { req } else { 0 }))
            .collect();
        if m.unmask(&inside) { return Ok(()); }
        for n in walk::ancestors(path).iter() {
            if m.unmask(&self.granted_at(n)) { return Ok(()); }
        }
        self.report_denial_masks(&m, RequestType::FsAccess, req);
        Err(Errno::Eacces)
    }

    /// Whether `peer` is this domain or one created beneath it at `level`.
    /// # C: O(1)
    fn peer_inside_at(&self, peer: Option<&Arc<Domain>>, level: usize) -> bool {
        match peer {
            None => false,
            Some(p) => p.ancestry.len() > level && p.ancestry[level] == self.ancestry[level],
        }
    }

    /// Whether `access` is allowed on `port`. Ports carry no hierarchy, so a
    /// layer is satisfied only by a rule naming the port itself.
    /// # C: O(N_layers × N_rules)
    pub fn check_net(&self, port: u16, access: AccessMask) -> Result<(), Errno> {
        let masks = self.net_masks();
        let (mut m, req) = LayerMasks::init(&masks, access);
        if req == 0 { return Ok(()); }
        let granted: Vec<Grant> =
            self.layers.iter().map(|l| l.granted_port(port)).collect();
        if m.unmask(&granted) { return Ok(()); }
        self.report_denial_masks(&m, RequestType::NetAccess, req);
        Err(Errno::Eacces)
    }

    /// Whether this domain isolates `scope` from `peer`.
    ///
    /// A scoped resource stays reachable inside the domain that scoped it: a
    /// peer is in scope when it is that same domain or one created beneath it,
    /// which is exactly "the peer's ancestry agrees with ours at the scoping
    /// layer". A peer with no domain at all is always outside.
    /// # C: O(N_layers)
    pub fn scope_denies(&self, scope: AccessMask, peer: Option<&Arc<Domain>>) -> bool {
        for (level, l) in self.layers.iter().enumerate() {
            if (l.scoped & scope) == 0 { continue; }
            if self.peer_inside_at(peer, level) { continue; }
            // A scope names no object, so there is no walk to run out of: the
            // layer that scopes it IS the layer that denied it.
            let ty = if scope == SCOPE_SIGNAL { RequestType::ScopeSignal }
                     else { RequestType::ScopeAbstractUnixSocket };
            crate::audit::log_denial(self, ty, level, 0, false,
                                     crate::audit::same_execution(level));
            return true;
        }
        false
    }

    /// Whether any layer scopes `scope` at all.
    /// # C: O(N_layers)
    pub fn scopes(&self, scope: AccessMask) -> bool {
        self.layers.iter().any(|l| (l.scoped & scope) != 0)
    }
}

/// Whether `subject`'s domain isolates it from `peer`'s for `scope`. Both sides
/// may be unconfined; an unconfined subject scopes nothing.
/// # C: O(N_layers)
pub fn scope_denied(subject: Option<&Arc<Domain>>, peer: Option<&Arc<Domain>>,
                    scope: AccessMask) -> bool
{
    match subject {
        None => false,
        Some(d) => d.scopes(scope) && d.scope_denies(scope, peer),
    }
}

#[cfg(test)]
#[path = "tests/domain.rs"]
mod tests;

impl Drop for Domain {
    /// Report every layer that dies with this domain.
    ///
    /// Only the LAST holder reports: a layer inherited by a stacked domain is
    /// still enforced somewhere, and announcing its id as gone would tell a
    /// reader it could stop resolving records that are still being produced.
    /// # C: O(N_layers)
    fn drop(&mut self) {
        for (i, l) in self.layers.iter().enumerate() {
            if Arc::strong_count(&l.log) != 1 { continue; }
            crate::audit::log_drop_layer(self.ancestry.get(i).copied().unwrap_or(0), l);
        }
    }
}
