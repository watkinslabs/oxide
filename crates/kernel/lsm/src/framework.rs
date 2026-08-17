// The framework as a value: which modules run, where they sit, and what
// per-object state each of them owns.
//
// Pure. One instance of it is the kernel's live framework, but nothing here
// reaches for that instance, so the whole decision — ordering, blob
// allocation, identity reporting — is checkable without a running kernel.

use alloc::vec::Vec;

use crate::blob::{BlobGrant, BlobKind, BlobSizes, BLOB_KINDS};
use crate::module::{LsmId, LsmInfo};
use crate::order::{resolve, Ordered, Selection, Skipped};

/// The resolved framework.
#[derive(Clone, Debug)]
pub struct Framework {
    modules: Vec<LsmInfo>,
    ordered: Ordered,
    sizes: BlobSizes,
    /// Blob grants, parallel to `modules`. A module that did not make the
    /// order holds no grant, so nothing can read state for a module that is
    /// not running.
    grants: Vec<[BlobGrant; BLOB_KINDS]>,
}

impl Framework {
    /// Resolve the order and allocate every module's per-object state.
    /// # C: O(modules * list)
    ///
    /// Allocation follows the resolved order, not the declaration order, so a
    /// module's region depends only on the modules ahead of it — which is
    /// what lets a module cache its own offset once and keep using it.
    pub fn start(modules: Vec<LsmInfo>, selection: Selection<'_>) -> Self {
        let ordered = resolve(&modules, selection);
        let mut sizes = BlobSizes::new();
        let mut grants = alloc::vec![[BlobGrant::default(); BLOB_KINDS]; modules.len()];
        for at in ordered.active.iter().copied() { grants[at] = sizes.grant(&modules[at].blobs); }
        Self { modules, ordered, sizes, grants }
    }

    /// Every module the kernel knows about, running or not. # C: O(1)
    pub fn modules(&self) -> &[LsmInfo] { &self.modules }

    /// The modules that run, in initialisation order. # C: O(active)
    pub fn active(&self) -> impl Iterator<Item = &LsmInfo> + '_ {
        self.ordered.active.iter().map(|at| &self.modules[*at])
    }

    /// Identities of the running modules, in order. # C: O(active)
    ///
    /// This is the list userspace reads to learn which modules it is subject
    /// to, so it must name every module that answers a hook and no other.
    pub fn id_list(&self) -> Vec<LsmId> { self.active().map(|m| m.id).collect() }

    /// How many modules run. # C: O(1)
    pub fn active_count(&self) -> usize { self.ordered.active.len() }

    /// Whether a module runs. # C: O(modules)
    pub fn is_active(&self, id: u64) -> bool {
        self.index_of(id).is_some_and(|at| self.ordered.is_active(at))
    }

    /// A running module's place in the order. # C: O(modules)
    ///
    /// Every hook registration carries this, so the hook lists are ordered by
    /// the boot line rather than by whichever module happened to initialise
    /// first.
    pub fn position(&self, id: u64) -> Option<u16> {
        let at = self.index_of(id)?;
        self.ordered.position(at).map(|p| p as u16)
    }

    /// Why a module is not running. # C: O(modules)
    pub fn skipped(&self, id: u64) -> Option<Skipped> {
        self.index_of(id).and_then(|at| self.ordered.skipped[at])
    }

    /// One module's region within a shared object. # C: O(modules)
    ///
    /// `None` when the module does not run or asked for nothing on this kind.
    /// A caller reading state must treat that as "this module has no state
    /// here", never as slot zero — slot zero belongs to another module.
    pub fn grant(&self, id: u64, kind: BlobKind) -> Option<BlobGrant> {
        let at = self.index_of(id)?;
        if !self.ordered.is_active(at) { return None; }
        let grant = self.grants[at][kind.index()];
        grant.present.then_some(grant)
    }

    /// One module's slot index on an object kind. # C: O(modules)
    pub fn blob_slot(&self, id: u64, kind: BlobKind) -> Option<u16> {
        self.grant(id, kind).map(|g| g.slot)
    }

    /// Total per-object allocation across every running module. # C: O(1)
    pub fn sizes(&self) -> &BlobSizes { &self.sizes }

    /// Slots a shared object of this kind must carry. # C: O(1)
    pub fn slots(&self, kind: BlobKind) -> usize { self.sizes.slots(kind) as usize }

    fn index_of(&self, id: u64) -> Option<usize> {
        self.modules.iter().position(|m| m.id.id == id)
    }
}

#[cfg(test)]
#[path = "tests/framework.rs"]
mod tests;
