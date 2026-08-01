// Per-namespace numbering of one PID identity.
//
// A PID identity carries a DISTINCT number in every namespace of the chain it
// belongs to: one for its own namespace, one for that namespace's parent, and
// so on up to the initial namespace. `mappings[0]` is the innermost (own
// namespace) entry and the last is the initial namespace, so the level of an
// entry counted from the initial namespace is `len - 1 - index`.
//
// Numbers are drawn from the namespace that owns them, so a nested namespace
// numbers its tasks from 1 the way a fresh system does, and every number an
// identity took is returned when the identity is dropped.

use alloc::boxed::Box;
use alloc::vec::Vec;

use namespace_identity::{NamespaceKind, NamespacePin, NamespaceRef, NamespaceWeak, PidNumberError};

use super::identity::PidIdentity;

/// One namespace's number for a PID identity.
pub struct PidMapping {
    pub(super) namespace: NamespaceWeak,
    pub(super) nr: u32,
    /// Whether dropping the identity returns `nr` to the namespace. False for
    /// a number the identity recorded but did not take (the initial task's
    /// number, which is permanent, and any number already held).
    pub(super) owned: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PidMappingError {
    AlreadyConfigured,
    Empty,
    InvalidNumber,
    NamespaceKind,
    Ancestry,
    /// Requested number is already naming a live identity in that namespace.
    Exists,
    /// Namespace has no free number left.
    Exhausted,
}

impl PidIdentity {
    /// Number this identity in `namespace` and in every ancestor, innermost
    /// first. `set_tid[i]` names the number at level `i` counted from the
    /// innermost namespace; levels the caller did not name are allocated.
    /// A failure at any level returns every number already taken.
    /// # C: O(depth log N_held)
    pub fn alloc_mappings(&self, namespace: &NamespaceRef, set_tid: &[u32])
        -> Result<Box<[u32]>, PidMappingError>
    {
        let chain = ancestor_chain(namespace)?;
        if set_tid.len() > chain.len() { return Err(PidMappingError::InvalidNumber); }
        let mut taken: Vec<(NamespacePin, u32)> = Vec::with_capacity(chain.len());
        for (level, owner) in chain.iter().enumerate() {
            let requested = set_tid.get(level).copied().unwrap_or(0);
            let outcome = if requested != 0 {
                owner.pid_numbers().reserve(requested).map(|()| requested)
            } else {
                owner.pid_numbers().alloc()
            };
            match outcome {
                Ok(nr) => taken.push((owner.clone(), nr)),
                Err(error) => {
                    for (owner, nr) in taken.iter() { owner.pid_numbers().free(*nr); }
                    return Err(number_error(error));
                }
            }
        }
        let numbers: Box<[u32]> = taken.iter().map(|(_, nr)| *nr).collect();
        let mappings = taken.into_iter().map(|(owner, nr)| PidMapping {
            namespace: NamespacePin::downgrade(&owner), nr, owned: true }).collect();
        self.install_mappings(mappings).map_err(|error| {
            self.free_pending(&chain, &numbers);
            error
        })?;
        Ok(numbers)
    }

    /// Record numbers this identity was stamped with outside the allocator —
    /// the initial task and the kernel threads the boot path names directly.
    /// Each number is claimed in its namespace so the allocator cannot hand it
    /// out again; a number already held is recorded without being claimed.
    /// `numbers[0]` belongs to `namespace`, each following one to its parent.
    /// # C: O(depth log N_held)
    pub fn configure_mappings(&self, namespace: &NamespaceRef, numbers: &[u32])
        -> Result<(), PidMappingError>
    {
        if numbers.is_empty() { return Err(PidMappingError::Empty); }
        if numbers.iter().any(|nr| *nr == 0) { return Err(PidMappingError::InvalidNumber); }
        let chain = ancestor_chain(namespace)?;
        if chain.len() != numbers.len() { return Err(PidMappingError::Ancestry); }
        let mut mappings = Vec::with_capacity(numbers.len());
        for (owner, nr) in chain.iter().zip(numbers.iter()) {
            let owned = owner.pid_numbers().reserve(*nr).is_ok();
            mappings.push(PidMapping {
                namespace: NamespacePin::downgrade(owner), nr: *nr, owned });
        }
        let reclaim: Vec<(usize, u32)> = mappings.iter().enumerate()
            .filter(|(_, mapping)| mapping.owned)
            .map(|(level, mapping)| (level, mapping.nr)).collect();
        self.install_mappings(mappings).map_err(|error| {
            for (level, nr) in reclaim { chain[level].pid_numbers().free(nr); }
            error
        })
    }

    /// The number this identity carries as seen from `namespace`; 0 when
    /// `namespace` does not number it at all (it is not an ancestor-or-self of
    /// the identity's own namespace). # C: O(depth)
    pub fn nr_in(&self, namespace: &NamespaceRef) -> u32 {
        let guard = self.mappings.lock();
        let Some(mappings) = guard.as_ref() else { return 0 };
        let want = namespace.pin();
        for mapping in mappings.iter() {
            let Some(owner) = mapping.namespace.upgrade() else { continue };
            if NamespacePin::ptr_eq(&owner, &want) { return mapping.nr; }
        }
        0
    }

    /// Namespace-visible thread number for one exact live namespace owner.
    /// # C: O(depth)
    pub fn visible_tid(&self, namespace: &NamespaceRef) -> Option<u32> {
        match self.nr_in(namespace) { 0 => None, nr => Some(nr) }
    }

    /// Numbers from `namespace`'s level inward to this identity's own, the
    /// order `/proc/<pid>/status` reports them. Empty when `namespace` does
    /// not number this identity. # C: O(depth)
    pub fn nr_chain_from(&self, namespace: &NamespaceRef) -> Vec<u32> {
        let guard = self.mappings.lock();
        let Some(mappings) = guard.as_ref() else { return Vec::new() };
        let want = namespace.pin();
        let mut index = None;
        for (position, mapping) in mappings.iter().enumerate() {
            let Some(owner) = mapping.namespace.upgrade() else { continue };
            if NamespacePin::ptr_eq(&owner, &want) { index = Some(position); break; }
        }
        let Some(index) = index else { return Vec::new() };
        (0..=index).rev().map(|position| mappings[position].nr).collect()
    }

    /// Live namespace owners this identity is numbered in, innermost first.
    /// # C: O(depth)
    pub fn namespaces(&self) -> Vec<NamespacePin> {
        let guard = self.mappings.lock();
        let Some(mappings) = guard.as_ref() else { return Vec::new() };
        mappings.iter().filter_map(|mapping| mapping.namespace.upgrade()).collect()
    }

    /// Depth of the namespace chain this identity is numbered in; 0 before any
    /// numbering is published. # C: O(1)
    pub fn depth(&self) -> usize {
        self.mappings.lock().as_ref().map_or(0, |mappings| mappings.len())
    }

    /// Whether numbers were published. # C: O(1)
    pub fn mappings_configured(&self) -> bool {
        self.mappings.lock().is_some()
    }

    /// Return every number this identity took to the namespace that owns it.
    /// # C: O(depth log N_held)
    pub(super) fn release_numbers(&self) {
        let Some(mappings) = self.mappings.lock().take() else { return };
        for mapping in mappings.iter() {
            if !mapping.owned { continue }
            let Some(owner) = mapping.namespace.upgrade() else { continue };
            owner.pid_numbers().free(mapping.nr);
        }
    }

    fn install_mappings(&self, mappings: Vec<PidMapping>) -> Result<(), PidMappingError> {
        let mut slot = self.mappings.lock();
        if slot.is_some() { return Err(PidMappingError::AlreadyConfigured); }
        *slot = Some(mappings.into_boxed_slice());
        Ok(())
    }

    fn free_pending(&self, chain: &[NamespacePin], numbers: &[u32]) {
        for (owner, nr) in chain.iter().zip(numbers.iter()) { owner.pid_numbers().free(*nr); }
    }
}

/// `namespace` and every ancestor, innermost first. # C: O(depth)
fn ancestor_chain(namespace: &NamespaceRef) -> Result<Vec<NamespacePin>, PidMappingError> {
    if namespace.kind() != NamespaceKind::Pid { return Err(PidMappingError::NamespaceKind); }
    let mut chain = Vec::new();
    let mut owner = Some(namespace.pin());
    while let Some(current) = owner {
        owner = current.parent();
        chain.push(current);
    }
    Ok(chain)
}

fn number_error(error: PidNumberError) -> PidMappingError {
    match error {
        PidNumberError::NotPidNamespace => PidMappingError::NamespaceKind,
        PidNumberError::OutOfRange => PidMappingError::InvalidNumber,
        PidNumberError::InUse => PidMappingError::Exists,
        PidNumberError::Exhausted => PidMappingError::Exhausted,
    }
}
