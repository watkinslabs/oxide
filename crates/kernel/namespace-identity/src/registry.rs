use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::identity::{Namespace, NamespaceId, NamespaceKind, NamespaceRef, Owner};
use crate::sync::SpinLock;
use crate::uapi::{FIRST_DYNAMIC_NSFS_INO, TIME_INIT_NSFS_INO};

const INIT_ID: NamespaceId = NamespaceId(0);
const FIRST_DYNAMIC_ID: u64 = 1;
const MAX_DYNAMIC_ID: u64 = TIME_INIT_NSFS_INO - FIRST_DYNAMIC_NSFS_INO - 1;

struct Registry {
    initial: BTreeMap<NamespaceKind, NamespaceRef>,
    by_id: BTreeMap<(NamespaceKind, NamespaceId), Weak<Namespace>>,
    by_nsfs_ino: BTreeMap<u64, Weak<Namespace>>,
}

impl Registry {
    const fn new() -> Self {
        Self {
            initial: BTreeMap::new(),
            by_id: BTreeMap::new(),
            by_nsfs_ino: BTreeMap::new(),
        }
    }

    fn publish(&mut self, namespace: &NamespaceRef) {
        let weak = Arc::downgrade(namespace);
        self.by_id.insert((namespace.kind, namespace.id), Weak::clone(&weak));
        self.by_nsfs_ino.insert(namespace.nsfs_ino, weak);
    }
}

static NEXT_ID: AtomicU64 = AtomicU64::new(FIRST_DYNAMIC_ID);
static NEXT_NSFS_INO: AtomicU64 = AtomicU64::new(FIRST_DYNAMIC_NSFS_INO);
static REGISTRY: SpinLock<Registry> = SpinLock::new(Registry::new());

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AllocError { IdExhausted, OwnerNotUserNamespace, ParentKindMismatch }

fn next_id() -> Result<NamespaceId, AllocError> {
    let mut current = NEXT_ID.load(Ordering::Relaxed);
    loop {
        if current > MAX_DYNAMIC_ID { return Err(AllocError::IdExhausted); }
        match NEXT_ID.compare_exchange_weak(current, current + 1,
            Ordering::Relaxed, Ordering::Relaxed)
        {
            Ok(_) => return Ok(NamespaceId(current)),
            Err(observed) => current = observed,
        }
    }
}

/// Allocate a globally unique dynamic nsfs inode for an external owner such as
/// VFS's canonical mount namespace object. # C: O(1)
pub fn allocate_nsfs_ino() -> Result<u64, AllocError> {
    let mut current = NEXT_NSFS_INO.load(Ordering::Relaxed);
    loop {
        if current == u64::MAX { return Err(AllocError::IdExhausted); }
        match NEXT_NSFS_INO.compare_exchange_weak(current, current + 1,
            Ordering::Relaxed, Ordering::Relaxed)
        {
            Ok(_) => return Ok(current),
            Err(observed) => current = observed,
        }
    }
}

fn initialize(registry: &mut Registry) {
    if !registry.initial.is_empty() { return; }
    let user = Arc::new(Namespace {
        kind: NamespaceKind::User,
        id: INIT_ID,
        nsfs_ino: NamespaceKind::User.initial_nsfs_ino(),
        owner_user_namespace: Owner::InitialUser,
        parent: None,
    });
    registry.publish(&user);
    registry.initial.insert(NamespaceKind::User, Arc::clone(&user));
    for kind in [NamespaceKind::Cgroup, NamespaceKind::Ipc, NamespaceKind::Pid,
        NamespaceKind::Time, NamespaceKind::Uts]
    {
        let namespace = Arc::new(Namespace {
            kind,
            id: INIT_ID,
            nsfs_ino: kind.initial_nsfs_ino(),
            owner_user_namespace: Owner::Ref(Arc::clone(&user)),
            parent: None,
        });
        registry.publish(&namespace);
        registry.initial.insert(kind, namespace);
    }
}

/// Return the canonical initial owner for `kind`.
/// # C: O(log N)
/// # Ctx: any; caller must not invoke from final-drop hooks
/// # Lk: takes private namespace-identity registry lock
/// # Sleeps: no
pub fn initial(kind: NamespaceKind) -> NamespaceRef {
    let mut registry = REGISTRY.lock();
    initialize(&mut registry);
    Arc::clone(registry.initial.get(&kind).expect("all initial kinds published"))
}

/// Allocate a canonical non-init namespace and publish weak indexes.
/// # C: O(log N)
/// # Ctx: any; caller must not invoke from final-drop hooks
/// # Lk: takes private namespace-identity registry lock
/// # Sleeps: no
pub fn allocate(kind: NamespaceKind, owner_user_namespace: NamespaceRef,
    parent: Option<NamespaceRef>) -> Result<NamespaceRef, AllocError>
{
    if owner_user_namespace.kind != NamespaceKind::User {
        return Err(AllocError::OwnerNotUserNamespace);
    }
    if parent.as_ref().is_some_and(|owner| owner.kind != kind) {
        return Err(AllocError::ParentKindMismatch);
    }
    let id = next_id()?;
    let namespace = Arc::new(Namespace {
        kind,
        id,
        nsfs_ino: allocate_nsfs_ino()?,
        owner_user_namespace: Owner::Ref(owner_user_namespace),
        parent,
    });
    REGISTRY.lock().publish(&namespace);
    Ok(namespace)
}

/// Retain a live namespace by `(kind,id)` without recreating dead owners.
/// # C: O(log N)
/// # Ctx: any; caller must not invoke from final-drop hooks
/// # Lk: takes private namespace-identity registry lock
/// # Sleeps: no
pub fn lookup(kind: NamespaceKind, id: NamespaceId) -> Option<NamespaceRef> {
    REGISTRY.lock().by_id.get(&(kind, id)).and_then(Weak::upgrade)
}

/// Retain a live namespace by its stable nsfs inode.
/// # C: O(log N)
/// # Ctx: any; caller must not invoke from final-drop hooks
/// # Lk: takes private namespace-identity registry lock
/// # Sleeps: no
pub fn lookup_nsfs_ino(nsfs_ino: u64) -> Option<NamespaceRef> {
    REGISTRY.lock().by_nsfs_ino.get(&nsfs_ino).and_then(Weak::upgrade)
}

/// Snapshot all live namespace identities as retained references.
/// # C: O(N)
/// # Ctx: any; caller must not invoke from final-drop hooks
/// # Lk: takes private namespace-identity registry lock
/// # Sleeps: no
pub fn live_snapshot() -> Vec<NamespaceRef> {
    REGISTRY.lock().by_id.values().filter_map(Weak::upgrade).collect()
}

/// Remove only weak entries that still identify this exact allocation. # C: O(log N)
pub(crate) fn remove(namespace: &Namespace) {
    let pointer = namespace as *const Namespace;
    let mut registry = REGISTRY.lock();
    let key = (namespace.kind, namespace.id);
    if registry.by_id.get(&key).is_some_and(|weak| weak.as_ptr() == pointer) {
        registry.by_id.remove(&key);
    }
    if registry.by_nsfs_ino.get(&namespace.nsfs_ino)
        .is_some_and(|weak| weak.as_ptr() == pointer)
    {
        registry.by_nsfs_ino.remove(&namespace.nsfs_ino);
    }
}

#[cfg(test)]
/// Current weak-index sizes for exact cleanup assertions. # C: O(1)
pub(crate) fn index_lengths() -> (usize, usize) {
    let registry = REGISTRY.lock();
    (registry.by_id.len(), registry.by_nsfs_ino.len())
}
