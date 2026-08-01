use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::ops::Bound;
use core::sync::atomic::Ordering;

use crate::identity::{Namespace, NamespaceId, NamespaceKind, NamespacePin, NamespaceRef, NsId,
    Owner};
use crate::sync::SpinLock;
use crate::uapi::{FIRST_DYNAMIC_NSFS_INO, FIRST_DYNAMIC_NS_ID};

const INIT_ID: NamespaceId = NamespaceId(0);
const FIRST_DYNAMIC_ID: u64 = 1;

struct Registry {
    initial: BTreeMap<NamespaceKind, NamespacePin>,
    lifetime_by_id: BTreeMap<(NamespaceKind, NamespaceId), Weak<Namespace>>,
    lifetime_by_ino: BTreeMap<u64, Weak<Namespace>>,
    active_global: BTreeMap<NsId, Weak<Namespace>>,
    active_kind: BTreeMap<(NamespaceKind, NsId), Weak<Namespace>>,
    active_owner: BTreeMap<(NsId, NsId), Weak<Namespace>>,
    next_id: [u64; 8],
    next_ns_id: u64,
    next_nsfs_ino: u64,
}

impl Registry {
    const fn new() -> Self {
        Self {
            initial: BTreeMap::new(), lifetime_by_id: BTreeMap::new(),
            lifetime_by_ino: BTreeMap::new(), active_global: BTreeMap::new(),
            active_kind: BTreeMap::new(), active_owner: BTreeMap::new(),
            next_id: [FIRST_DYNAMIC_ID; 8], next_ns_id: FIRST_DYNAMIC_NS_ID,
            next_nsfs_ino: FIRST_DYNAMIC_NSFS_INO,
        }
    }

    fn owner_ns_id(namespace: &Namespace) -> NsId {
        match &namespace.owner_user_namespace {
            Owner::InitialUser => namespace.ns_id,
            Owner::Ref(owner) => owner.ns_id,
        }
    }

    fn publish_lifetime(&mut self, namespace: &Arc<Namespace>) {
        let weak = Arc::downgrade(namespace);
        self.lifetime_by_id.insert((namespace.kind, namespace.id), Weak::clone(&weak));
        self.lifetime_by_ino.insert(namespace.nsfs_ino, weak);
    }

    fn publish_active(&mut self, namespace: &Arc<Namespace>) {
        let weak = Arc::downgrade(namespace);
        self.active_global.insert(namespace.ns_id, Weak::clone(&weak));
        self.active_kind.insert((namespace.kind, namespace.ns_id), Weak::clone(&weak));
        if namespace.kind != NamespaceKind::User || !namespace.is_initial() {
            self.active_owner.insert((Self::owner_ns_id(namespace), namespace.ns_id), weak);
        }
    }

    fn remove_active(&mut self, namespace: &Namespace) {
        self.active_global.remove(&namespace.ns_id);
        self.active_kind.remove(&(namespace.kind, namespace.ns_id));
        self.active_owner.remove(&(Self::owner_ns_id(namespace), namespace.ns_id));
    }

    fn next_id(&mut self, kind: NamespaceKind) -> Result<NamespaceId, AllocError> {
        let next = &mut self.next_id[kind.slot()];
        if *next == u64::MAX { return Err(AllocError::IdExhausted); }
        let id = NamespaceId(*next); *next += 1; Ok(id)
    }

    fn next_ns_id(&mut self) -> Result<NsId, AllocError> {
        if self.next_ns_id == u64::MAX { return Err(AllocError::IdExhausted); }
        let id = NsId(self.next_ns_id); self.next_ns_id += 1; Ok(id)
    }

    fn next_nsfs_ino(&mut self) -> Result<u64, AllocError> {
        if self.next_nsfs_ino == u64::MAX { return Err(AllocError::IdExhausted); }
        let ino = self.next_nsfs_ino; self.next_nsfs_ino += 1; Ok(ino)
    }
}

static REGISTRY: SpinLock<Registry> = SpinLock::new(Registry::new());

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AllocError { IdExhausted, OwnerNotUserNamespace, ParentKindMismatch }

fn initialize(registry: &mut Registry) {
    if !registry.initial.is_empty() { return; }
    let user = Arc::new(Namespace {
        kind: NamespaceKind::User, id: INIT_ID,
        ns_id: NamespaceKind::User.initial_ns_id(),
        nsfs_ino: NamespaceKind::User.initial_nsfs_ino(),
        owner_user_namespace: Owner::InitialUser, parent: None,
        pid_memfd_noexec_scope: core::sync::atomic::AtomicU8::new(0),
        pid_numbers: crate::pid_numbers::PidNumberSpace::for_kind(NamespaceKind::User, true),
        active: core::sync::atomic::AtomicUsize::new(1), finalizers: SpinLock::new(Vec::new()),
    });
    registry.publish_lifetime(&user);
    registry.publish_active(&user);
    registry.initial.insert(NamespaceKind::User, NamespacePin::from_arc(Arc::clone(&user)));
    for kind in NamespaceKind::ALL {
        if kind == NamespaceKind::User { continue; }
        let namespace = Arc::new(Namespace {
            kind, id: INIT_ID, ns_id: kind.initial_ns_id(), nsfs_ino: kind.initial_nsfs_ino(),
            owner_user_namespace: Owner::Ref(NamespacePin::from_arc(Arc::clone(&user))),
            parent: None, pid_memfd_noexec_scope: core::sync::atomic::AtomicU8::new(0),
            pid_numbers: crate::pid_numbers::PidNumberSpace::for_kind(kind, true),
            active: core::sync::atomic::AtomicUsize::new(1),
            finalizers: SpinLock::new(Vec::new()),
        });
        registry.publish_lifetime(&namespace);
        registry.publish_active(&namespace);
        registry.initial.insert(kind, NamespacePin::from_arc(namespace));
    }
}

fn acquire_locked(registry: &mut Registry, inner: Arc<Namespace>) -> NamespaceRef {
    if inner.is_initial() { return NamespaceRef::new(inner); }
    if inner.active.fetch_add(1, Ordering::Relaxed) == 0 {
        if let Owner::Ref(owner) = &inner.owner_user_namespace {
            acquire_count_locked(registry, &owner.inner);
        }
        registry.publish_active(&inner);
    }
    NamespaceRef::new(inner)
}

fn acquire_count_locked(registry: &mut Registry, inner: &Arc<Namespace>) {
    if inner.is_initial() { return; }
    if inner.active.fetch_add(1, Ordering::Relaxed) != 0 { return; }
    if let Owner::Ref(owner) = &inner.owner_user_namespace {
        acquire_count_locked(registry, &owner.inner);
    }
    registry.publish_active(inner);
}

pub(crate) fn acquire_active(inner: Arc<Namespace>) -> NamespaceRef {
    acquire_locked(&mut REGISTRY.lock(), inner)
}

pub(crate) fn clone_active(owner: &NamespaceRef) -> NamespaceRef {
    acquire_active(Arc::clone(&owner.inner))
}

pub(crate) fn get_active(inner: &Arc<Namespace>) -> Option<NamespaceRef> {
    let mut registry = REGISTRY.lock();
    if !inner.is_initial() && inner.active.load(Ordering::Relaxed) == 0 { return None; }
    Some(acquire_locked(&mut registry, Arc::clone(inner)))
}

pub(crate) fn upgrade_pin(owner: &Weak<Namespace>) -> Option<NamespacePin> {
    let mut rejected = None;
    let result = {
        let _registry = REGISTRY.lock();
        match owner.upgrade() {
            Some(inner) if inner.active.load(Ordering::Relaxed) != 0 =>
                Some(NamespacePin::from_arc(inner)),
            Some(inner) => { rejected = Some(inner); None }
            None => None,
        }
    };
    drop(rejected);
    result
}

pub(crate) fn release_active(inner: &Arc<Namespace>) {
    if inner.is_initial() { return; }
    let mut registry = REGISTRY.lock();
    release_count_locked(&mut registry, inner);
}

fn release_count_locked(registry: &mut Registry, inner: &Arc<Namespace>) {
    if inner.is_initial() { return; }
    let previous = inner.active.fetch_sub(1, Ordering::Relaxed);
    debug_assert!(previous > 0);
    if previous != 1 { return; }
    registry.remove_active(inner);
    if let Owner::Ref(owner) = &inner.owner_user_namespace {
        release_count_locked(registry, &owner.inner);
    }
}

/// Allocate one standalone Linux global namespace-tree ID. # C: O(1)
pub fn allocate_ns_id() -> Result<NsId, AllocError> { REGISTRY.lock().next_ns_id() }
/// Allocate one standalone globally unique nsfs inode. # C: O(1)
pub fn allocate_nsfs_ino() -> Result<u64, AllocError> { REGISTRY.lock().next_nsfs_ino() }

/// Return the canonical initial owner for `kind`. # C: O(log N)
pub fn initial(kind: NamespaceKind) -> NamespaceRef {
    initial_pin(kind).activate()
}

pub(crate) fn initial_pin(kind: NamespaceKind) -> NamespacePin {
    let mut registry = REGISTRY.lock(); initialize(&mut registry);
    registry.initial.get(&kind).expect("all initial kinds published").clone()
}

/// Allocate and activate one canonical non-init namespace. # C: O(log N)
pub fn allocate(kind: NamespaceKind, owner_user_namespace: NamespaceRef,
    parent: Option<NamespaceRef>) -> Result<NamespaceRef, AllocError>
{
    if owner_user_namespace.kind != NamespaceKind::User {
        return Err(AllocError::OwnerNotUserNamespace);
    }
    if parent.as_ref().is_some_and(|owner| owner.kind != kind) {
        return Err(AllocError::ParentKindMismatch);
    }
    let owner = owner_user_namespace.pin();
    let parent = parent.as_ref().map(NamespaceRef::pin);
    let pin = allocate_inactive_inner(kind, owner, parent)?;
    Ok(pin.activate())
}

/// Allocate one canonical inactive identity for a separately published owner. # C: O(log N)
pub fn allocate_inactive(kind: NamespaceKind, owner_user_namespace: NamespaceRef,
    parent: Option<NamespaceRef>) -> Result<NamespacePin, AllocError>
{
    if owner_user_namespace.kind != NamespaceKind::User {
        return Err(AllocError::OwnerNotUserNamespace);
    }
    if parent.as_ref().is_some_and(|owner| owner.kind != kind) {
        return Err(AllocError::ParentKindMismatch);
    }
    allocate_inactive_inner(kind, owner_user_namespace.pin(),
        parent.as_ref().map(NamespaceRef::pin))
}

fn allocate_inactive_inner(kind: NamespaceKind, owner: NamespacePin,
    parent: Option<NamespacePin>) -> Result<NamespacePin, AllocError>
{
    let mut registry = REGISTRY.lock(); initialize(&mut registry);
    let pid_memfd_noexec_scope = if kind == NamespaceKind::Pid {
        parent.as_ref().map_or(0, |namespace| {
            namespace.pid_memfd_noexec_scope()
                .expect("validated PID namespace parent")
        })
    } else {
        0
    };
    let namespace = Arc::new(Namespace {
        kind, id: registry.next_id(kind)?, ns_id: registry.next_ns_id()?,
        nsfs_ino: registry.next_nsfs_ino()?, owner_user_namespace: Owner::Ref(owner),
        parent, pid_memfd_noexec_scope: core::sync::atomic::AtomicU8::new(
            pid_memfd_noexec_scope),
        pid_numbers: crate::pid_numbers::PidNumberSpace::for_kind(kind, false),
        active: core::sync::atomic::AtomicUsize::new(0),
        finalizers: SpinLock::new(Vec::new()),
    });
    registry.publish_lifetime(&namespace);
    Ok(NamespacePin::from_arc(namespace))
}

fn active_from_weak(weak: &Weak<Namespace>) -> Option<NamespacePin> {
    upgrade_pin(weak)
}

pub fn lookup(kind: NamespaceKind, id: NamespaceId) -> Option<NamespacePin> {
    let weak = REGISTRY.lock().lifetime_by_id.get(&(kind, id))?.clone();
    active_from_weak(&weak)
}

pub fn lookup_nsfs_ino(nsfs_ino: u64) -> Option<NamespacePin> {
    let weak = REGISTRY.lock().lifetime_by_ino.get(&nsfs_ino)?.clone();
    active_from_weak(&weak)
}

pub fn lookup_ns_id(ns_id: NsId) -> Option<NamespacePin> {
    let weak = REGISTRY.lock().active_global.get(&ns_id)?.clone();
    active_from_weak(&weak)
}

fn page(weak: Vec<Weak<Namespace>>, capacity: usize) -> Vec<NamespacePin>
{
    weak.into_iter().filter_map(|owner| active_from_weak(&owner)).take(capacity).collect()
}

pub fn active_page(cursor: NsId, capacity: usize) -> Vec<NamespacePin> {
    let weak = REGISTRY.lock().active_global.range((Bound::Excluded(cursor), Bound::Unbounded))
        .map(|(_, owner)| owner.clone()).collect();
    page(weak, capacity)
}

pub fn active_kind_page(kind: NamespaceKind, cursor: NsId, capacity: usize)
    -> Vec<NamespacePin>
{
    let weak = REGISTRY.lock().active_kind.range((Bound::Excluded((kind, cursor)),
        Bound::Included((kind, NsId(u64::MAX)))))
        .map(|(_, owner)| owner.clone()).collect();
    page(weak, capacity)
}

pub fn active_owner_page(owner: &NamespacePin, cursor: NsId, capacity: usize)
    -> Vec<NamespacePin>
{
    let owner_id = owner.ns_id;
    let weak = REGISTRY.lock().active_owner.range((Bound::Excluded((owner_id, cursor)),
        Bound::Included((owner_id, NsId(u64::MAX)))))
        .map(|(_, child)| child.clone()).collect();
    page(weak, capacity)
}

pub fn live_snapshot() -> Vec<NamespacePin> { active_page(NsId(0), usize::MAX) }

pub(crate) fn remove(namespace: &Namespace) {
    let pointer = namespace as *const Namespace;
    let mut registry = REGISTRY.lock();
    let key = (namespace.kind, namespace.id);
    if registry.lifetime_by_id.get(&key).is_some_and(|weak| weak.as_ptr() == pointer) {
        registry.lifetime_by_id.remove(&key);
    }
    if registry.lifetime_by_ino.get(&namespace.nsfs_ino)
        .is_some_and(|weak| weak.as_ptr() == pointer)
    { registry.lifetime_by_ino.remove(&namespace.nsfs_ino); }
}
