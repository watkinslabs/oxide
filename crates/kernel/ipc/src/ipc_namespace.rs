//! Canonical IPC namespace ownership boundary. Callers retain the exact
//! namespace while deriving its numeric registry key; final drop reaps every
//! namespace-keyed IPC registry.

use namespace_identity::{NamespaceId, NamespaceKind, NamespaceRef};

pub(crate) struct IpcOwner {
    namespace: NamespaceRef,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum OwnerError { Kind, Missing }

impl IpcOwner {
    fn try_from(namespace: NamespaceRef) -> Result<Self, OwnerError> {
        if namespace.kind() != NamespaceKind::Ipc { return Err(OwnerError::Kind); }
        namespace.register_finalizer(finalize);
        Ok(Self { namespace })
    }

    /// Internal table key derived from this retained exact owner. # C: O(1)
    pub(crate) fn key(&self) -> NamespaceId { self.namespace.id() }
}

/// Snapshot and retain the exact current IPC namespace owner. # C: O(1)
pub(crate) fn current() -> Result<IpcOwner, OwnerError> {
    let namespace = match sched::current() {
        Some(task) => task.namespace_owner(NamespaceKind::Ipc).ok_or(OwnerError::Missing)?,
        None => namespace_identity::initial(NamespaceKind::Ipc),
    };
    IpcOwner::try_from(namespace)
}

fn finalize(kind: NamespaceKind, id: NamespaceId) {
    if kind != NamespaceKind::Ipc { return; }
    crate::sysv_shm::reap_namespace(id);
    test_reap(0, id);
    reap_sem(id);
    reap_msg(id);
    reap_mq(id);
}

/// `sysv::sem` and `sysv::msg` both compile on either target, so each gets one
/// arm covering kernel and hosted; `test_reap` keeps the per-table accounting
/// the hosted finalize test asserts.
fn reap_sem(id: NamespaceId) {
    crate::sysv::sem::reap_namespace(id);
    test_reap(1, id);
}

fn reap_msg(id: NamespaceId) {
    crate::sysv::msg::reap_namespace(id);
    test_reap(2, id);
}

#[cfg(target_os = "oxide-kernel")]
fn reap_mq(id: NamespaceId) { crate::live::posix_mq::reap_namespace(id); }

#[cfg(not(target_os = "oxide-kernel"))]
fn reap_mq(id: NamespaceId) { test_reap(3, id); }

#[cfg(not(target_os = "oxide-kernel"))]
fn test_reap(_table: usize, _id: NamespaceId) {
    #[cfg(test)]
    tests::record_table_reap(_table, _id);
}

#[cfg(target_os = "oxide-kernel")]
fn test_reap(_table: usize, _id: NamespaceId) {}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::Mutex;
    use namespace_identity::{allocate, lookup};
    use super::*;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static FINAL_DROPS: AtomicUsize = AtomicUsize::new(0);
    static REAP_ID: AtomicU64 = AtomicU64::new(0);
    static TABLE_REAPS: [AtomicUsize; 4] = [
        AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0),
        AtomicUsize::new(0),
    ];

    pub(super) fn record_table_reap(table: usize, id: NamespaceId) {
        if id.as_u64() == REAP_ID.load(Ordering::Acquire) {
            TABLE_REAPS[table].fetch_add(1, Ordering::AcqRel);
        }
    }

    fn count_final_drop(kind: NamespaceKind, _id: NamespaceId) {
        assert_eq!(kind, NamespaceKind::Ipc);
        FINAL_DROPS.fetch_add(1, Ordering::AcqRel);
    }

    fn task(tid: u32) -> sched::Task {
        sched::Task::new(tid, "ipc-namespace-owner",
            sched::SchedClass::Normal { weight: 1024 })
    }

    fn owner(task: &sched::Task) -> IpcOwner {
        IpcOwner::try_from(task.namespace_owner(NamespaceKind::Ipc).unwrap()).unwrap()
    }

    #[test]
    fn typed_owner_rejects_non_ipc_identity_without_substitution() {
        let _serial = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let uts = allocate(NamespaceKind::Uts,
            namespace_identity::initial(NamespaceKind::User), None).unwrap();
        let id = uts.id();
        assert!(matches!(IpcOwner::try_from(uts), Err(OwnerError::Kind)));
        assert!(lookup(NamespaceKind::Uts, id).is_none(),
            "rejected owner is not retained or replaced with initial IPC");
    }

    #[test]
    fn exact_owner_controls_sharing_isolation_and_final_cleanup() {
        let _serial = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        FINAL_DROPS.store(0, Ordering::Release);
        let first = task(8651);
        let peer = task(8652);
        let isolated = task(8653);
        let user = first.namespace_owner(NamespaceKind::User).unwrap();
        let shared = allocate(NamespaceKind::Ipc, user.clone(), None).unwrap();
        let separate = allocate(NamespaceKind::Ipc, user, None).unwrap();
        let shared_id = shared.id();
        let separate_id = separate.id();
        REAP_ID.store(shared_id.as_u64(), Ordering::Release);
        for count in &TABLE_REAPS { count.store(0, Ordering::Release); }
        shared.register_finalizer(count_final_drop);
        separate.register_finalizer(count_final_drop);
        assert!(first.replace_namespace(shared.clone()).is_ok());
        assert!(peer.replace_namespace(shared.clone()).is_ok());
        assert!(isolated.replace_namespace(separate.clone()).is_ok());

        let first_owner = owner(&first);
        let peer_owner = owner(&peer);
        let isolated_owner = owner(&isolated);
        assert!(NamespaceRef::ptr_eq(&first_owner.namespace, &peer_owner.namespace), "shared tasks retain one exact owner");
        assert_eq!(first_owner.key(), peer_owner.key());
        assert!(!NamespaceRef::ptr_eq(&first_owner.namespace, &isolated_owner.namespace), "distinct owners isolate state");
        assert_ne!(first_owner.key(), isolated_owner.key());

        let nsfd = first_owner.namespace.clone();
        let snapshot = first_owner.namespace.clone();
        drop(first_owner);
        drop(peer_owner);
        drop(shared);
        first.release_namespaces();
        peer.release_namespaces();
        assert!(lookup(NamespaceKind::Ipc, shared_id).is_some(), "nsfd and snapshot retain owner");
        assert_eq!(FINAL_DROPS.load(Ordering::Acquire), 0);
        drop(nsfd);
        assert!(lookup(NamespaceKind::Ipc, shared_id).is_some(), "snapshot delays cleanup");
        drop(snapshot);
        assert!(lookup(NamespaceKind::Ipc, shared_id).is_none(), "dead owner cannot be reconstructed");
        assert_eq!(FINAL_DROPS.load(Ordering::Acquire), 1, "shared owner finalizes exactly once");
        assert_eq!(TABLE_REAPS.each_ref().map(|count| count.load(Ordering::Acquire)), [1, 1, 1, 1],
            "shm, sem, msg, and mq tables each receive one exact-owner cleanup");

        drop(isolated_owner);
        drop(separate);
        isolated.release_namespaces();
        assert!(lookup(NamespaceKind::Ipc, separate_id).is_none());
        assert_eq!(FINAL_DROPS.load(Ordering::Acquire), 2, "each exact owner finalizes once");
    }
}
