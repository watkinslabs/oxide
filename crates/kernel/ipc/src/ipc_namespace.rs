//! Canonical IPC namespace ownership boundary. Callers retain the exact
//! namespace while deriving its numeric registry key; final drop reaps every
//! namespace-keyed IPC registry.

use namespace_identity::{NamespaceId, NamespaceKind, NamespaceRef};

fn register(namespace: NamespaceRef) -> NamespaceRef {
    assert!(namespace.kind() == NamespaceKind::Ipc,
        "IPC state requires an IPC namespace owner");
    namespace.register_finalizer(finalize);
    namespace
}

/// Snapshot and retain the exact current IPC namespace owner. # C: O(1)
pub(crate) fn current() -> NamespaceRef {
    let namespace = sched::current()
        .and_then(|task| task.namespace_owner(NamespaceKind::Ipc))
        .unwrap_or_else(|| namespace_identity::initial(NamespaceKind::Ipc));
    register(namespace)
}

/// Derive the internal registry key from a retained IPC owner. # C: O(1)
pub(crate) fn table_key(namespace: &NamespaceRef) -> NamespaceId {
    assert!(namespace.kind() == NamespaceKind::Ipc,
        "IPC table key requires an IPC namespace owner");
    namespace.id()
}

fn finalize(kind: NamespaceKind, id: NamespaceId) {
    if kind != NamespaceKind::Ipc { return; }
    crate::sysv_shm::reap_namespace(id);
    test_reap(0, id);
    reap_sem(id);
    reap_msg(id);
    reap_mq(id);
}

#[cfg(target_os = "oxide-kernel")]
fn reap_sem(id: NamespaceId) { crate::live::sysv_sem::reap_namespace(id); }
#[cfg(target_os = "oxide-kernel")]
fn reap_msg(id: NamespaceId) { crate::live::sysv_msg::reap_namespace(id); }
#[cfg(target_os = "oxide-kernel")]
fn reap_mq(id: NamespaceId) { crate::live::posix_mq::reap_namespace(id); }

#[cfg(not(target_os = "oxide-kernel"))]
fn reap_sem(id: NamespaceId) { test_reap(1, id); }
#[cfg(not(target_os = "oxide-kernel"))]
fn reap_msg(id: NamespaceId) { test_reap(2, id); }
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
    use alloc::sync::Arc;
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

    fn owner(task: &sched::Task) -> NamespaceRef {
        register(task.namespace_owner(NamespaceKind::Ipc).unwrap())
    }

    #[test]
    fn exact_owner_controls_sharing_isolation_and_final_cleanup() {
        let _serial = TEST_LOCK.lock().unwrap();
        FINAL_DROPS.store(0, Ordering::Release);
        let first = task(8651);
        let peer = task(8652);
        let isolated = task(8653);
        let user = first.namespace_owner(NamespaceKind::User).unwrap();
        let shared = allocate(NamespaceKind::Ipc, Arc::clone(&user), None).unwrap();
        let separate = allocate(NamespaceKind::Ipc, user, None).unwrap();
        let shared_id = shared.id();
        let separate_id = separate.id();
        REAP_ID.store(shared_id.as_u64(), Ordering::Release);
        for count in &TABLE_REAPS { count.store(0, Ordering::Release); }
        shared.register_finalizer(count_final_drop);
        separate.register_finalizer(count_final_drop);
        assert!(first.replace_namespace(Arc::clone(&shared)).is_ok());
        assert!(peer.replace_namespace(Arc::clone(&shared)).is_ok());
        assert!(isolated.replace_namespace(Arc::clone(&separate)).is_ok());

        let first_owner = owner(&first);
        let peer_owner = owner(&peer);
        let isolated_owner = owner(&isolated);
        assert!(Arc::ptr_eq(&first_owner, &peer_owner), "shared tasks retain one exact owner");
        assert_eq!(table_key(&first_owner), table_key(&peer_owner));
        assert!(!Arc::ptr_eq(&first_owner, &isolated_owner), "distinct owners isolate state");
        assert_ne!(table_key(&first_owner), table_key(&isolated_owner));

        let nsfd = Arc::clone(&first_owner);
        let snapshot = Arc::clone(&first_owner);
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
