pub(crate) static LIFETIME_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Allocate a test network namespace owned by the canonical initial user. # C: O(log N)
pub(crate) fn allocate_namespace() -> network_namespace::NetworkNamespaceRef {
    super::install_final_drop_pending_notifier().expect("install final-drop pending notifier");
    network_namespace::allocate(namespace_identity::initial(namespace_identity::NamespaceKind::User))
        .expect("allocate test network namespace")
}

pub(crate) fn finish_claimed(stack: &crate::NetStack,
    ids: &[network_namespace::NetworkNamespaceId])
{
    for id in ids {
        let _ = super::destroy_namespace_into(stack, id.as_u64());
        assert!(network_namespace::finish_teardown(*id));
    }
}

pub(crate) fn assert_finished(stack: &crate::NetStack,
    id: network_namespace::NetworkNamespaceId)
{
    let ns = id.as_u64();
    assert!(network_namespace::lookup(id).is_none(), "finished namespace leaves registry");
    assert!(!super::NET_NS.lock().contains_key(&ns), "finished namespace leaves state map");
    assert!(!super::destroy_namespace_into(stack, ns), "finished namespace leaves no net state");
    assert!(!network_namespace::finish_teardown(id), "finished namespace leaves no claim");
}
