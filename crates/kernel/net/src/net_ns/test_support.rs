pub(crate) static LIFETIME_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
