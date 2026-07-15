pub(crate) static LIFETIME_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub(crate) fn finish_claimed(stack: &crate::NetStack,
    ids: &[network_namespace::NetworkNamespaceId])
{
    for id in ids {
        let _ = super::destroy_namespace_into(stack, id.as_u64());
        assert!(network_namespace::finish_teardown(*id));
    }
}
