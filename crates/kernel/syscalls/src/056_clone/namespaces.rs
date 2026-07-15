use syscall::errno::Errno;

/// Inherit one retained namespace set and publish clone-time replacements.
/// # C: O(snapshotted mount entries)
pub(super) fn inherit_and_publish(parent: &sched::Task, child: &sched::Task, flags: u64)
    -> Result<(), Errno>
{
    let snapshot = parent.namespace_snapshot().ok_or(Errno::Esrch)?;
    let net_namespace = parent.network_namespace_snapshot().ok_or(Errno::Esrch)?;
    let bits = crate::s272_unshare::ns_bits_from_flags(flags);
    crate::s272_unshare::apply_new_namespaces(child, snapshot, Some(net_namespace), bits,
        crate::s272_unshare::NamespaceChange::CloneChild)
}
