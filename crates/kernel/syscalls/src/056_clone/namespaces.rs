use core::sync::atomic::Ordering;

use syscall::errno::Errno;

/// Inherit parent namespaces and publish clone-time replacements. # C: O(snapshotted entries)
pub(super) fn inherit_and_publish(parent: &sched::Task, child: &sched::Task, flags: u64)
    -> Result<(), Errno>
{
    let net_namespace = parent.network_namespace_snapshot().ok_or(Errno::Esrch)?;
    child.replace_network_namespace(net_namespace).map_err(|_| Errno::Esrch)?;
    // Namespaces inherit across clone/fork (Linux `copy_namespaces`): the
    // child shares the parent's namespaces unless clone requests CLONE_NEW*.
    child.ns_membership.store(parent.ns_membership.load(Ordering::Acquire), Ordering::Release);
    child.ipc_ns.store(parent.ipc_ns.load(Ordering::Acquire), Ordering::Release);
    child.user_ns.store(parent.user_ns.load(Ordering::Acquire), Ordering::Release);
    child.parent_user_ns.store(parent.parent_user_ns.load(Ordering::Acquire), Ordering::Release);
    child.cgroup_ns.store(parent.cgroup_ns.load(Ordering::Acquire), Ordering::Release);
    child.mount_ns.store(parent.mount_ns.load(Ordering::Acquire), Ordering::Release);
    // UTS identity is shared until clone-time CLONE_NEWUTS replaces it.
    child.uts_ns.store(parent.uts_ns.load(Ordering::Acquire), Ordering::Release);

    let new_ns_bits = crate::s272_unshare::ns_bits_from_flags(flags);
    if new_ns_bits != 0 {
        crate::s272_unshare::apply_new_namespaces(child, new_ns_bits)?;
        child.ns_membership.fetch_or(new_ns_bits, Ordering::Release);
    }
    vfs::mntns::mnt_ns_enter(child.mount_ns.load(Ordering::Acquire));
    Ok(())
}
