use alloc::vec::Vec;
use syscall::errno::Errno;

/// Inherit one retained namespace set and publish clone-time replacements.
/// # C: O(snapshotted mount entries)
pub(super) fn inherit_and_publish(parent: &sched::Task, child: &sched::Task, flags: u64,
    parent_visible_tid: u32)
    -> Result<(), Errno>
{
    let snapshot = parent.namespace_snapshot().ok_or(Errno::Esrch)?;
    let net_namespace = parent.network_namespace_snapshot().ok_or(Errno::Esrch)?;
    let bits = crate::s272_unshare::ns_bits_from_flags(flags);
    crate::s272_unshare::apply_new_namespaces(child, snapshot, Some(net_namespace), bits, false,
        crate::s272_unshare::NamespaceChange::CloneChild {
            share_vm: (flags & super::CLONE_VM) != 0,
        })?;

    let namespace = child.namespace_owner(namespace_identity::NamespaceKind::Pid)
        .ok_or(Errno::Esrch)?;
    let mut depth = 1usize;
    let mut ancestor = namespace.parent();
    while let Some(current) = ancestor {
        depth += 1;
        ancestor = current.parent();
    }
    let inner = child.vtid.load(core::sync::atomic::Ordering::Acquire);
    let mut numbers = Vec::with_capacity(depth);
    numbers.push(inner);
    numbers.resize(depth, parent_visible_tid);
    child.configure_pid_mappings(&numbers).map_err(|_| Errno::Eio)
}
