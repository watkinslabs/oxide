use namespace_identity::NamespaceKind;
use syscall::errno::Errno;

/// Inherit one retained namespace set, publish clone-time replacements, then
/// number the child in its own PID namespace and in every ancestor. Returns
/// the child's number as the CALLER's PID namespace sees it — the value
/// `clone` reports and `CLONE_PARENT_SETTID` writes, both of which are read in
/// the caller's namespace, not the child's.
/// # C: O(snapshotted mount entries + pid-ns depth)
pub(super) fn inherit_and_publish(parent: &sched::Task, child: &sched::Task, flags: u64,
    set_tid: &[u32])
    -> Result<u32, Errno>
{
    let snapshot = parent.namespace_snapshot().ok_or(Errno::Esrch)?;
    let net_namespace = parent.network_namespace_snapshot().ok_or(Errno::Esrch)?;
    let bits = crate::s272_unshare::ns_bits_from_flags(flags);
    crate::s272_unshare::apply_new_namespaces(child, snapshot, Some(net_namespace), bits, false,
        crate::s272_unshare::NamespaceChange::CloneChild {
            share_vm: (flags & super::CLONE_VM) != 0,
        })?;

    // `clone3` `set_tid[]` names the child's pid at each level, innermost
    // first. Levels the caller did not name are drawn from the namespace that
    // owns them, so a nested namespace numbers its tasks from 1 rather than
    // repeating the number an outer namespace picked.
    let group_leader = (flags & super::CLONE_THREAD) == 0;
    child.alloc_pid_mappings(set_tid, group_leader).map_err(mapping_error)?;
    let caller_ns = parent.namespace_owner(NamespaceKind::Pid).ok_or(Errno::Esrch)?;
    Ok(child.pid_nr_ns(&caller_ns))
}

fn mapping_error(error: sched::pid::PidMappingError) -> Errno {
    match error {
        sched::pid::PidMappingError::Exists => Errno::Eexist,
        sched::pid::PidMappingError::Exhausted => Errno::Eagain,
        sched::pid::PidMappingError::InvalidNumber => Errno::Einval,
        sched::pid::PidMappingError::AlreadyConfigured
        | sched::pid::PidMappingError::Empty
        | sched::pid::PidMappingError::NamespaceKind
        | sched::pid::PidMappingError::Ancestry => Errno::Eio,
    }
}
