// 272 unshare - one syscall, one file (docs/53 section 0).
#![cfg(any(target_os = "oxide-kernel", test))]

use alloc::sync::Arc;

use namespace_identity::{NamespaceKind, NamespaceRef};
use syscall::{errno::Errno, SyscallArgs};

const CLONE_NEWTIME:  u64 = 0x00000080;
const CLONE_VM:       u64 = 0x00000100;
const CLONE_FS:       u64 = 0x00000200;
const CLONE_FILES:    u64 = 0x00000400;
const CLONE_SIGHAND:  u64 = 0x00000800;
const CLONE_THREAD:   u64 = 0x00010000;
const CLONE_NEWNS:    u64 = 0x00020000;
const CLONE_SYSVSEM:  u64 = 0x00040000;
const UNSHARE_EMPTY_MNTNS: u64 = 0x00100000;
const CLONE_NEWCGROUP:u64 = 0x02000000;
const CLONE_NEWUTS:   u64 = 0x04000000;
const CLONE_NEWIPC:   u64 = 0x08000000;
const CLONE_NEWUSER:  u64 = 0x10000000;
const CLONE_NEWPID:   u64 = 0x20000000;
const CLONE_NEWNET:   u64 = 0x40000000;

const MNT_BIT:    u32 = 0;
const UTS_BIT:    u32 = 1;
const IPC_BIT:    u32 = 2;
const USER_BIT:   u32 = 3;
const PID_BIT:    u32 = 4;
const NET_BIT:    u32 = 5;
const CGROUP_BIT: u32 = 6;
const TIME_BIT:   u32 = 7;

const CLONE_NS_ALL: u64 = CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS | CLONE_NEWIPC
    | CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWTIME;
const UNSHARE_ALLOWED: u64 = CLONE_THREAD | CLONE_FS | CLONE_SIGHAND | CLONE_VM
    | CLONE_FILES | CLONE_SYSVSEM | CLONE_NS_ALL | UNSHARE_EMPTY_MNTNS;

#[derive(Copy, Clone, Eq, PartialEq)]
pub(crate) enum NamespaceChange { CloneChild { share_vm: bool }, Unshare }

#[inline]
fn ns_bit_for_clone(clone_flag: u64) -> Option<u32> {
    Some(match clone_flag {
        CLONE_NEWNS      => MNT_BIT,
        CLONE_NEWUTS     => UTS_BIT,
        CLONE_NEWIPC     => IPC_BIT,
        CLONE_NEWUSER    => USER_BIT,
        CLONE_NEWPID     => PID_BIT,
        CLONE_NEWNET     => NET_BIT,
        CLONE_NEWCGROUP  => CGROUP_BIT,
        CLONE_NEWTIME    => TIME_BIT,
        _ => return None,
    })
}

fn has_bit(bits: u64, bit: u32) -> bool { (bits & (1u64 << bit)) != 0 }

/// Translate CLONE_NEW* flags into requested replacement bits. # C: O(1)
pub(crate) fn ns_bits_from_flags(flags: u64) -> u64 {
    let mut bits = 0u64;
    for clone_flag in [CLONE_NEWNS, CLONE_NEWUTS, CLONE_NEWIPC, CLONE_NEWUSER,
        CLONE_NEWPID, CLONE_NEWNET, CLONE_NEWCGROUP, CLONE_NEWTIME]
    {
        if (flags & clone_flag) != 0 {
            if let Some(bit) = ns_bit_for_clone(clone_flag) { bits |= 1u64 << bit; }
        }
    }
    bits
}

/// Validate namespace flags implemented by the canonical owners. # C: O(1)
pub(crate) fn validate_namespace_flags(_flags: u64) -> Result<(), Errno> { Ok(()) }

fn identity_error(error: namespace_identity::AllocError) -> Errno {
    match error {
        namespace_identity::AllocError::IdExhausted => Errno::Enospc,
        namespace_identity::AllocError::OwnerNotUserNamespace
        | namespace_identity::AllocError::ParentKindMismatch => Errno::Eio,
    }
}

fn uts_error(_: nscg::uts_ns::UtsError) -> Errno { Errno::Eio }

fn allocate_identity(kind: NamespaceKind, owner: &NamespaceRef,
    parent: Option<NamespaceRef>) -> Result<NamespaceRef, Errno>
{
    namespace_identity::allocate(kind, owner.clone(), parent).map_err(identity_error)
}

/// `sys_unshare(flags)` - slot 272. # C: O(snapshotted mount entries)
pub fn sys_unshare(args: &SyscallArgs) -> i64 {
    let mut flags = args.a0;
    if let Err(error) = validate_namespace_flags(flags) {
        return -(error.as_i32() as i64);
    }
    if (flags & CLONE_NEWUSER) != 0 { flags |= CLONE_THREAD | CLONE_FS; }
    if (flags & CLONE_VM) != 0 { flags |= CLONE_SIGHAND; }
    if (flags & CLONE_SIGHAND) != 0 { flags |= CLONE_THREAD; }
    if (flags & UNSHARE_EMPTY_MNTNS) != 0 { flags |= CLONE_NEWNS; }
    if (flags & CLONE_NEWNS) != 0 { flags |= CLONE_FS; }
    if (flags & !UNSHARE_ALLOWED) != 0 { return -(Errno::Einval.as_i32() as i64); }
    let unshare_files = (flags & CLONE_FILES) != 0;
    let bits = ns_bits_from_flags(flags);
    if bits == 0 && !unshare_files { return 0; }
    let cur = match sched::live::current() { Some(task) => task, None => return 0 };
    let new_fd_table = if unshare_files {
        // SAFETY: current task owns its fd-table slot; publication happens only
        // after every requested namespace replacement has succeeded.
        unsafe { cur.fd_table_ref().map(|table| Arc::new(table.fork_clone())) }
    } else {
        None
    };
    if bits != 0 {
        let snapshot = match cur.namespace_snapshot() {
            Some(snapshot) => snapshot,
            None => return -(Errno::Esrch.as_i32() as i64),
        };
        if let Err(error) = apply_new_namespaces(cur, snapshot, None, bits,
            NamespaceChange::Unshare)
        {
            return -(error.as_i32() as i64);
        }
    }
    if let Some(table) = new_fd_table {
        // SAFETY: current task is the sole writer of its fd-table owner slot.
        unsafe { cur.replace_fd_table(Some(table)); }
    }
    0
}

/// Build and publish a concrete namespace set for clone or unshare.
/// # C: O(snapshotted mount entries)
pub(crate) fn apply_new_namespaces(task: &sched::Task,
    mut snapshot: sched::task::TaskNamespaceSnapshot,
    inherited_network: Option<network_namespace::NetworkNamespaceRef>, bits: u64,
    change: NamespaceChange) -> Result<(), Errno>
{
    let current_user = snapshot.user.clone();
    if has_bit(bits, USER_BIT) {
        snapshot.user = allocate_identity(NamespaceKind::User, &current_user,
            Some(current_user.clone()))?;
    }
    let owner_user = snapshot.user.clone();

    let mut uts_state = None;
    if has_bit(bits, UTS_BIT) {
        let host = crate::hostname::host_for(&snapshot.uts).map_err(uts_error)?;
        let dom = crate::hostname::dom_for(&snapshot.uts).map_err(uts_error)?;
        let namespace = allocate_identity(NamespaceKind::Uts, &owner_user, None)?;
        uts_state = Some((namespace, host, dom));
    }
    if has_bit(bits, IPC_BIT) {
        snapshot.ipc = allocate_identity(NamespaceKind::Ipc, &owner_user, None)?;
    }
    if has_bit(bits, CGROUP_BIT) {
        snapshot.cgroup = allocate_identity(NamespaceKind::Cgroup, &owner_user, None)?;
    }
    if has_bit(bits, TIME_BIT) {
        let old = snapshot.time_for_children.clone();
        let namespace = allocate_identity(NamespaceKind::Time, &owner_user, None)?;
        nscg::time_ns::clone_from(&namespace, &old).map_err(|_| Errno::Eio)?;
        snapshot.time_for_children = namespace;
    }
    if has_bit(bits, PID_BIT) {
        if !NamespaceRef::ptr_eq(&snapshot.pid, &snapshot.pid_for_children) {
            return Err(Errno::Einval);
        }
        let parent = snapshot.pid.clone();
        let namespace = allocate_identity(NamespaceKind::Pid, &owner_user, Some(parent))?;
        snapshot.pid_for_children = namespace.clone();
        if matches!(change, NamespaceChange::CloneChild { .. }) {
            snapshot.pid = namespace;
            task.vtgid.store(1, core::sync::atomic::Ordering::Release);
            task.vtid.store(1, core::sync::atomic::Ordering::Release);
        }
    } else if matches!(change, NamespaceChange::CloneChild { .. }) {
        let enters_child_namespace = !NamespaceRef::ptr_eq(&snapshot.pid, &snapshot.pid_for_children);
        snapshot.pid = snapshot.pid_for_children.clone();
        if enters_child_namespace {
            task.vtgid.store(1, core::sync::atomic::Ordering::Release);
            task.vtid.store(1, core::sync::atomic::Ordering::Release);
        }
    }
    if matches!(change, NamespaceChange::CloneChild { share_vm: false })
        && !NamespaceRef::ptr_eq(&snapshot.time, &snapshot.time_for_children)
    {
        nscg::time_ns::freeze(&snapshot.time_for_children).map_err(|_| Errno::Eio)?;
        snapshot.time = snapshot.time_for_children.clone();
    }
    let mut mount_parent = None;
    if has_bit(bits, MNT_BIT) {
        let parent = Arc::clone(&snapshot.mount);
        let namespace = vfs::mntns::allocate(owner_user.pin()).map_err(|error| match error {
            vfs::mntns::MntNamespaceAllocError::IdExhausted => Errno::Enospc,
            vfs::mntns::MntNamespaceAllocError::OwnerNotUserNamespace => Errno::Eio,
        })?;
        mount_parent = Some(parent);
        snapshot.mount = namespace;
    }

    let network = if has_bit(bits, NET_BIT) {
        Some(net::net_ns::create_namespace(owner_user.pin()).map_err(|error| match error {
            net::net_ns::CreateError::CallbackConflict
            | net::net_ns::CreateError::ReaperUnavailable => Errno::Eio,
            net::net_ns::CreateError::Allocation(network_namespace::AllocError::IdExhausted) =>
                Errno::Enospc,
            net::net_ns::CreateError::Allocation(
                network_namespace::AllocError::FinalDropCallbackMissing)
            | net::net_ns::CreateError::Allocation(
                network_namespace::AllocError::OwnerNotUserNamespace) => Errno::Eio,
        })?)
    } else { inherited_network };

    if let Some((namespace, host, dom)) = uts_state {
        nscg::uts_ns::allocate(&namespace, host, dom).map_err(uts_error)?;
        snapshot.uts = namespace;
    }
    if let Some(parent) = mount_parent {
        devfs::snapshot_ns(&parent, &snapshot.mount);
        let mount_map = vfs::mount::snapshot_ns_map(&parent, &snapshot.mount)
            .map_err(|error| match error {
                vfs::VfsError::Enospc => Errno::Enospc,
                _ => Errno::Eio,
            })?;
        remap_task_fs_paths(task, &mount_map);
    }

    task.replace_namespace_set(snapshot).map_err(|_| Errno::Esrch)?;
    if let Some(namespace) = network {
        task.replace_network_namespace(namespace).map_err(|_| Errno::Esrch)?;
    }
    Ok(())
}

fn remap_task_fs_paths(task: &sched::Task, mount_map: &[(u64, u64)]) {
    fn mapped(id: u64, mount_map: &[(u64, u64)]) -> Option<u64> {
        mount_map.iter().find_map(|(old, new)| if *old == id { Some(*new) } else { None })
    }
    fn remap_one(path: &mut Option<vfs::VfsPath>, mount_map: &[(u64, u64)]) {
        if let Some(path) = path.as_mut() {
            if let Some(new_id) = mapped(path.mnt_id, mount_map) { path.mnt_id = new_id; }
        }
    }
    // SAFETY: caller is the running task or an unpublished clone child, so
    // these filesystem path slots have no concurrent writer.
    unsafe {
        remap_one(&mut *task.cwd_vfs.get(), mount_map);
        remap_one(&mut *task.root_vfs.get(), mount_map);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_namespace_flags_are_accepted_at_syscall_boundaries() {
        assert_eq!(validate_namespace_flags(CLONE_NEWTIME), Ok(()));
        assert_eq!(validate_namespace_flags(CLONE_NEWUTS | CLONE_NEWTIME), Ok(()));
    }
}
