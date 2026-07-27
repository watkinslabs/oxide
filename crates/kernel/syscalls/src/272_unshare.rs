// 272 unshare - one syscall, one file (docs/53 section 0).
#![cfg(any(target_os = "oxide-kernel", test))]

use alloc::sync::Arc;

use namespace_identity::{NamespaceKind, NamespaceRef};
use syscall::{errno::Errno, SyscallArgs};

use crate::unshare_policy::{
    CLONE_FILES, CLONE_FS, CLONE_NEWCGROUP, CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWNS,
    CLONE_NEWPID, CLONE_NEWTIME, CLONE_NEWUSER, CLONE_NEWUTS,
    check_unshare_flags, detaches_sysvsem, expand_implied, needs_sys_admin,
};

const MNT_BIT:    u32 = 0;
const UTS_BIT:    u32 = 1;
const IPC_BIT:    u32 = 2;
const USER_BIT:   u32 = 3;
const PID_BIT:    u32 = 4;
const NET_BIT:    u32 = 5;
const CGROUP_BIT: u32 = 6;
const TIME_BIT:   u32 = 7;

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

/// `sys_unshare(flags)` - slot 272 (Linux `ksys_unshare`). Order: implied-flag
/// expansion, `check_unshare_flags`, then the per-resource unshares, with the
/// namespace set's single `ns_capable(user_ns, CAP_SYS_ADMIN)` gate.
/// # C: O(snapshotted mount entries)
pub fn sys_unshare(args: &SyscallArgs) -> i64 {
    let flags = expand_implied(args.a0);
    let cur = match sched::live::current() { Some(task) => task, None => return 0 };
    if let Err(error) = check_unshare_flags(flags, cur.thread_group.is_single_member(),
        cur.sigactions_shared())
    {
        return -(error.as_i32() as i64);
    }
    let unshare_files = (flags & CLONE_FILES) != 0;
    let unshare_fs = (flags & CLONE_FS) != 0;
    let sysvsem = detaches_sysvsem(flags);
    let bits = ns_bits_from_flags(flags);
    if bits == 0 && !unshare_files && !unshare_fs && !sysvsem { return 0; }
    // Linux `unshare_nsproxy_namespaces`: ONE capability test covers the whole
    // requested namespace set, in the user namespace the new set will be owned
    // by. `CLONE_NEWUSER` alone is exempt — creating a user namespace is
    // unprivileged. Checking against the caller's own user namespace is the
    // same decision as checking against the not-yet-allocated child, because
    // `has_cap_for` accepts the caller's namespace and every descendant of it.
    if needs_sys_admin(flags) {
        if let Err(error) = may_unshare_namespaces(&cur) {
            return -(error.as_i32() as i64);
        }
    }
    #[cfg(feature = "debug-fdlife")]
    if let Some(table) = unsafe { cur.fd_table_ref() } {
        crate::fd_life::op(cur, table, b"unshare", flags as i32, -1, 0);
    }
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
            unshare_fs, NamespaceChange::Unshare)
        {
            return -(error.as_i32() as i64);
        }
    } else if unshare_fs {
        cur.unshare_fs_context();
    }
    // Linux: "CLONE_SYSVSEM is equivalent to sys_exit()" — the undo list is
    // dropped once every namespace replacement succeeded, so a failed unshare
    // leaves the caller's SEM_UNDO adjustments intact. `CLONE_NEWIPC` triggers
    // it too: the arrays the entries name are unreachable from the new
    // namespace, so leaving them registered would apply an adjustment to an
    // array the caller can no longer see.
    if sysvsem {
        let vtg = cur.vtgid.load(core::sync::atomic::Ordering::Acquire);
        let tg = cur.tgid.load(core::sync::atomic::Ordering::Acquire);
        ipc::sysv::sem::exit_sem(if vtg != 0 { vtg } else { tg });
    }
    if let Some(table) = new_fd_table {
        // SAFETY: current task is the sole writer of its fd-table owner slot.
        unsafe { cur.replace_fd_table(Some(table)); }
    }
    0
}

/// Linux `unshare_nsproxy_namespaces`'s `ns_capable(user_ns, CAP_SYS_ADMIN)`.
/// A task whose namespace set has already been released has no user namespace
/// to test against and reports ESRCH, ahead of the capability answer.
/// # C: O(userns-depth)
fn may_unshare_namespaces(cur: &sched::Task) -> Result<(), Errno> {
    let Some(user_ns) = cur.namespace_owner(NamespaceKind::User) else {
        return Err(Errno::Esrch);
    };
    if nscg::proc_ns::has_cap_for(cur, &user_ns.pin(), sched::cap::SYS_ADMIN) { Ok(()) }
    else { Err(Errno::Eperm) }
}

/// Build and publish a concrete namespace set for clone or unshare.
/// # C: O(snapshotted mount entries)
pub(crate) fn apply_new_namespaces(task: &sched::Task,
    mut snapshot: sched::task::TaskNamespaceSnapshot,
    inherited_network: Option<network_namespace::NetworkNamespaceRef>, bits: u64, private_fs: bool,
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
        // Linux `copy_cgroup_ns` pins the CREATING task's `css_set`, so the
        // cgroup it currently sits in becomes the new namespace's `/`.
        let root = cgroup::cgroup_path_of(cgroup_key(task));
        let namespace = allocate_identity(NamespaceKind::Cgroup, &owner_user, None)?;
        nscg::cgroup_ns::allocate(&namespace, root).map_err(|_| Errno::Eio)?;
        snapshot.cgroup = namespace;
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
    if private_fs { task.unshare_fs_context(); }
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

/// cgroup membership is stored per thread GROUP; a non-leader thread must
/// resolve to its leader or it reads the root cgroup. # C: O(1)
fn cgroup_key(task: &sched::Task) -> u64 {
    let tgid = task.tgid.load(core::sync::atomic::Ordering::Acquire);
    if tgid != 0 { tgid as u64 } else { task.tid as u64 }
}

fn remap_task_fs_paths(task: &sched::Task, mount_map: &[(u64, u64)]) {
    task.remap_fs_mount_ids(mount_map);
}

