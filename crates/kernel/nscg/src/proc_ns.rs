// `/proc/<pid>/ns/<type>` real Inode (NsInode). Per `26§R01`.
//
// open(/proc/self/ns/uts) yields a fd whose inode is an NsInode;
// setns(fd, nstype) downcasts via Inode::as_any, validates kind
// matches nstype, and installs the captured namespace in the caller.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use namespace_identity::{NamespaceKind, NamespacePin};
#[cfg(test)]
use namespace_identity::NamespaceRef;
use network_namespace::NetworkNamespaceRef;
use vfs::inode::InodeBuilder;
use vfs::inode_ops::{default_inode_ops, mk_mode};
use vfs::file_ops::default_file_ops;
use vfs::{FileType, Ino, Inode, InodeOps, InodeRef, KResult, LinkTarget, VfsError, VfsPath};

use crate::owner::NsOwner;

/// Linux CLONE_NEW* bits — match clone(2) for setns(fd, nstype) checks.
pub const CLONE_NEWNS:    u64 = 0x00020000;
pub const CLONE_NEWTIME:  u64 = 0x00000080;
pub const CLONE_NEWCGROUP:u64 = 0x02000000;
pub const CLONE_NEWUTS:   u64 = 0x04000000;
pub const CLONE_NEWIPC:   u64 = 0x08000000;
pub const CLONE_NEWUSER:  u64 = 0x10000000;
pub const CLONE_NEWPID:   u64 = 0x20000000;
pub const CLONE_NEWNET:   u64 = 0x40000000;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum NsKind {
    Mnt, Cgroup, Uts, Ipc, User, Pid, PidForChildren, Net, Time, TimeForChildren,
}

impl NsKind {
    /// Return the matching CLONE_NEW* bit for setns(fd, nstype) check.
    /// # C: O(1)
    pub fn clone_bit(self) -> u64 {
        match self {
            NsKind::Mnt    => CLONE_NEWNS,
            NsKind::Cgroup => CLONE_NEWCGROUP,
            NsKind::Uts    => CLONE_NEWUTS,
            NsKind::Ipc    => CLONE_NEWIPC,
            NsKind::User   => CLONE_NEWUSER,
            NsKind::Pid    => CLONE_NEWPID,
            NsKind::PidForChildren => CLONE_NEWPID,
            NsKind::Net    => CLONE_NEWNET,
            NsKind::Time | NsKind::TimeForChildren => CLONE_NEWTIME,
        }
    }

    /// nsfs link prefix — Linux `readlink(/proc/<pid>/ns/<t>)` returns
    /// "<proc_name>:[<inode>]" (`ns_prune_dentry`/`ns_get_name`). # C: O(1)
    pub fn proc_name(self) -> &'static str {
        match self {
            NsKind::Mnt    => "mnt",
            NsKind::Cgroup => "cgroup",
            NsKind::Uts    => "uts",
            NsKind::Ipc    => "ipc",
            NsKind::User   => "user",
            NsKind::Pid    => "pid",
            NsKind::PidForChildren => "pid",
            NsKind::Net    => "net",
            NsKind::Time | NsKind::TimeForChildren => "time",
        }
    }

    /// Parse the leaf name from /proc/<pid>/ns/<leaf> into an NsKind.
    /// # C: O(1)
    pub fn from_leaf(s: &str) -> Option<Self> {
        Some(match s {
            "mnt"    => NsKind::Mnt,
            "cgroup" => NsKind::Cgroup,
            "uts"    => NsKind::Uts,
            "ipc"    => NsKind::Ipc,
            "user"   => NsKind::User,
            "pid"    => NsKind::Pid,
            "pid_for_children" => NsKind::PidForChildren,
            "net"    => NsKind::Net,
            "time"   => NsKind::Time,
            "time_for_children" => NsKind::TimeForChildren,
            _        => return None,
        })
    }
}

/// Point-in-time concrete ownership snapshot held by a proc magic link or nsfd.
pub struct NsInode {
    pub kind: NsKind,
    owner: NsOwner,
}

impl NsInode {
    fn new(kind: NsKind, owner: NsOwner) -> Self { Self { kind, owner } }

    fn ino(&self) -> Ino { self.owner.ino() }

    fn clone_for_node(&self) -> Self {
        Self { kind: self.kind, owner: self.owner.clone_ref() }
    }
}

/// `i_op` for the `/proc/<pid>/ns/<type>` MAGIC symlink (Linux nsfs). A walk
/// THROUGH it (`open`/`access`/`stat` with LOOKUP_FOLLOW) does `nd_jump_link`
/// (Linux `proc_ns_get_link`) to the backing nsfs node, so `open(2)` returns a
/// fd whose inode `setns(2)` can downcast to `NsInode`; `readlink(2)` returns
/// the "<type>:[<ino>]" TEXT. Without a real target the default `readlink`
/// yields `EINVAL`, which made `access("/proc/self/ns/uts", F_OK)` fail —
/// systemd then logs "the kernel does not support UTS namespaces" and
/// `open("/proc/self/ns/net")` failed the same way, tripping the PrivateNetwork
/// "does not support ... network namespace" path.
struct NsLinkOps;
impl InodeOps for NsLinkOps {
    /// `readlink(2)` text — Linux nsfs "<type>:[<inode>]". # C: O(1)
    fn readlink(&self, inode: &Inode) -> KResult<Vec<u8>> {
        use core::fmt::Write as _;
        let d = inode.private::<NsInode>().ok_or(VfsError::Einval)?;
        let mut s = String::new();
        let _ = write!(s, "{}:[{}]", d.kind.proc_name(), d.ino());
        Ok(s.into_bytes())
    }

    /// Magic-link follow — jump to a fresh nsfs node carrying the SAME
    /// `(kind, id)` (Linux `nd_jump_link` into nsfs). `mnt_id 0` = anonymous
    /// inode (nsfs owns no vfsmount in this tree; matches pipe/socket fds).
    /// # C: O(1)
    fn get_link(&self, inode: &Inode) -> KResult<LinkTarget> {
        let d = inode.private::<NsInode>().ok_or(VfsError::Einval)?;
        let target = ns_node(d);
        let dentry = vfs::d_obtain_alias(target.clone());
        Ok(LinkTarget::Jump(VfsPath { mnt_id: 0, dentry, inode: target, last_component: None }))
    }
}

/// The nsfs node the `/proc/<pid>/ns/<type>` magic link JUMPS to — a non-symlink
/// inode whose `i_private` carries `(kind, id)` for `setns(2)` to downcast. Not
/// a symlink (Linux nsfs files aren't links; only the `/proc/.../ns/<t>` entry
/// is), so the walk terminates here instead of re-following. # C: O(1)
fn ns_node(ns: &NsInode) -> InodeRef {
    InodeBuilder::new(ns.ino(), mk_mode(FileType::Regular, 0o444), default_inode_ops(), default_file_ops())
        .private(Arc::new(ns.clone_for_node()))
        .build()
}

/// Build an nsfs node retaining a concrete network namespace owner. # C: O(1)
pub fn net_ns_inode(namespace: NetworkNamespaceRef) -> InodeRef {
    let ns = NsInode::new(NsKind::Net, NsOwner::Net(namespace));
    ns_node(&ns)
}

/// Construct the `/proc/<pid>/ns/<type>` inode retaining `task`'s exact owner for
/// `kind`. A `S_IFLNK` magic node (Linux nsfs): a walk through it jumps to
/// [`ns_node`]; `readlink` yields the "<type>:[<ino>]" text; the captured
/// the namespace in `i_private` for an `O_NOFOLLOW`/`O_PATH` `setns`.
/// Returns `ENOENT` when lookup races task namespace release. # C: O(1)
pub fn ns_inode_for(task: &sched::Task, kind: NsKind) -> KResult<InodeRef> {
    let owner = match kind {
        NsKind::Cgroup => NsOwner::Cgroup(task.namespace_owner(NamespaceKind::Cgroup).ok_or(VfsError::Enoent)?),
        NsKind::Ipc => NsOwner::Ipc(task.namespace_owner(NamespaceKind::Ipc).ok_or(VfsError::Enoent)?),
        NsKind::Pid => NsOwner::Pid(task.namespace_owner(NamespaceKind::Pid).ok_or(VfsError::Enoent)?),
        NsKind::PidForChildren => NsOwner::Pid(task.pid_namespace_for_children().ok_or(VfsError::Enoent)?),
        NsKind::Time => NsOwner::Time(task.namespace_owner(NamespaceKind::Time).ok_or(VfsError::Enoent)?),
        NsKind::TimeForChildren => NsOwner::Time(task.time_namespace_for_children().ok_or(VfsError::Enoent)?),
        NsKind::User => NsOwner::User(task.namespace_owner(NamespaceKind::User).ok_or(VfsError::Enoent)?),
        NsKind::Uts => NsOwner::Uts(task.namespace_owner(NamespaceKind::Uts).ok_or(VfsError::Enoent)?),
        NsKind::Mnt => NsOwner::Mnt(task.mount_namespace_snapshot().ok_or(VfsError::Enoent)?),
        NsKind::Net => NsOwner::Net(task.network_namespace_snapshot().ok_or(VfsError::Enoent)?),
    };
    let ns = NsInode::new(kind, owner);
    Ok(InodeBuilder::new(ns.ino(), mk_mode(FileType::Symlink, 0o777), Arc::new(NsLinkOps), default_file_ops())
        .private(Arc::new(ns))
        .build())
}

/// True when `ancestor` is the exact owner or a concrete retained parent.
/// # C: O(depth)
pub fn user_ns_is_ancestor(ancestor: &NamespacePin, descendant: &NamespacePin) -> bool {
    let mut cur = Some(descendant.clone());
    while let Some(namespace) = cur {
        if NamespacePin::ptr_eq(ancestor, &namespace) { return true; }
        cur = namespace.parent();
    }
    false
}

/// Per-user-NS cap check (`27§R01`). Returns true when `cur` holds
/// `cap` in its effective set AND `target_user_ns` is `cur.user_ns`
/// or a descendant of it.
/// # C: O(depth)
pub fn has_cap_for(cur: &sched::Task, target_user_ns: &NamespacePin, cap: u32) -> bool {
    if !cur.has_cap(cap) { return false; }
    let Some(cur_ns) = cur.namespace_owner(NamespaceKind::User) else { return false; };
    user_ns_is_ancestor(&cur_ns.pin(), target_user_ns)
}

/// True when `cur` has CAP_NET_ADMIN in the user namespace that owns
/// `namespace`, or in one of that owner's ancestors.
/// # C: O(depth)
pub fn has_net_admin_for(cur: &sched::Task, namespace: &NetworkNamespaceRef) -> bool {
    has_cap_for(cur, &namespace.owner_user_namespace(), sched::cap::NET_ADMIN)
}

/// True when `cur` has CAP_NET_RAW in the user namespace owning `namespace`.
/// # C: O(depth)
pub fn has_net_raw_for(cur: &sched::Task, namespace: &NetworkNamespaceRef) -> bool {
    has_cap_for(cur, &namespace.owner_user_namespace(), sched::cap::NET_RAW)
}

/// True when `cur` has CAP_NET_BIND_SERVICE in the user namespace owning
/// `namespace`, or in one of that owner's ancestors. # C: O(depth)
pub fn has_net_bind_service_for(cur: &sched::Task, namespace: &NetworkNamespaceRef) -> bool {
    has_cap_for(cur, &namespace.owner_user_namespace(), sched::cap::NET_BIND_SERVICE)
}

/// Apply an NsInode (resolved from setns's fd arg) to the calling
/// task. Returns 0 on success or -EINVAL when nstype mismatches.
/// # C: O(1)
pub fn setns_apply(ns: &NsInode, nstype: u64, cur: &sched::Task) -> i64 {
    use syscall::errno::Errno;
    if nstype != 0 && nstype != ns.kind.clone_bit() {
        return -(Errno::Einval.as_i32() as i64);
    }
    if matches!(ns.kind, NsKind::Time | NsKind::TimeForChildren) {
        let NsOwner::Time(owner) = &ns.owner else {
            return -(Errno::Einval.as_i32() as i64);
        };
        if !cur.thread_group.is_single_member() {
            return -(Errno::Eusers.as_i32() as i64);
        }
        let target_user = owner.owner_user_namespace();
        let Some(current_user) = cur.namespace_owner(NamespaceKind::User) else {
            return -(Errno::Esrch.as_i32() as i64);
        };
        if !has_cap_for(cur, &target_user, sched::cap::SYS_ADMIN)
            || !has_cap_for(cur, &current_user.pin(), sched::cap::SYS_ADMIN)
        {
            return -(Errno::Eperm.as_i32() as i64);
        }
        if crate::time_ns::freeze(owner).is_err() {
            return -(Errno::Eio.as_i32() as i64);
        }
        let installed = cur.replace_time_namespace_pair(
            owner.clone(), owner.clone()).is_ok();
        return if installed { 0 } else { -(Errno::Esrch.as_i32() as i64) };
    }
    let installed = match &ns.owner {
        NsOwner::Pid(owner) => cur.replace_pid_namespace_for_children(owner.clone()).is_ok(),
        NsOwner::Cgroup(owner) | NsOwner::Ipc(owner)
        | NsOwner::User(owner) | NsOwner::Uts(owner) => cur.replace_namespace(owner.clone()).is_ok(),
        NsOwner::Time(_) => false,
        NsOwner::Mnt(owner) => cur.replace_mount_namespace(owner.clone()).is_ok(),
        NsOwner::Net(owner) => cur.replace_network_namespace(owner.clone()).is_ok(),
    };
    if !installed { return -(Errno::Esrch.as_i32() as i64); }
    0
}

fn setns_from_fd_with<F>(fdt: &vfs::FdTable, fd: i32, nstype: u64,
    cur: &sched::Task, after_pin: F) -> i64
where F: FnOnce() {
    use syscall::errno::Errno;
    let file = match fdt.get(fd) {
        Ok(file) => file,
        Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    after_pin();
    let ns = match file.inode().private::<NsInode>() {
        Some(ns) => ns,
        None => return -(Errno::Einval.as_i32() as i64),
    };
    setns_apply(ns, nstype, cur)
}

/// Resolve and apply one namespace fd while retaining its open-file pin. # C: O(1)
pub fn setns_from_fd(fdt: &vfs::FdTable, fd: i32, nstype: u64, cur: &sched::Task) -> i64 {
    setns_from_fd_with(fdt, fd, nstype, cur, || {})
}

#[cfg(test)]
#[test]
fn time_setns_installs_both_slots_and_freezes_offsets() {
    let user = namespace_identity::initial(NamespaceKind::User);
    let time = namespace_identity::allocate(NamespaceKind::Time, user, None).unwrap();
    crate::time_ns::clone_from(&time,
        &namespace_identity::initial(NamespaceKind::Time)).unwrap();
    let ns = NsInode::new(NsKind::Time, NsOwner::Time(time.clone()));
    let destination = sched::Task::new(84, "time-destination",
        sched::SchedClass::Normal { weight: 1024 });

    assert_eq!(setns_apply(&ns, CLONE_NEWTIME, &destination), 0);
    assert!(NamespaceRef::ptr_eq(&destination.namespace_owner(NamespaceKind::Time).unwrap(), &time));
    assert!(NamespaceRef::ptr_eq(&destination.time_namespace_for_children().unwrap(), &time));
    assert!(crate::time_ns::snapshot(&time).unwrap().frozen);
}

#[cfg(test)]
fn time_test_inode() -> (NamespaceRef, NsInode) {
    let time = namespace_identity::allocate(NamespaceKind::Time,
        namespace_identity::initial(NamespaceKind::User), None).unwrap();
    crate::time_ns::clone_from(&time,
        &namespace_identity::initial(NamespaceKind::Time)).unwrap();
    let ns = NsInode::new(NsKind::Time, NsOwner::Time(time.clone()));
    (time, ns)
}

#[cfg(test)]
#[test]
fn time_setns_checks_type_then_single_thread_then_capabilities() {
    let (_time, ns) = time_test_inode();
    let destination = sched::Task::new(85, "time-errors",
        sched::SchedClass::Normal { weight: 1024 });
    assert_eq!(setns_apply(&ns, CLONE_NEWUTS, &destination),
        -(syscall::errno::Errno::Einval.as_i32() as i64));

    let mut sibling = sched::Task::new(86, "time-sibling",
        sched::SchedClass::Normal { weight: 1024 });
    sibling.join_thread_group(Arc::clone(&destination.thread_group));
    sibling.thread_group.commit_member();
    assert_eq!(setns_apply(&ns, CLONE_NEWTIME, &destination),
        -(syscall::errno::Errno::Eusers.as_i32() as i64));

    let no_cap = sched::Task::new(87, "time-no-cap",
        sched::SchedClass::Normal { weight: 1024 });
    no_cap.creds.cap_effective.store(0, core::sync::atomic::Ordering::Release);
    assert_eq!(setns_apply(&ns, CLONE_NEWTIME, &no_cap),
        -(syscall::errno::Errno::Eperm.as_i32() as i64));
}

#[cfg(test)]
#[test]
fn time_setns_rejects_released_destination_without_freezing_target() {
    let (time, ns) = time_test_inode();
    let destination = sched::Task::new(88, "time-released",
        sched::SchedClass::Normal { weight: 1024 });
    destination.release_namespaces();

    assert_eq!(setns_apply(&ns, CLONE_NEWTIME, &destination),
        -(syscall::errno::Errno::Esrch.as_i32() as i64));
    assert!(!crate::time_ns::snapshot(&time).unwrap().frozen);
}

#[cfg(test)]
fn final_drop_notify() {}

#[cfg(test)]
mod setns_fd_tests;

#[cfg(test)]
mod tests;
