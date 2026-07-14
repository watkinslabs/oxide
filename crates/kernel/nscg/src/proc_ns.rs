// `/proc/<pid>/ns/<type>` real Inode (NsInode). Per `26§R01`.
//
// open(/proc/self/ns/uts) yields a fd whose inode is an NsInode;
// setns(fd, nstype) downcasts via Inode::as_any, validates kind
// matches nstype, and writes the captured ns id into the calling
// task's matching slot.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use vfs::inode::InodeBuilder;
use vfs::inode_ops::{default_inode_ops, mk_mode};
use vfs::file_ops::default_file_ops;
use vfs::{FileType, Ino, Inode, InodeOps, InodeRef, KResult, LinkTarget, VfsError, VfsPath};

/// Linux CLONE_NEW* bits — match clone(2) for setns(fd, nstype) checks.
pub const CLONE_NEWNS:    u64 = 0x00020000;
pub const CLONE_NEWCGROUP:u64 = 0x02000000;
pub const CLONE_NEWUTS:   u64 = 0x04000000;
pub const CLONE_NEWIPC:   u64 = 0x08000000;
pub const CLONE_NEWUSER:  u64 = 0x10000000;
pub const CLONE_NEWPID:   u64 = 0x20000000;
pub const CLONE_NEWNET:   u64 = 0x40000000;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum NsKind {
    Mnt, Cgroup, Uts, Ipc, User, Pid, Net,
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
            NsKind::Net    => CLONE_NEWNET,
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
            NsKind::Net    => "net",
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
            "pid" | "pid_for_children" => NsKind::Pid,
            "net"    => NsKind::Net,
            _        => return None,
        })
    }
}

static NS_GLOBAL_IDS: sync::Spinlock<alloc::collections::BTreeMap<(NsKind, u64), u64>, sync::TaskList> =
    sync::Spinlock::new(alloc::collections::BTreeMap::new());
static NS_NEXT_GLOBAL_ID: AtomicU64 = AtomicU64::new(9);

/// Linux `ns_common.ns_id` value for a namespace. Initial IDs are the public
/// nsfs ABI constants; non-init IDs are unique across kinds. # C: O(log N)
pub fn ns_global_id(kind: NsKind, id: u64) -> u64 {
    if id == 0 {
        return match kind {
            NsKind::Ipc    => 1,
            NsKind::Uts    => 2,
            NsKind::User   => 3,
            NsKind::Pid    => 4,
            NsKind::Cgroup => 5,
            NsKind::Net    => 7,
            NsKind::Mnt    => 8,
        };
    }
    let mut g = NS_GLOBAL_IDS.lock();
    if let Some(v) = g.get(&(kind, id)) { return *v; }
    let v = NS_NEXT_GLOBAL_ID.fetch_add(1, Ordering::Relaxed);
    g.insert((kind, id), v);
    v
}

/// Inode-number tag — high byte 0x72 ("r" for "ref").
const NS_INO_MARKER: Ino = 0x7200_0000;

/// Stable, per-(kind,id) inode number for an nsfs node. Two tasks in the
/// SAME namespace resolve to the SAME `st_ino`, so `stat`-based
/// same-namespace comparison (systemd `inode_same`) sees them as identical;
/// distinct kinds/ids never collide. Also the numeric shown by
/// `readlink` ("net:[<ino>]"). # C: O(1)
fn ns_ino(kind: NsKind, id: u64) -> Ino {
    // The INITIAL namespaces (id 0) must report Linux's reserved nsfs inode
    // numbers (include/linux/proc_ns.h `PROC_*_INIT_INO`). systemd's
    // `namespace_is_init()` — the decisive test in `detect_container()` — stats
    // /proc/1/ns/{pid,cgroup,…} and compares `st_ino` to these EXACT constants
    // to decide host-vs-container. A synthetic inode makes it conclude "running
    // in a pid namespace" and report the VM as `container-other`, which skips
    // every ConditionVirtualization=!container unit (plymouth, …) and breaks the
    // gdm graphical greeter. net/mnt have no reserved init ino in Linux (they get
    // dynamic nsfs inodes there too), so they keep the synthetic scheme.
    if id == 0 {
        match kind {
            NsKind::Ipc    => return 0xEFFF_FFFF,
            NsKind::Uts    => return 0xEFFF_FFFE,
            NsKind::User   => return 0xEFFF_FFFD,
            NsKind::Pid    => return 0xEFFF_FFFC,
            NsKind::Cgroup => return 0xEFFF_FFFB,
            NsKind::Mnt | NsKind::Net => {}
        }
    }
    // low nibble = kind (< 7), id shifted clear of it; marker in the high word.
    NS_INO_MARKER | ((id & 0x00FF_FFFF) << 8) | (kind as Ino)
}

/// Per-NS id snapshot. Backend-private state (`i_private`) of the
/// `/proc/<pid>/ns/<type>` inode: captured at lookup time, stable for the
/// lifetime of the open fd. `setns` recovers it via `inode.private::<NsInode>()`,
/// reading this id + kind to update the caller's per-task slot.
pub struct NsInode {
    pub kind: NsKind,
    pub id:   u64,
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
        let _ = write!(s, "{}:[{}]", d.kind.proc_name(), ns_ino(d.kind, d.id));
        Ok(s.into_bytes())
    }

    /// Magic-link follow — jump to a fresh nsfs node carrying the SAME
    /// `(kind, id)` (Linux `nd_jump_link` into nsfs). `mnt_id 0` = anonymous
    /// inode (nsfs owns no vfsmount in this tree; matches pipe/socket fds).
    /// # C: O(1)
    fn get_link(&self, inode: &Inode) -> KResult<LinkTarget> {
        let d = inode.private::<NsInode>().ok_or(VfsError::Einval)?;
        let target = ns_node(d.kind, d.id);
        let dentry = vfs::d_obtain_alias(target.clone());
        Ok(LinkTarget::Jump(VfsPath { mnt_id: 0, dentry, inode: target, last_component: None }))
    }
}

/// The nsfs node the `/proc/<pid>/ns/<type>` magic link JUMPS to — a non-symlink
/// inode whose `i_private` carries `(kind, id)` for `setns(2)` to downcast. Not
/// a symlink (Linux nsfs files aren't links; only the `/proc/.../ns/<t>` entry
/// is), so the walk terminates here instead of re-following. # C: O(1)
fn ns_node(kind: NsKind, id: u64) -> InodeRef {
    InodeBuilder::new(ns_ino(kind, id), mk_mode(FileType::Regular, 0o444), default_inode_ops(), default_file_ops())
        .private(Arc::new(NsInode { kind, id }))
        .build()
}

/// Construct the `/proc/<pid>/ns/<type>` inode capturing `task`'s current id for
/// `kind`. A `S_IFLNK` magic node (Linux nsfs): a walk through it jumps to
/// [`ns_node`]; `readlink` yields the "<type>:[<ino>]" text; the captured
/// `(kind, id)` lives in `i_private` for an `O_NOFOLLOW`/`O_PATH` `setns`.
/// # C: O(1)
pub fn ns_inode_for(task: &sched::Task, kind: NsKind) -> InodeRef {
    use core::sync::atomic::Ordering;
    let id = match kind {
        NsKind::Uts    => task.uts_ns.load(Ordering::Acquire),
        NsKind::Ipc    => task.ipc_ns.load(Ordering::Acquire),
        NsKind::Pid    => task.pid_ns.load(Ordering::Acquire),
        NsKind::Net    => task.net_ns.load(Ordering::Acquire),
        NsKind::User   => task.user_ns.load(Ordering::Acquire),
        NsKind::Cgroup => task.cgroup_ns.load(Ordering::Acquire),
        NsKind::Mnt    => task.mount_ns.load(Ordering::Acquire),
    };
    InodeBuilder::new(ns_ino(kind, id), mk_mode(FileType::Symlink, 0o777), Arc::new(NsLinkOps), default_file_ops())
        .private(Arc::new(NsInode { kind, id }))
        .build()
}

/// Global registry mapping `user_ns id → parent_user_ns id` so the
/// `has_cap_for` ancestor walk works without scanning every task.
/// Init NS (id 0) has parent 0 (self-loop terminator).
static USER_NS_PARENT: sync::Spinlock<alloc::collections::BTreeMap<u64, u64>, sync::TaskList> =
    sync::Spinlock::new(alloc::collections::BTreeMap::new());

/// Global registry mapping `net_ns id -> owning user_ns id`. Linux assigns
/// ownership when the network namespace is created; init net_ns is owned by
/// init user_ns and is represented by the implicit `(0, 0)` default.
static NET_NS_OWNER: sync::Spinlock<alloc::collections::BTreeMap<u64, u64>, sync::TaskList> =
    sync::Spinlock::new(alloc::collections::BTreeMap::new());

/// Record `(child_id, parent_id)` at unshare(CLONE_NEWUSER) time.
/// # C: O(log N)
pub fn user_ns_record(child_id: u64, parent_id: u64) {
    let mut g = USER_NS_PARENT.lock();
    g.insert(child_id, parent_id);
}

/// Look up the parent of `id`. Init NS or unrecorded → returns 0.
/// # C: O(log N)
pub fn user_ns_parent(id: u64) -> u64 {
    if id == 0 { return 0; }
    let g = USER_NS_PARENT.lock();
    g.get(&id).copied().unwrap_or(0)
}

/// Record the user namespace that owns a newly created network namespace.
/// # C: O(log N)
pub fn net_ns_record_owner(net_ns: u64, user_ns: u64) {
    let mut g = NET_NS_OWNER.lock();
    g.insert(net_ns, user_ns);
}

/// Return the user namespace that owns `net_ns`. Init and legacy unrecorded
/// namespaces are owned by init user_ns.
/// # C: O(log N)
pub fn net_ns_owner(net_ns: u64) -> u64 {
    if net_ns == 0 { return 0; }
    let g = NET_NS_OWNER.lock();
    g.get(&net_ns).copied().unwrap_or(0)
}

/// True if `ancestor` is `descendant` itself or any ancestor up the
/// user_ns chain. Init NS (id 0) is the implicit ancestor of every
/// NS.
/// # C: O(depth)
pub fn user_ns_is_ancestor(ancestor: u64, descendant: u64) -> bool {
    if ancestor == 0 { return true; }
    let mut cur = descendant;
    let mut steps = 0;
    while cur != 0 && steps < 64 {
        if cur == ancestor { return true; }
        cur = user_ns_parent(cur);
        steps += 1;
    }
    false
}

/// Per-user-NS cap check (`27§R01`). Returns true when `cur` holds
/// `cap` in its effective set AND `target_user_ns` is `cur.user_ns`
/// or a descendant of it.
/// # C: O(depth)
pub fn has_cap_for(cur: &sched::Task, target_user_ns: u64, cap: u32) -> bool {
    use core::sync::atomic::Ordering;
    if !cur.has_cap(cap) { return false; }
    let cur_ns = cur.user_ns.load(Ordering::Acquire);
    user_ns_is_ancestor(cur_ns, target_user_ns)
}

/// True when `cur` has CAP_NET_ADMIN in the user namespace that owns
/// `net_ns`, or in one of that owner's ancestors.
/// # C: O(log N + depth)
pub fn has_net_admin_for(cur: &sched::Task, net_ns: u64) -> bool {
    has_cap_for(cur, net_ns_owner(net_ns), sched::cap::NET_ADMIN)
}

/// True when `cur` has CAP_NET_RAW in the user namespace owning `net_ns`.
/// # C: O(log N + depth)
pub fn has_net_raw_for(cur: &sched::Task, net_ns: u64) -> bool {
    has_cap_for(cur, net_ns_owner(net_ns), sched::cap::NET_RAW)
}

/// Apply an NsInode (resolved from setns's fd arg) to the calling
/// task. Returns 0 on success or -EINVAL when nstype mismatches.
/// # C: O(1)
pub fn setns_apply(ns: &NsInode, nstype: u64, cur: &sched::Task) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    if nstype != 0 && nstype != ns.kind.clone_bit() {
        return -(Errno::Einval.as_i32() as i64);
    }
    match ns.kind {
        NsKind::Uts => {
            // Join the target UTS namespace: point the task at that ns id —
            // uname/sethostname now resolve the shared registry entry, so
            // setns correctly adopts the namespace's hostname + domainname.
            cur.uts_ns.store(ns.id, Ordering::Release);
            cur.ns_membership.fetch_or(1u64 << 1, Ordering::Release);
        }
        NsKind::Ipc    => cur.ipc_ns.store(ns.id, Ordering::Release),
        NsKind::Pid    => cur.pid_ns.store(ns.id, Ordering::Release),
        NsKind::Net    => cur.net_ns.store(ns.id, Ordering::Release),
        NsKind::User   => cur.user_ns.store(ns.id, Ordering::Release),
        NsKind::Cgroup => cur.cgroup_ns.store(ns.id, Ordering::Release),
        NsKind::Mnt    => {
            let old = cur.mount_ns.swap(ns.id, Ordering::AcqRel);
            if old != ns.id {
                vfs::mntns::mnt_ns_enter(ns.id);
                vfs::mntns::mnt_ns_exit(old);
            }
        }
    }
    0
}

#[cfg(test)]
mod ns_link_tests {
    use super::*;
    use alloc::format;

    /// Build the `/proc/<pid>/ns/<t>` magic symlink WITHOUT a Task (the only
    /// Task-independent difference from `ns_inode_for`), so the nsfs link
    /// behaviour is provable in a hosted unit test.
    fn ns_symlink(kind: NsKind, id: u64) -> InodeRef {
        InodeBuilder::new(ns_ino(kind, id), mk_mode(FileType::Symlink, 0o777), Arc::new(NsLinkOps), default_file_ops())
            .private(Arc::new(NsInode { kind, id }))
            .build()
    }

    #[test]
    fn readlink_returns_nsfs_text() {
        // Linux nsfs: readlink(/proc/self/ns/net) == "net:[<ino>]".
        let l = ns_symlink(NsKind::Net, 7);
        assert_eq!(l.readlink().unwrap(), format!("net:[{}]", ns_ino(NsKind::Net, 7)).into_bytes());
    }

    #[test]
    fn follow_jumps_to_downcastable_non_symlink() {
        // A walk THROUGH the link (open/access/stat) must jump to a node whose
        // inode setns(2) can downcast — the whole point of the fix that makes
        // systemd's PrivateNetwork/ProtectHostname sandbox setup succeed.
        let l = ns_symlink(NsKind::Uts, 3);
        match l.follow_link().unwrap() {
            LinkTarget::Jump(vp) => {
                assert_eq!(vp.mnt_id, 0, "nsfs node is an anonymous inode");
                let ns = vp.inode.private::<NsInode>().expect("setns downcast target");
                assert_eq!(ns.kind, NsKind::Uts);
                assert_eq!(ns.id, 3);
                assert_ne!(vp.inode.file_type(), FileType::Symlink, "jump target is not itself a link");
            }
            LinkTarget::Path(_) => panic!("nsfs magic link must Jump, not splice a Path"),
        }
    }

    #[test]
    fn same_ns_same_ino_distinct_ns_distinct_ino() {
        assert_eq!(ns_ino(NsKind::Net, 5), ns_ino(NsKind::Net, 5), "same ns -> same st_ino");
        assert_ne!(ns_ino(NsKind::Net, 5), ns_ino(NsKind::Net, 6), "distinct id -> distinct");
        assert_ne!(ns_ino(NsKind::Net, 5), ns_ino(NsKind::Uts, 5), "distinct kind -> distinct");
    }

    #[test]
    fn setns_rejects_nonexact_type_mask_for_namespace_fd() {
        use core::sync::atomic::Ordering;
        let t = sched::Task::new(77, "t", sched::SchedClass::Normal { weight: 1024 });
        let ns = NsInode { kind: NsKind::Uts, id: 9 };
        let mixed = CLONE_NEWUTS | CLONE_NEWNET;
        assert_eq!(setns_apply(&ns, mixed, &t), -(syscall::errno::Errno::Einval.as_i32() as i64));
        assert_eq!(t.uts_ns.load(Ordering::Acquire), 0);
        assert_eq!(setns_apply(&ns, CLONE_NEWUTS, &t), 0);
        assert_eq!(t.uts_ns.load(Ordering::Acquire), 9);
    }

    #[test]
    fn namespace_global_ids_do_not_collide_across_kinds() {
        assert_eq!(ns_global_id(NsKind::User, 0), 3);
        assert_eq!(ns_global_id(NsKind::Mnt, 0), 8);
        assert_ne!(ns_global_id(NsKind::User, 4), ns_global_id(NsKind::Mnt, 4));
    }


    #[test]
    fn network_namespace_owner_scopes_network_capabilities() {
        use core::sync::atomic::Ordering;
        const OWNER_PARENT: u64 = 0x8250;
        const OWNER: u64 = 0x8251;
        const SIBLING: u64 = 0x8252;
        const NET_NS: u64 = 0x8253;
        user_ns_record(OWNER_PARENT, 0);
        user_ns_record(OWNER, OWNER_PARENT);
        user_ns_record(SIBLING, 0);
        net_ns_record_owner(NET_NS, OWNER);

        let parent = sched::Task::new(78, "parent", sched::SchedClass::Normal { weight: 1024 });
        parent.user_ns.store(OWNER_PARENT, Ordering::Release);
        assert!(has_net_admin_for(&parent, NET_NS));
        assert!(has_net_raw_for(&parent, NET_NS));

        let sibling = sched::Task::new(79, "sibling", sched::SchedClass::Normal { weight: 1024 });
        sibling.user_ns.store(SIBLING, Ordering::Release);
        assert!(!has_net_admin_for(&sibling, NET_NS));
        assert!(!has_net_raw_for(&sibling, NET_NS));
        sibling.creds.cap_effective.store(0, Ordering::Release);
        assert!(!has_net_admin_for(&sibling, 0));
        assert!(!has_net_raw_for(&sibling, 0));
    }
}
