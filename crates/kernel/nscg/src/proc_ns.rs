// `/proc/<pid>/ns/<type>` real Inode (NsInode). Per `26§R01`.
//
// open(/proc/self/ns/uts) yields a fd whose inode is an NsInode;
// setns(fd, nstype) downcasts via Inode::as_any, validates kind
// matches nstype, and writes the captured ns id into the calling
// task's matching slot.

use alloc::sync::Arc;
use core::any::Any;

use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

/// Linux CLONE_NEW* bits — match clone(2) for setns(fd, nstype) checks.
pub const CLONE_NEWNS:    u64 = 0x00020000;
pub const CLONE_NEWCGROUP:u64 = 0x02000000;
pub const CLONE_NEWUTS:   u64 = 0x04000000;
pub const CLONE_NEWIPC:   u64 = 0x08000000;
pub const CLONE_NEWUSER:  u64 = 0x10000000;
pub const CLONE_NEWPID:   u64 = 0x20000000;
pub const CLONE_NEWNET:   u64 = 0x40000000;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
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

/// Inode-number tag — high byte 0x72 ("r" for "ref").
const NS_INO_MARKER: Ino = 0x7200_0000;

/// Per-NS id snapshot. Captured at /proc/<pid>/ns/<type> lookup time;
/// stable for the lifetime of the open fd. setns reads this id +
/// kind to update the caller's per-task slot.
pub struct NsInode {
    pub kind: NsKind,
    pub id:   u64,
}

impl Inode for NsInode {
    fn as_any(&self) -> Option<&dyn Any> { Some(self) }
    fn ino(&self) -> Ino { NS_INO_MARKER | (self.kind as Ino) }
    fn file_type(&self) -> FileType { FileType::Symlink }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
}

/// Construct an NsInode capturing `task`'s current id for `kind`.
/// # C: O(1)
pub fn ns_inode_for(task: &sched::Task, kind: NsKind) -> InodeRef {
    use core::sync::atomic::Ordering;
    let id = match kind {
        NsKind::Uts    => (task.ns_membership.load(Ordering::Acquire) >> 1) & 0xff_ffff_ffff,
        NsKind::Ipc    => task.ipc_ns.load(Ordering::Acquire),
        NsKind::Pid    => task.pid_ns.load(Ordering::Acquire),
        NsKind::Net    => task.net_ns.load(Ordering::Acquire),
        NsKind::User   => task.user_ns.load(Ordering::Acquire),
        NsKind::Cgroup => task.cgroup_ns.load(Ordering::Acquire),
        NsKind::Mnt    => task.mount_ns.load(Ordering::Acquire),
    };
    Arc::new(NsInode { kind, id }) as InodeRef
}

/// Global registry mapping `user_ns id → parent_user_ns id` so the
/// `has_cap_for` ancestor walk works without scanning every task.
/// Init NS (id 0) has parent 0 (self-loop terminator).
static USER_NS_PARENT: sync::Spinlock<alloc::collections::BTreeMap<u64, u64>, sync::TaskList> =
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

/// Apply an NsInode (resolved from setns's fd arg) to the calling
/// task. Returns 0 on success or -EINVAL when nstype mismatches.
/// # C: O(1)
pub fn setns_apply(ns: &NsInode, nstype: u64, cur: &sched::Task) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    if nstype != 0 && (nstype & ns.kind.clone_bit()) == 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    match ns.kind {
        NsKind::Uts => {
            // Set membership bit but the per-task hostname slot is
            // owned by unshare/sethostname; setns alone doesn't
            // mutate it. Programs using uts NS via setns are rare
            // — record the bit so subsequent uname() consults the
            // task slot (which may be empty → falls back to global).
            cur.ns_membership.fetch_or(1u64 << 1, Ordering::Release);
        }
        NsKind::Ipc    => cur.ipc_ns.store(ns.id, Ordering::Release),
        NsKind::Pid    => cur.pid_ns.store(ns.id, Ordering::Release),
        NsKind::Net    => cur.net_ns.store(ns.id, Ordering::Release),
        NsKind::User   => cur.user_ns.store(ns.id, Ordering::Release),
        NsKind::Cgroup => cur.cgroup_ns.store(ns.id, Ordering::Release),
        NsKind::Mnt    => cur.mount_ns.store(ns.id, Ordering::Release),
    }
    0
}
