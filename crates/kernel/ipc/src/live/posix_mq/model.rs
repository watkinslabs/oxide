// The mqueue objects: one queue per inode, one directory per IPC namespace.
//
// Linux shape (`ipc/mqueue.c`): every IPC namespace owns a private mqueuefs
// mount whose root is a sticky 01777 directory; each queue is one `S_IFREG`
// inode in it whose `i_private` is the `mqueue_inode_info`. This file keeps
// exactly that: `REG` is the set of per-namespace directories, an entry is a
// (name, inode) link, and `MqQueue` is the inode's private state. There is no
// second, name-keyed table — the inode IS the queue.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use namespace_identity::NamespaceId;
use sync::{Spinlock, TaskList as MqLockClass};
use vfs::inode::InodeBuilder;
use vfs::inode_ops::{default_inode_ops, mk_mode};
use vfs::{FileType, InodeRef};

use crate::mqueue_policy::attr::MqSysctls;
use crate::mqueue_policy::limits::MQ_ROOT_PERM;
use crate::mqueue_policy::notify::NotifyKind;

use super::fops::mq_file_ops;

/// One record in a queue's priority-ordered buffer.
#[derive(Clone)]
pub struct MqMsg {
    pub priority: u32,
    pub bytes: Vec<u8>,
}

/// Linux `info->notify_owner` + `info->notify` — the single registration a
/// queue may carry.
#[derive(Clone)]
pub struct MqNotifyReg {
    /// `task_tgid(current)`: the registering PROCESS, so any thread of it may
    /// deregister and the notification is process-directed.
    pub owner_tgid: u32,
    pub kind: NotifyKind,
    /// `sigev_value`, delivered as `si_value`.
    pub value: u64,
    /// SIGEV_THREAD: the netlink socket `sigev_signo` named (`info->notify_sock`,
    /// held by reference, not by fd number) plus the `NOTIFY_COOKIE_LEN` cookie
    /// read from `sigev_value.sival_ptr` (`info->notify_cookie`).
    pub sock: Option<Arc<netlink::NetlinkSocket>>,
    pub cookie: Vec<u8>,
}

/// Linux `struct mqueue_inode_info` — an mq inode's `i_private`.
pub struct MqQueue {
    pub ns: NamespaceId,
    /// `info->attr.mq_maxmsg` / `mq_msgsize`, fixed at creation.
    pub maxmsg: usize,
    pub msgsize: usize,
    /// RLIMIT_MSGQUEUE charge held against `charged_uid` until destruction.
    pub mq_bytes: u64,
    pub charged_uid: u32,
    pub msgs: Spinlock<Vec<MqMsg>, MqLockClass>,
    pub wait_send: sched::live::WaitList,
    pub wait_recv: sched::live::WaitList,
    pub notify: Spinlock<Option<MqNotifyReg>, MqLockClass>,
    /// Open file descriptions referring to this queue. Linux gets the same
    /// answer from `i_count`; we count explicitly so the "unlinked and last
    /// description closed" decision is a single guarded test.
    pub opens: AtomicU32,
    /// `mq_unlink` dropped the directory link; the queue dies with its last
    /// description (POSIX: an unlinked queue stays usable through open fds).
    pub unlinked: AtomicBool,
}

impl MqQueue {
    /// # C: O(1)
    pub fn curmsgs(&self) -> usize { self.msgs.lock().len() }
}

/// One directory link: a name and the inode it resolves to.
struct MqEntry {
    name: String,
    inode: InodeRef,
}

/// One IPC namespace's mqueuefs: its root directory inode, its sysctls, its
/// links, and its `mq_queues_count`.
struct MqDir {
    ns: NamespaceId,
    root: InodeRef,
    sysctls: MqSysctls,
    /// Linux `ipc_ns->mq_queues_count` — live inodes, linked or not.
    count: u32,
    entries: Vec<MqEntry>,
}

static REG: Spinlock<Vec<MqDir>, MqLockClass> = Spinlock::new(Vec::new());

/// Accumulated `mq_bytes` per creating uid — Linux `ucounts`
/// `UCOUNT_RLIMIT_MSGQUEUE`. Guarded by `REG` (never locked the other way
/// round) so admission and charging are one critical section.
static CHARGED: Spinlock<Vec<(u32, u64)>, MqLockClass> = Spinlock::new(Vec::new());

/// `i_ino` shared by every mqueue root directory.
const MQ_ROOT_INO: vfs::Ino = super::super::ids::POSIX_MQ_ROOT_INO;

fn build_root() -> InodeRef {
    // `mqueue_fill_super`: root is `S_IFDIR | S_ISVTX | S_IRWXUGO`, owned by
    // root, so any user may create a queue and only its owner may unlink it.
    InodeBuilder::new(MQ_ROOT_INO, mk_mode(FileType::Directory, MQ_ROOT_PERM),
                      default_inode_ops(), vfs::file_ops::default_file_ops())
        .owner(0, 0)
        .build()
}

fn dir_index(reg: &mut Vec<MqDir>, ns: NamespaceId) -> usize {
    if let Some(i) = reg.iter().position(|d| d.ns == ns) { return i; }
    reg.push(MqDir { ns, root: build_root(), sysctls: MqSysctls::linux_defaults(),
                     count: 0, entries: Vec::new() });
    reg.len() - 1
}

/// The namespace's mqueuefs root inode — `mq_unlink`'s `may_delete` parent.
/// # C: O(N_ns)
pub fn root_inode(ns: NamespaceId) -> InodeRef {
    let mut g = REG.lock();
    let i = dir_index(&mut g, ns);
    g[i].root.clone()
}

/// `/proc/sys/fs/mqueue/*` for this namespace. # C: O(N_ns)
pub fn sysctls(ns: NamespaceId) -> MqSysctls {
    let mut g = REG.lock();
    let i = dir_index(&mut g, ns);
    g[i].sysctls
}

/// Resolve a linked name to its inode. # C: O(N_queues)
pub fn lookup(ns: NamespaceId, name: &str) -> Option<InodeRef> {
    let mut g = REG.lock();
    let i = dir_index(&mut g, ns);
    g[i].entries.iter().find(|e| e.name == name).map(|e| e.inode.clone())
}

/// The `MqQueue` behind an inode, or `None` when the inode is not an mq inode
/// (Linux `f_op != &mqueue_file_operations` → EBADF). # C: O(1)
pub fn queue_of(inode: &InodeRef) -> Option<Arc<MqQueue>> {
    inode.private::<MqInodePrivate>().map(|p| p.queue.clone())
}

/// `i_private` payload. A newtype rather than a bare `Arc<MqQueue>` so
/// `private::<T>()` cannot alias another subsystem's `Arc<...>`.
pub struct MqInodePrivate {
    pub queue: Arc<MqQueue>,
}

/// Build a queue inode and link it under `name`. Fails with `EEXIST` when a
/// racing `mq_open` linked the same name first (the caller released `REG`
/// between its lookup and this call). `charge` is the already-validated
/// RLIMIT_MSGQUEUE cost, taken under the same lock as the admission test so
/// two concurrent creates cannot both pass a limit only one fits under.
/// # C: O(N_queues)
pub fn create_linked(
    ns: NamespaceId, name: &str, mode: u16, uid: u32, gid: u32,
    maxmsg: usize, msgsize: usize, mq_bytes: u64, rlimit_cur: u64, cap_sys_resource: bool,
) -> Result<InodeRef, syscall::errno::Errno> {
    use crate::mqueue_policy::attr::{admit_new_queue, charge_msgqueue};
    // Build the object BEFORE the registry lock: allocation must not run under
    // it, and an inode that loses the admission race below simply drops — it
    // carries no open description and no charge until it is linked.
    let queue = Arc::new(MqQueue {
        ns, maxmsg, msgsize, mq_bytes, charged_uid: uid,
        msgs: Spinlock::new(Vec::new()),
        wait_send: sched::live::WaitList::new(),
        wait_recv: sched::live::WaitList::new(),
        notify: Spinlock::new(None),
        opens: AtomicU32::new(0),
        unlinked: AtomicBool::new(false),
    });
    let inode = InodeBuilder::new(vfs::get_next_ino() as vfs::Ino,
                                  mk_mode(FileType::Regular, mode),
                                  default_inode_ops(), mq_file_ops())
        .owner(uid, gid)
        .private(Arc::new(MqInodePrivate { queue }))
        .build();
    let name = String::from(name);
    let mut g = REG.lock();
    let i = dir_index(&mut g, ns);
    if g[i].entries.iter().any(|e| e.name == name) { return Err(syscall::errno::Errno::Eexist); }
    admit_new_queue(g[i].count, g[i].sysctls.queues_max, cap_sys_resource)?;
    {
        let mut c = CHARGED.lock();
        let slot = match c.iter().position(|&(u, _)| u == uid) {
            Some(p) => p,
            None => { c.push((uid, 0)); c.len() - 1 }
        };
        let total = charge_msgqueue(c[slot].1, mq_bytes, rlimit_cur)?;
        c[slot].1 = total;
    }
    g[i].count += 1;
    g[i].entries.push(MqEntry { name, inode: inode.clone() });
    Ok(inode)
}

/// Drop the directory link for `name`. Returns the unlinked inode so the
/// caller drops it OUTSIDE the registry lock. # C: O(N_queues)
pub fn unlink(ns: NamespaceId, name: &str) -> Option<InodeRef> {
    let removed = {
        let mut g = REG.lock();
        let i = dir_index(&mut g, ns);
        let p = g[i].entries.iter().position(|e| e.name == name)?;
        g[i].entries.swap_remove(p).inode
    };
    if let Some(q) = queue_of(&removed) {
        q.unlinked.store(true, Ordering::Release);
        if q.opens.load(Ordering::Acquire) == 0 { destroy(&q); }
    }
    Some(removed)
}

/// One more open file description on `q`. # C: O(1)
pub fn open_ref(q: &MqQueue) { q.opens.fetch_add(1, Ordering::AcqRel); }

/// Release one open file description. An unlinked queue whose last description
/// just went away is destroyed here — Linux `mqueue_evict_inode`.
/// # C: O(N_ns)
pub fn release_ref(q: &MqQueue) {
    if q.opens.fetch_sub(1, Ordering::AcqRel) == 1 && q.unlinked.load(Ordering::Acquire) {
        destroy(q);
    }
}

/// Refund the RLIMIT_MSGQUEUE charge and the namespace queue count exactly
/// once. Idempotent via `mq_bytes`-zeroing on the charge table entry: the
/// count is decremented only on the transition that also refunds.
/// # C: O(N_ns)
fn destroy(q: &MqQueue) {
    let mut g = REG.lock();
    let Some(i) = g.iter().position(|d| d.ns == q.ns) else { return };
    if g[i].count > 0 { g[i].count -= 1; }
    let mut c = CHARGED.lock();
    if let Some(p) = c.iter().position(|&(u, _)| u == q.charged_uid) {
        c[p].1 = c[p].1.saturating_sub(q.mq_bytes);
    }
}

/// Namespace teardown: unlink every queue and wake anything parked on them.
/// # C: O(N_queues)
pub(crate) fn reap_namespace(ns: NamespaceId) {
    let dir = {
        let mut g = REG.lock();
        match g.iter().position(|d| d.ns == ns) { Some(i) => g.swap_remove(i), None => return }
    };
    for e in &dir.entries {
        if let Some(q) = queue_of(&e.inode) {
            q.unlinked.store(true, Ordering::Release);
            q.wait_send.wake_all();
            q.wait_recv.wake_all();
        }
    }
    let mut c = CHARGED.lock();
    for e in &dir.entries {
        if let Some(q) = queue_of(&e.inode) {
            if let Some(p) = c.iter().position(|&(u, _)| u == q.charged_uid) {
                c[p].1 = c[p].1.saturating_sub(q.mq_bytes);
            }
        }
    }
}
