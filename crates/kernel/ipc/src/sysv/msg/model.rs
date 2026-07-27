//! Linux `struct msg_queue` (`ipc/msg.c`) and its per-namespace registry.
//!
//! The mutable half sits behind the queue's own lock so `msgsnd` / `msgrcv`
//! evaluate the queue-full / message-match condition AND register on a wait
//! list inside one critical section. `removed` is set under that same lock
//! (B1427): `IPC_RMID` and namespace teardown wake the wait lists exactly
//! once, so a park landing after that one-shot wake would never be woken
//! again — the id is already out of the registry and no later `msgsnd` /
//! `msgrcv` (nor a second `IPC_RMID`) can fire another wake. Checking
//! `removed` under the same lock the waiter parks under turns every ordering
//! against removal into an immediate `EIDRM` instead of a possible hang.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use namespace_identity::NamespaceId;
use sync::{Spinlock, TaskList as MsgLockClass};
use syscall::errno::Errno;

use crate::sysv::block::{self, WaitList};
use crate::sysv::ids::IpcIds;
use crate::sysv::limits::MSGMNB;
use crate::sysv::perm::{IpcCred, IpcPerm};

/// `struct msgbuf`'s `mtype` header, ahead of `mtext[]`. `__kernel_long_t` is
/// 8 bytes on both targets this kernel builds.
pub const MTYPE_BYTES: usize = 8;

/// Linux `struct msg_msg`: the type word plus the payload whose length is
/// `m_ts`.
pub struct Msg {
    pub mtype: i64,
    pub data: Vec<u8>,
}

impl Msg {
    /// Linux `m_ts` — payload length in bytes. # C: O(1)
    pub fn ts(&self) -> u64 { self.data.len() as u64 }
}

/// The lock-protected half of `struct msg_queue`: the FIFO plus every
/// `msqid64_ds` accounting field Linux mutates under `ipc_lock_object`.
pub struct QueueState {
    pub msgs: VecDeque<Msg>,
    /// `q_stime` / `q_rtime` / `q_ctime`, wall-clock seconds.
    pub stime: i64,
    pub rtime: i64,
    pub ctime: i64,
    /// `q_cbytes` — payload bytes currently queued.
    pub cbytes: u64,
    /// `q_qnum` — messages currently queued.
    pub qnum: u64,
    /// `q_qbytes` — the queue's byte budget, `MSGMNB` at creation.
    pub qbytes: u64,
    /// `q_lspid` / `q_lrpid` — TGID of the last sender / receiver.
    pub lspid: u32,
    pub lrpid: u32,
}

impl QueueState {
    /// Linux `msg_fits_inqueue`. Both halves matter: the byte budget bounds
    /// the payload, and `q_qbytes` doubles as the message-count bound so a
    /// flood of zero-length messages cannot grow the queue without limit.
    /// # C: O(1)
    pub fn fits(&self, msgsz: u64) -> bool {
        msgsz.saturating_add(self.cbytes) <= self.qbytes
            && self.qnum.saturating_add(1) <= self.qbytes
    }
}

/// One SysV message queue.
pub struct MsgQueue {
    pub perm: IpcPerm,
    /// Registry key derived from the canonical IPC namespace owner.
    pub ns: NamespaceId,
    pub state: Spinlock<QueueState, MsgLockClass>,
    /// Linux `q_senders` — `msgsnd` callers parked on a full queue.
    pub senders: WaitList,
    /// Linux `q_receivers` — `msgrcv` callers parked with no match.
    pub receivers: WaitList,
    /// Linux `ipc_valid_object()`. See the module comment for why this is
    /// read under `state` rather than inferred from a registry miss.
    removed: AtomicBool,
}

impl MsgQueue {
    /// Linux `!ipc_valid_object()`. Callers MUST read this under `state`.
    /// # C: O(1)
    pub fn is_removed(&self) -> bool { self.removed.load(Ordering::Acquire) }
}

/// Every namespace's message-queue identifier space. Linux keys this off
/// `ns->ids[IPC_MSG_IDS]`; the registry lock stands in for `ids.rwsem`.
static REG: Spinlock<IpcIds<MsgQueue>, MsgLockClass> = Spinlock::new(IpcIds::new());

/// Run `f` against the namespace identifier space with the registry held, so
/// a key lookup and the create that follows it are one atomic `ipcget`.
/// # C: O(f)
/// # Lk: msg registry
pub fn with_ids<R>(f: impl FnOnce(&mut IpcIds<MsgQueue>) -> R) -> R {
    let mut g = REG.lock();
    f(&mut g)
}

/// Linux `newque` minus the identifier allocation: build the queue object for
/// a caller that already reserved `(idx, seq, id)`. # C: O(1)
pub fn new_queue(ns: NamespaceId, key: i32, id: i32, seq: u16, msgflg: i32, cred: &IpcCred) -> Arc<MsgQueue> {
    Arc::new(MsgQueue {
        perm: IpcPerm::new(key, id, seq, msgflg, cred),
        ns,
        state: Spinlock::new(QueueState {
            msgs: VecDeque::new(),
            stime: 0,
            rtime: 0,
            ctime: block::real_seconds(),
            cbytes: 0,
            qnum: 0,
            qbytes: MSGMNB as u64,
            lspid: 0,
            lrpid: 0,
        }),
        senders: WaitList::new(),
        receivers: WaitList::new(),
        removed: AtomicBool::new(false),
    })
}

/// The calling task's IPC namespace registry key. # C: O(1)
pub fn current_ns() -> Result<NamespaceId, Errno> {
    match crate::ipc_namespace::current() {
        Ok(owner) => Ok(owner.key()),
        Err(_) => Err(Errno::Einval),
    }
}

/// Linux `msq_obtain_object_check` — index by id, then reject a stale
/// sequence half (`ipc_checkid`). # C: O(1)
/// # Lk: msg registry
pub fn lookup_checked(ns: NamespaceId, id: i32) -> Result<Arc<MsgQueue>, Errno> {
    REG.lock().lookup_checked(ns, id, |q| q.perm.seq).ok_or(Errno::Einval)
}

/// Linux `msq_obtain_object` — `MSG_STAT` addresses by raw index and does not
/// check the sequence half. # C: O(1)
/// # Lk: msg registry
pub fn lookup_idx(ns: NamespaceId, idx: i32) -> Result<Arc<MsgQueue>, Errno> {
    REG.lock().lookup_idx(ns, idx).ok_or(Errno::Einval)
}

/// Linux `freeque`: publish the removal under `state`, wake every parked
/// sender and receiver so each returns `EIDRM`, then drop the queued
/// messages. The caller has already unpublished the queue from the registry.
/// # C: O(N_msgs + N_waiters)
/// # Lk: MsgQueue.state -> WaitList.waiters -> runqueue.inner
pub fn freeque(q: &Arc<MsgQueue>) {
    let mut st = q.state.lock();
    // B1427: the flag-set and the one-shot wake are both gated by `state`, the
    // lock the waiters evaluate their condition and register under.
    q.removed.store(true, Ordering::Release);
    q.receivers.wake_all();
    q.senders.wake_all();
    st.msgs.clear();
    st.cbytes = 0;
    st.qnum = 0;
}

/// Tear down every queue an exiting IPC namespace owned. # C: O(N_queues)
/// # Lk: msg registry, then MsgQueue.state per queue
pub fn reap_namespace(ns: NamespaceId) {
    let doomed: Vec<Arc<MsgQueue>> = REG.lock().drain_namespace(ns);
    for q in doomed.iter() { freeque(q); }
}

/// `MSG_INFO`'s per-namespace totals: `(in_use, msg headers, msg bytes,
/// max_idx)`. Linux keeps the header/byte totals in per-CPU counters; summing
/// the live queues yields the same value from one source of truth.
/// # C: O(N_queues)
/// # Lk: msg registry, then MsgQueue.state per queue
pub fn info_counters(ns: NamespaceId) -> (usize, u64, u64, i64) {
    let (queues, in_use, max_idx) = {
        let g = REG.lock();
        (g.all(ns), g.in_use(ns), g.max_idx(ns))
    };
    let mut hdrs = 0u64;
    let mut bytes = 0u64;
    for q in queues.iter() {
        let st = q.state.lock();
        hdrs = hdrs.saturating_add(st.qnum);
        bytes = bytes.saturating_add(st.cbytes);
    }
    (in_use, hdrs, bytes, max_idx)
}
