// SysV message queues per `24` follow-up — msgget/msgsnd/msgrcv/
// msgctl with real POSIX-blocking semantics on full/empty.
//
// Scope:
//   * msgget(key, flg) → queue id; queues default empty.
//   * msgsnd(msqid, msgp, msgsz, flg) appends a copy of
//     {mtype, mtext[0..msgsz]} to the queue FIFO. If the queue
//     is full (16 messages cap) the caller blocks on the per-
//     queue `wait_send` list until a msgrcv pops a message;
//     IPC_NOWAIT short-circuits to -EAGAIN.
//   * msgrcv(msqid, msgp, msgsz, msgtyp, flg):
//       msgtyp == 0  → first message, any type
//       msgtyp >  0  → first message with mtype == msgtyp
//       msgtyp <  0  → first message with mtype <= |msgtyp|,
//                       least mtype first
//     Empty / no-match → block on `wait_recv` until a msgsnd
//     publishes; IPC_NOWAIT short-circuits to -ENOMSG.
//   * msgctl: IPC_RMID (wakes both wait lists; sleepers return
//     -EIDRM on retry), IPC_STAT, IPC_INFO.

#![allow(dead_code)]

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, Ordering};

use sync::{Spinlock, TaskList as MsgLockClass};

const IPC_PRIVATE: i32 = 0;

/// `msgctl` cmd values (Linux).
const IPC_RMID: u64 = 0;
const IPC_SET:  u64 = 1;
const IPC_STAT: u64 = 2;
const IPC_INFO: u64 = 3;

/// `msgsnd` / `msgrcv` flag bit (only one we honor).
const IPC_NOWAIT_FLAG: i32 = 0o4000;

/// Per-message cap (mtext bytes). Linux default is 8 KiB; we use
/// 4 KiB so each message fits in a single allocation.
const MSG_MAX_SIZE:    usize = 4096;
/// Per-queue cap (number of pending messages).
const MSG_MAX_PER_Q:   usize = 16;

#[derive(Clone)]
struct Msg {
    pub mtype: i64,
    pub data:  Vec<u8>,
}

/// One SysV message queue. Messages protected by per-queue lock;
/// `wait_send` parks msgsnd callers when full, `wait_recv` parks
/// msgrcv callers when empty/no-match. Both are woken under the
/// per-queue lock to close the lost-wakeup race.
pub struct MsgQueue {
    pub id:        i32,
    pub key:       i32,
    /// IPC namespace id (CLONE_NEWIPC). 0 = init NS.
    pub ns:        u64,
    pub q:         Spinlock<VecDeque<Msg>, MsgLockClass>,
    pub wait_send: sched::live::WaitList,
    pub wait_recv: sched::live::WaitList,
}

fn current_ipc_ns() -> u64 {
    use core::sync::atomic::Ordering;
    sched::live::current().map(|t| t.ipc_ns.load(Ordering::Acquire)).unwrap_or(0)
}

struct MsgRegistry {
    next_id: AtomicI32,
    queues:  Spinlock<Vec<Arc<MsgQueue>>, MsgLockClass>,
}

static REG: MsgRegistry = MsgRegistry {
    next_id: AtomicI32::new(1),
    queues:  Spinlock::new(Vec::new()),
};

fn lookup_by_id(id: i32) -> Option<Arc<MsgQueue>> {
    let ns = current_ipc_ns();
    let g = REG.queues.lock();
    g.iter().find(|q| q.id == id && q.ns == ns).cloned()
}

fn lookup_by_key(key: i32) -> Option<Arc<MsgQueue>> {
    if key == IPC_PRIVATE { return None; }
    let ns = current_ipc_ns();
    let g = REG.queues.lock();
    g.iter().find(|q| q.key == key && q.ns == ns).cloned()
}

/// `msgget(key, msgflg)` — slot NR_MSGGET.
/// # C: O(N_queues)
pub fn sys_msgget(args: &syscall::SyscallArgs) -> i64 {
    let key  = args.a0 as i32;
    let _flg = args.a1;
    if let Some(q) = lookup_by_key(key) {
        return q.id as i64;
    }
    let id = REG.next_id.fetch_add(1, Ordering::AcqRel);
    let q = Arc::new(MsgQueue {
        id, key, ns: current_ipc_ns(),
        q: Spinlock::new(VecDeque::new()),
        wait_send: sched::live::WaitList::new(),
        wait_recv: sched::live::WaitList::new(),
    });
    REG.queues.lock().push(q);
    id as i64
}

/// `msgsnd(msqid, msgp, msgsz, msgflg)` — slot NR_MSGSND.
/// `msgp` is `struct { long mtype; char mtext[]; }` (8 + msgsz bytes).
///
/// Copies the message bytes from user space FIRST (outside the
/// queue lock so a user-page fault doesn't deadlock against
/// concurrent waiters). Then takes the queue lock; if full, blocks
/// on `wait_send` (unless IPC_NOWAIT). On commit, wakes one
/// receiver under the lock to close the lost-wakeup race.
/// # C: O(msgsz) on copy + O(N_retries) on contention
/// # Lk: MsgQueue.q → WaitList.waiters → runqueue.inner
pub fn sys_msgsnd(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let msqid = args.a0 as i32;
    let uptr  = args.a1;
    let sz    = args.a2 as usize;
    let flg   = args.a3 as i32;
    if sz > MSG_MAX_SIZE { return -(Errno::Einval.as_i32() as i64); }
    let nowait = (flg & IPC_NOWAIT_FLAG) != 0;

    let mq = match lookup_by_id(msqid) {
        Some(q) => q, None => return -(Errno::Einval.as_i32() as i64),
    };
    let mut data: Vec<u8> = Vec::new();
    if data.try_reserve_exact(sz).is_err() {
        return -(Errno::Enomem.as_i32() as i64);
    }
    data.resize(sz, 0);
    // SAFETY: msgsnd takes a user pointer to {long mtype, char mtext[]} (8+sz bytes); CPL=0 raw deref through caller's AS during syscall handling — NULL/garbage produces a fault.
    let mtype = unsafe {
        let mt = core::ptr::read_volatile(uptr as *const i64);
        if sz > 0 {
            core::ptr::copy_nonoverlapping(
                (uptr + 8) as *const u8,
                data.as_mut_ptr(),
                sz,
            );
        }
        mt
    };

    let msg = Msg { mtype, data };
    let mut msg_slot = Some(msg);
    loop {
        let mut g = mq.q.lock();
        if g.len() < MSG_MAX_PER_Q {
            // Take ownership of the queued message via Option::take
            // so we don't move out across the loop iteration.
            let m = msg_slot.take().expect("msg owned by sender");
            g.push_back(m);
            // Wake one receiver under the lock — the receiver
            // pushed onto wait_recv while holding `q`, so wake
            // sequencing under `q` rules out lost-wakeup.
            mq.wait_recv.wake_one();
            drop(g);
            return 0;
        }
        if nowait {
            drop(g);
            return -(Errno::Eagain.as_i32() as i64);
        }
        // Block. Push self under `q`, drop `q`, schedule.
        // SAFETY: process ctx; runqueue installed; preempt-off; we yield via schedule() immediately after parking; wait list lock briefly nests under q which the publisher always wakes under.
        unsafe { mq.wait_send.park(); }
        drop(g);
        // SAFETY: process ctx; runqueue installed; preempt-off.
        unsafe { sched::live::schedule(); }
        if lookup_by_id(msqid).is_none() {
            return -(Errno::Eidrm.as_i32() as i64);
        }
    }
}

/// Find queue index satisfying msgtyp matcher; returns the
/// position into the VecDeque or None.
fn pick_index(q: &VecDeque<Msg>, msgtyp: i64) -> Option<usize> {
    if q.is_empty() { return None; }
    if msgtyp == 0 {
        return Some(0);
    }
    if msgtyp > 0 {
        return q.iter().position(|m| m.mtype == msgtyp);
    }
    // msgtyp < 0: pick lowest mtype ≤ |msgtyp|.
    let cap = -msgtyp;
    let mut best: Option<(usize, i64)> = None;
    for (i, m) in q.iter().enumerate() {
        if m.mtype <= cap {
            match best {
                None => best = Some((i, m.mtype)),
                Some((_, bv)) if m.mtype < bv => best = Some((i, m.mtype)),
                _ => {}
            }
        }
    }
    best.map(|(i, _)| i)
}

/// `msgrcv(msqid, msgp, msgsz, msgtyp, msgflg)` — slot NR_MSGRCV.
///
/// Pops the first matching message; if none, blocks on
/// `wait_recv` until a msgsnd publishes (unless IPC_NOWAIT, which
/// short-circuits to -ENOMSG). The user-buffer copy happens AFTER
/// dropping the queue lock so a user-page fault doesn't deadlock
/// against concurrent senders.
///
/// Returns the bytes copied into `msgp.mtext` (excludes the mtype
/// header).
/// # C: O(N_msgs_in_queue + msgsz)
/// # Lk: MsgQueue.q → WaitList.waiters → runqueue.inner
pub fn sys_msgrcv(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let msqid  = args.a0 as i32;
    let uptr   = args.a1;
    let sz     = args.a2 as usize;
    let msgtyp = args.a3 as i64;
    let flg    = args.a4 as i32;
    if sz > MSG_MAX_SIZE { return -(Errno::Einval.as_i32() as i64); }
    let nowait = (flg & IPC_NOWAIT_FLAG) != 0;
    let mq = match lookup_by_id(msqid) {
        Some(q) => q, None => return -(Errno::Einval.as_i32() as i64),
    };

    let m = loop {
        let mut g = mq.q.lock();
        match pick_index(&g, msgtyp) {
            Some(i) => {
                let m = g.remove(i).expect("pick_index returned in-bounds");
                // Wake one sender under the lock — symmetric with
                // msgsnd's wake-receiver-under-lock.
                mq.wait_send.wake_one();
                drop(g);
                break m;
            }
            None => {
                if nowait {
                    drop(g);
                    return -(Errno::Enomsg.as_i32() as i64);
                }
                // SAFETY: process ctx; runqueue installed; preempt-off; we yield via schedule() immediately after parking; wait list lock briefly nests under q.
                unsafe { mq.wait_recv.park(); }
                drop(g);
                // SAFETY: process ctx; runqueue installed; preempt-off.
                unsafe { sched::live::schedule(); }
                if lookup_by_id(msqid).is_none() {
                    return -(Errno::Eidrm.as_i32() as i64);
                }
            }
        }
    };

    let to_copy = core::cmp::min(sz, m.data.len());
    // SAFETY: msgrcv writes {long mtype, char mtext[]} (8+to_copy bytes) into the user pointer; CPL=0 raw deref through caller's AS during syscall handling — NULL/garbage produces a fault.
    unsafe {
        core::ptr::write_volatile(uptr as *mut i64, m.mtype);
        if to_copy > 0 {
            core::ptr::copy_nonoverlapping(
                m.data.as_ptr(),
                (uptr + 8) as *mut u8,
                to_copy,
            );
        }
    }
    to_copy as i64
}

/// `msgctl(msqid, cmd, buf)` — slot NR_MSGCTL.
/// # C: O(N_queues) lookup
pub fn sys_msgctl(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let msqid = args.a0 as i32;
    let cmd   = args.a1;
    let _buf  = args.a2;
    match cmd {
        IPC_RMID => {
            let removed: Option<Arc<MsgQueue>> = {
                let mut g = REG.queues.lock();
                let pos = g.iter().position(|q| q.id == msqid);
                pos.map(|i| g.swap_remove(i))
            };
            match removed {
                Some(q) => {
                    // Wake every parker; sleepers re-check
                    // lookup_by_id and return -EIDRM.
                    q.wait_send.wake_all();
                    q.wait_recv.wake_all();
                    0
                }
                None => -(Errno::Einval.as_i32() as i64),
            }
        }
        IPC_STAT | IPC_INFO | IPC_SET => {
            // Lookup just to validate id, then succeed.
            match lookup_by_id(msqid) {
                Some(_) => 0,
                None    => -(Errno::Einval.as_i32() as i64),
            }
        }
        _ => -(Errno::Einval.as_i32() as i64),
    }
}
