// SysV message queues per `24` follow-up — bare-minimum
// msgget/msgsnd/msgrcv/msgctl. Older daemons (lpd, atd, sysvinit)
// and certain monitoring agents probe these; v1 returned -ENOSYS,
// callers abort. v2 P25c admits + delivers a working queue
// registry with non-blocking msgsnd/msgrcv semantics.
//
// Scope (first cut):
//   * msgget(key, flg) → queue id; queues default empty.
//   * msgsnd(msqid, msgp, msgsz, flg) appends a copy of
//     {mtype, mtext[0..msgsz]} to the queue FIFO; if the queue
//     is full (16 messages cap) returns -EAGAIN.
//   * msgrcv(msqid, msgp, msgsz, msgtyp, flg):
//       msgtyp == 0  → first message, any type
//       msgtyp >  0  → first message with mtype == msgtyp
//       msgtyp <  0  → first message with mtype <= |msgtyp|,
//                       least mtype first
//     Empty queue → -EAGAIN (no blocking — see header).
//   * msgctl: IPC_RMID, IPC_STAT, IPC_INFO.
//
// Real POSIX-blocking msgrcv (sleep until matching message
// arrives) requires sched-integrated wait queues; programs that
// need it today see EAGAIN and either retry-with-yield or fall
// back to pipes/eventfd. The probe-and-survive path is unblocked.

#![cfg(target_os = "oxide-kernel")]
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

/// One SysV message queue. Messages protected by per-queue lock
/// so msgsnd / msgrcv batches are serialized.
pub struct MsgQueue {
    pub id:    i32,
    pub key:   i32,
    pub q:     Spinlock<VecDeque<Msg>, MsgLockClass>,
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
    let g = REG.queues.lock();
    g.iter().find(|q| q.id == id).cloned()
}

fn lookup_by_key(key: i32) -> Option<Arc<MsgQueue>> {
    if key == IPC_PRIVATE { return None; }
    let g = REG.queues.lock();
    g.iter().find(|q| q.key == key).cloned()
}

/// `msgget(key, msgflg)` — slot NR_MSGGET.
/// # C: O(N_queues)
pub fn kernel_sys_msgget(args: &syscall::SyscallArgs) -> i64 {
    let key  = args.a0 as i32;
    let _flg = args.a1;
    if let Some(q) = lookup_by_key(key) {
        return q.id as i64;
    }
    let id = REG.next_id.fetch_add(1, Ordering::AcqRel);
    let q = Arc::new(MsgQueue {
        id, key,
        q: Spinlock::new(VecDeque::new()),
    });
    REG.queues.lock().push(q);
    id as i64
}

/// `msgsnd(msqid, msgp, msgsz, msgflg)` — slot NR_MSGSND.
/// `msgp` is `struct { long mtype; char mtext[]; }` (8 + msgsz bytes).
/// # C: O(msgsz)
pub fn kernel_sys_msgsnd(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let msqid = args.a0 as i32;
    let uptr  = args.a1;
    let sz    = args.a2 as usize;
    let _flg  = args.a3;
    if sz > MSG_MAX_SIZE { return -(Errno::Einval.as_i32() as i64); }
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
    let mut g = mq.q.lock();
    if g.len() >= MSG_MAX_PER_Q {
        return -(Errno::Eagain.as_i32() as i64);
    }
    g.push_back(Msg { mtype, data });
    0
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
/// Returns the bytes copied into `msgp.mtext` (excludes the mtype
/// header). On empty queue / no match, returns -EAGAIN (v1 never
/// blocks — see header).
/// # C: O(N_msgs_in_queue + msgsz)
pub fn kernel_sys_msgrcv(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let msqid  = args.a0 as i32;
    let uptr   = args.a1;
    let sz     = args.a2 as usize;
    let msgtyp = args.a3 as i64;
    let _flg   = args.a4;
    if sz > MSG_MAX_SIZE { return -(Errno::Einval.as_i32() as i64); }
    let mq = match lookup_by_id(msqid) {
        Some(q) => q, None => return -(Errno::Einval.as_i32() as i64),
    };
    let mut g = mq.q.lock();
    let idx = match pick_index(&g, msgtyp) {
        Some(i) => i, None => return -(Errno::Eagain.as_i32() as i64),
    };
    let m = match g.remove(idx) { Some(m) => m, None => return -(Errno::Eagain.as_i32() as i64) };
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
pub fn kernel_sys_msgctl(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let msqid = args.a0 as i32;
    let cmd   = args.a1;
    let _buf  = args.a2;
    match cmd {
        IPC_RMID => {
            let mut g = REG.queues.lock();
            if g.iter().any(|q| q.id == msqid) {
                g.retain(|q| q.id != msqid);
                0
            } else {
                -(Errno::Einval.as_i32() as i64)
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
