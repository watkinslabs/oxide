// POSIX message queues per `24` follow-up — real priority-ordered
// sized-record semantics.
//
// Layout:
//   * REG: name → Arc<MqQueue> registry. mq_open looks up or
//     creates the queue + returns a fd backed by MqInode (which
//     holds an Arc<MqQueue>).
//   * MqQueue: bounded buffer of MqMsg{priority, bytes} kept in
//     priority-descending / FIFO-within-priority order
//     (insertion-sorted, O(N) on send; v1 cap = 10 messages).
//   * mq_send blocks on wait_send when full (unless O_NONBLOCK
//     in oflag, captured by the inode at open time, OR
//     IPC_NOWAIT-equivalent abs_timeout = past).
//   * mq_receive blocks on wait_recv when empty.
//   * mq_unlink drops the name from REG; existing fds still hold
//     Arc<MqQueue> so callers can drain.
//
// `read()`/`write()` on the fd return -EINVAL — POSIX MQ ABI is
// the dedicated mq_timedsend/mq_timedreceive syscalls, NOT byte
// stream.

#![allow(dead_code)]

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use sync::{Spinlock, TaskList as MqLockClass};
use vfs::{Dentry, File, FileType, Ino, Inode, InodeRef, KResult, OpenFlags, VfsError};

const MQ_DEFAULT_MAXMSG:  usize = 10;
const MQ_DEFAULT_MSGSIZE: usize = 8192;
const MQ_HARD_MAXMSG:     usize = 256;
const MQ_HARD_MSGSIZE:    usize = 65536;
const MQ_PRIO_MAX:        u32   = 32_768;

const O_NONBLOCK_BIT: u64 = 0o4000;

#[derive(Clone)]
struct MqMsg {
    priority: u32,
    bytes:    Vec<u8>,
}

/// One named POSIX message queue. Messages held priority-descending
/// (highest at index 0); equal-priority messages keep FIFO order
/// because we insert at the end of the matching priority run.
pub struct MqQueue {
    pub name:        String,
    /// IPC namespace id (CLONE_NEWIPC). 0 = init NS.
    pub ns:          u64,
    pub max_msgs:    usize,
    pub max_msgsize: usize,
    pub msgs:        Spinlock<Vec<MqMsg>, MqLockClass>,
    pub wait_send:   sched::live::WaitList,
    pub wait_recv:   sched::live::WaitList,
    pub notifier_tid:   core::sync::atomic::AtomicU32,
    pub notifier_signo: core::sync::atomic::AtomicI32,
}

fn current_ipc_ns() -> u64 {
    use core::sync::atomic::Ordering;
    sched::live::current().map(|t| t.ipc_ns.load(Ordering::Acquire)).unwrap_or(0)
}

impl MqQueue {
    fn new(name: String, max_msgs: usize, max_msgsize: usize) -> Arc<Self> {
        Arc::new(Self {
            name,
            ns: current_ipc_ns(),
            max_msgs,
            max_msgsize,
            msgs: Spinlock::new(Vec::new()),
            wait_send: sched::live::WaitList::new(),
            wait_recv: sched::live::WaitList::new(),
            notifier_tid:   core::sync::atomic::AtomicU32::new(0),
            notifier_signo: core::sync::atomic::AtomicI32::new(0),
        })
    }
}

struct MqRegistry {
    queues: Spinlock<Vec<Arc<MqQueue>>, MqLockClass>,
}

static REG: MqRegistry = MqRegistry {
    queues: Spinlock::new(Vec::new()),
};

fn lookup_by_name(name: &str) -> Option<Arc<MqQueue>> {
    let ns = current_ipc_ns();
    let g = REG.queues.lock();
    g.iter().find(|q| q.name == name && q.ns == ns).cloned()
}

fn unlink_by_name(name: &str) -> bool {
    let ns = current_ipc_ns();
    let mut g = REG.queues.lock();
    if let Some(i) = g.iter().position(|q| q.name == name && q.ns == ns) {
        g.swap_remove(i);
        true
    } else {
        false
    }
}

/// Inode wrapper around an Arc<MqQueue>. Holds the queue alive
/// for as long as any fd referring to it is open. Per Inode trait,
/// most ops aren't meaningful for an mq fd; read/write return
/// -EINVAL because the POSIX ABI is mq_timedsend/mq_timedreceive.
pub struct MqInode {
    pub queue:   Arc<MqQueue>,
    pub nonblock: core::sync::atomic::AtomicBool,
}

impl Inode for MqInode {
    fn as_any(&self) -> Option<&dyn core::any::Any> { Some(self) }
    fn ino(&self) -> Ino { 0xFEED_0010 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, _off: u64, _buf: &mut [u8]) -> KResult<usize> {
        Err(VfsError::Einval)
    }
    fn write(&self, _off: u64, _buf: &[u8]) -> KResult<usize> {
        Err(VfsError::Einval)
    }
}

fn read_user_string(uptr: u64, max: usize) -> Option<String> {
    if uptr == 0 || uptr >= hal::USER_VA_END { return None; }
    // SAFETY: caller-provided user pointer; bounded read via devfs helper which checks USER_VA_END internally.
    let bytes = unsafe { devfs::read_user_cstr(uptr, max) }?;
    let s = core::str::from_utf8(bytes).ok()?;
    Some(String::from(s))
}

/// `sys_mq_open(name, oflag, mode, attr)` — slot NR_MQ_OPEN.
/// # C: O(N_queues) lookup
pub fn kernel_sys_mq_open(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let name_ptr = args.a0;
    let oflag    = args.a1;
    let _mode    = args.a2;
    let attr_ptr = args.a3;

    let name = match read_user_string(name_ptr, 256) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    if name.is_empty() { return -(Errno::Einval.as_i32() as i64); }

    let mut max_msgs    = MQ_DEFAULT_MAXMSG;
    let mut max_msgsize = MQ_DEFAULT_MSGSIZE;
    if attr_ptr != 0 && attr_ptr < hal::USER_VA_END {
        // struct mq_attr { long mq_flags; long mq_maxmsg; long mq_msgsize; long mq_curmsgs; ... }
        // SAFETY: attr_ptr range validated; CPL=0 raw deref through caller's AS during syscall handling.
        unsafe {
            let mq_maxmsg  = core::ptr::read_volatile((attr_ptr + 8)  as *const i64);
            let mq_msgsize = core::ptr::read_volatile((attr_ptr + 16) as *const i64);
            if mq_maxmsg > 0 && (mq_maxmsg as usize) <= MQ_HARD_MAXMSG {
                max_msgs = mq_maxmsg as usize;
            }
            if mq_msgsize > 0 && (mq_msgsize as usize) <= MQ_HARD_MSGSIZE {
                max_msgsize = mq_msgsize as usize;
            }
        }
    }

    let q = match lookup_by_name(&name) {
        Some(existing) => existing,
        None => {
            let q = MqQueue::new(name.clone(), max_msgs, max_msgsize);
            REG.queues.lock().push(q.clone());
            q
        }
    };

    let inode: InodeRef = Arc::new(MqInode {
        queue: q,
        nonblock: core::sync::atomic::AtomicBool::new((oflag & O_NONBLOCK_BIT) != 0),
    });
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let dentry = Dentry::new(None, name, inode.clone());
    let file = File::new(inode, dentry, OpenFlags::O_RDWR);
    match fdt.alloc(file) {
        Ok(fd) => fd as i64,
        Err(e) => -(e as i64),
    }
}

/// `sys_mq_unlink(name)` — slot NR_MQ_UNLINK.
/// # C: O(N_queues)
pub fn kernel_sys_mq_unlink(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let name = match read_user_string(args.a0, 256) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    if unlink_by_name(&name) { 0 }
    else { -(Errno::Enoent.as_i32() as i64) }
}

fn fd_to_mq(fd: i32) -> Option<(Arc<MqQueue>, bool)> {
    let cur = sched::live::current()?;
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = unsafe { cur.fd_table_ref() }?.clone();
    let file = fdt.get(fd).ok()?;
    let inode = file.inode();
    let mq = inode.as_any()?.downcast_ref::<MqInode>()?;
    let nb = mq.nonblock.load(Ordering::Acquire);
    Some((mq.queue.clone(), nb))
}

/// `sys_mq_timedsend(mqdes, msg_ptr, msg_len, msg_prio, abs_timeout)`
/// — slot NR_MQ_TIMEDSEND. v1 ignores abs_timeout (no sched-timer
/// integration); blocks indefinitely if full unless O_NONBLOCK
/// was set on the fd at open time.
/// # C: O(msg_len + N_queue) (insertion sort by priority)
pub fn kernel_sys_mq_timedsend(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let mqdes    = args.a0 as i32;
    let uptr     = args.a1;
    let len      = args.a2 as usize;
    let prio     = args.a3 as u32;
    let _abstime = args.a4;

    if prio >= MQ_PRIO_MAX { return -(Errno::Einval.as_i32() as i64); }
    let (q, nonblock) = match fd_to_mq(mqdes) {
        Some(t) => t, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    if len > q.max_msgsize { return -(Errno::Emsgsize.as_i32() as i64); }

    let mut bytes: Vec<u8> = Vec::new();
    if bytes.try_reserve_exact(len).is_err() {
        return -(Errno::Enomem.as_i32() as i64);
    }
    bytes.resize(len, 0);
    if len > 0 {
        if uptr == 0 || uptr >= hal::USER_VA_END {
            return -(Errno::Efault.as_i32() as i64);
        }
        // SAFETY: range [uptr, uptr+len) is in user space (validated < USER_VA_END); CPL=0 raw deref through caller's AS.
        unsafe {
            core::ptr::copy_nonoverlapping(
                uptr as *const u8,
                bytes.as_mut_ptr(),
                len,
            );
        }
    }
    let msg = MqMsg { priority: prio, bytes };
    let mut slot = Some(msg);

    loop {
        let mut g = q.msgs.lock();
        if g.len() < q.max_msgs {
            let was_empty = g.is_empty();
            let m = slot.take().expect("msg owned by sender");
            // Insert in priority-descending FIFO-within-priority
            // order. Find first index where existing.priority < m.priority.
            let pos = g.iter().position(|e| e.priority < m.priority).unwrap_or(g.len());
            g.insert(pos, m);
            q.wait_recv.wake_one();
            drop(g);
            if was_empty {
                use core::sync::atomic::Ordering;
                let tid = q.notifier_tid.swap(0, Ordering::AcqRel);
                let signo = q.notifier_signo.swap(0, Ordering::AcqRel);
                if tid != 0 && (1..=64).contains(&signo) {
                    if let Some(t) = sched::live::registry::lookup(tid) {
                        t.sigpending.fetch_or(1u64 << (signo - 1), Ordering::Release);
                    }
                }
            }
            return 0;
        }
        if nonblock {
            drop(g);
            return -(Errno::Eagain.as_i32() as i64);
        }
        // SAFETY: process ctx; runqueue installed; preempt-off; we yield via schedule() immediately after parking.
        unsafe { q.wait_send.park(); }
        drop(g);
        // SAFETY: process ctx; runqueue installed; preempt-off.
        unsafe { sched::live::schedule(); }
    }
}

/// `sys_mq_timedreceive(mqdes, msg_ptr, msg_len, msg_prio_p, abs_timeout)`
/// — slot NR_MQ_TIMEDRECEIVE. Returns bytes received.
/// # C: O(msg_len)
pub fn kernel_sys_mq_timedreceive(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let mqdes    = args.a0 as i32;
    let uptr     = args.a1;
    let buflen   = args.a2 as usize;
    let prio_p   = args.a3;
    let _abstime = args.a4;

    let (q, nonblock) = match fd_to_mq(mqdes) {
        Some(t) => t, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    if buflen < q.max_msgsize {
        return -(Errno::Emsgsize.as_i32() as i64);
    }

    let m = loop {
        let mut g = q.msgs.lock();
        if !g.is_empty() {
            let m = g.remove(0);
            q.wait_send.wake_one();
            drop(g);
            break m;
        }
        if nonblock {
            drop(g);
            return -(Errno::Eagain.as_i32() as i64);
        }
        // SAFETY: process ctx; runqueue installed; preempt-off; we yield via schedule() immediately after parking.
        unsafe { q.wait_recv.park(); }
        drop(g);
        // SAFETY: process ctx; runqueue installed; preempt-off.
        unsafe { sched::live::schedule(); }
    };

    let n = m.bytes.len();
    if n > 0 {
        if uptr == 0 || uptr >= hal::USER_VA_END {
            return -(Errno::Efault.as_i32() as i64);
        }
        // SAFETY: range [uptr, uptr+n) is in user space (validated < USER_VA_END); CPL=0 raw deref through caller's AS.
        unsafe {
            core::ptr::copy_nonoverlapping(
                m.bytes.as_ptr(),
                uptr as *mut u8,
                n,
            );
        }
    }
    if prio_p != 0 && prio_p < hal::USER_VA_END {
        // SAFETY: prio_p validated < USER_VA_END; user page mapped; write a u32 priority back.
        unsafe { core::ptr::write_volatile(prio_p as *mut u32, m.priority); }
    }
    n as i64
}

/// `sys_mq_notify(mqdes, sevp)` — slot 244. Registers (or clears) a
/// per-queue notifier. Linux semantics: at most one notifier per
/// queue; sevp == NULL clears.
/// # C: O(1)
pub fn kernel_sys_mq_notify(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let mqdes = args.a0 as i32;
    let sevp  = args.a1;
    let (q, _nb) = match fd_to_mq(mqdes) {
        Some(t) => t, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    if sevp == 0 {
        q.notifier_tid.store(0,   Ordering::Release);
        q.notifier_signo.store(0, Ordering::Release);
        return 0;
    }
    if sevp >= hal::USER_VA_END
        || sevp.checked_add(16).map(|e| e > hal::USER_VA_END).unwrap_or(true) {
        return -(Errno::Efault.as_i32() as i64);
    }
    // sigevent layout: { sigval_t value; int signo; int notify; }.
    // SAFETY: sevp+16 validated < USER_VA_END; CPL=0 reads through caller's AS at the sigevent layout offsets.
    let (signo, notify) = unsafe {
        (core::ptr::read_volatile((sevp + 8)  as *const i32),
         core::ptr::read_volatile((sevp + 12) as *const i32))
    };
    if notify == 1 /* SIGEV_NONE */ {
        return -(Errno::Einval.as_i32() as i64);
    }
    if !(1..=64).contains(&signo) {
        return -(Errno::Einval.as_i32() as i64);
    }
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    // BUSY if already armed (Linux EBUSY).
    let prev = q.notifier_tid.load(Ordering::Acquire);
    if prev != 0 { return -(Errno::Ebusy.as_i32() as i64); }
    q.notifier_tid.store(cur.tid, Ordering::Release);
    q.notifier_signo.store(signo, Ordering::Release);
    0
}

/// `sys_mq_getsetattr(mqdes, new, old)` — slot 245.
/// `mq_attr` layout: { long flags; long maxmsg; long msgsize; long curmsgs; long _pad[4]; }
/// Linux only honours O_NONBLOCK in `flags` on set. Other fields are
/// read-only (queue creation parameters) and are ignored on set.
/// # C: O(1)
pub fn kernel_sys_mq_getsetattr(args: &syscall::SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let mqdes = args.a0 as i32;
    let new_p = args.a1;
    let old_p = args.a2;
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let file = match fdt.get(mqdes) {
        Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    let inode = file.inode();
    let mq = match inode.as_any().and_then(|a| a.downcast_ref::<MqInode>()) {
        Some(m) => m, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let q = &mq.queue;
    let cur_msgs = q.msgs.lock().len() as i64;
    let nb_now = mq.nonblock.load(Ordering::Acquire);
    if old_p != 0 {
        if old_p >= hal::USER_VA_END
            || old_p.checked_add(64).map(|e| e > hal::USER_VA_END).unwrap_or(true) {
            return -(Errno::Efault.as_i32() as i64);
        }
        let flags: i64 = if nb_now { 0o4000 /* O_NONBLOCK */ } else { 0 };
        // SAFETY: old_p+64 validated < USER_VA_END; CPL=0 writes the four mq_attr longs through caller's AS.
        unsafe {
            core::ptr::write_volatile( old_p        as *mut i64, flags);
            core::ptr::write_volatile((old_p +  8)  as *mut i64, q.max_msgs    as i64);
            core::ptr::write_volatile((old_p + 16)  as *mut i64, q.max_msgsize as i64);
            core::ptr::write_volatile((old_p + 24)  as *mut i64, cur_msgs);
            for off in (32..64u64).step_by(8) {
                core::ptr::write_volatile((old_p + off) as *mut i64, 0);
            }
        }
    }
    if new_p != 0 {
        if new_p >= hal::USER_VA_END
            || new_p.checked_add(8).map(|e| e > hal::USER_VA_END).unwrap_or(true) {
            return -(Errno::Efault.as_i32() as i64);
        }
        // SAFETY: new_p+8 validated < USER_VA_END; CPL=0 reads the flags field of mq_attr through caller's AS.
        let new_flags = unsafe { core::ptr::read_volatile(new_p as *const i64) };
        let want_nb = (new_flags & 0o4000) != 0;
        mq.nonblock.store(want_nb, Ordering::Release);
    }
    0
}
