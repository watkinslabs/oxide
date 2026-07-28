// `mq_timedsend(2)` / `mq_timedreceive(2)` — Linux `do_mq_timedsend`
// (`ipc/mqueue.c:1037-1140`) and `do_mq_timedreceive` (`:1142-1231`).

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use syscall::errno::Errno;
use vfs::File;

use crate::mqueue_policy::limits::MQ_PRIO_MAX;
use crate::mqueue_policy::open::{open_fmode, O_NONBLOCK};

use super::model::{queue_of, MqMsg, MqQueue};
use super::user::{errno, read_user_bytes, write_user_bytes, write_user_u32};
use super::wait::{mq_abs_deadline, mq_wait_verdict};

/// The descriptor half of `do_mq_timedsend`/`do_mq_timedreceive`: `EBADF` for
/// a closed fd, `EBADF` again when the fd is not an mq descriptor (Linux
/// `f_op != &mqueue_file_operations`, `mqueue.c:1066`), and `EBADF` a third
/// time when the open description lacks the needed access
/// (`!(f_mode & FMODE_WRITE)`, `:1071`). The access mode is recomputed with
/// Linux's `OPEN_FMODE` from the description's own flags, so an `O_RDONLY`
/// queue descriptor genuinely cannot send.
/// # C: O(1)
fn fd_to_mq(fd: i32, want_write: bool) -> Result<(Arc<MqQueue>, bool), Errno> {
    let cur = sched::live::current().ok_or(Errno::Ebadf)?;
    // SAFETY: running task on this CPU; preempt-off; sole reader of the fd_table slot.
    let fdt = (unsafe { cur.fd_table_ref() }).map(|t| t.clone()).ok_or(Errno::Ebadf)?;
    let file: Arc<File> = fdt.get(fd).map_err(|_| Errno::Ebadf)?;
    let q = queue_of(&file.inode()).ok_or(Errno::Ebadf)?;
    let flags = file.flags().bits() as i32;
    let (may_read, may_write) = open_fmode(flags);
    if want_write && !may_write { return Err(Errno::Ebadf); }
    if !want_write && !may_read { return Err(Errno::Ebadf); }
    // O_NONBLOCK lives on the open file description, so `fcntl(F_SETFL)` and
    // `mq_setattr` are one truth rather than two.
    Ok((q, flags & O_NONBLOCK != 0))
}

/// `sys_mq_timedsend(mqdes, msg_ptr, msg_len, msg_prio, abs_timeout)` — slot
/// `NR_MQ_TIMEDSEND`. `abs_timeout` is an ABSOLUTE CLOCK_REALTIME deadline;
/// expiry is `ETIMEDOUT` and a deliverable signal is `ERESTARTSYS`, signal
/// first (`ipc/mqueue.c:738-744`).
/// # C: O(msg_len + N_queue)
pub fn sys_mq_timedsend(args: &syscall::SyscallArgs) -> i64 {
    let mqdes = args.a0 as i32;
    let uptr = args.a1;
    let len = args.a2 as usize;
    let prio = args.a3 as u32;

    // `prepare_timeout` runs in the syscall wrapper, ahead of the descriptor
    // lookup (`mqueue.c:1236-1244`).
    let deadline = match mq_abs_deadline(args.a4) { Ok(d) => d, Err(rv) => return rv };
    if prio >= MQ_PRIO_MAX { return errno(Errno::Einval); }
    let (q, nonblock) = match fd_to_mq(mqdes, true) { Ok(t) => t, Err(e) => return errno(e) };
    if len > q.msgsize { return errno(Errno::Emsgsize); }

    let mut bytes: Vec<u8> = Vec::new();
    if bytes.try_reserve_exact(len).is_err() { return errno(Errno::Enomem); }
    bytes.resize(len, 0);
    if let Err(e) = read_user_bytes(uptr, &mut bytes) { return errno(e); }
    let mut slot = Some(MqMsg { priority: prio, bytes });

    loop {
        let mut g = q.msgs.lock();
        if g.len() < q.maxmsg {
            let notify_due = g.is_empty() && !q.wait_recv.has_waiters();
            let m = slot.take().expect("message owned by the sender");
            // Priority-descending, FIFO within a priority: insert before the
            // first strictly-lower priority, i.e. after every equal one.
            let pos = g.iter().position(|e| e.priority < m.priority).unwrap_or(g.len());
            g.insert(pos, m);
            drop(g);
            q.wait_recv.wake_one();
            // `mq_curmsgs` grew, so `mqueue_poll_file` now reports EPOLLIN:
            // wake `info->wait_q` (Linux `__do_notify`'s trailing `wake_up`,
            // `mqueue.c:835`). Unconditional here, unlike the notification
            // below, because this implementation always INSERTS the message —
            // it has no `pipelined_send` hand-off that leaves `mq_curmsgs`
            // unchanged, so the polled observable changes on every send.
            q.notify_readable();
            // `__do_notify` fires only when the queue went 0 -> 1 AND nobody
            // was waiting synchronously: Linux hands a pipelined message
            // straight to a waiting receiver and skips the notification
            // (`mqueue.c:779-783, :1121-1130`).
            if notify_due { notify_sender_side(&q); }
            return 0;
        }
        if nonblock { drop(g); return errno(Errno::Eagain); }
        if let Some(rv) = mq_wait_verdict(deadline) { drop(g); return rv; }
        // SAFETY: process ctx; runqueue installed; preempt-off; we yield via schedule() immediately after parking.
        unsafe { q.wait_send.park_interruptible_with_deadline(deadline.unwrap_or(0)); }
        drop(g);
        // SAFETY: process ctx; runqueue installed; preempt-off.
        unsafe { sched::live::schedule(); }
        if let Some(rv) = mq_wait_verdict(deadline) { return rv; }
    }
}

/// # C: O(1)
fn notify_sender_side(q: &MqQueue) {
    let Some(cur) = sched::live::current() else { return };
    let vpid = sched::session::process_vpid(&cur);
    let uid = cur.creds.euid.load(Ordering::Acquire);
    super::notify::do_notify(q, vpid, uid);
}

/// `sys_mq_timedreceive(mqdes, msg_ptr, msg_len, msg_prio_p, abs_timeout)` —
/// slot `NR_MQ_TIMEDRECEIVE`. Returns the byte count received; the message's
/// priority goes to `msg_prio_p` when non-NULL (`mqueue.c:1224`).
/// # C: O(msg_len)
pub fn sys_mq_timedreceive(args: &syscall::SyscallArgs) -> i64 {
    let mqdes = args.a0 as i32;
    let uptr = args.a1;
    let buflen = args.a2 as usize;
    let prio_p = args.a3;

    let deadline = match mq_abs_deadline(args.a4) { Ok(d) => d, Err(rv) => return rv };
    let (q, nonblock) = match fd_to_mq(mqdes, false) { Ok(t) => t, Err(e) => return errno(e) };
    // `mqueue.c:1175`: the buffer must be able to hold ANY message the queue
    // may carry, not merely the one at its head.
    if buflen < q.msgsize { return errno(Errno::Emsgsize); }

    let m = loop {
        let mut g = q.msgs.lock();
        if !g.is_empty() {
            let m = g.remove(0);
            drop(g);
            q.wait_send.wake_one();
            // A slot came free: `mq_curmsgs < mq_maxmsg` now holds, so the
            // queue reports EPOLLOUT (Linux `pipelined_receive`'s
            // `/* for poll */ wake_up_interruptible(&info->wait_q)`,
            // `mqueue.c:1029`). Unconditional for the same reason as the send
            // side: the removal always happens, so the observable always moves.
            q.notify_writable();
            break m;
        }
        if nonblock { drop(g); return errno(Errno::Eagain); }
        if let Some(rv) = mq_wait_verdict(deadline) { drop(g); return rv; }
        // SAFETY: process ctx; runqueue installed; preempt-off; we yield via schedule() immediately after parking.
        unsafe { q.wait_recv.park_interruptible_with_deadline(deadline.unwrap_or(0)); }
        drop(g);
        // SAFETY: process ctx; runqueue installed; preempt-off.
        unsafe { sched::live::schedule(); }
        if let Some(rv) = mq_wait_verdict(deadline) { return rv; }
    };

    let n = m.bytes.len();
    if prio_p != 0 {
        if let Err(e) = write_user_u32(prio_p, m.priority) { return errno(e); }
    }
    if let Err(e) = write_user_bytes(uptr, &m.bytes) { return errno(e); }
    n as i64
}
