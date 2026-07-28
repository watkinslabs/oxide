// `mq_getsetattr(2)` (slot `NR_MQ_GETSETATTR`) — Linux `do_mq_getsetattr`
// (`ipc/mqueue.c:1387-1425`) and `SYSCALL_DEFINE3(mq_getsetattr)` (`:1427-…`).

use syscall::errno::Errno;
use vfs::OpenFlags;

use crate::mqueue_policy::attr::setattr_flags;
use crate::mqueue_policy::limits::{
    MQ_ATTR_BYTES, MQ_ATTR_CURMSGS_OFF, MQ_ATTR_MAXMSG_OFF, MQ_ATTR_MSGSIZE_OFF,
};
use crate::mqueue_policy::open::O_NONBLOCK;

use super::model::queue_of;
use super::user::{errno, read_user_i64, write_user_i64};

/// `sys_mq_getsetattr(mqdes, new, old)` — slot `NR_MQ_GETSETATTR`.
///
/// `mq_maxmsg`/`mq_msgsize`/`mq_curmsgs` are read-only queue facts; the only
/// settable field is `O_NONBLOCK` in `mq_flags`, and any other bit in a
/// supplied `mq_flags` is `EINVAL` BEFORE the descriptor is fetched
/// (`mqueue.c:1392-1393`), so it outranks `EBADF`.
///
/// `mq_flags` reported in `old` is the OPEN FILE DESCRIPTION's `O_NONBLOCK`
/// (`mqueue.c:1409`), which is the same bit `fcntl(F_SETFL)` moves — one truth,
/// not a per-inode shadow copy.
/// # C: O(1)
pub fn sys_mq_getsetattr(args: &syscall::SyscallArgs) -> i64 {
    let mqdes = args.a0 as i32;
    let new_p = args.a1;
    let old_p = args.a2;

    let want_nonblock = if new_p == 0 { None } else {
        // `SYSCALL_DEFINE3` copies the whole struct (EFAULT) before
        // `do_mq_getsetattr` inspects `mq_flags` (EINVAL).
        if new_p >= hal::USER_VA_END
            || new_p.checked_add(MQ_ATTR_BYTES as u64).map(|e| e > hal::USER_VA_END).unwrap_or(true) {
            return errno(Errno::Efault);
        }
        for off in (0..MQ_ATTR_BYTES as u64).step_by(8) {
            if let Err(e) = read_user_i64(new_p + off) { return errno(e); }
        }
        let flags = match read_user_i64(new_p) { Ok(v) => v, Err(e) => return errno(e) };
        match setattr_flags(flags) { Ok(b) => Some(b), Err(e) => return errno(e) }
    };

    let Some(cur) = sched::live::current() else { return errno(Errno::Ebadf) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of the fd_table slot.
    let Some(fdt) = (unsafe { cur.fd_table_ref() }).map(|t| t.clone()) else {
        return errno(Errno::Ebadf);
    };
    let Ok(file) = fdt.get(mqdes) else { return errno(Errno::Ebadf) };
    let Some(q) = queue_of(&file.inode()) else { return errno(Errno::Ebadf) };

    if old_p != 0 {
        if old_p >= hal::USER_VA_END
            || old_p.checked_add(MQ_ATTR_BYTES as u64).map(|e| e > hal::USER_VA_END).unwrap_or(true) {
            return errno(Errno::Efault);
        }
        let nb = file.flags().contains(OpenFlags::O_NONBLOCK);
        let flags: i64 = if nb { O_NONBLOCK as i64 } else { 0 };
        let curmsgs = q.curmsgs() as i64;
        let writes = [
            (0u64, flags),
            (MQ_ATTR_MAXMSG_OFF, q.maxmsg as i64),
            (MQ_ATTR_MSGSIZE_OFF, q.msgsize as i64),
            (MQ_ATTR_CURMSGS_OFF, curmsgs),
        ];
        for (off, v) in writes { if let Err(e) = write_user_i64(old_p + off, v) { return errno(e); } }
        for off in (32..MQ_ATTR_BYTES as u64).step_by(8) {
            if let Err(e) = write_user_i64(old_p + off, 0) { return errno(e); }
        }
    }

    if let Some(nb) = want_nonblock {
        let mut fl = file.flags();
        fl.set(OpenFlags::O_NONBLOCK, nb);
        file.set_flags(fl);
    }
    0
}
