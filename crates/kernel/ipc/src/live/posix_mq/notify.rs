// `mq_notify(2)` (slot `NR_MQ_NOTIFY`) — Linux `do_mq_notify`
// (`ipc/mqueue.c:1266-1385`) and the delivery half `__do_notify` (`:777-836`).

use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::mqueue_policy::limits::{
    NOTIFY_COOKIE_LEN, NOTIFY_REMOVED, NOTIFY_WOKENUP, SIGEVENT_BYTES, SIGEVENT_NOTIFY_OFF,
    SIGEVENT_SIGNO_OFF,
};
use crate::mqueue_policy::notify::{notify_action, notify_check, NotifyAction, NotifyKind};

use super::model::{queue_of, MqNotifyReg, MqQueue};
use super::user::{
    current_tgid, errno, read_user_bytes, read_user_i32, read_user_i64,
};

/// Detach a registration under the queue lock. The SIGEV_THREAD side effect
/// Linux's `remove_notification` (`ipc/mqueue.c:848-859`) runs — the cookie
/// goes back on the notification socket stamped `NOTIFY_REMOVED`, so a helper
/// thread learns the registration died rather than waiting forever — is
/// [`finish_removal`]'s job, run AFTER the lock is dropped: it enqueues on a
/// netlink socket and wakes its pollers.
/// # C: O(1)
pub(super) fn detach_notification(slot: &mut Option<MqNotifyReg>) -> Option<MqNotifyReg> {
    slot.take()
}

/// # C: O(NOTIFY_COOKIE_LEN)
pub(super) fn finish_removal(reg: Option<MqNotifyReg>) {
    let Some(reg) = reg else { return };
    if matches!(reg.kind, NotifyKind::Thread) { send_cookie(&reg, NOTIFY_REMOVED); }
}

/// Deliver the SIGEV_THREAD cookie on the registered notification socket.
/// # C: O(NOTIFY_COOKIE_LEN)
fn send_cookie(reg: &MqNotifyReg, code: u8) {
    let Some(sock) = reg.sock.as_ref() else { return };
    let mut cookie = reg.cookie.clone();
    if cookie.is_empty() { return; }
    let last = cookie.len() - 1;
    cookie[last] = code;
    super::thread_notify::sendskb(sock, &cookie);
}

/// Linux `__do_notify` (`ipc/mqueue.c:777-836`): fires when a send takes the
/// queue from empty to one message AND no receiver was waiting synchronously,
/// then UNREGISTERS — a notification is one-shot.
/// # C: O(1)
pub(super) fn do_notify(q: &MqQueue, sender_vpid: u32, sender_uid: u32) {
    // Detach under the queue lock, deliver outside it: both delivery arms take
    // foreign locks (the target task's signal queue and runqueue, or a netlink
    // socket's RX queue and its waiters).
    let taken = { let mut g = q.notify.lock(); g.take() };
    let Some(reg) = taken else { return };
    match reg.kind {
        NotifyKind::None => {}
        NotifyKind::Signal(signo) => {
            // `do_mq_notify` accepts `sigev_signo == 0`; `__do_notify` then
            // sends nothing (`mqueue.c:793-795`).
            if signo != 0 { queue_mesgq_signal(&reg, signo, sender_vpid, sender_uid); }
        }
        NotifyKind::Thread => send_cookie(&reg, NOTIFY_WOKENUP),
    }
}

/// Post `signo` at the registered thread group with `si_code == SI_MESGQ`,
/// `si_pid` = the sending process and `si_value` = the registered
/// `sigev_value` (`ipc/mqueue.c:797-820`). Linux bypasses
/// `check_kill_permission` here — the signal is from the kernel. `si_pid` is
/// `task_tgid_nr_ns(current, ns_of_pid(info->notify_owner))`, i.e. the sender's
/// NAMESPACE pid, never the opaque internal tgid.
/// # C: O(1)
fn queue_mesgq_signal(reg: &MqNotifyReg, signo: u32, sender_vpid: u32, sender_uid: u32) {
    let Some(bit) = sched::signum::bit_for(signo) else { return };
    let Some(target) = sched::live::registry::lookup(reg.owner_tgid) else { return };
    target.sigq_reserve(signo);
    // Linux `__do_notify` -> `do_send_sig_info(sig, &sig_i, task, PIDTYPE_TGID)`:
    // the `mq_notify(SIGEV_SIGNAL)` delivery is PROCESS-directed, so any thread
    // of the registrant that has not blocked the signal can take it.
    let _ = bit;
    let info = sched::SigInfo {
        signo,
        code: sched::signum::SI_MESGQ,
        pid: sender_vpid,
        uid: sender_uid,
        value: reg.value,
        sys: None, fault: None, poll: None
    };
    let _ = sched::live::send_signal(&target, signo, sched::sigsend::SigSource::Info(info),
                                     sched::sigsend::SigTarget::Process);
}

/// Read the `struct sigevent` prefix `mq_notify` consumes.
/// `SYSCALL_DEFINE2(mq_notify)` copies it before `do_mq_notify` runs
/// (`ipc/mqueue.c:1379-1383`), so a bad pointer is `EFAULT` ahead of `EBADF`.
/// # C: O(1)
fn read_sigevent(uptr: u64) -> Result<(u64, i32, i32), Errno> {
    if uptr == 0 || uptr >= hal::USER_VA_END
        || uptr.checked_add(SIGEVENT_BYTES as u64).map(|e| e > hal::USER_VA_END).unwrap_or(true) {
        return Err(Errno::Efault);
    }
    Ok((read_user_i64(uptr)? as u64,
        read_user_i32(uptr + SIGEVENT_SIGNO_OFF)?,
        read_user_i32(uptr + SIGEVENT_NOTIFY_OFF)?))
}

/// `sys_mq_notify(mqdes, sevp)` — slot `NR_MQ_NOTIFY`.
///
/// Order is Linux's: the sigevent is copied and validated (and, for
/// SIGEV_THREAD, the cookie read and the socket resolved) BEFORE `mqdes` is
/// looked up, so `EINVAL`/`EFAULT` on the notification beat `EBADF`.
/// # C: O(1)
pub fn sys_mq_notify(args: &syscall::SyscallArgs) -> i64 {
    let mqdes = args.a0 as i32;
    let sevp = args.a1;

    let mut pending: Option<MqNotifyReg> = None;
    let Some(tgid) = current_tgid() else { return errno(Errno::Esrch) };
    if sevp != 0 {
        let (value, signo, notify) = match read_sigevent(sevp) { Ok(t) => t, Err(e) => return errno(e) };
        let kind = match notify_check(notify, signo) { Ok(k) => k, Err(e) => return errno(e) };
        let mut cookie: Vec<u8> = Vec::new();
        let mut sock = None;
        if matches!(kind, NotifyKind::Thread) {
            // `sigev_value.sival_ptr` addresses a NOTIFY_COOKIE_LEN cookie and
            // `sigev_signo` is the netlink socket fd (`mqueue.c:1287-1318`).
            // Both are consumed BEFORE `mqdes` is fetched, so their errors
            // outrank EBADF on the queue descriptor.
            if cookie.try_reserve_exact(NOTIFY_COOKIE_LEN).is_err() { return errno(Errno::Enomem); }
            cookie.resize(NOTIFY_COOKIE_LEN, 0);
            if let Err(e) = read_user_bytes(value, &mut cookie) { return errno(e); }
            match super::thread_notify::getsockbyfd(signo) {
                Ok(s) => sock = Some(s), Err(e) => return errno(e),
            }
        }
        pending = Some(MqNotifyReg { owner_tgid: tgid, kind, value, sock, cookie });
    }

    let Some(cur) = sched::live::current() else { return errno(Errno::Esrch) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of the fd_table slot.
    let Some(fdt) = (unsafe { cur.fd_table_ref() }).map(|t| t.clone()) else {
        return errno(Errno::Ebadf);
    };
    let Ok(file) = fdt.get(mqdes) else { return errno(Errno::Ebadf) };
    let Some(q) = queue_of(&file.inode()) else { return errno(Errno::Ebadf) };

    let (rv, detached) = {
        let mut g = q.notify.lock();
        let owner = g.as_ref().map(|r| r.owner_tgid);
        match notify_action(pending.is_some(), owner, tgid) {
            Err(e) => (errno(e), None),
            Ok(NotifyAction::NoOp) => (0, None),
            Ok(NotifyAction::Deregister) => (0, detach_notification(&mut g)),
            Ok(NotifyAction::Register) => { *g = pending; (0, None) }
        }
    };
    finish_removal(detached);
    rv
}
