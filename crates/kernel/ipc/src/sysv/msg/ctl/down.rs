//! Linux `msgctl_down` — the owner-gated `IPC_SET` / `IPC_RMID` commands.

use namespace_identity::NamespaceId;
use syscall::errno::Errno;

use crate::sysv::block;
use crate::sysv::limits::MSGMNB;
use crate::sysv::msg::model;
use crate::sysv::perm::IpcCred;
use crate::sysv::uapi::{decode_ipc64_perm, get_u64, MSQID64_DS_BYTES, MSQID64_QBYTES_OFF};
use crate::sysv::user;

/// `msgctl_down` reports success as `0`.
const MSGCTL_DOWN_OK: i64 = 0;

/// Linux `msgctl_down(IPC_SET)`. The new `msg_qbytes` is taken from the
/// user-supplied `msqid64_ds`; raising it above `MSGMNB` needs
/// `CAP_SYS_RESOURCE`. Blocked receivers are woken because a stricter mode may
/// now exclude them, and blocked senders because a larger queue may now admit
/// them (Linux `expunge_all(-EAGAIN)` + `ss_wakeup`: both mean "re-evaluate").
/// # C: O(N_waiters)
/// # Lk: msg registry, then MsgQueue.state -> WaitList.waiters -> runqueue.inner
pub fn ipc_set(ns: NamespaceId, msqid: i32, buf: u64, cred: &IpcCred) -> Result<i64, Errno> {
    let mut inb = [0u8; MSQID64_DS_BYTES];
    user::read_bytes(buf, &mut inb)?;
    let perm_in = decode_ipc64_perm(&inb);
    // `ksys_msgctl` hands `msqid64.msg_qbytes` to `msgctl_down`'s `int
    // msg_qbytes` parameter, so the 64-bit field userspace supplied is
    // truncated to a signed 32-bit value before both the CAP_SYS_RESOURCE
    // comparison and the store into the `unsigned long q_qbytes`.
    let qbytes = get_u64(&inb, MSQID64_QBYTES_OFF) as i32;

    let q = model::lookup_checked(ns, msqid)?;
    if !q.perm.admin_allowed(cred) { return Err(Errno::Eperm); }
    if qbytes as i64 > MSGMNB as i64 && !cred.cap_sys_resource { return Err(Errno::Eperm); }

    let mut st = q.state.lock();
    if q.is_removed() { return Err(Errno::Eidrm); }
    q.perm.update(perm_in.uid, perm_in.gid, perm_in.mode);
    st.qbytes = qbytes as i64 as u64;
    st.ctime = block::real_seconds();
    q.receivers.wake_all();
    q.senders.wake_all();
    Ok(MSGCTL_DOWN_OK)
}

/// Linux `msgctl_down(IPC_RMID)` + `freeque`. The ownership check and the
/// unpublish run under the registry lock so two racing removals cannot both
/// tear the queue down.
/// # C: O(N_msgs + N_waiters)
/// # Lk: msg registry, then MsgQueue.state -> WaitList.waiters -> runqueue.inner
pub fn ipc_rmid(ns: NamespaceId, msqid: i32, cred: &IpcCred) -> Result<i64, Errno> {
    let doomed = model::with_ids(|ids| {
        let q = ids.lookup_checked(ns, msqid, |q| q.perm.seq).ok_or(Errno::Einval)?;
        if !q.perm.admin_allowed(cred) { return Err(Errno::Eperm); }
        ids.remove(ns, msqid);
        Ok(q)
    })?;
    model::freeque(&doomed);
    Ok(MSGCTL_DOWN_OK)
}
