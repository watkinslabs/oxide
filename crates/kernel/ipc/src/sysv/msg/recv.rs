//! Linux `ksys_msgrcv` / `do_msgrcv` / `do_msg_fill` (`ipc/msg.c`).

use alloc::vec::Vec;
use namespace_identity::NamespaceId;
use syscall::errno::Errno;

use super::model::{self, Msg, MTYPE_BYTES};
use super::select;
use crate::sysv::block::{self, Wake};
use crate::sysv::limits::{IPC_NOWAIT, MSGMAX, MSG_COPY, MSG_EXCEPT, MSG_NOERROR, S_IRUGO};
use crate::sysv::perm::{current_ipc_cred, IpcCred};
use crate::sysv::user;

/// `msgsnd`/`msgrcv` have no timeout: they sleep until a peer makes progress.
const NO_DEADLINE: u64 = 0;

/// Linux `do_msgrcv`. `uptr` addresses `struct { long mtype; char mtext[]; }`;
/// the return is the number of `mtext` bytes stored, excluding the type word.
/// # C: O(N_msgs + bufsz) plus the sleep on an empty queue
/// # Lk: MsgQueue.state -> WaitList.waiters -> runqueue.inner
/// # Ctx: process
/// # Sleeps: yes, unless `IPC_NOWAIT`
pub fn msgrcv(ns: NamespaceId, msqid: i32, uptr: u64, bufsz: u64, msgtyp: i64, msgflg: i32, cred: &IpcCred) -> Result<i64, Errno> {
    if msqid < 0 || (bufsz as i64) < 0 { return Err(Errno::Einval); }
    let copying = (msgflg & MSG_COPY) != 0;
    if copying {
        if (msgflg & MSG_EXCEPT) != 0 || (msgflg & IPC_NOWAIT) == 0 { return Err(Errno::Einval); }
        // Linux `prepare_copy` builds the destination with `load_msg`, which
        // reads `min(bufsz, msg_ctlmax)` bytes off the user buffer first.
        user::validate(uptr, core::cmp::min(bufsz, MSGMAX as u64) as usize, false)?;
    }
    let (mode, mut msgtyp) = select::convert_mode(msgtyp, msgflg);
    let q = model::lookup_checked(ns, msqid)?;

    let msg = loop {
        // Linux tests `ipcperms` outside `ipc_lock_object`, ahead of the
        // removal check, so a stricter mode installed by IPC_SET is EACCES.
        if !q.perm.permitted(cred, S_IRUGO) { return Err(Errno::Eacces); }
        let mut st = q.state.lock();
        // B1427: read under the same lock the park below registers under.
        if q.is_removed() { return Err(Errno::Eidrm); }
        match select::find_msg(&st.msgs, &mut msgtyp, mode) {
            Some(i) => {
                let ts = st.msgs[i].ts();
                if bufsz < ts && (msgflg & MSG_NOERROR) == 0 { return Err(Errno::E2big); }
                if copying {
                    // Linux `copy_msg`: the destination was sized `bufsz`, so a
                    // longer message is EINVAL. Only reachable with MSG_NOERROR;
                    // without it the E2BIG above already fired.
                    if ts > bufsz { return Err(Errno::Einval); }
                    let src = &st.msgs[i];
                    let mut data: Vec<u8> = Vec::new();
                    data.try_reserve_exact(src.data.len()).map_err(|_| Errno::Enomem)?;
                    data.extend_from_slice(&src.data);
                    break Msg { mtype: src.mtype, data };
                }
                let taken = match st.msgs.remove(i) {
                    Some(m) => m,
                    // Unreachable: `find_msg` only ever reports a live index.
                    None => return Err(Errno::Enomsg),
                };
                st.qnum -= 1;
                st.rtime = block::real_seconds();
                st.lrpid = block::current_tgid();
                st.cbytes -= taken.ts();
                q.senders.wake_all();
                break taken;
            }
            None => {
                if (msgflg & IPC_NOWAIT) != 0 { return Err(Errno::Enomsg); }
                // SAFETY: process context on the running task with the runqueue installed and preemption disabled; `arm` publishes the park under `state`, dropped before the yield below so no waker-visible lock is held across it.
                unsafe { block::publish_park(&q.receivers, NO_DEADLINE); }
                drop(st);
                // SAFETY: the park armed above is published and `state` is dropped, satisfying `yield_and_classify`'s contract that the caller holds no lock a waker needs.
                if unsafe { block::yield_and_classify(NO_DEADLINE) } == Wake::Signal {
                    block::unpublish_park(&q.receivers);
                    return Err(Errno::Eintr);
                }
            }
        }
    };

    fill(uptr, &msg, bufsz)
}

/// Linux `do_msg_fill`: the type word then `min(bufsz, m_ts)` payload bytes.
/// A fault here loses an already-dequeued message, exactly as Linux's
/// `free_msg` after a failed `store_msg` does. # C: O(bufsz)
fn fill(uptr: u64, msg: &Msg, bufsz: u64) -> Result<i64, Errno> {
    user::write_bytes(uptr, &msg.mtype.to_le_bytes())?;
    let n = core::cmp::min(bufsz, msg.ts()) as usize;
    let text = uptr.checked_add(MTYPE_BYTES as u64).ok_or(Errno::Efault)?;
    user::write_bytes(text, &msg.data[..n])?;
    Ok(n as i64)
}

/// `msgrcv(msqid, msgp, msgsz, msgtyp, msgflg)` — slot `NR_MSGRCV`.
/// # C: O(N_msgs + msgsz) plus the sleep on an empty queue
pub fn sys_msgrcv(args: &syscall::SyscallArgs) -> i64 {
    let ns = match model::current_ns() { Ok(n) => n, Err(e) => return user::errno(e) };
    let cred = current_ipc_cred();
    match msgrcv(ns, args.a0 as i32, args.a1, args.a2, args.a3 as i64, args.a4 as i32, &cred) {
        Ok(v) => v,
        Err(e) => user::errno(e),
    }
}
