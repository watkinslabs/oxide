//! Linux `ksys_msgsnd` / `do_msgsnd` (`ipc/msg.c`).
//!
//! Linux's `pipelined_send` hands the message straight to a parked receiver
//! whose `r_msgtype` matches and whose `r_maxsize` fits. Here the message is
//! always appended and every parked receiver is woken to re-run `find_msg`
//! under the queue lock, which reaches the same observable end state (the
//! selecting receiver dequeues it; a receiver whose buffer is too small still
//! gets `E2BIG` with the message left queued) without needing to wake one
//! specific task off a shared wait list.

use alloc::vec::Vec;
use namespace_identity::NamespaceId;
use syscall::errno::Errno;

use super::model::{self, Msg, MTYPE_BYTES};
use super::park;
use crate::sysv::block::{self, Wake};
use crate::sysv::limits::{IPC_NOWAIT, MSGMAX, S_IWUGO};
use crate::sysv::perm::{current_ipc_cred, IpcCred};
use crate::sysv::user;

/// `msgsnd`'s success return; Linux reports `0`, not a byte count.
const MSGSND_OK: i64 = 0;

/// Linux `mtype < 1` floor.
const MIN_MTYPE: i64 = 1;

/// Linux `ksys_msgsnd` + `do_msgsnd`. `uptr` addresses
/// `struct { long mtype; char mtext[msgsz]; }`.
/// # C: O(msgsz) plus the sleep on a full queue
/// # Lk: MsgQueue.state -> WaitList.waiters -> runqueue.inner
/// # Ctx: process
/// # Sleeps: yes, unless `IPC_NOWAIT`
pub fn msgsnd(ns: NamespaceId, msqid: i32, uptr: u64, msgsz: u64, msgflg: i32, cred: &IpcCred) -> Result<i64, Errno> {
    // `ksys_msgsnd` reads `msgp->mtype` before `do_msgsnd` validates anything,
    // so a bad pointer is EFAULT even when msgsz/msqid are also bogus.
    let mut hdr = [0u8; MTYPE_BYTES];
    user::read_bytes(uptr, &mut hdr)?;
    let mtype = i64::from_le_bytes(hdr);

    if msgsz > MSGMAX as u64 || (msgsz as i64) < 0 || msqid < 0 { return Err(Errno::Einval); }
    if mtype < MIN_MTYPE { return Err(Errno::Einval); }

    // Linux `load_msg`: the payload is copied in before the queue is located,
    // so a faulting `mtext` never leaves a half-committed queue behind.
    let len = msgsz as usize;
    let mut data: Vec<u8> = Vec::new();
    data.try_reserve_exact(len).map_err(|_| Errno::Enomem)?;
    data.resize(len, 0);
    let text = uptr.checked_add(MTYPE_BYTES as u64).ok_or(Errno::Efault)?;
    user::read_bytes(text, &mut data)?;

    let q = model::lookup_checked(ns, msqid)?;
    loop {
        let mut st = q.state.lock();
        if !q.perm.permitted(cred, S_IWUGO) { return Err(Errno::Eacces); }
        // B1427: `removed` is read under the same lock the park below registers
        // under, so a racing IPC_RMID is EIDRM rather than a lost wakeup.
        if q.is_removed() { return Err(Errno::Eidrm); }
        if st.fits(msgsz) {
            st.lspid = block::current_tgid();
            st.stime = block::real_seconds();
            // `take` hands the payload over without moving `data` out of a
            // loop body the borrow checker can re-enter.
            st.msgs.push_back(Msg { mtype, data: core::mem::take(&mut data) });
            st.cbytes += msgsz;
            st.qnum += 1;
            q.receivers.wake_all();
            return Ok(MSGSND_OK);
        }
        if (msgflg & IPC_NOWAIT) != 0 { return Err(Errno::Eagain); }
        // SAFETY: process context on the running task with the runqueue installed and preemption disabled; `arm` publishes the park under `state`, which is dropped before the yield below and is not held by any waker at that point.
        unsafe { park::arm(&q.senders); }
        drop(st);
        // SAFETY: the park armed above is published and `state` is dropped, satisfying `yield_and_classify`'s contract that no waker-visible lock is held across the yield.
        if unsafe { park::yield_and_classify() } == Wake::Signal { return Err(Errno::Eintr); }
    }
}

/// `msgsnd(msqid, msgp, msgsz, msgflg)` — slot `NR_MSGSND`.
/// # C: O(msgsz) plus the sleep on a full queue
pub fn sys_msgsnd(args: &syscall::SyscallArgs) -> i64 {
    let ns = match model::current_ns() { Ok(n) => n, Err(e) => return user::errno(e) };
    let cred = current_ipc_cred();
    match msgsnd(ns, args.a0 as i32, args.a1, args.a2, args.a3 as i32, &cred) {
        Ok(v) => v,
        Err(e) => user::errno(e),
    }
}
