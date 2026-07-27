//! Linux `msgctl_stat` — `struct msqid64_ds` for `IPC_STAT` / `MSG_STAT` /
//! `MSG_STAT_ANY`.

use namespace_identity::NamespaceId;
use syscall::errno::Errno;

use crate::sysv::limits::{IPC_STAT, MSG_STAT_ANY, S_IRUGO};
use crate::sysv::msg::model;
use crate::sysv::perm::IpcCred;
use crate::sysv::uapi::{
    encode_ipc64_perm, put_i32, put_i64, put_u64, MSQID64_CBYTES_OFF, MSQID64_CTIME_OFF,
    MSQID64_DS_BYTES, MSQID64_LRPID_OFF, MSQID64_LSPID_OFF, MSQID64_QBYTES_OFF, MSQID64_QNUM_OFF,
    MSQID64_RTIME_OFF, MSQID64_STIME_OFF,
};
use crate::sysv::user;

/// `IPC_STAT` reports success as `0`; the Linux-specific `MSG_STAT` /
/// `MSG_STAT_ANY` report the full identifier instead.
const IPC_STAT_OK: i64 = 0;

/// Linux `msgctl_stat`. `IPC_STAT` addresses the queue by checked id;
/// `MSG_STAT` / `MSG_STAT_ANY` address it by raw index the way `ipcs(1)` walks
/// the namespace. `MSG_STAT_ANY` skips the read-permission gate.
/// # C: O(1)
/// # Lk: msg registry, then MsgQueue.state
pub fn msgctl_stat(ns: NamespaceId, msqid: i32, cmd: i32, buf: u64, cred: &IpcCred) -> Result<i64, Errno> {
    let q = if cmd == IPC_STAT { model::lookup_checked(ns, msqid)? } else { model::lookup_idx(ns, msqid)? };
    if cmd != MSG_STAT_ANY && !q.perm.permitted(cred, S_IRUGO) { return Err(Errno::Eacces); }
    let mut out = [0u8; MSQID64_DS_BYTES];
    encode_ipc64_perm(&mut out, &q.perm);
    {
        let st = q.state.lock();
        if q.is_removed() { return Err(Errno::Eidrm); }
        put_i64(&mut out, MSQID64_STIME_OFF, st.stime);
        put_i64(&mut out, MSQID64_RTIME_OFF, st.rtime);
        put_i64(&mut out, MSQID64_CTIME_OFF, st.ctime);
        put_u64(&mut out, MSQID64_CBYTES_OFF, st.cbytes);
        put_u64(&mut out, MSQID64_QNUM_OFF, st.qnum);
        put_u64(&mut out, MSQID64_QBYTES_OFF, st.qbytes);
        put_i32(&mut out, MSQID64_LSPID_OFF, st.lspid as i32);
        put_i32(&mut out, MSQID64_LRPID_OFF, st.lrpid as i32);
    }
    user::write_bytes(buf, &out)?;
    Ok(if cmd == IPC_STAT { IPC_STAT_OK } else { q.perm.id as i64 })
}
