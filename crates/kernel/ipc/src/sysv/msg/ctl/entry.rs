//! Linux `ksys_msgctl` — argument validation plus command dispatch.

use namespace_identity::NamespaceId;
use syscall::errno::Errno;

use super::{down, info, stat};
use crate::sysv::limits::{IPC_INFO, IPC_RMID, IPC_SET, IPC_STAT, MSG_INFO, MSG_STAT, MSG_STAT_ANY};
use crate::sysv::msg::model;
use crate::sysv::perm::{current_ipc_cred, IpcCred};
use crate::sysv::user;

/// Linux `ksys_msgctl`. # C: O(N_queues) for the `*_INFO` totals, else O(1)
pub fn msgctl(ns: NamespaceId, msqid: i32, cmd: i32, buf: u64, cred: &IpcCred) -> Result<i64, Errno> {
    if msqid < 0 || cmd < 0 { return Err(Errno::Einval); }
    match cmd {
        IPC_INFO | MSG_INFO => info::msgctl_info(ns, cmd, buf),
        IPC_STAT | MSG_STAT | MSG_STAT_ANY => stat::msgctl_stat(ns, msqid, cmd, buf, cred),
        IPC_SET => down::ipc_set(ns, msqid, buf, cred),
        IPC_RMID => down::ipc_rmid(ns, msqid, cred),
        _ => Err(Errno::Einval),
    }
}

/// `msgctl(msqid, cmd, buf)` — slot `NR_MSGCTL`.
/// # C: O(N_queues) for the `*_INFO` totals, else O(1)
pub fn sys_msgctl(args: &syscall::SyscallArgs) -> i64 {
    let ns = match model::current_ns() { Ok(n) => n, Err(e) => return user::errno(e) };
    let cred = current_ipc_cred();
    match msgctl(ns, args.a0 as i32, args.a1 as i32, args.a2, &cred) {
        Ok(v) => v,
        Err(e) => user::errno(e),
    }
}
