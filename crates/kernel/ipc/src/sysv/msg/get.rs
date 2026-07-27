//! Linux `ksys_msgget` -> `ipcget` -> `newque` (`ipc/msg.c`, `ipc/util.c`).

use namespace_identity::NamespaceId;
use syscall::errno::Errno;

use super::model::{self, MsgQueue};
use crate::sysv::ids::IpcIds;
use crate::sysv::limits::{IPC_CREAT, IPC_EXCL, IPC_PRIVATE, MSGMNI};
use crate::sysv::perm::{current_ipc_cred, IpcCred};
use crate::sysv::user;

/// Linux `newque`: reserve an identifier, build the queue, publish it.
/// # C: O(MSGMNI) worst case
fn newque(ids: &mut IpcIds<MsgQueue>, ns: NamespaceId, key: i32, msgflg: i32, cred: &IpcCred) -> Result<i32, Errno> {
    let (idx, seq, id) = ids.alloc_idx(ns, MSGMNI).ok_or(Errno::Enospc)?;
    ids.install(ns, idx, model::new_queue(ns, key, id, seq, msgflg, cred));
    Ok(id)
}

/// Linux `ipcget` specialised to message queues (`msg_ops` has no
/// `more_checks`). The whole key rule runs under the registry lock so a
/// concurrent `msgget` cannot create a second queue for the same key.
/// # C: O(N_queues)
/// # Lk: msg registry
pub fn msgget(ns: NamespaceId, key: i32, msgflg: i32, cred: &IpcCred) -> Result<i32, Errno> {
    model::with_ids(|ids| {
        if key == IPC_PRIVATE { return newque(ids, ns, key, msgflg, cred); }
        match ids.lookup_key(ns, key, |q| q.perm.key) {
            None => {
                if (msgflg & IPC_CREAT) == 0 { return Err(Errno::Enoent); }
                newque(ids, ns, key, msgflg, cred)
            }
            Some(q) => {
                if (msgflg & IPC_CREAT) != 0 && (msgflg & IPC_EXCL) != 0 { return Err(Errno::Eexist); }
                if !q.perm.permitted(cred, msgflg) { return Err(Errno::Eacces); }
                Ok(q.perm.id)
            }
        }
    })
}

/// `msgget(key, msgflg)` — slot `NR_MSGGET`.
/// # C: O(N_queues)
pub fn sys_msgget(args: &syscall::SyscallArgs) -> i64 {
    let ns = match model::current_ns() { Ok(n) => n, Err(e) => return user::errno(e) };
    let cred = current_ipc_cred();
    match msgget(ns, args.a0 as i32, args.a1 as i32, &cred) {
        Ok(id) => id as i64,
        Err(e) => user::errno(e),
    }
}
