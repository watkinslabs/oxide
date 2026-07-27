//! `semctl_down` — `IPC_SET` and `IPC_RMID`, the two commands gated on
//! ownership rather than on the mode bits (`ipcctl_obtain_check`).

use namespace_identity::NamespaceId;
use syscall::errno::Errno;

use super::super::super::block;
use super::super::super::perm::IpcCred;
use super::super::super::uapi::Ipc64PermIn;
use super::super::model;

/// Linux `IPC_SET`: install uid/gid wholesale, replace only the `S_IRWXUGO`
/// bits of the mode, and restamp `sem_ctime`. # C: O(1)
pub fn semctl_set(ns: NamespaceId, cred: &IpcCred, semid: i32, new: Ipc64PermIn)
    -> Result<i64, Errno>
{
    let set = model::lookup_checked(ns, semid).ok_or(Errno::Einval)?;
    if !set.perm.admin_allowed(cred) { return Err(Errno::Eperm); }
    let mut st = set.state.lock();
    if st.removed { return Err(Errno::Eidrm); }
    set.perm.update(new.uid, new.gid, new.mode);
    st.ctime = block::real_seconds();
    Ok(0)
}

/// Linux `IPC_RMID` → `freeary`. # C: O(N_undo + N_waiters)
pub fn semctl_rmid(ns: NamespaceId, cred: &IpcCred, semid: i32) -> Result<i64, Errno> {
    let set = model::lookup_checked(ns, semid).ok_or(Errno::Einval)?;
    if !set.perm.admin_allowed(cred) { return Err(Errno::Eperm); }
    model::freeary(&set);
    Ok(0)
}
