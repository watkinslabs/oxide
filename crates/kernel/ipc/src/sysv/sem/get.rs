//! `semget(2)` — Linux `ksys_semget` → `ipcget` → `newary` / `sem_more_checks`
//! (`ipc/sem.c`, `ipc/util.c`).

use namespace_identity::NamespaceId;
use syscall::errno::Errno;

use super::super::limits::{IPC_CREAT, IPC_EXCL, IPC_PRIVATE, SEMMSL};
use super::super::perm::{current_ipc_cred, IpcCred};
use super::super::user::errno;
use super::model;

/// Body of `ksys_semget` with the namespace and credentials resolved, so the
/// key/permission algebra is exercisable without a running task.
/// # C: O(max_idx) key scan + O(nsems) create
pub fn semget_in(ns: NamespaceId, cred: &IpcCred, key: i32, nsems: i32, semflg: i32)
    -> Result<i32, Errno>
{
    // `ksys_semget` bounds `nsems` BEFORE `ipcget` looks at the key, so an
    // out-of-range count is EINVAL even for a key that does not exist.
    if nsems < 0 || nsems as usize > SEMMSL { return Err(Errno::Einval); }
    let nsems = nsems as usize;

    // `ipcget`: IPC_PRIVATE never consults the key space.
    if key == IPC_PRIVATE { return model::newary(ns, key, nsems, semflg, cred); }

    // `ipcget_public`.
    let Some(set) = model::lookup_key(ns, key) else {
        if semflg & IPC_CREAT == 0 { return Err(Errno::Enoent); }
        return model::newary(ns, key, nsems, semflg, cred);
    };
    if semflg & IPC_CREAT != 0 && semflg & IPC_EXCL != 0 { return Err(Errno::Eexist); }
    // `sem_more_checks`: an existing set must be at least as wide as asked for.
    if nsems > set.nsems { return Err(Errno::Einval); }
    // `ipc_check_perms`: the requested mode bits must be granted.
    if !set.perm.permitted(cred, semflg) { return Err(Errno::Eacces); }
    Ok(set.perm.id)
}

/// `semget(key, nsems, semflg)` — slot `NR_SEMGET`. # C: O(max_idx) + O(nsems)
pub fn sys_semget(args: &syscall::SyscallArgs) -> i64 {
    let ns = match model::current_ns() { Ok(n) => n, Err(e) => return errno(e) };
    let cred = current_ipc_cred();
    match semget_in(ns, &cred, args.a0 as i32, args.a1 as i32, args.a2 as i32) {
        Ok(id) => id as i64,
        Err(e) => errno(e),
    }
}
