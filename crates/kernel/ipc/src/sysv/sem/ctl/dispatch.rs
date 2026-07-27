//! `ksys_semctl` command fan-out.

use namespace_identity::NamespaceId;
use syscall::errno::Errno;

use super::super::super::limits::{
    GETALL, GETNCNT, GETPID, GETVAL, GETZCNT, IPC_INFO, IPC_RMID, IPC_SET, IPC_STAT, SETALL,
    SETVAL, SEM_INFO, SEM_STAT, SEM_STAT_ANY,
};
use super::super::super::perm::{current_ipc_cred, IpcCred};
use super::super::super::uapi::{decode_ipc64_perm, IPC64_PERM_BYTES};
use super::super::super::user::{self, errno};
use super::super::model;

/// Body of `ksys_semctl` with namespace and credentials resolved.
///
/// `arg` is the `union semun` word. On a 64-bit little-endian ABI `SETVAL`
/// reads it as `int val` — the low 32 bits — and every other command that takes
/// one treats it as a user pointer.
/// # C: O(nsems) worst case (`GETALL`/`SETALL`)
pub fn semctl_in(ns: NamespaceId, cred: &IpcCred, semid: i32, semnum: i32, cmd: i32, arg: u64)
    -> Result<i64, Errno>
{
    if semid < 0 { return Err(Errno::Einval); }
    match cmd {
        IPC_INFO | SEM_INFO => super::semctl_info(ns, cmd, arg),
        IPC_STAT | SEM_STAT | SEM_STAT_ANY => super::semctl_stat(ns, cred, semid, cmd, arg),
        GETALL | GETVAL | GETPID | GETNCNT | GETZCNT | SETALL =>
            super::semctl_main(ns, cred, semid, semnum, cmd, arg),
        SETVAL => super::semctl_setval(ns, cred, semid, semnum, arg as i32),
        IPC_SET => {
            let mut buf = [0u8; IPC64_PERM_BYTES];
            user::read_bytes(arg, &mut buf)?;
            super::semctl_set(ns, cred, semid, decode_ipc64_perm(&buf))
        }
        IPC_RMID => super::semctl_rmid(ns, cred, semid),
        _ => Err(Errno::Einval),
    }
}

/// `semctl(semid, semnum, cmd, arg)` — slot `NR_SEMCTL`. # C: O(nsems)
pub fn sys_semctl(args: &syscall::SyscallArgs) -> i64 {
    let ns = match model::current_ns() { Ok(n) => n, Err(e) => return errno(e) };
    let cred = current_ipc_cred();
    match semctl_in(ns, &cred, args.a0 as i32, args.a1 as i32, args.a2 as i32, args.a3) {
        Ok(v) => v,
        Err(e) => errno(e),
    }
}
