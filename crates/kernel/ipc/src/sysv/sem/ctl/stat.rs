//! `semctl_stat` / `semctl_info` — the read-only reporting commands.

use alloc::sync::Arc;
use namespace_identity::NamespaceId;
use syscall::errno::Errno;

use super::super::super::limits::{
    IPC_STAT, SEMAEM, SEMMAP, SEMMNI, SEMMNS, SEMMNU, SEMMSL, SEMOPM, SEMUME, SEMUSZ, SEMVMX,
    SEM_INFO, SEM_STAT, SEM_STAT_ANY, S_IRUGO,
};
use super::super::super::perm::IpcCred;
use super::super::super::uapi::{
    encode_ipc64_perm, put_i32, put_i64, put_u64, SEMID64_CTIME_OFF, SEMID64_DS_BYTES,
    SEMID64_NSEMS_OFF, SEMID64_OTIME_OFF, SEMINFO_BYTES, SEMINFO_SEMAEM_OFF, SEMINFO_SEMMAP_OFF,
    SEMINFO_SEMMNI_OFF, SEMINFO_SEMMNS_OFF, SEMINFO_SEMMNU_OFF, SEMINFO_SEMMSL_OFF,
    SEMINFO_SEMOPM_OFF, SEMINFO_SEMUME_OFF, SEMINFO_SEMUSZ_OFF, SEMINFO_SEMVMX_OFF,
};
use super::super::super::user;
use super::super::model::{self, SemSet};

/// Linux `semctl_stat`. `IPC_STAT` addresses by checked id and returns 0;
/// `SEM_STAT`/`SEM_STAT_ANY` address by RAW INDEX (what `ipcs(1)` iterates) and
/// return the full id, sequence half included. `SEM_STAT_ANY` is the deliberate
/// permission bypass Linux added for `ipcs -i`.
/// # C: O(1) + O(SEMID64_DS_BYTES) copy
pub fn semctl_stat(ns: NamespaceId, cred: &IpcCred, semid: i32, cmd: i32, buf: u64)
    -> Result<i64, Errno>
{
    let set: Arc<SemSet> = match cmd {
        SEM_STAT | SEM_STAT_ANY => model::lookup_idx(ns, semid),
        _ => model::lookup_checked(ns, semid),
    }.ok_or(Errno::Einval)?;

    if cmd != SEM_STAT_ANY && !set.perm.permitted(cred, S_IRUGO) { return Err(Errno::Eacces); }

    let mut out = [0u8; SEMID64_DS_BYTES];
    {
        let st = set.state.lock();
        if st.removed { return Err(Errno::Eidrm); }
        encode_ipc64_perm(&mut out, &set.perm);
        put_i64(&mut out, SEMID64_OTIME_OFF, st.otime);
        put_i64(&mut out, SEMID64_CTIME_OFF, st.ctime);
        put_u64(&mut out, SEMID64_NSEMS_OFF, set.nsems as u64);
    }
    user::write_bytes(buf, &out)?;
    if cmd == IPC_STAT { Ok(0) } else { Ok(set.perm.id as i64) }
}

/// Linux `semctl_info`. `SEM_INFO` reports live occupancy (`ids.in_use`,
/// `ns->used_sems`) where `IPC_INFO` reports the static `SEMUSZ`/`SEMAEM`
/// constants; both return the highest live index, or 0 when the space is empty.
/// # C: O(1) + O(SEMINFO_BYTES) copy
pub fn semctl_info(ns: NamespaceId, cmd: i32, buf: u64) -> Result<i64, Errno> {
    let (in_use, used_sems, max_idx) = model::info_counters(ns);
    let mut out = [0u8; SEMINFO_BYTES];
    put_i32(&mut out, SEMINFO_SEMMAP_OFF, SEMMAP as i32);
    put_i32(&mut out, SEMINFO_SEMMNI_OFF, SEMMNI as i32);
    put_i32(&mut out, SEMINFO_SEMMNS_OFF, SEMMNS as i32);
    put_i32(&mut out, SEMINFO_SEMMNU_OFF, SEMMNU as i32);
    put_i32(&mut out, SEMINFO_SEMMSL_OFF, SEMMSL as i32);
    put_i32(&mut out, SEMINFO_SEMOPM_OFF, SEMOPM as i32);
    put_i32(&mut out, SEMINFO_SEMUME_OFF, SEMUME as i32);
    put_i32(&mut out, SEMINFO_SEMVMX_OFF, SEMVMX);
    if cmd == SEM_INFO {
        put_i32(&mut out, SEMINFO_SEMUSZ_OFF, in_use as i32);
        put_i32(&mut out, SEMINFO_SEMAEM_OFF, used_sems as i32);
    } else {
        put_i32(&mut out, SEMINFO_SEMUSZ_OFF, SEMUSZ as i32);
        put_i32(&mut out, SEMINFO_SEMAEM_OFF, SEMAEM);
    }
    user::write_bytes(buf, &out)?;
    Ok(if max_idx < 0 { 0 } else { max_idx })
}
