//! `semctl_main` + `semctl_setval` — the commands that read or write semaphore
//! values.

use alloc::vec::Vec;
use namespace_identity::NamespaceId;
use syscall::errno::Errno;

use super::super::super::block;
use super::super::super::limits::{
    GETALL, GETNCNT, GETPID, GETVAL, GETZCNT, SEMVMX, SETALL, S_IRUGO, S_IWUGO,
};
use super::super::super::perm::IpcCred;
use super::super::super::user;
use super::super::model;
use super::super::undo;

/// Width of one `GETALL`/`SETALL` element (`unsigned short`).
const SEMVAL_BYTES: usize = 2;

/// Linux `semctl_main`: `GETALL`/`SETALL` plus the four per-semaphore reads.
/// The permission demand is `S_IWUGO` for `SETALL` and `S_IRUGO` for everything
/// else, and the `semnum` bound is checked only AFTER that — an unreadable set
/// reports `EACCES`, not `EINVAL`.
/// # C: O(nsems)
pub fn semctl_main(ns: NamespaceId, cred: &IpcCred, semid: i32, semnum: i32, cmd: i32, arg: u64)
    -> Result<i64, Errno>
{
    let set = model::lookup_checked(ns, semid).ok_or(Errno::Einval)?;
    let nsems = set.nsems;
    let want = if cmd == SETALL { S_IWUGO } else { S_IRUGO };
    if !set.perm.permitted(cred, want) { return Err(Errno::Eacces); }

    if cmd == GETALL {
        let mut out: Vec<u8> = Vec::new();
        if out.try_reserve_exact(nsems * SEMVAL_BYTES).is_err() { return Err(Errno::Enomem); }
        {
            let st = set.state.lock();
            if st.removed { return Err(Errno::Eidrm); }
            for s in st.sems.iter() { out.extend_from_slice(&(s.val as u16).to_le_bytes()); }
        }
        // Copied out with no lock held, as Linux does.
        user::write_bytes(arg, &out)?;
        return Ok(0);
    }

    if cmd == SETALL {
        let mut raw: Vec<u8> = Vec::new();
        if raw.try_reserve_exact(nsems * SEMVAL_BYTES).is_err() { return Err(Errno::Enomem); }
        raw.resize(nsems * SEMVAL_BYTES, 0);
        user::read_bytes(arg, &mut raw)?;
        // All-or-nothing: every value is range-checked BEFORE any is written,
        // so an `ERANGE` leaves the set exactly as it was.
        let mut vals: Vec<i32> = Vec::new();
        if vals.try_reserve_exact(nsems).is_err() { return Err(Errno::Enomem); }
        for i in 0..nsems {
            let v = u16::from_le_bytes([raw[i * SEMVAL_BYTES], raw[i * SEMVAL_BYTES + 1]]) as i32;
            if v > SEMVMX { return Err(Errno::Erange); }
            vals.push(v);
        }
        let pid = block::current_tgid();
        let mut st = set.state.lock();
        if st.removed { return Err(Errno::Eidrm); }
        for (i, v) in vals.iter().enumerate() {
            st.sems[i].val = *v;
            st.sems[i].pid = pid;
        }
        // An explicit assignment invalidates every pending exit adjustment.
        undo::clear_adjustments(ns, semid, None);
        st.ctime = block::real_seconds();
        set.commit_wake(&mut st);
        return Ok(0);
    }

    if semnum < 0 || semnum as usize >= nsems { return Err(Errno::Einval); }
    let idx = semnum as usize;
    let st = set.state.lock();
    if st.removed { return Err(Errno::Eidrm); }
    match cmd {
        GETVAL => Ok(st.sems[idx].val as i64),
        GETPID => Ok(st.sems[idx].pid as i64),
        GETNCNT => Ok(st.sems[idx].ncnt as i64),
        GETZCNT => Ok(st.sems[idx].zcnt as i64),
        _ => Err(Errno::Einval),
    }
}

/// Linux `semctl_setval`. Error order is fixed: `ERANGE` on the value first,
/// then the id, then `semnum`, then the write permission.
/// # C: O(N_undo)
pub fn semctl_setval(ns: NamespaceId, cred: &IpcCred, semid: i32, semnum: i32, val: i32)
    -> Result<i64, Errno>
{
    if val > SEMVMX || val < 0 { return Err(Errno::Erange); }
    let set = model::lookup_checked(ns, semid).ok_or(Errno::Einval)?;
    if semnum < 0 || semnum as usize >= set.nsems { return Err(Errno::Einval); }
    if !set.perm.permitted(cred, S_IWUGO) { return Err(Errno::Eacces); }

    let idx = semnum as usize;
    let mut st = set.state.lock();
    if st.removed { return Err(Errno::Eidrm); }
    undo::clear_adjustments(ns, semid, Some(idx));
    st.sems[idx].val = val;
    st.sems[idx].pid = block::current_tgid();
    st.ctime = block::real_seconds();
    set.commit_wake(&mut st);
    Ok(0)
}
