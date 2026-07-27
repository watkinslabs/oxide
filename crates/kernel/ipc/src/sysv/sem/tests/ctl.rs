//! Every `semctl` command, including the `semid64_ds` / `seminfo` byte layout.

use syscall::errno::Errno;

use super::super::super::limits::{
    GETALL, GETNCNT, GETPID, GETVAL, GETZCNT, IPCMNI_IDX_MASK, IPC_CREAT, IPC_INFO, IPC_PRIVATE,
    IPC_RMID, IPC_SET, IPC_STAT, SEMAEM, SEMMNI, SEMMNS, SEMMSL, SEMOPM, SEMUSZ, SEMVMX, SETALL,
    SETVAL, SEM_INFO, SEM_STAT, SEM_STAT_ANY,
};
use super::super::super::uapi::{
    get_u32, get_u64, IPC64_PERM_BYTES, IPC64_PERM_CUID_OFF, IPC64_PERM_GID_OFF,
    IPC64_PERM_KEY_OFF, IPC64_PERM_MODE_OFF, IPC64_PERM_UID_OFF, SEMID64_CTIME_OFF,
    SEMID64_DS_BYTES, SEMID64_NSEMS_OFF, SEMID64_OTIME_OFF, SEMINFO_BYTES, SEMINFO_SEMAEM_OFF,
    SEMINFO_SEMMNI_OFF, SEMINFO_SEMMNS_OFF, SEMINFO_SEMMSL_OFF, SEMINFO_SEMOPM_OFF,
    SEMINFO_SEMUSZ_OFF, SEMINFO_SEMVMX_OFF,
};
use super::super::{model, semctl_in, semget_in, semop_in, Sembuf};
use super::common::{cred, ns, reset, root, uptr, uptr_mut, TEST_LOCK};

fn sop(num: u16, op: i16, flg: i16) -> Sembuf { Sembuf { sem_num: num, sem_op: op, sem_flg: flg } }

fn geti32(b: &[u8], off: usize) -> i32 { get_u32(b, off) as i32 }

#[test]
fn getval_setval_and_getpid_round_trip() {
    let _g = TEST_LOCK.lock().unwrap();
    reset();
    let (ns, c) = (ns(), root());
    let id = semget_in(ns, &c, IPC_PRIVATE, 3, 0o600).unwrap();
    assert_eq!(semctl_in(ns, &c, id, 1, GETVAL, 0), Ok(0), "a new set starts at zero");
    assert_eq!(semctl_in(ns, &c, id, 1, SETVAL, 12), Ok(0));
    assert_eq!(semctl_in(ns, &c, id, 1, GETVAL, 0), Ok(12));
    // sempid is the last mutator's thread-group id (0 with no task hosted).
    assert_eq!(semctl_in(ns, &c, id, 1, GETPID, 0), Ok(0));

    assert_eq!(semctl_in(ns, &c, id, 1, SETVAL, SEMVMX as u64 + 1), Err(Errno::Erange));
    assert_eq!(semctl_in(ns, &c, id, 1, SETVAL, (-1i64) as u64), Err(Errno::Erange));
    assert_eq!(semctl_in(ns, &c, id, 3, SETVAL, 1), Err(Errno::Einval), "semnum bound");
    assert_eq!(semctl_in(ns, &c, id, -1, GETVAL, 0), Err(Errno::Einval));
    assert_eq!(semctl_in(ns, &c, id, 3, GETVAL, 0), Err(Errno::Einval));
    assert_eq!(semctl_in(ns, &c, id, 1, GETVAL, 0), Ok(12), "no failed call changed a value");
}

#[test]
fn getall_and_setall_copy_the_whole_array() {
    let _g = TEST_LOCK.lock().unwrap();
    reset();
    let (ns, c) = (ns(), root());
    let id = semget_in(ns, &c, IPC_PRIVATE, 3, 0o600).unwrap();
    let src = [7u16, 8, 9];
    assert_eq!(semctl_in(ns, &c, id, 0, SETALL, uptr(&src)), Ok(0));
    let mut dst = [0u16; 3];
    assert_eq!(semctl_in(ns, &c, id, 0, GETALL, uptr_mut(&mut dst)), Ok(0));
    assert_eq!(dst, src);
    assert_eq!(semctl_in(ns, &c, id, 0, GETALL, 0), Err(Errno::Efault));
}

#[test]
fn setall_is_all_or_nothing_on_erange() {
    let _g = TEST_LOCK.lock().unwrap();
    reset();
    let (ns, c) = (ns(), root());
    let id = semget_in(ns, &c, IPC_PRIVATE, 3, 0o600).unwrap();
    let good = [1u16, 2, 3];
    assert_eq!(semctl_in(ns, &c, id, 0, SETALL, uptr(&good)), Ok(0));
    // The last element is out of range; nothing at all may be written.
    let bad = [5u16, 6, SEMVMX as u16 + 1];
    assert_eq!(semctl_in(ns, &c, id, 0, SETALL, uptr(&bad)), Err(Errno::Erange));
    let mut dst = [0u16; 3];
    assert_eq!(semctl_in(ns, &c, id, 0, GETALL, uptr_mut(&mut dst)), Ok(0));
    assert_eq!(dst, good, "an ERANGE SETALL leaves every value untouched");
}

#[test]
fn getncnt_and_getzcnt_report_blocked_waiters() {
    let _g = TEST_LOCK.lock().unwrap();
    reset();
    let (ns, c) = (ns(), root());
    let id = semget_in(ns, &c, IPC_PRIVATE, 2, 0o600).unwrap();
    assert_eq!(semctl_in(ns, &c, id, 0, GETNCNT, 0), Ok(0));
    assert_eq!(semctl_in(ns, &c, id, 0, GETZCNT, 0), Ok(0));

    // The tally is charged around the park; with no scheduler the hosted park
    // returns immediately, so drive the accounting the way a parked waiter does.
    {
        let set = model::lookup_checked(ns, id).unwrap();
        let mut st = set.state.lock();
        st.count_blocked(0, -1, true);
        st.count_blocked(0, -1, true);
        st.count_blocked(1, 0, true);
    }
    assert_eq!(semctl_in(ns, &c, id, 0, GETNCNT, 0), Ok(2));
    assert_eq!(semctl_in(ns, &c, id, 0, GETZCNT, 0), Ok(0));
    assert_eq!(semctl_in(ns, &c, id, 1, GETZCNT, 0), Ok(1));
    assert_eq!(semctl_in(ns, &c, id, 1, GETNCNT, 0), Ok(0));
    {
        let set = model::lookup_checked(ns, id).unwrap();
        set.state.lock().count_blocked(0, -1, false);
    }
    assert_eq!(semctl_in(ns, &c, id, 0, GETNCNT, 0), Ok(1));
}

#[test]
fn ipc_stat_writes_semid64_ds_at_the_documented_offsets() {
    let _g = TEST_LOCK.lock().unwrap();
    reset();
    let ns = ns();
    let owner = cred(1234, 5678);
    let id = semget_in(ns, &owner, 42, 4, IPC_CREAT | 0o640).unwrap();
    assert_eq!(semop_in(ns, &owner, id, &[sop(0, 1, 0)], None), Ok(()));

    let mut buf = [0u8; SEMID64_DS_BYTES];
    assert_eq!(semctl_in(ns, &owner, id, 0, IPC_STAT, uptr_mut(&mut buf)), Ok(0),
        "IPC_STAT returns 0, not the id");
    assert_eq!(geti32(&buf, IPC64_PERM_KEY_OFF), 42);
    assert_eq!(get_u32(&buf, IPC64_PERM_UID_OFF), 1234);
    assert_eq!(get_u32(&buf, IPC64_PERM_GID_OFF), 5678);
    assert_eq!(get_u32(&buf, IPC64_PERM_CUID_OFF), 1234);
    assert_eq!(get_u32(&buf, IPC64_PERM_MODE_OFF), 0o640);
    assert_eq!(get_u64(&buf, SEMID64_NSEMS_OFF), 4);
    // otime/ctime are wall seconds; both are plausible and distinct fields.
    assert_eq!(get_u64(&buf, SEMID64_OTIME_OFF) as i64,
        model::lookup_checked(ns, id).unwrap().state.lock().otime);
    assert_eq!(get_u64(&buf, SEMID64_CTIME_OFF) as i64,
        model::lookup_checked(ns, id).unwrap().state.lock().ctime);
    assert_eq!(semctl_in(ns, &owner, id, 0, IPC_STAT, 0), Err(Errno::Efault));
}

#[test]
fn sem_stat_addresses_by_index_and_returns_the_full_id() {
    let _g = TEST_LOCK.lock().unwrap();
    reset();
    let ns = ns();
    let owner = cred(1000, 1000);
    let other = cred(1001, 1001);
    let id = semget_in(ns, &owner, IPC_PRIVATE, 1, 0o600).unwrap();
    let idx = id & IPCMNI_IDX_MASK;

    let mut buf = [0u8; SEMID64_DS_BYTES];
    assert_eq!(semctl_in(ns, &owner, idx, 0, SEM_STAT, uptr_mut(&mut buf)), Ok(id as i64));
    // SEM_STAT enforces read permission; SEM_STAT_ANY deliberately does not.
    assert_eq!(semctl_in(ns, &other, idx, 0, SEM_STAT, uptr_mut(&mut buf)), Err(Errno::Eacces));
    assert_eq!(semctl_in(ns, &other, idx, 0, SEM_STAT_ANY, uptr_mut(&mut buf)), Ok(id as i64));
    // IPC_STAT on the bare index is a stale id unless index and id coincide.
    if idx != id {
        assert_eq!(semctl_in(ns, &owner, idx, 0, IPC_STAT, uptr_mut(&mut buf)), Err(Errno::Einval));
    }
}

#[test]
fn ipc_info_and_sem_info_report_static_versus_live_counters() {
    let _g = TEST_LOCK.lock().unwrap();
    reset();
    let (ns, c) = (ns(), root());
    let mut buf = [0u8; SEMINFO_BYTES];

    // Empty space: max_idx is -1, reported as 0.
    assert_eq!(semctl_in(ns, &c, 0, 0, SEM_INFO, uptr_mut(&mut buf)), Ok(0));
    assert_eq!(geti32(&buf, SEMINFO_SEMUSZ_OFF), 0);
    assert_eq!(geti32(&buf, SEMINFO_SEMAEM_OFF), 0);

    semget_in(ns, &c, IPC_PRIVATE, 3, 0o600).unwrap();
    semget_in(ns, &c, IPC_PRIVATE, 4, 0o600).unwrap();
    let max_idx = semctl_in(ns, &c, 0, 0, SEM_INFO, uptr_mut(&mut buf)).unwrap();
    assert_eq!(max_idx, 1, "two sets occupy indexes 0 and 1");
    assert_eq!(geti32(&buf, SEMINFO_SEMUSZ_OFF), 2, "SEM_INFO semusz = ids.in_use");
    assert_eq!(geti32(&buf, SEMINFO_SEMAEM_OFF), 7, "SEM_INFO semaem = used_sems");
    assert_eq!(geti32(&buf, SEMINFO_SEMMNI_OFF), SEMMNI as i32);
    assert_eq!(geti32(&buf, SEMINFO_SEMMNS_OFF), SEMMNS as i32);
    assert_eq!(geti32(&buf, SEMINFO_SEMMSL_OFF), SEMMSL as i32);
    assert_eq!(geti32(&buf, SEMINFO_SEMOPM_OFF), SEMOPM as i32);
    assert_eq!(geti32(&buf, SEMINFO_SEMVMX_OFF), SEMVMX);

    assert_eq!(semctl_in(ns, &c, 0, 0, IPC_INFO, uptr_mut(&mut buf)), Ok(1));
    assert_eq!(geti32(&buf, SEMINFO_SEMUSZ_OFF), SEMUSZ as i32, "IPC_INFO reports the constant");
    assert_eq!(geti32(&buf, SEMINFO_SEMAEM_OFF), SEMAEM);
}

#[test]
fn ipc_set_is_owner_gated_and_replaces_only_the_permission_bits() {
    let _g = TEST_LOCK.lock().unwrap();
    reset();
    let ns = ns();
    let owner = cred(1000, 1000);
    let other = cred(1001, 1001);
    let id = semget_in(ns, &owner, IPC_PRIVATE, 1, 0o600).unwrap();

    let mut perm = [0u8; IPC64_PERM_BYTES];
    perm[IPC64_PERM_UID_OFF..IPC64_PERM_UID_OFF + 4].copy_from_slice(&2000u32.to_le_bytes());
    perm[IPC64_PERM_GID_OFF..IPC64_PERM_GID_OFF + 4].copy_from_slice(&2001u32.to_le_bytes());
    perm[IPC64_PERM_MODE_OFF..IPC64_PERM_MODE_OFF + 4].copy_from_slice(&0o666u32.to_le_bytes());

    assert_eq!(semctl_in(ns, &other, id, 0, IPC_SET, uptr(&perm)), Err(Errno::Eperm));
    assert_eq!(semctl_in(ns, &owner, id, 0, IPC_SET, uptr(&perm)), Ok(0));

    let mut buf = [0u8; SEMID64_DS_BYTES];
    assert_eq!(semctl_in(ns, &owner, id, 0, IPC_STAT, uptr_mut(&mut buf)), Ok(0),
        "the creator uid still passes the owner gate");
    assert_eq!(get_u32(&buf, IPC64_PERM_UID_OFF), 2000);
    assert_eq!(get_u32(&buf, IPC64_PERM_GID_OFF), 2001);
    assert_eq!(get_u32(&buf, IPC64_PERM_MODE_OFF), 0o666);
    assert_eq!(get_u32(&buf, IPC64_PERM_CUID_OFF), 1000, "creator ids are immutable");
    assert_eq!(semctl_in(ns, &owner, id, 0, IPC_SET, 0), Err(Errno::Efault));
}

#[test]
fn ipc_rmid_is_owner_gated_and_unpublishes_the_id() {
    let _g = TEST_LOCK.lock().unwrap();
    reset();
    let ns = ns();
    let owner = cred(1000, 1000);
    let other = cred(1001, 1001);
    let id = semget_in(ns, &owner, 5, 2, IPC_CREAT | 0o600).unwrap();
    assert_eq!(semctl_in(ns, &other, id, 0, IPC_RMID, 0), Err(Errno::Eperm));
    assert_eq!(semctl_in(ns, &owner, id, 0, IPC_RMID, 0), Ok(0));
    assert_eq!(semctl_in(ns, &owner, id, 0, GETVAL, 0), Err(Errno::Einval));
    // The key is free again, and used_sems was released with the set.
    assert_eq!(semget_in(ns, &owner, 5, 2, 0o600), Err(Errno::Enoent));
    let mut buf = [0u8; SEMINFO_BYTES];
    semctl_in(ns, &owner, 0, 0, SEM_INFO, uptr_mut(&mut buf)).unwrap();
    assert_eq!(geti32(&buf, SEMINFO_SEMUSZ_OFF), 0);
    assert_eq!(geti32(&buf, SEMINFO_SEMAEM_OFF), 0);
}

#[test]
fn a_negative_semid_or_unknown_command_is_einval() {
    let _g = TEST_LOCK.lock().unwrap();
    reset();
    let (ns, c) = (ns(), root());
    let id = semget_in(ns, &c, IPC_PRIVATE, 1, 0o600).unwrap();
    assert_eq!(semctl_in(ns, &c, -1, 0, GETVAL, 0), Err(Errno::Einval));
    assert_eq!(semctl_in(ns, &c, id, 0, 999, 0), Err(Errno::Einval));
}

#[test]
fn read_and_write_commands_demand_the_matching_permission() {
    let _g = TEST_LOCK.lock().unwrap();
    reset();
    let ns = ns();
    let owner = cred(1000, 1000);
    let other = cred(1001, 1001);
    // Others may read but not write.
    let id = semget_in(ns, &owner, IPC_PRIVATE, 2, 0o644).unwrap();
    let mut dst = [0u16; 2];
    assert_eq!(semctl_in(ns, &other, id, 0, GETALL, uptr_mut(&mut dst)), Ok(0));
    assert_eq!(semctl_in(ns, &other, id, 0, GETVAL, 0), Ok(0));
    let src = [1u16, 1];
    assert_eq!(semctl_in(ns, &other, id, 0, SETALL, uptr(&src)), Err(Errno::Eacces));
    assert_eq!(semctl_in(ns, &other, id, 0, SETVAL, 1), Err(Errno::Eacces));

    // The two bodies order their checks differently, and Linux's do too:
    // semctl_setval bounds semnum BEFORE ipcperms...
    assert_eq!(semctl_in(ns, &other, id, 99, SETVAL, 1), Err(Errno::Einval));
    // ...while semctl_main runs ipcperms first, so an unreadable set reports
    // EACCES even for an out-of-range semnum.
    let shut = semget_in(ns, &owner, IPC_PRIVATE, 2, 0o600).unwrap();
    assert_eq!(semctl_in(ns, &other, shut, 99, GETVAL, 0), Err(Errno::Eacces));
    assert_eq!(semctl_in(ns, &other, shut, 0, GETVAL, 0), Err(Errno::Eacces));
}
