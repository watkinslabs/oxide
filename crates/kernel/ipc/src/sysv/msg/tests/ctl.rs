//! `msgctl` — every command, its byte layout and its permission gate.

use alloc::vec::Vec;
use syscall::errno::Errno;

use super::support::{other_cred, owner_cred, resource_cred, Buf, Ns};
use crate::sysv::limits::{
    IPCMNI_IDX_MASK, IPC_INFO, IPC_PRIVATE, IPC_RMID, IPC_SET, IPC_STAT, MSGMAP, MSGMAX, MSGMNB,
    MSGMNI, MSGPOOL, MSGSEG, MSGSSZ, MSGTQL, MSG_INFO, MSG_STAT, MSG_STAT_ANY,
};
use crate::sysv::msg::ctl::msgctl;
use crate::sysv::msg::get::msgget;
use crate::sysv::msg::recv::msgrcv;
use crate::sysv::msg::send::msgsnd;
use crate::sysv::perm::IpcCred;
use crate::sysv::uapi::{
    get_u32, get_u64, put_u32, put_u64, IPC64_PERM_GID_OFF, IPC64_PERM_KEY_OFF,
    IPC64_PERM_MODE_OFF, IPC64_PERM_UID_OFF, MSGINFO_BYTES, MSGINFO_MSGMAP_OFF,
    MSGINFO_MSGMAX_OFF, MSGINFO_MSGMNB_OFF, MSGINFO_MSGMNI_OFF, MSGINFO_MSGPOOL_OFF,
    MSGINFO_MSGSEG_OFF, MSGINFO_MSGSSZ_OFF, MSGINFO_MSGTQL_OFF, MSQID64_CBYTES_OFF,
    MSQID64_DS_BYTES, MSQID64_LRPID_OFF, MSQID64_LSPID_OFF, MSQID64_QBYTES_OFF, MSQID64_QNUM_OFF,
};

const MODE_RW_ALL: i32 = 0o666;
const MODE_RW_OWNER: i32 = 0o600;
const MODE_NEW: u32 = 0o640;
const NO_FLAGS: i32 = 0;
const ANY_TYPE: i64 = 0;
const TYPE_ONE: i64 = 1;
const UNKNOWN_CMD: i32 = 999;
const NEW_UID: u32 = 1000;
const NEW_GID: u32 = 1001;
const SMALL_QBYTES: u64 = 64;
/// Bits above the `int` the kernel narrows `msg_qbytes` to.
const HIGH_HALF_ONLY: u64 = 1 << 32;
/// Linux `ipc_min_cycle` — the floor on `ipc_ids`' cyclic allocation window,
/// so filling and draining this many slots forces the next `seq` bump.
const IPC_MIN_CYCLE: usize = 16;

fn queue(ns: &Ns, cred: &IpcCred, mode: i32) -> i32 {
    msgget(ns.id(), IPC_PRIVATE, mode, cred).unwrap()
}

fn send(ns: &Ns, cred: &IpcCred, id: i32, text: &[u8]) {
    let mut buf = Buf::out(TYPE_ONE, text);
    assert_eq!(msgsnd(ns.id(), id, buf.ptr(), text.len() as u64, NO_FLAGS, cred), Ok(0));
}

/// `msqid64_ds` input for `IPC_SET`.
fn set_buf(uid: u32, gid: u32, mode: u32, qbytes: u64) -> Buf {
    let mut b = Buf::bytes(MSQID64_DS_BYTES);
    put_u32(b.raw_mut(), IPC64_PERM_UID_OFF, uid);
    put_u32(b.raw_mut(), IPC64_PERM_GID_OFF, gid);
    put_u32(b.raw_mut(), IPC64_PERM_MODE_OFF, mode);
    put_u64(b.raw_mut(), MSQID64_QBYTES_OFF, qbytes);
    b
}

#[test]
fn ipc_stat_fills_the_documented_msqid64_ds_offsets() {
    let ns = Ns::new();
    let cred = owner_cred();
    let id = queue(&ns, &cred, MODE_RW_ALL);
    send(&ns, &cred, id, b"12345");
    let mut out = Buf::bytes(MSQID64_DS_BYTES);
    assert_eq!(msgctl(ns.id(), id, IPC_STAT, out.ptr(), &cred), Ok(0));
    assert_eq!(get_u32(out.raw(), IPC64_PERM_KEY_OFF), IPC_PRIVATE as u32);
    assert_eq!(get_u32(out.raw(), IPC64_PERM_MODE_OFF), MODE_RW_ALL as u32);
    assert_eq!(get_u64(out.raw(), MSQID64_CBYTES_OFF), 5);
    assert_eq!(get_u64(out.raw(), MSQID64_QNUM_OFF), 1);
    assert_eq!(get_u64(out.raw(), MSQID64_QBYTES_OFF), MSGMNB as u64);
    let tgid = crate::sysv::block::current_tgid();
    assert_eq!(get_u32(out.raw(), MSQID64_LSPID_OFF), tgid);
    assert_eq!(get_u32(out.raw(), MSQID64_LRPID_OFF), 0, "nothing has received yet");
    let mut rx = Buf::recv(8);
    assert_eq!(msgrcv(ns.id(), id, rx.ptr(), 8, ANY_TYPE, NO_FLAGS, &cred), Ok(5));
    assert_eq!(msgctl(ns.id(), id, IPC_STAT, out.ptr(), &cred), Ok(0));
    assert_eq!(get_u32(out.raw(), MSQID64_LRPID_OFF), tgid);
    assert_eq!(get_u64(out.raw(), MSQID64_QNUM_OFF), 0);
}

#[test]
fn msg_stat_takes_an_index_and_returns_the_full_id() {
    let ns = Ns::new();
    let cred = owner_cred();
    // Fill and drain the cyclic allocation window so the next identifier
    // carries a non-zero sequence half and stops being equal to its index.
    let mut spent = Vec::new();
    for _ in 0..IPC_MIN_CYCLE { spent.push(queue(&ns, &cred, MODE_RW_ALL)); }
    for id in spent { assert_eq!(msgctl(ns.id(), id, IPC_RMID, 0, &cred), Ok(0)); }
    let id = queue(&ns, &cred, MODE_RW_ALL);
    let idx = id & IPCMNI_IDX_MASK;
    assert_ne!(id, idx, "the sequence half is what distinguishes id from index");

    let mut out = Buf::bytes(MSQID64_DS_BYTES);
    assert_eq!(msgctl(ns.id(), idx, MSG_STAT, out.ptr(), &cred), Ok(id as i64));
    assert_eq!(msgctl(ns.id(), id, MSG_STAT, out.ptr(), &cred), Err(Errno::Einval),
        "MSG_STAT indexes the namespace and cannot take a full identifier");
    assert_eq!(msgctl(ns.id(), id, IPC_STAT, out.ptr(), &cred), Ok(0));
    assert_eq!(msgctl(ns.id(), idx, IPC_STAT, out.ptr(), &cred), Err(Errno::Einval),
        "IPC_STAT rejects the stale sequence half a bare index carries");
}

#[test]
fn msg_stat_any_skips_the_read_permission_check() {
    let ns = Ns::new();
    let cred = owner_cred();
    let id = queue(&ns, &cred, MODE_RW_OWNER);
    let idx = id & IPCMNI_IDX_MASK;
    let intruder = other_cred();
    let mut out = Buf::bytes(MSQID64_DS_BYTES);
    assert_eq!(msgctl(ns.id(), idx, MSG_STAT, out.ptr(), &intruder), Err(Errno::Eacces));
    assert_eq!(msgctl(ns.id(), id, IPC_STAT, out.ptr(), &intruder), Err(Errno::Eacces));
    assert_eq!(msgctl(ns.id(), idx, MSG_STAT_ANY, out.ptr(), &intruder), Ok(id as i64));
}

#[test]
fn ipc_info_reports_the_static_tunables() {
    let ns = Ns::new();
    let cred = owner_cred();
    let mut out = Buf::bytes(MSGINFO_BYTES);
    assert_eq!(msgctl(ns.id(), 0, IPC_INFO, out.ptr(), &cred), Ok(0),
        "an empty namespace reports 0, not -1");
    queue(&ns, &cred, MODE_RW_ALL);
    let second = queue(&ns, &cred, MODE_RW_ALL);
    assert_eq!(msgctl(ns.id(), 0, IPC_INFO, out.ptr(), &cred),
        Ok((second & IPCMNI_IDX_MASK) as i64));
    assert_eq!(get_u32(out.raw(), MSGINFO_MSGMNI_OFF), MSGMNI as u32);
    assert_eq!(get_u32(out.raw(), MSGINFO_MSGMAX_OFF), MSGMAX as u32);
    assert_eq!(get_u32(out.raw(), MSGINFO_MSGMNB_OFF), MSGMNB as u32);
    assert_eq!(get_u32(out.raw(), MSGINFO_MSGSSZ_OFF), MSGSSZ as u32);
    assert_eq!(get_u32(out.raw(), MSGINFO_MSGMAP_OFF), MSGMAP as u32);
    assert_eq!(get_u32(out.raw(), MSGINFO_MSGPOOL_OFF), MSGPOOL as u32);
    assert_eq!(get_u32(out.raw(), MSGINFO_MSGTQL_OFF), MSGTQL as u32);
    let seg = u16::from_le_bytes([out.raw()[MSGINFO_MSGSEG_OFF], out.raw()[MSGINFO_MSGSEG_OFF + 1]]);
    assert_eq!(seg, MSGSEG);
}

#[test]
fn msg_info_reports_the_live_namespace_totals() {
    let ns = Ns::new();
    let cred = owner_cred();
    let first = queue(&ns, &cred, MODE_RW_ALL);
    let second = queue(&ns, &cred, MODE_RW_ALL);
    send(&ns, &cred, first, b"abc");
    send(&ns, &cred, second, b"de");
    send(&ns, &cred, second, b"f");
    let mut out = Buf::bytes(MSGINFO_BYTES);
    assert_eq!(msgctl(ns.id(), 0, MSG_INFO, out.ptr(), &cred),
        Ok((second & IPCMNI_IDX_MASK) as i64));
    assert_eq!(get_u32(out.raw(), MSGINFO_MSGPOOL_OFF), 2, "msgpool is ids.in_use");
    assert_eq!(get_u32(out.raw(), MSGINFO_MSGMAP_OFF), 3, "msgmap is the header total");
    assert_eq!(get_u32(out.raw(), MSGINFO_MSGTQL_OFF), 6, "msgtql is the byte total");
    assert_eq!(get_u32(out.raw(), MSGINFO_MSGMNI_OFF), MSGMNI as u32);
}

#[test]
fn ipc_set_installs_the_new_owner_mode_and_qbytes() {
    let ns = Ns::new();
    let cred = owner_cred();
    let id = queue(&ns, &cred, MODE_RW_ALL);
    let mut inb = set_buf(NEW_UID, NEW_GID, MODE_NEW, SMALL_QBYTES);
    assert_eq!(msgctl(ns.id(), id, IPC_SET, inb.ptr(), &cred), Ok(0));
    let mut out = Buf::bytes(MSQID64_DS_BYTES);
    assert_eq!(msgctl(ns.id(), id, IPC_STAT, out.ptr(), &cred), Ok(0));
    assert_eq!(get_u32(out.raw(), IPC64_PERM_UID_OFF), NEW_UID);
    assert_eq!(get_u32(out.raw(), IPC64_PERM_GID_OFF), NEW_GID);
    assert_eq!(get_u32(out.raw(), IPC64_PERM_MODE_OFF), MODE_NEW);
    assert_eq!(get_u64(out.raw(), MSQID64_QBYTES_OFF), SMALL_QBYTES);
}

#[test]
fn raising_qbytes_above_msgmnb_needs_cap_sys_resource() {
    let ns = Ns::new();
    let cred = owner_cred();
    let id = queue(&ns, &cred, MODE_RW_ALL);
    let raised = MSGMNB as u64 + 1;
    let mut inb = set_buf(0, 0, MODE_RW_ALL as u32, raised);
    assert_eq!(msgctl(ns.id(), id, IPC_SET, inb.ptr(), &cred), Err(Errno::Eperm));
    assert_eq!(msgctl(ns.id(), id, IPC_SET, inb.ptr(), &resource_cred()), Ok(0));
    let mut out = Buf::bytes(MSQID64_DS_BYTES);
    assert_eq!(msgctl(ns.id(), id, IPC_STAT, out.ptr(), &cred), Ok(0));
    assert_eq!(get_u64(out.raw(), MSQID64_QBYTES_OFF), raised);
}

#[test]
fn ipc_set_truncates_qbytes_to_an_int_the_way_linux_does() {
    let ns = Ns::new();
    let cred = owner_cred();
    let id = queue(&ns, &cred, MODE_RW_ALL);
    // `ksys_msgctl` narrows `msqid64_ds.msg_qbytes` into `msgctl_down`'s
    // `int msg_qbytes`, so the high half userspace supplied is discarded
    // before both the CAP_SYS_RESOURCE gate and the store.
    let mut inb = set_buf(0, 0, MODE_RW_ALL as u32, HIGH_HALF_ONLY | SMALL_QBYTES);
    assert_eq!(msgctl(ns.id(), id, IPC_SET, inb.ptr(), &cred), Ok(0));
    let mut out = Buf::bytes(MSQID64_DS_BYTES);
    assert_eq!(msgctl(ns.id(), id, IPC_STAT, out.ptr(), &cred), Ok(0));
    assert_eq!(get_u64(out.raw(), MSQID64_QBYTES_OFF), SMALL_QBYTES);
}

#[test]
fn ipc_set_and_ipc_rmid_are_owner_only() {
    let ns = Ns::new();
    let cred = owner_cred();
    let id = queue(&ns, &cred, MODE_RW_ALL);
    let intruder = other_cred();
    let mut inb = set_buf(0, 0, MODE_RW_ALL as u32, SMALL_QBYTES);
    assert_eq!(msgctl(ns.id(), id, IPC_SET, inb.ptr(), &intruder), Err(Errno::Eperm));
    assert_eq!(msgctl(ns.id(), id, IPC_RMID, 0, &intruder), Err(Errno::Eperm));
    assert_eq!(msgctl(ns.id(), id, IPC_RMID, 0, &cred), Ok(0));
}

#[test]
fn ipc_rmid_unpublishes_the_queue() {
    let ns = Ns::new();
    let cred = owner_cred();
    let id = queue(&ns, &cred, MODE_RW_ALL);
    send(&ns, &cred, id, b"abc");
    assert_eq!(msgctl(ns.id(), id, IPC_RMID, 0, &cred), Ok(0));
    let mut out = Buf::bytes(MSQID64_DS_BYTES);
    assert_eq!(msgctl(ns.id(), id, IPC_STAT, out.ptr(), &cred), Err(Errno::Einval));
    assert_eq!(msgctl(ns.id(), id, IPC_RMID, 0, &cred), Err(Errno::Einval));
    let mut tx = Buf::out(TYPE_ONE, b"x");
    assert_eq!(msgsnd(ns.id(), id, tx.ptr(), 1, NO_FLAGS, &cred), Err(Errno::Einval));
}

#[test]
fn bad_arguments_are_einval() {
    let ns = Ns::new();
    let cred = owner_cred();
    let id = queue(&ns, &cred, MODE_RW_ALL);
    let mut out = Buf::bytes(MSQID64_DS_BYTES);
    assert_eq!(msgctl(ns.id(), -1, IPC_STAT, out.ptr(), &cred), Err(Errno::Einval));
    assert_eq!(msgctl(ns.id(), id, -1, out.ptr(), &cred), Err(Errno::Einval));
    assert_eq!(msgctl(ns.id(), id, UNKNOWN_CMD, out.ptr(), &cred), Err(Errno::Einval));
}
