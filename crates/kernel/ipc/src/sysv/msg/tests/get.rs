//! `msgget` — Linux `ipcget` key, create and permission rules.

use syscall::errno::Errno;

use super::support::{other_cred, owner_cred, Ns};
use crate::sysv::limits::{IPC_CREAT, IPC_EXCL, IPC_PRIVATE, S_IRWXUGO};
use crate::sysv::msg::get::msgget;
use crate::sysv::msg::model;

const MODE_RW_OWNER: i32 = 0o600;
const MODE_RW_ALL: i32 = 0o666;
const KEY_A: i32 = 0x4d534741;
const KEY_B: i32 = 0x4d534742;

#[test]
fn ipc_private_always_creates_a_distinct_queue() {
    let ns = Ns::new();
    let cred = owner_cred();
    let first = msgget(ns.id(), IPC_PRIVATE, MODE_RW_ALL, &cred).unwrap();
    let second = msgget(ns.id(), IPC_PRIVATE, MODE_RW_ALL, &cred).unwrap();
    assert_ne!(first, second, "IPC_PRIVATE never resolves an existing key");
}

#[test]
fn absent_key_without_ipc_creat_is_enoent() {
    let ns = Ns::new();
    assert_eq!(msgget(ns.id(), KEY_A, MODE_RW_ALL, &owner_cred()), Err(Errno::Enoent));
}

#[test]
fn existing_key_is_returned_and_excl_rejects_it() {
    let ns = Ns::new();
    let cred = owner_cred();
    let id = msgget(ns.id(), KEY_A, IPC_CREAT | MODE_RW_ALL, &cred).unwrap();
    assert_eq!(msgget(ns.id(), KEY_A, MODE_RW_ALL, &cred), Ok(id));
    assert_eq!(msgget(ns.id(), KEY_A, IPC_CREAT | MODE_RW_ALL, &cred), Ok(id));
    assert_eq!(
        msgget(ns.id(), KEY_A, IPC_CREAT | IPC_EXCL | MODE_RW_ALL, &cred),
        Err(Errno::Eexist)
    );
}

#[test]
fn mode_comes_from_the_low_nine_flag_bits() {
    let ns = Ns::new();
    let cred = owner_cred();
    let id = msgget(ns.id(), KEY_B, IPC_CREAT | IPC_EXCL | MODE_RW_OWNER, &cred).unwrap();
    let q = model::lookup_checked(ns.id(), id).unwrap();
    let mode = q.perm.mode.load(core::sync::atomic::Ordering::Acquire);
    assert_eq!(mode, MODE_RW_OWNER as u32);
    assert_eq!(mode & !S_IRWXUGO, 0, "IPC_CREAT/IPC_EXCL never reach the mode");
    assert_eq!(q.perm.key, KEY_B);
    assert_eq!(q.perm.cuid, 0);
}

#[test]
fn resolving_an_existing_key_enforces_ipcperms() {
    let ns = Ns::new();
    let creator = owner_cred();
    msgget(ns.id(), KEY_A, IPC_CREAT | MODE_RW_OWNER, &creator).unwrap();
    assert_eq!(msgget(ns.id(), KEY_A, MODE_RW_ALL, &other_cred()), Err(Errno::Eacces));
}

#[test]
fn created_queue_starts_with_the_linux_defaults() {
    let ns = Ns::new();
    let id = msgget(ns.id(), IPC_PRIVATE, MODE_RW_ALL, &owner_cred()).unwrap();
    let q = model::lookup_checked(ns.id(), id).unwrap();
    let st = q.state.lock();
    assert_eq!((st.stime, st.rtime), (0, 0));
    assert_eq!((st.cbytes, st.qnum), (0, 0));
    assert_eq!(st.qbytes, crate::sysv::limits::MSGMNB as u64);
    assert_eq!((st.lspid, st.lrpid), (0, 0));
}
