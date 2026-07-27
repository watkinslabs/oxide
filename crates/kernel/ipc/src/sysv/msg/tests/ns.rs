//! Namespace isolation: the same key resolves to different queues, and an
//! identifier minted in one namespace is invisible in the other.

use syscall::errno::Errno;

use super::support::{owner_cred, Buf, Ns};
use crate::sysv::limits::{IPC_CREAT, IPC_STAT};
use crate::sysv::msg::ctl::msgctl;
use crate::sysv::msg::get::msgget;
use crate::sysv::msg::model;
use crate::sysv::msg::send::msgsnd;
use crate::sysv::uapi::MSQID64_DS_BYTES;

const MODE_RW_ALL: i32 = 0o666;
const NO_FLAGS: i32 = 0;
const SHARED_KEY: i32 = 0x4d534e53;
const TYPE_ONE: i64 = 1;

#[test]
fn one_key_yields_one_queue_per_namespace() {
    let left = Ns::new();
    let right = Ns::new();
    let cred = owner_cred();
    let a = msgget(left.id(), SHARED_KEY, IPC_CREAT | MODE_RW_ALL, &cred).unwrap();
    let b = msgget(right.id(), SHARED_KEY, IPC_CREAT | MODE_RW_ALL, &cred).unwrap();
    assert_eq!(msgget(left.id(), SHARED_KEY, MODE_RW_ALL, &cred), Ok(a));
    assert_eq!(msgget(right.id(), SHARED_KEY, MODE_RW_ALL, &cred), Ok(b));

    let mut tx = Buf::out(TYPE_ONE, b"left");
    assert_eq!(msgsnd(left.id(), a, tx.ptr(), 4, NO_FLAGS, &cred), Ok(0));
    assert_eq!(model::lookup_checked(left.id(), a).unwrap().state.lock().qnum, 1);
    assert_eq!(model::lookup_checked(right.id(), b).unwrap().state.lock().qnum, 0,
        "the peer namespace's queue is untouched");
}

#[test]
fn an_identifier_does_not_cross_namespaces() {
    let left = Ns::new();
    let right = Ns::new();
    let cred = owner_cred();
    // Force distinct identifiers so the test cannot pass by index collision.
    let a = msgget(left.id(), SHARED_KEY, IPC_CREAT | MODE_RW_ALL, &cred).unwrap();
    msgget(right.id(), SHARED_KEY, IPC_CREAT | MODE_RW_ALL, &cred).unwrap();
    let b = msgget(right.id(), SHARED_KEY + 1, IPC_CREAT | MODE_RW_ALL, &cred).unwrap();
    assert_ne!(a, b);
    let mut out = Buf::bytes(MSQID64_DS_BYTES);
    assert_eq!(msgctl(right.id(), a, IPC_STAT, out.ptr(), &cred), Ok(0),
        "index 0 exists in both namespaces but names a different queue");
    assert_eq!(msgctl(left.id(), b, IPC_STAT, out.ptr(), &cred), Err(Errno::Einval));
    assert_eq!(model::lookup_checked(left.id(), b).err(), Some(Errno::Einval));
}

#[test]
fn reaping_a_namespace_drops_its_queues() {
    let cred = owner_cred();
    let doomed = Ns::new();
    let survivor = Ns::new();
    let gone = msgget(doomed.id(), SHARED_KEY, IPC_CREAT | MODE_RW_ALL, &cred).unwrap();
    let kept = msgget(survivor.id(), SHARED_KEY, IPC_CREAT | MODE_RW_ALL, &cred).unwrap();
    let mut tx = Buf::out(TYPE_ONE, b"x");
    assert_eq!(msgsnd(doomed.id(), gone, tx.ptr(), 1, NO_FLAGS, &cred), Ok(0));
    model::reap_namespace(doomed.id());
    assert_eq!(model::lookup_checked(doomed.id(), gone).err(), Some(Errno::Einval));
    assert!(model::lookup_checked(survivor.id(), kept).is_ok(),
        "reaping one namespace leaves its peers alone");
}
