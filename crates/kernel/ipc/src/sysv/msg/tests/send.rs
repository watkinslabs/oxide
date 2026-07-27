//! `msgsnd` — validation, permissions and the `msg_fits_inqueue` rule.

use alloc::vec;
use syscall::errno::Errno;

use super::support::{owner_cred, Buf, Ns};
use crate::sysv::block;
use crate::sysv::limits::{IPC_NOWAIT, IPC_PRIVATE, MSGMAX, MSGMNB};
use crate::sysv::msg::get::msgget;
use crate::sysv::msg::model;
use crate::sysv::msg::send::msgsnd;
use crate::sysv::perm::IpcCred;

const MODE_RW_ALL: i32 = 0o666;
const MODE_R_OWNER: i32 = 0o400;
const NO_FLAGS: i32 = 0;
const TYPE_ONE: i64 = 1;
/// `q_qbytes` low enough that the message-count half of `msg_fits_inqueue`
/// trips before the byte half ever can.
const TINY_QBYTES: u64 = 3;

fn queue(ns: &Ns, cred: &IpcCred, mode: i32) -> i32 {
    msgget(ns.id(), IPC_PRIVATE, mode, cred).unwrap()
}

#[test]
fn success_appends_and_updates_the_accounting_fields() {
    let ns = Ns::new();
    let cred = owner_cred();
    let id = queue(&ns, &cred, MODE_RW_ALL);
    let mut buf = Buf::out(TYPE_ONE, b"hello");
    assert_eq!(msgsnd(ns.id(), id, buf.ptr(), 5, NO_FLAGS, &cred), Ok(0));
    let q = model::lookup_checked(ns.id(), id).unwrap();
    let st = q.state.lock();
    assert_eq!((st.qnum, st.cbytes), (1, 5));
    assert_eq!(st.lspid, block::current_tgid());
    assert_eq!(st.msgs[0].mtype, TYPE_ONE);
    assert_eq!(&st.msgs[0].data[..], b"hello");
}

#[test]
fn mtype_below_one_is_einval() {
    let ns = Ns::new();
    let cred = owner_cred();
    let id = queue(&ns, &cred, MODE_RW_ALL);
    for bad in [0i64, -1, i64::MIN] {
        let mut buf = Buf::out(bad, b"x");
        assert_eq!(msgsnd(ns.id(), id, buf.ptr(), 1, NO_FLAGS, &cred), Err(Errno::Einval));
    }
}

#[test]
fn msgsz_above_msgmax_is_einval() {
    let ns = Ns::new();
    let cred = owner_cred();
    let id = queue(&ns, &cred, MODE_RW_ALL);
    let mut buf = Buf::out(TYPE_ONE, &vec![0u8; MSGMAX + 1]);
    assert_eq!(
        msgsnd(ns.id(), id, buf.ptr(), MSGMAX as u64 + 1, NO_FLAGS, &cred),
        Err(Errno::Einval)
    );
    // The cap itself is legal.
    assert_eq!(msgsnd(ns.id(), id, buf.ptr(), MSGMAX as u64, NO_FLAGS, &cred), Ok(0));
}

#[test]
fn negative_msqid_and_stale_id_are_einval() {
    let ns = Ns::new();
    let cred = owner_cred();
    let id = queue(&ns, &cred, MODE_RW_ALL);
    let mut buf = Buf::out(TYPE_ONE, b"x");
    assert_eq!(msgsnd(ns.id(), -1, buf.ptr(), 1, NO_FLAGS, &cred), Err(Errno::Einval));
    assert_eq!(msgsnd(ns.id(), id + 1, buf.ptr(), 1, NO_FLAGS, &cred), Err(Errno::Einval));
}

#[test]
fn write_permission_is_required() {
    let ns = Ns::new();
    let cred = owner_cred();
    let id = queue(&ns, &cred, MODE_R_OWNER);
    let mut buf = Buf::out(TYPE_ONE, b"x");
    assert_eq!(msgsnd(ns.id(), id, buf.ptr(), 1, NO_FLAGS, &cred), Err(Errno::Eacces));
}

#[test]
fn queue_full_is_byte_based_not_message_count_based() {
    let ns = Ns::new();
    let cred = owner_cred();
    let id = queue(&ns, &cred, MODE_RW_ALL);
    let payload = vec![0u8; MSGMAX];
    let mut buf = Buf::out(TYPE_ONE, &payload);
    // MSGMNB / MSGMAX == 2 maximal messages fit; the third exceeds the budget
    // even though the queue holds only two messages.
    for _ in 0..(MSGMNB / MSGMAX) {
        assert_eq!(msgsnd(ns.id(), id, buf.ptr(), MSGMAX as u64, NO_FLAGS, &cred), Ok(0));
    }
    assert_eq!(
        msgsnd(ns.id(), id, buf.ptr(), MSGMAX as u64, IPC_NOWAIT, &cred),
        Err(Errno::Eagain)
    );
    let q = model::lookup_checked(ns.id(), id).unwrap();
    assert_eq!(q.state.lock().cbytes, MSGMNB as u64);
}

#[test]
fn qbytes_also_bounds_the_message_count() {
    let ns = Ns::new();
    let cred = owner_cred();
    let id = queue(&ns, &cred, MODE_RW_ALL);
    model::lookup_checked(ns.id(), id).unwrap().state.lock().qbytes = TINY_QBYTES;
    let mut buf = Buf::out(TYPE_ONE, b"");
    // Zero-length messages never consume the byte budget, so only the
    // `1 + q_qnum <= q_qbytes` half of msg_fits_inqueue can stop them.
    for _ in 0..TINY_QBYTES {
        assert_eq!(msgsnd(ns.id(), id, buf.ptr(), 0, NO_FLAGS, &cred), Ok(0));
    }
    assert_eq!(msgsnd(ns.id(), id, buf.ptr(), 0, IPC_NOWAIT, &cred), Err(Errno::Eagain));
    let q = model::lookup_checked(ns.id(), id).unwrap();
    assert_eq!(q.state.lock().cbytes, 0);
}

#[test]
fn a_blocking_send_on_a_full_queue_unwinds_instead_of_spinning() {
    let ns = Ns::new();
    let cred = owner_cred();
    let id = queue(&ns, &cred, MODE_RW_ALL);
    model::lookup_checked(ns.id(), id).unwrap().state.lock().qbytes = 0;
    let mut buf = Buf::out(TYPE_ONE, b"x");
    // Hosted builds have no scheduler: `park::yield_and_classify` reports a
    // pending signal, so the retry loop terminates the same way an interrupted
    // blocked sender does on the kernel target — with Linux's
    // `-ERESTARTNOHAND` (`ipc/msg.c:930`), NOT `-EINTR`. The sentinel is not an
    // errno, so it rides the `Ok` channel to the dispatch tail, which restarts
    // the call when no handler frame was built.
    assert_eq!(msgsnd(ns.id(), id, buf.ptr(), 1, NO_FLAGS, &cred),
               Ok(syscall::restart::restart_nohand()));
}
