//! `msgrcv` — selection, `E2BIG`, `MSG_NOERROR`, `MSG_COPY`.

use syscall::errno::Errno;

use super::support::{owner_cred, Buf, Ns};
use crate::sysv::block;
use crate::sysv::limits::{IPC_NOWAIT, IPC_PRIVATE, MSG_COPY, MSG_EXCEPT, MSG_NOERROR};
use crate::sysv::msg::get::msgget;
use crate::sysv::msg::model;
use crate::sysv::msg::recv::msgrcv;
use crate::sysv::msg::send::msgsnd;
use crate::sysv::perm::IpcCred;

const MODE_RW_ALL: i32 = 0o666;
const MODE_W_OWNER: i32 = 0o200;
const NO_FLAGS: i32 = 0;
const ANY_TYPE: i64 = 0;

fn queue(ns: &Ns, cred: &IpcCred, mode: i32) -> i32 {
    msgget(ns.id(), IPC_PRIVATE, mode, cred).unwrap()
}

fn send(ns: &Ns, cred: &IpcCred, id: i32, mtype: i64, text: &[u8]) {
    let mut buf = Buf::out(mtype, text);
    assert_eq!(msgsnd(ns.id(), id, buf.ptr(), text.len() as u64, NO_FLAGS, cred), Ok(0));
}

/// Receive into a fresh buffer, returning `(result, mtype, payload)`.
fn recv(ns: &Ns, cred: &IpcCred, id: i32, cap: usize, msgtyp: i64, flg: i32)
    -> (Result<i64, Errno>, i64, alloc::vec::Vec<u8>)
{
    let mut buf = Buf::recv(cap);
    let r = msgrcv(ns.id(), id, buf.ptr(), cap as u64, msgtyp, flg, cred);
    let n = r.unwrap_or(0).max(0) as usize;
    (r, buf.mtype(), buf.text(n).to_vec())
}

#[test]
fn msgtyp_zero_takes_the_first_message() {
    let ns = Ns::new();
    let cred = owner_cred();
    let id = queue(&ns, &cred, MODE_RW_ALL);
    send(&ns, &cred, id, 5, b"first");
    send(&ns, &cred, id, 2, b"second");
    let (r, mtype, text) = recv(&ns, &cred, id, 16, ANY_TYPE, NO_FLAGS);
    assert_eq!((r, mtype, &text[..]), (Ok(5), 5, &b"first"[..]));
}

#[test]
fn positive_msgtyp_selects_an_exact_type() {
    let ns = Ns::new();
    let cred = owner_cred();
    let id = queue(&ns, &cred, MODE_RW_ALL);
    send(&ns, &cred, id, 5, b"five");
    send(&ns, &cred, id, 9, b"nine");
    let (r, mtype, text) = recv(&ns, &cred, id, 16, 9, NO_FLAGS);
    assert_eq!((r, mtype, &text[..]), (Ok(4), 9, &b"nine"[..]));
}

#[test]
fn msg_except_selects_the_first_non_matching_type() {
    let ns = Ns::new();
    let cred = owner_cred();
    let id = queue(&ns, &cred, MODE_RW_ALL);
    send(&ns, &cred, id, 5, b"five");
    send(&ns, &cred, id, 9, b"nine");
    let (r, mtype, text) = recv(&ns, &cred, id, 16, 5, MSG_EXCEPT);
    assert_eq!((r, mtype, &text[..]), (Ok(4), 9, &b"nine"[..]));
}

#[test]
fn negative_msgtyp_takes_the_lowest_type_with_a_fifo_tie_break() {
    let ns = Ns::new();
    let cred = owner_cred();
    let id = queue(&ns, &cred, MODE_RW_ALL);
    send(&ns, &cred, id, 8, b"eight");
    send(&ns, &cred, id, 2, b"two-a");
    send(&ns, &cred, id, 5, b"five");
    send(&ns, &cred, id, 2, b"two-b");
    let (r, mtype, text) = recv(&ns, &cred, id, 16, -8, NO_FLAGS);
    assert_eq!((r, mtype, &text[..]), (Ok(5), 2, &b"two-a"[..]));
}

#[test]
fn long_min_msgtyp_behaves_as_long_max() {
    let ns = Ns::new();
    let cred = owner_cred();
    let id = queue(&ns, &cred, MODE_RW_ALL);
    send(&ns, &cred, id, i64::MAX, b"huge");
    send(&ns, &cred, id, 3, b"low");
    let (r, mtype, text) = recv(&ns, &cred, id, 16, i64::MIN, NO_FLAGS);
    assert_eq!((r, mtype, &text[..]), (Ok(3), 3, &b"low"[..]));
}

#[test]
fn oversized_message_is_e2big_and_stays_queued() {
    let ns = Ns::new();
    let cred = owner_cred();
    let id = queue(&ns, &cred, MODE_RW_ALL);
    send(&ns, &cred, id, 1, b"0123456789");
    let (r, _, _) = recv(&ns, &cred, id, 4, ANY_TYPE, NO_FLAGS);
    assert_eq!(r, Err(Errno::E2big));
    let q = model::lookup_checked(ns.id(), id).unwrap();
    let st = q.state.lock();
    assert_eq!((st.qnum, st.cbytes), (1, 10), "E2BIG leaves the message on the queue");
}

#[test]
fn msg_noerror_truncates_and_removes() {
    let ns = Ns::new();
    let cred = owner_cred();
    let id = queue(&ns, &cred, MODE_RW_ALL);
    send(&ns, &cred, id, 1, b"0123456789");
    let (r, mtype, text) = recv(&ns, &cred, id, 4, ANY_TYPE, MSG_NOERROR);
    assert_eq!((r, mtype, &text[..]), (Ok(4), 1, &b"0123"[..]));
    let q = model::lookup_checked(ns.id(), id).unwrap();
    let st = q.state.lock();
    assert_eq!((st.qnum, st.cbytes), (0, 0), "the full m_ts leaves q_cbytes");
}

#[test]
fn removal_updates_the_receive_accounting() {
    let ns = Ns::new();
    let cred = owner_cred();
    let id = queue(&ns, &cred, MODE_RW_ALL);
    send(&ns, &cred, id, 1, b"abc");
    send(&ns, &cred, id, 1, b"de");
    assert_eq!(recv(&ns, &cred, id, 8, ANY_TYPE, NO_FLAGS).0, Ok(3));
    let q = model::lookup_checked(ns.id(), id).unwrap();
    let st = q.state.lock();
    assert_eq!((st.qnum, st.cbytes), (1, 2));
    assert_eq!(st.lrpid, block::current_tgid());
}

#[test]
fn msg_copy_indexes_the_queue_and_leaves_it_intact() {
    let ns = Ns::new();
    let cred = owner_cred();
    let id = queue(&ns, &cred, MODE_RW_ALL);
    send(&ns, &cred, id, 4, b"zero");
    send(&ns, &cred, id, 5, b"one");
    let flg = MSG_COPY | IPC_NOWAIT;
    let (r, mtype, text) = recv(&ns, &cred, id, 16, 1, flg);
    assert_eq!((r, mtype, &text[..]), (Ok(3), 5, &b"one"[..]));
    let q = model::lookup_checked(ns.id(), id).unwrap();
    assert_eq!(q.state.lock().qnum, 2, "MSG_COPY never dequeues");
    // An index past the end is simply "no match".
    assert_eq!(recv(&ns, &cred, id, 16, 2, flg).0, Err(Errno::Enomsg));
}

#[test]
fn msg_copy_requires_nowait_and_rejects_msg_except() {
    let ns = Ns::new();
    let cred = owner_cred();
    let id = queue(&ns, &cred, MODE_RW_ALL);
    send(&ns, &cred, id, 4, b"zero");
    assert_eq!(recv(&ns, &cred, id, 16, 0, MSG_COPY).0, Err(Errno::Einval));
    assert_eq!(
        recv(&ns, &cred, id, 16, 0, MSG_COPY | MSG_EXCEPT | IPC_NOWAIT).0,
        Err(Errno::Einval)
    );
}

#[test]
fn msg_copy_into_a_short_buffer_is_e2big_or_einval() {
    let ns = Ns::new();
    let cred = owner_cred();
    let id = queue(&ns, &cred, MODE_RW_ALL);
    send(&ns, &cred, id, 4, b"0123456789");
    let flg = MSG_COPY | IPC_NOWAIT;
    assert_eq!(recv(&ns, &cred, id, 4, 0, flg).0, Err(Errno::E2big));
    // With MSG_NOERROR the E2BIG gate is skipped and Linux's copy_msg rejects
    // the too-small destination instead.
    assert_eq!(recv(&ns, &cred, id, 4, 0, flg | MSG_NOERROR).0, Err(Errno::Einval));
}

#[test]
fn no_match_with_nowait_is_enomsg() {
    let ns = Ns::new();
    let cred = owner_cred();
    let id = queue(&ns, &cred, MODE_RW_ALL);
    assert_eq!(recv(&ns, &cred, id, 8, ANY_TYPE, IPC_NOWAIT).0, Err(Errno::Enomsg));
    send(&ns, &cred, id, 7, b"x");
    assert_eq!(recv(&ns, &cred, id, 8, 9, IPC_NOWAIT).0, Err(Errno::Enomsg));
}

#[test]
fn read_permission_is_required() {
    let ns = Ns::new();
    let cred = owner_cred();
    let id = queue(&ns, &cred, MODE_W_OWNER);
    assert_eq!(recv(&ns, &cred, id, 8, ANY_TYPE, IPC_NOWAIT).0, Err(Errno::Eacces));
}

#[test]
fn negative_msqid_or_bufsz_is_einval() {
    let ns = Ns::new();
    let cred = owner_cred();
    let id = queue(&ns, &cred, MODE_RW_ALL);
    let mut buf = Buf::recv(8);
    assert_eq!(msgrcv(ns.id(), -1, buf.ptr(), 8, ANY_TYPE, IPC_NOWAIT, &cred), Err(Errno::Einval));
    assert_eq!(
        msgrcv(ns.id(), id, buf.ptr(), u64::MAX, ANY_TYPE, IPC_NOWAIT, &cred),
        Err(Errno::Einval)
    );
}

#[test]
fn a_blocking_receive_on_an_empty_queue_unwinds_instead_of_spinning() {
    let ns = Ns::new();
    let cred = owner_cred();
    let id = queue(&ns, &cred, MODE_RW_ALL);
    assert_eq!(recv(&ns, &cred, id, 8, ANY_TYPE, NO_FLAGS).0, Err(Errno::Eintr));
}
