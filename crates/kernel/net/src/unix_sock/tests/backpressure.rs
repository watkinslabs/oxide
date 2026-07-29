use super::*;

#[test]
fn stream_capacity_is_partial_and_reusable_after_dequeue() {
    let _serial = test_guard();
    let pair = UnixPair::new();

    assert_eq!(pair.write_bounded(UnixEnd::A, b"abcdef", 4), Ok(4));
    assert_eq!(pair.write_bounded(UnixEnd::A, b"ef", 4),
        Err(UnixStreamSendError::WouldBlock));
    assert_eq!(pair.read(UnixEnd::B, 2), b"ab");
    assert_eq!(pair.write_bounded(UnixEnd::A, b"ef", 4), Ok(2));
    assert_eq!(pair.read(UnixEnd::B, 8), b"cdef");
}

fn atomic_pair_capacity(kind: UnixMsgKind) {
    let pair = match kind {
        UnixMsgKind::Datagram => UnixMsgPair::new_datagram(),
        UnixMsgKind::SeqPacket => UnixMsgPair::new(),
    };

    assert_eq!(pair.send_bounded(UnixEnd::A, b"abc", 5), Ok(3));
    assert_eq!(pair.send_bounded(UnixEnd::A, b"def", 5),
        Err(UnixMsgSendError::WouldBlock));
    assert_eq!(pair.recv(UnixEnd::B, 8).unwrap(), b"abc");
    assert_eq!(pair.send_bounded(UnixEnd::A, b"def", 5), Ok(3));
    assert_eq!(pair.recv(UnixEnd::B, 8).unwrap(), b"def");
    assert_eq!(pair.send_bounded(UnixEnd::A, b"123456", 5),
        Err(UnixMsgSendError::MessageTooLarge));
    assert!(pair.recv(UnixEnd::B, 8).is_none());
}

#[test]
fn seqpacket_capacity_is_atomic() {
    let _serial = test_guard();
    atomic_pair_capacity(UnixMsgKind::SeqPacket);
}

#[test]
fn socketpair_datagram_capacity_is_atomic() {
    let _serial = test_guard();
    atomic_pair_capacity(UnixMsgKind::Datagram);
}

fn datagram(payload: &[u8]) -> UnixDgram {
    UnixDgram { payload: payload.to_vec(), creds: (1, 2, 3), fds: alloc::vec::Vec::new() }
}

#[test]
fn pathname_datagram_capacity_is_atomic_and_accounted() {
    let _serial = test_guard();
    let queue = UnixDgramQueue::new();

    assert_eq!(queue.try_push_from_with_rights_bounded(datagram(b"abc"), None,
        GcRights::from_files(alloc::vec::Vec::new()), 5), Ok(()));
    assert_eq!(queue.queued_bytes(), 3);
    assert_eq!(queue.try_push_from_with_rights_bounded(datagram(b"def"), None,
        GcRights::from_files(alloc::vec::Vec::new()), 5), Err(crate::NetError::Eagain));
    assert_eq!(queue.queued_bytes(), 3);
    assert_eq!(queue.pop().unwrap().payload, b"abc");
    assert_eq!(queue.queued_bytes(), 0);
    assert_eq!(queue.try_push_from_with_rights_bounded(datagram(b"def"), None,
        GcRights::from_files(alloc::vec::Vec::new()), 5), Ok(()));
    assert_eq!(queue.pop().unwrap().payload, b"def");
    assert_eq!(queue.try_push_from_with_rights_bounded(datagram(b"123456"), None,
        GcRights::from_files(alloc::vec::Vec::new()), 5), Err(crate::NetError::Emsgsize));
}

#[test]
fn datagram_shutdown_transition_has_one_generation() {
    let _serial = test_guard();
    let pair = UnixMsgPair::new_datagram();
    let pair_generation = pair.shutdown_generation(UnixEnd::B);
    pair.shutdown_reader(UnixEnd::B);
    assert_eq!(pair.shutdown_generation(UnixEnd::B), pair_generation.wrapping_add(1));
    pair.shutdown_reader(UnixEnd::B);
    assert_eq!(pair.shutdown_generation(UnixEnd::B), pair_generation.wrapping_add(1));

    let queue = UnixDgramQueue::new();
    let queue_generation = queue.shutdown_generation();
    queue.shutdown_reader();
    assert_eq!(queue.shutdown_generation(), queue_generation.wrapping_add(1));
    queue.shutdown_reader();
    assert_eq!(queue.shutdown_generation(), queue_generation.wrapping_add(1));
}

// --- symmetric-pair flow control (net/unix/af_unix.c) ------------------------
// `unix_dgram_sendmsg` refuses with EAGAIN only when
//   `other != sk && unix_peer(other) != sk && unix_recvq_full_lockless(other)`,
// and `unix_dgram_poll` clears writability under the IDENTICAL guard. The guard
// existed on the poll side alone, so a socketpair — symmetric by construction —
// polled writable forever while every send returned EAGAIN. A writer that
// trusts poll then spins: gnome-shell's KMS thread burned a core on 236k
// sendmsg calls per 3.7s that way.

use crate::unix_sock::dgram_symmetric_pair;
use crate::UnixAddr;

fn addr(name: &str) -> UnixAddr { UnixAddr::from_abstract_or_test_path(alloc::string::String::from(name)) }

#[test]
fn a_mutually_connected_pair_is_symmetric() {
    let a = addr("/run/a");
    let b = addr("/run/b");
    // peer's peer == us -> symmetric.
    assert!(dgram_symmetric_pair(Some(&a), Some(&a)));
    // peer points elsewhere -> not symmetric, recvq flow control applies.
    assert!(!dgram_symmetric_pair(Some(&b), Some(&a)));
    // an unconnected peer, or an unbound sender, is never symmetric.
    assert!(!dgram_symmetric_pair(None, Some(&a)));
    assert!(!dgram_symmetric_pair(Some(&a), None));
}

/// THE invariant: for one pair, the cap the send applies and the cap poll
/// consults must be the same number. Symmetric -> unbounded on both sides;
/// asymmetric -> the receive queue bounds both.
#[test]
fn poll_and_send_agree_on_the_same_cap() {
    let _serial = test_guard();
    const CAP: usize = 5;
    for symmetric in [false, true] {
        let q = UnixDgramQueue::new();
        // Fill past CAP the way the send path would.
        let send_cap = if symmetric { usize::MAX } else { CAP };
        assert_eq!(q.try_push_from_with_rights_bounded(datagram(b"abcdef"), None,
            GcRights::from_files(alloc::vec::Vec::new()), send_cap),
            if symmetric { Ok(()) } else { Err(crate::NetError::Emsgsize) },
            "symmetric={symmetric}: send bound");
        if !symmetric { continue; }
        // Symmetric: the queue is over CAP, and the send still succeeds — so
        // poll must NOT be reporting a bound the send does not enforce.
        assert!(q.queued_bytes() > CAP, "symmetric queue exceeded the recvq cap");
        assert!(crate::unix_sock::dgram_peer_writable(q.queued_bytes(), usize::MAX),
            "symmetric pair stays writable, matching the send that just succeeded");
        // ...and the asymmetric bound is what would have refused it.
        assert!(!crate::unix_sock::dgram_peer_writable(q.queued_bytes(), CAP),
            "the recvq bound is real — it just does not apply to a symmetric pair");
    }
}

// --- sk_wmem_alloc accounting (Linux sock_alloc_send_pskb / sock_wfree) ------
// A symmetric pair skips the destination's receive-queue bound, so the SENDER's
// own write memory is the only thing bounding it. Charged on send, released by
// the queued record's destructor against the SENDER.

#[test]
fn a_send_charges_the_sender_and_the_receive_releases_it() {
    let _serial = test_guard();
    let sender = UnixDgramQueue::new();
    let dest = UnixDgramQueue::new();
    const SNDBUF: usize = 4096;

    assert_eq!(sender.wmem_alloc(), 0, "a fresh socket owes nothing");
    dest.try_push_owned(datagram(b"abcd"), None, GcRights::from_files(alloc::vec::Vec::new()),
        usize::MAX, &sender, SNDBUF).expect("send");
    // Charged to the SENDER, not the destination — that is the whole point.
    assert_eq!(sender.wmem_alloc(), 4, "sender charged skb->truesize");
    assert_eq!(dest.wmem_alloc(), 0, "the destination owes nothing for a receive");

    // `sock_wfree` runs from the record's destructor on receive.
    assert_eq!(dest.pop().unwrap().payload, b"abcd");
    assert_eq!(sender.wmem_alloc(), 0, "receive released the sender's charge");
}

/// The charge must survive every removal path, not just the happy one — the
/// destructor is what guarantees it, so dropping the whole queue settles it too.
#[test]
fn dropping_an_undelivered_queue_still_releases_the_sender() {
    let _serial = test_guard();
    let sender = UnixDgramQueue::new();
    {
        let dest = UnixDgramQueue::new();
        dest.try_push_owned(datagram(b"xyz"), None, GcRights::from_files(alloc::vec::Vec::new()),
            usize::MAX, &sender, 4096).expect("send");
        assert_eq!(sender.wmem_alloc(), 3);
    }
    assert_eq!(sender.wmem_alloc(), 0, "queue teardown released the charge");
}

/// `unix_writable`'s quarter-of-sndbuf watermark bounds a sender even when the
/// destination is unbounded (`cap = usize::MAX`, the symmetric-pair case).
/// Without this a socketpair would queue without limit.
#[test]
fn wmem_bounds_a_sender_whose_destination_is_unbounded() {
    let _serial = test_guard();
    let sender = UnixDgramQueue::new();
    let dest = UnixDgramQueue::new();
    const SNDBUF: usize = 64;                 // watermark = 64/4 = 16 bytes
    let mut sent = 0usize;
    for _ in 0..100 {
        match dest.try_push_owned(datagram(b"0123456789"), None,
            GcRights::from_files(alloc::vec::Vec::new()), usize::MAX, &sender, SNDBUF) {
            Ok(()) => sent += 1,
            Err(crate::NetError::Eagain) => break,
            Err(e) => panic!("unexpected {e:?}"),
        }
    }
    assert!(sent > 0, "the first send fits under the watermark");
    assert!(sent < 100, "wmem stopped an otherwise unbounded symmetric send");
    // Linux's watermark is tested against the CURRENT wmem in `unix_writable`
    // (poll), while the send additionally requires the NEW charge to fit
    // (`sock_alloc_send_pskb`). So the refusal means one more datagram would
    // cross the line, not that the socket is already past it.
    let charged = sender.wmem_alloc();
    assert!(!crate::unix_sock::unix_writable(charged + 10, SNDBUF),
        "one more datagram would cross the watermark — that is why send refused");
    // A receive releases the charge, re-opening the window (`sk_write_space`).
    let _ = dest.pop();
    assert!(sender.wmem_alloc() < charged, "receive gave the sender its memory back");
    dest.try_push_owned(datagram(b"0123456789"), None,
        GcRights::from_files(alloc::vec::Vec::new()), usize::MAX, &sender, SNDBUF)
        .expect("the freed charge re-opened the send");
}
