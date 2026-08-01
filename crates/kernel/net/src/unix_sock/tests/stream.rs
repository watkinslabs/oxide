use super::*;

#[test]
fn round_trip() {
    let _serial = test_guard();
    let p = UnixPair::new();
    p.write(UnixEnd::A, b"hello").unwrap();
    let got = p.read(UnixEnd::B, 64);
    assert_eq!(&got[..], b"hello");
    p.write(UnixEnd::B, b"world").unwrap();
    let got = p.read(UnixEnd::A, 64);
    assert_eq!(&got[..], b"world");
}

#[test]
fn close_writer_then_eof() {
    let _serial = test_guard();
    let p = UnixPair::new();
    p.write(UnixEnd::A, b"abc").unwrap();
    p.close_writer(UnixEnd::A);
    let got = p.read(UnixEnd::B, 64);
    assert_eq!(&got[..], b"abc");
    assert!(p.is_eof(UnixEnd::B));
    let e = p.write(UnixEnd::A, b"more").unwrap_err();
    assert_eq!(e, UnixStreamError::PeerClosed);
}

#[test]
fn empty_read_returns_empty() {
    let _serial = test_guard();
    let p = UnixPair::new();
    let got = p.read(UnixEnd::A, 16);
    assert!(got.is_empty());
}

#[test]
fn empty_open_stream_is_not_eof_but_closed_is() {
    let _serial = test_guard();
    // Exact contract InetSocket::read_nonblock relies on: an empty but still-
    // OPEN stream reads empty AND reports !is_eof → nonblocking read must return
    // EAGAIN, never a spurious EOF that would truncate a systemd varlink reply.
    // Once the peer closes with the stream drained, the same empty read is EOF.
    let p = UnixPair::new();
    assert!(p.read(UnixEnd::B, 64).is_empty());
    assert!(!p.is_eof(UnixEnd::B), "open+empty must not be EOF (→ EAGAIN)");
    p.close_writer(UnixEnd::A);
    assert!(p.read(UnixEnd::B, 64).is_empty());
    assert!(p.is_eof(UnixEnd::B), "closed+drained must be EOF (→ Ok(0))");
}

#[test]
fn msgpair_empty_open_recv_is_none_closed_is_some_empty() {
    let _serial = test_guard();
    // recv() contract the msg-pair arm of read_nonblock relies on: None when
    // nothing pending AND not EOF (→ EAGAIN); Some(empty) once peer closed (→ EOF).
    let p = UnixMsgPair::new();
    assert!(p.recv(UnixEnd::B, 64).is_none(), "open+empty recv → None (EAGAIN)");
    p.close_writer(UnixEnd::A);
    assert_eq!(p.recv(UnixEnd::B, 64), Some(alloc::vec::Vec::new()), "closed → Some(empty) (EOF)");
}

#[test]
fn msgpair_preserves_boundaries() {
    let _serial = test_guard();
    let p = UnixMsgPair::new();
    p.send(UnixEnd::A, b"one").unwrap();
    p.send(UnixEnd::A, b"two").unwrap();
    assert_eq!(p.recv(UnixEnd::B, 64).unwrap(), b"one");
    assert_eq!(p.recv(UnixEnd::B, 64).unwrap(), b"two");
    assert!(p.recv(UnixEnd::B, 64).is_none());
}

// Regression: SCM_CREDENTIALS on a socketpair shared by many senders must be
// per-MESSAGE, not last-sender-wins. systemd-udevd's worker_watch socketpair is
// written by every udev worker; when the manager drained a completion it read
// the wrong worker's pid (whoever sent most recently), idled the wrong worker,
// and wedged the udev event queue → card0 never tagged → no gdm greeter. Two
// messages from different senders, recv'd in FIFO order, must each carry their
// own sender creds. (Hosted `send` has no `current()`, so push the ring directly
// to simulate two distinct senders — `UnixMsgRing.msgs` is pub.)
#[test]
fn msgpair_creds_are_per_message_fifo() {
    let _serial = test_guard();
    use super::msg_pair::UnixMsg;
    let p = UnixMsgPair::new();
    // Two senders write end A (read by end B), sender 100 then sender 200.
    {
        let mut g = p.b_to_a.lock();
        g.msgs.push_back(UnixMsg { payload: b"first".to_vec(),  fds: alloc::vec::Vec::new(), rights: None, creds: crate::unix_sock::MsgCred::from_ids((100, 0, 0)) });
        g.msgs.push_back(UnixMsg { payload: b"second".to_vec(), fds: alloc::vec::Vec::new(), rights: None, creds: crate::unix_sock::MsgCred::from_ids((200, 0, 0)) });
    }
    let m1 = p.recv_msg(UnixEnd::A, 64).expect("first");
    assert_eq!(m1.payload, b"first");
    assert_eq!(m1.creds, (100, 0, 0), "first message must carry its OWN sender, not last-sender-wins");
    let m2 = p.recv_msg(UnixEnd::A, 64).expect("second");
    assert_eq!(m2.payload, b"second");
    assert_eq!(m2.creds, (200, 0, 0));
}

#[test]
fn msgpair_truncates_to_buf() {
    let _serial = test_guard();
    let p = UnixMsgPair::new();
    p.send(UnixEnd::A, b"abcdefgh").unwrap();
    let got = p.recv(UnixEnd::B, 3).unwrap();
    assert_eq!(&got[..], b"abc");
    assert!(p.recv(UnixEnd::B, 64).is_none());
}

#[test]
fn msgpair_peek_truncates_without_consuming() {
    let _serial = test_guard();
    let p = UnixMsgPair::new();
    p.send(UnixEnd::A, b"abcdefgh").unwrap();
    let (got, full_len) = p.recv_payload(UnixEnd::B, 3, true).unwrap();
    assert_eq!(&got[..], b"abc");
    assert_eq!(full_len, 8);
    assert_eq!(p.recv(UnixEnd::B, 64).unwrap(), b"abcdefgh");
}

#[test]
fn msgpair_eof_after_close() {
    let _serial = test_guard();
    let p = UnixMsgPair::new();
    p.send(UnixEnd::A, b"final").unwrap();
    p.close_writer(UnixEnd::A);
    assert_eq!(p.recv(UnixEnd::B, 64).unwrap(), b"final");
    assert_eq!(p.recv(UnixEnd::B, 64).unwrap(), b"");
    assert!(p.is_eof(UnixEnd::B));
    assert!(matches!(p.send(UnixEnd::A, b"more"), Err(UnixMsgError::PeerClosed)));
}

#[test]
fn msgpair_bidirectional() {
    let _serial = test_guard();
    let p = UnixMsgPair::new();
    p.send(UnixEnd::A, b"hello").unwrap();
    p.send(UnixEnd::B, b"world").unwrap();
    assert_eq!(p.recv(UnixEnd::B, 64).unwrap(), b"hello");
    assert_eq!(p.recv(UnixEnd::A, 64).unwrap(), b"world");
}

// SW1: getpeername/getsockname on a connected AF_UNIX pair must report the
// real sun_path. The client (end B) sees the listener's bound path it
// connected to; the accepted server socket (end A) inherits that path as its
// LOCAL name and sees the (unnamed) client as its peer. Regression:
// getpeername returned ENOTCONN for every AF_UNIX fd (broke sd-bus/dbus).
#[test]
fn connected_pair_reports_bind_path() {
    let _serial = test_guard();
    let p = UnixPair::new();
    p.set_bind_path(b"/run/systemd/private".to_vec());

    // Client (end B): peer = the listener path; local = unnamed.
    assert_eq!(p.peer_path(UnixEnd::B).as_deref(), Some(&b"/run/systemd/private"[..]));
    assert_eq!(p.local_path(UnixEnd::B), None);

    // Accepted server (end A): local = the listener path; peer = unnamed client.
    assert_eq!(p.local_path(UnixEnd::A).as_deref(), Some(&b"/run/systemd/private"[..]));
    assert_eq!(p.peer_path(UnixEnd::A), None);
}

#[test]
fn socketpair_has_no_bind_path() {
    let _serial = test_guard();
    // A socketpair / an unbound connect leaves both ends unnamed (bare AF_UNIX).
    let p = UnixPair::new();
    assert_eq!(p.peer_path(UnixEnd::A), None);
    assert_eq!(p.peer_path(UnixEnd::B), None);
    assert_eq!(p.local_path(UnixEnd::A), None);
    assert_eq!(p.local_path(UnixEnd::B), None);
}

// --- SCM_RIGHTS fd/byte-boundary binding on SOCK_STREAM (S8) ---
// Regression: AF_UNIX SOCK_STREAM held SCM_RIGHTS fds in a FIFO fully
// decoupled from byte position, so a recvmsg popped the front burst
// regardless of which bytes it read. Through the dbus-broker relay this
// desynced fds from their owning D-Bus message: logind's CreateSession /
// Inhibit reply fifo fd got attached to an earlier fd-less message and
// dropped (upowerd saw `g_unix_fd_list_get_length: G_IS_UNIX_FD_LIST`).
// Fix ties each burst to the stream offset of its carrying write; a read
// never crosses an fd boundary (Linux `unix_stream_read_generic`).
//
// The PRIOR attempt (B541, reverted) deadlocked the boot: its `read()`
// (the blocking-read/park path) could return EMPTY while data/fds were
// buffered (a re-queue branch + capping), so a parked reader never woke.
// This fix keeps `read()` byte-identical to the original (drains all
// bytes, drops fds, never re-queues, never returns empty when bytes
// exist) and routes boundary logic through `read_stream`, used ONLY by
// recvmsg's busy-yield loop which never parks.

#[test]
fn stream_fds_bind_to_their_write_not_an_earlier_one() {
    let _serial = test_guard();
    let p = UnixPair::new();
    let fd = anon_file();
    // msg1 (no fds) then msg2 (one fd), coalesced in the ring.
    p.write(UnixEnd::A, b"AAAA").unwrap();
    p.write_with_fds(UnixEnd::A, b"BBBB", alloc::vec![alloc::sync::Arc::clone(&fd)]).unwrap();

    // First recvmsg reads msg1's bytes: must NOT carry the fd, and must
    // stop at the fd boundary (only "AAAA", even though 64 was asked).
    let (b1, f1, _) = p.read_stream(UnixEnd::B, 64);
    assert_eq!(&b1[..], b"AAAA", "read capped at the fd boundary");
    assert!(f1.is_empty(), "fd must not ride the earlier fd-less message");

    // Second recvmsg reaches the boundary: delivers msg2's bytes + the fd.
    let (b2, f2, _) = p.read_stream(UnixEnd::B, 64);
    assert_eq!(&b2[..], b"BBBB");
    assert_eq!(f2.len(), 1, "fd delivered with its own message");
    assert!(alloc::sync::Arc::ptr_eq(&f2[0], &fd));

    // No fds left over.
    let (_b3, f3, _) = p.read_stream(UnixEnd::B, 64);
    assert!(f3.is_empty());
}

#[test]
fn stream_fd_on_first_byte_delivers_immediately() {
    let _serial = test_guard();
    let p = UnixPair::new();
    let fd = anon_file();
    p.write_with_fds(UnixEnd::A, b"HELLO", alloc::vec![alloc::sync::Arc::clone(&fd)]).unwrap();
    let (b, f, _) = p.read_stream(UnixEnd::B, 64);
    assert_eq!(&b[..], b"HELLO");
    assert_eq!(f.len(), 1);
    assert!(alloc::sync::Arc::ptr_eq(&f[0], &fd));
}

#[test]
fn stream_partial_read_delivers_fd_once_with_first_chunk() {
    let _serial = test_guard();
    let p = UnixPair::new();
    let fd = anon_file();
    p.write_with_fds(UnixEnd::A, b"XYZW", alloc::vec![alloc::sync::Arc::clone(&fd)]).unwrap();
    let (b1, f1, _) = p.read_stream(UnixEnd::B, 2); // partial
    assert_eq!(&b1[..], b"XY");
    assert_eq!(f1.len(), 1, "fd rides the first byte of its write");
    let (b2, f2, _) = p.read_stream(UnixEnd::B, 2);
    assert_eq!(&b2[..], b"ZW");
    assert!(f2.is_empty(), "fd not re-delivered on the rest of the same write");
}

#[test]
fn stream_fd_only_message_transfers_nothing() {
    let _serial = test_guard();
    let p = UnixPair::new();
    let fd = anon_file();
    assert_eq!(p.write_with_fds(UnixEnd::A, b"", alloc::vec![alloc::sync::Arc::clone(&fd)]).unwrap(), 0);
    let (b, f, _) = p.read_stream(UnixEnd::B, 64);
    assert!(b.is_empty());
    assert!(f.is_empty(), "Linux stream SCM requires at least one payload byte");
}

#[test]
fn stream_read_with_fds_never_returns_empty_when_bytes_present() {
    let _serial = test_guard();
    // DEADLOCK REGRESSION GUARD (the B541 boot hang): the blocking-read /
    // park path calls `read()`. If `read()` ever returns EMPTY while the
    // ring has buffered bytes (as B541's read() could, by re-queuing fds
    // or capping to 0), the parked reader sleeps forever after the
    // writer's wake already fired = lost wakeup / CPU stall. `read()` must
    // ALWAYS drain the available bytes and never re-queue.
    let p = UnixPair::new();
    let fd = anon_file();
    // fd rides the FIRST byte — the exact case B541 stalled on.
    p.write_with_fds(UnixEnd::A, b"PAYLOAD", alloc::vec![alloc::sync::Arc::clone(&fd)]).unwrap();
    let got = p.read(UnixEnd::B, 64);
    assert_eq!(&got[..], b"PAYLOAD", "read() must return bytes, never park with data buffered");
    // fd was dropped (no cmsg buffer on a plain read) and NOT left dangling
    // for a stale later delivery.
    let (b2, f2, _) = p.read_stream(UnixEnd::B, 64);
    assert!(b2.is_empty());
    assert!(f2.is_empty(), "read() dropped the fd; nothing stale re-delivered");
}

#[test]
fn stream_read_drops_only_passed_fds_keeps_future_ones() {
    let _serial = test_guard();
    // read() drops msg1's fd (no cmsg buffer took it) but must not run past
    // msg1's last byte: a descriptor-bearing segment ends the receive, so
    // msg2 and its fd stay queued for a later recvmsg, never desynced.
    let p = UnixPair::new();
    let fd1 = anon_file();
    let fd2 = anon_file();
    p.write_with_fds(UnixEnd::A, b"AAAA", alloc::vec![alloc::sync::Arc::clone(&fd1)]).unwrap();
    p.write_with_fds(UnixEnd::A, b"BBBB", alloc::vec![alloc::sync::Arc::clone(&fd2)]).unwrap();
    let got = p.read(UnixEnd::B, 8);
    assert_eq!(&got[..], b"AAAA", "a descriptor-bearing segment ends the receive");
    assert_eq!(alloc::sync::Arc::strong_count(&fd1), 1, "fd1 released, not requeued");
    let (b2, f2, _) = p.read_stream(UnixEnd::B, 64);
    assert_eq!(&b2[..], b"BBBB");
    assert_eq!(f2.len(), 1, "fd2 stayed bound to its own bytes");
    assert!(alloc::sync::Arc::ptr_eq(&f2[0], &fd2));
}

#[test]
fn dgram_message_preserves_sender_creds() {
    let _serial = test_guard();
    let q = UnixDgramQueue::new();
    q.try_push(UnixDgram {
        payload: b"READY=1".to_vec(),
        creds: crate::unix_sock::MsgCred::from_ids((40, 0, 0)),
        fds: alloc::vec::Vec::new(),
    }).unwrap();
    let got = q.pop().expect("one queued message");
    assert_eq!(&got.payload[..], b"READY=1");
    assert_eq!(got.creds, (40, 0, 0));
    assert!(q.pop().is_none());
}

