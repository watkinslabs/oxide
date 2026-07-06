use super::*;
use alloc::string::String;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Weak};

struct WakeCounter {
    hits: AtomicU32,
}

impl WakeCounter {
    fn new() -> Arc<Self> {
        Arc::new(Self { hits: AtomicU32::new(0) })
    }
}

impl vfs::EpollNotify for WakeCounter {
    fn notify(&self) {
        self.hits.fetch_add(1, Ordering::Relaxed);
    }
}

fn hits(c: &Arc<WakeCounter>) -> u32 {
    c.hits.load(Ordering::Relaxed)
}

fn wake_ref(c: &Arc<WakeCounter>) -> Weak<dyn vfs::EpollNotify> {
    Arc::downgrade(&(c.clone() as Arc<dyn vfs::EpollNotify>))
}

#[test]
fn abstract_and_literal_at_paths_are_distinct() {
    let registry = UnixRegistry::new();

    registry.bind(String::from("\0svc")).unwrap();
    registry.bind(String::from("@svc")).unwrap();

    assert!(registry.lookup_listener("\0svc").is_some());
    assert!(registry.lookup_listener("@svc").is_some());
    assert_eq!(registry.snapshot_paths().len(), 2);
}

#[test]
fn abstract_path_display_uses_procfs_at_prefix() {
    assert!(unix_path_is_abstract("\0svc"));
    assert!(!unix_path_is_abstract("@svc"));
    assert_eq!(unix_path_display("\0svc"), "@svc");
    assert_eq!(unix_path_display("@svc"), "@svc");
}

#[test]
fn udev_control_path_connect_wakes_accept_and_round_trips() {
    let registry = UnixRegistry::new();
    let listener = registry.bind(String::from("/run/udev/control")).unwrap();
    let subs = Arc::new(vfs::PollSubscribers::new());
    let waiter = WakeCounter::new();
    subs.subscribe(1, wake_ref(&waiter));
    listener.register_subs(&subs);

    let client = registry.connect("/run/udev/control").expect("connect to udev control");
    assert_eq!(hits(&waiter), 1, "connect must wake the accepting server");
    assert_eq!(listener.accept_q.lock().len(), 1);

    let server = listener.accept_q.lock().pop_front().expect("accepted pair");
    assert!(Arc::ptr_eq(&server, &client));
    assert_eq!(server.local_path(UnixEnd::A).as_deref(), Some("/run/udev/control"));
    assert_eq!(client.peer_path(UnixEnd::B).as_deref(), Some("/run/udev/control"));

    assert_eq!(client.write(UnixEnd::B, b"reload"), 6);
    assert_eq!(server.read(UnixEnd::A, 64), b"reload".to_vec());
    assert_eq!(server.write(UnixEnd::A, b"ok"), 2);
    assert_eq!(client.read(UnixEnd::B, 64), b"ok".to_vec());
}

#[test]
fn round_trip() {
    let p = UnixPair::new();
    p.write(UnixEnd::A, b"hello");
    let got = p.read(UnixEnd::B, 64);
    assert_eq!(&got[..], b"hello");
    p.write(UnixEnd::B, b"world");
    let got = p.read(UnixEnd::A, 64);
    assert_eq!(&got[..], b"world");
}

#[test]
fn close_writer_then_eof() {
    let p = UnixPair::new();
    p.write(UnixEnd::A, b"abc");
    p.close_writer(UnixEnd::A);
    let got = p.read(UnixEnd::B, 64);
    assert_eq!(&got[..], b"abc");
    assert!(p.is_eof(UnixEnd::B));
    let n = p.write(UnixEnd::A, b"more");
    assert_eq!(n, 0);
}

#[test]
fn empty_read_returns_empty() {
    let p = UnixPair::new();
    let got = p.read(UnixEnd::A, 16);
    assert!(got.is_empty());
}

#[test]
fn msgpair_preserves_boundaries() {
    let p = UnixMsgPair::new();
    p.send(UnixEnd::A, b"one");
    p.send(UnixEnd::A, b"two");
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
    use super::msg_pair::UnixMsg;
    let p = UnixMsgPair::new();
    // Two senders write end A (read by end B), sender 100 then sender 200.
    {
        let mut g = p.b_to_a.lock();
        g.msgs.push_back(UnixMsg { payload: b"first".to_vec(),  fds: alloc::vec::Vec::new(), creds: (100, 0, 0) });
        g.msgs.push_back(UnixMsg { payload: b"second".to_vec(), fds: alloc::vec::Vec::new(), creds: (200, 0, 0) });
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
    let p = UnixMsgPair::new();
    p.send(UnixEnd::A, b"abcdefgh");
    let got = p.recv(UnixEnd::B, 3).unwrap();
    assert_eq!(&got[..], b"abc");
    assert!(p.recv(UnixEnd::B, 64).is_none());
}

#[test]
fn msgpair_peek_truncates_without_consuming() {
    let p = UnixMsgPair::new();
    p.send(UnixEnd::A, b"abcdefgh");
    let (got, full_len) = p.recv_payload(UnixEnd::B, 3, true).unwrap();
    assert_eq!(&got[..], b"abc");
    assert_eq!(full_len, 8);
    assert_eq!(p.recv(UnixEnd::B, 64).unwrap(), b"abcdefgh");
}

#[test]
fn msgpair_eof_after_close() {
    let p = UnixMsgPair::new();
    p.send(UnixEnd::A, b"final");
    p.close_writer(UnixEnd::A);
    assert_eq!(p.recv(UnixEnd::B, 64).unwrap(), b"final");
    assert_eq!(p.recv(UnixEnd::B, 64).unwrap(), b"");
    assert!(p.is_eof(UnixEnd::B));
    assert_eq!(p.send(UnixEnd::A, b"more"), 0);
}

#[test]
fn msgpair_bidirectional() {
    let p = UnixMsgPair::new();
    p.send(UnixEnd::A, b"hello");
    p.send(UnixEnd::B, b"world");
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
    use alloc::string::String;
    let p = UnixPair::new();
    p.set_bind_path(String::from("/run/systemd/private"));

    // Client (end B): peer = the listener path; local = unnamed.
    assert_eq!(p.peer_path(UnixEnd::B).as_deref(), Some("/run/systemd/private"));
    assert_eq!(p.local_path(UnixEnd::B), None);

    // Accepted server (end A): local = the listener path; peer = unnamed client.
    assert_eq!(p.local_path(UnixEnd::A).as_deref(), Some("/run/systemd/private"));
    assert_eq!(p.peer_path(UnixEnd::A), None);
}

#[test]
fn socketpair_has_no_bind_path() {
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

struct NullOps;
impl vfs::FileOps for NullOps {
    fn read(&self, _i: &vfs::inode::Inode, _o: u64, b: &mut [u8]) -> vfs::KResult<usize> { Ok(b.len()) }
    fn write(&self, _i: &vfs::inode::Inode, _o: u64, b: &[u8]) -> vfs::KResult<usize> { Ok(b.len()) }
}

fn anon_file() -> alloc::sync::Arc<vfs::File> {
    let ino: vfs::InodeRef = vfs::InodeBuilder::new(
        0xF00D,
        vfs::mk_mode(vfs::FileType::Socket, 0o600),
        vfs::default_inode_ops(),
        alloc::sync::Arc::new(NullOps),
    ).build();
    let d = vfs::Dentry::new(None, "s".into(), alloc::sync::Arc::clone(&ino));
    vfs::File::new_at(ino, d, vfs::OpenFlags::O_RDWR, 0, vfs::Cred::root())
}

#[test]
fn stream_fds_bind_to_their_write_not_an_earlier_one() {
    let p = UnixPair::new();
    let fd = anon_file();
    // msg1 (no fds) then msg2 (one fd), coalesced in the ring.
    p.write(UnixEnd::A, b"AAAA");
    p.write_with_fds(UnixEnd::A, b"BBBB", alloc::vec![alloc::sync::Arc::clone(&fd)]);

    // First recvmsg reads msg1's bytes: must NOT carry the fd, and must
    // stop at the fd boundary (only "AAAA", even though 64 was asked).
    let (b1, f1) = p.read_stream(UnixEnd::B, 64);
    assert_eq!(&b1[..], b"AAAA", "read capped at the fd boundary");
    assert!(f1.is_empty(), "fd must not ride the earlier fd-less message");

    // Second recvmsg reaches the boundary: delivers msg2's bytes + the fd.
    let (b2, f2) = p.read_stream(UnixEnd::B, 64);
    assert_eq!(&b2[..], b"BBBB");
    assert_eq!(f2.len(), 1, "fd delivered with its own message");
    assert!(alloc::sync::Arc::ptr_eq(&f2[0], &fd));

    // No fds left over.
    let (_b3, f3) = p.read_stream(UnixEnd::B, 64);
    assert!(f3.is_empty());
}

#[test]
fn stream_fd_on_first_byte_delivers_immediately() {
    let p = UnixPair::new();
    let fd = anon_file();
    p.write_with_fds(UnixEnd::A, b"HELLO", alloc::vec![alloc::sync::Arc::clone(&fd)]);
    let (b, f) = p.read_stream(UnixEnd::B, 64);
    assert_eq!(&b[..], b"HELLO");
    assert_eq!(f.len(), 1);
    assert!(alloc::sync::Arc::ptr_eq(&f[0], &fd));
}

#[test]
fn stream_partial_read_delivers_fd_once_with_first_chunk() {
    let p = UnixPair::new();
    let fd = anon_file();
    p.write_with_fds(UnixEnd::A, b"XYZW", alloc::vec![alloc::sync::Arc::clone(&fd)]);
    let (b1, f1) = p.read_stream(UnixEnd::B, 2); // partial
    assert_eq!(&b1[..], b"XY");
    assert_eq!(f1.len(), 1, "fd rides the first byte of its write");
    let (b2, f2) = p.read_stream(UnixEnd::B, 2);
    assert_eq!(&b2[..], b"ZW");
    assert!(f2.is_empty(), "fd not re-delivered on the rest of the same write");
}

#[test]
fn stream_fd_only_message_delivers_without_looping() {
    // An empty-payload message that carries only fds must hand the fds to
    // read_stream immediately (empty bytes, non-empty fds) so recvmsg's
    // yield loop delivers them and does NOT spin/park waiting for bytes.
    let p = UnixPair::new();
    let fd = anon_file();
    p.write_with_fds(UnixEnd::A, b"", alloc::vec![alloc::sync::Arc::clone(&fd)]);
    let (b, f) = p.read_stream(UnixEnd::B, 64);
    assert!(b.is_empty());
    assert_eq!(f.len(), 1, "fd-only message delivered, not re-queued");
    assert!(alloc::sync::Arc::ptr_eq(&f[0], &fd));
}

#[test]
fn stream_read_with_fds_never_returns_empty_when_bytes_present() {
    // DEADLOCK REGRESSION GUARD (the B541 boot hang): the blocking-read /
    // park path calls `read()`. If `read()` ever returns EMPTY while the
    // ring has buffered bytes (as B541's read() could, by re-queuing fds
    // or capping to 0), the parked reader sleeps forever after the
    // writer's wake already fired = lost wakeup / CPU stall. `read()` must
    // ALWAYS drain the available bytes and never re-queue.
    let p = UnixPair::new();
    let fd = anon_file();
    // fd rides the FIRST byte — the exact case B541 stalled on.
    p.write_with_fds(UnixEnd::A, b"PAYLOAD", alloc::vec![alloc::sync::Arc::clone(&fd)]);
    let got = p.read(UnixEnd::B, 64);
    assert_eq!(&got[..], b"PAYLOAD", "read() must return bytes, never park with data buffered");
    // fd was dropped (no cmsg buffer on a plain read) and NOT left dangling
    // for a stale later delivery.
    let (b2, f2) = p.read_stream(UnixEnd::B, 64);
    assert!(b2.is_empty());
    assert!(f2.is_empty(), "read() dropped the fd; nothing stale re-delivered");
}

#[test]
fn stream_read_drops_only_passed_fds_keeps_future_ones() {
    // read() past msg1 must drop msg1's fd but keep msg2's fd for a later
    // recvmsg (the fd stays bound to its own bytes, never desynced).
    let p = UnixPair::new();
    let fd1 = anon_file();
    let fd2 = anon_file();
    p.write_with_fds(UnixEnd::A, b"AAAA", alloc::vec![alloc::sync::Arc::clone(&fd1)]);
    p.write_with_fds(UnixEnd::A, b"BBBB", alloc::vec![alloc::sync::Arc::clone(&fd2)]);
    // Plain read drains everything up to max, dropping fd1 (rode "AAAA")
    // AND fd2 (rode "BBBB") since both are now behind the cursor.
    let got = p.read(UnixEnd::B, 8);
    assert_eq!(&got[..], b"AAAABBBB");
    let (b2, f2) = p.read_stream(UnixEnd::B, 64);
    assert!(b2.is_empty() && f2.is_empty(), "all fds consumed/dropped, nothing desynced");
}

#[test]
fn dgram_message_preserves_sender_creds() {
    let q = UnixDgramQueue::new();
    q.push(UnixDgram {
        payload: b"READY=1".to_vec(),
        creds: (40, 0, 0),
        #[cfg(not(target_os = "oxide-kernel"))]
        fds: alloc::vec::Vec::new(),
    });
    let got = q.pop().expect("one queued message");
    assert_eq!(&got.payload[..], b"READY=1");
    assert_eq!(got.creds, (40, 0, 0));
    assert!(q.pop().is_none());
}
