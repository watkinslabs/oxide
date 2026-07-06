use super::*;
use alloc::string::String;

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

// --- SCM_RIGHTS fd/byte-boundary binding on SOCK_STREAM (X3) ---
// Regression: AF_UNIX SOCK_STREAM held SCM_RIGHTS fds in a FIFO fully
// decoupled from byte position, so a recvmsg popped the front burst
// regardless of which bytes it read. Through the dbus-broker relay this
// desynced fds from their owning D-Bus message: logind's CreateSession /
// Inhibit reply fifo fd got attached to an earlier fd-less message and
// dropped, so pam_systemd never obtained runtime_path → user@979's
// `systemd --user` aborted "$XDG_RUNTIME_DIR is not set". Fix ties each
// burst to the stream offset of its carrying write; a read never crosses
// an fd boundary (Linux `unix_stream_read_generic` skb-`fp` semantics).

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
