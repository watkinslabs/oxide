use super::*;

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
