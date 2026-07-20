use super::*;
use alloc::sync::Arc;

#[test]
fn stream_shutdown_read_drains_queue_then_rejects_peer_writes() {
    let _serial = test_guard();
    let pair = UnixPair::new();
    pair.write(UnixEnd::A, b"queued").unwrap();
    pair.shutdown_reader(UnixEnd::B);

    assert_eq!(pair.read(UnixEnd::B, 64), b"queued");
    assert!(pair.is_eof(UnixEnd::B));
    assert!(matches!(pair.write(UnixEnd::A, b"late"), Err(UnixStreamError::PeerClosed)));
    assert_eq!(pair.poll_mask(UnixEnd::B) & (vfs::POLL_IN | vfs::POLL_RDHUP),
        vfs::POLL_IN | vfs::POLL_RDHUP);
}

#[test]
fn stream_shutdown_write_publishes_rdhup_before_drain() {
    let _serial = test_guard();
    let pair = UnixPair::new();
    pair.write(UnixEnd::A, b"queued").unwrap();
    pair.close_writer(UnixEnd::A);

    let mask = pair.poll_mask(UnixEnd::B);
    assert_ne!(mask & vfs::POLL_IN, 0);
    assert_ne!(mask & vfs::POLL_RDHUP, 0);
    assert_eq!(mask & vfs::POLL_HUP, 0);
    assert_eq!(pair.read(UnixEnd::B, 64), b"queued");
    assert!(pair.is_eof(UnixEnd::B));
}

#[test]
fn stream_shutdown_both_publishes_hup_at_both_ends() {
    let _serial = test_guard();
    let pair = UnixPair::new();
    pair.shutdown_reader(UnixEnd::A);
    pair.close_writer(UnixEnd::A);

    for end in [UnixEnd::A, UnixEnd::B] {
        let mask = pair.poll_mask(end);
        assert_eq!(mask & (vfs::POLL_IN | vfs::POLL_OUT | vfs::POLL_HUP | vfs::POLL_RDHUP),
            vfs::POLL_IN | vfs::POLL_OUT | vfs::POLL_HUP | vfs::POLL_RDHUP);
    }
}

#[test]
fn stream_release_discards_unread_rights_after_peer_data_then_resets() {
    let _serial = test_guard();
    let pair = UnixPair::new();
    let file = anon_file();
    pair.write(UnixEnd::A, b"reply").unwrap();
    pair.write_with_fds(UnixEnd::B, b"request", alloc::vec![file.clone()]).unwrap();
    assert_eq!(Arc::strong_count(&file), 2);

    pair.release_end(UnixEnd::A);

    assert_eq!(Arc::strong_count(&file), 1, "dead endpoint releases unread SCM_RIGHTS");
    assert_eq!(pair.read(UnixEnd::B, 64), b"reply");
    assert!(pair.take_reset(UnixEnd::B), "reset follows queued peer data");
    assert!(pair.is_eof(UnixEnd::B));
    assert!(matches!(pair.write(UnixEnd::B, b"late"), Err(UnixStreamError::PeerClosed)));
}

#[test]
fn stream_reset_is_published_and_consumed_through_canonical_error() {
    let _serial = test_guard();
    let pair = UnixPair::new();
    let error = Arc::new(crate::SocketError::new());
    pair.attach_end_error(UnixEnd::B, &error);
    pair.write(UnixEnd::A, b"reply").unwrap();
    pair.write(UnixEnd::B, b"unread").unwrap();

    pair.release_end(UnixEnd::A);

    assert!(error.has(), "peer close publishes canonical socket error");
    assert_eq!(pair.read(UnixEnd::B, 64), b"reply", "queued data precedes error");
    assert!(pair.take_reset(UnixEnd::B));
    assert!(!error.has(), "receive consumes the same canonical error as SO_ERROR");
}

#[test]
fn so_error_consumption_clears_stream_reset_readiness() {
    let _serial = test_guard();
    let pair = UnixPair::new();
    let error = pair.end_error(UnixEnd::B);
    pair.write(UnixEnd::B, b"unread").unwrap();
    pair.release_end(UnixEnd::A);

    assert_ne!(pair.poll_mask(UnixEnd::B) & vfs::POLL_ERR, 0);
    assert_eq!(error.take(), syscall::errno::Errno::Econnreset as i32);
    assert_eq!(pair.poll_mask(UnixEnd::B) & vfs::POLL_ERR, 0);
    assert!(!pair.take_reset(UnixEnd::B), "lifecycle marker cannot redeliver consumed SO_ERROR");
    assert!(pair.is_eof(UnixEnd::B));
}

#[test]
fn message_pair_shutdown_and_release_match_stream_lifecycle() {
    let _serial = test_guard();
    let pair = UnixMsgPair::new();
    pair.send(UnixEnd::A, b"queued").unwrap();
    pair.shutdown_reader(UnixEnd::B);
    assert_eq!(pair.recv(UnixEnd::B, 64).unwrap(), b"queued");
    assert!(pair.is_eof(UnixEnd::B));
    assert!(matches!(pair.send(UnixEnd::A, b"late"), Err(UnixMsgError::PeerClosed)));

    let pair = UnixMsgPair::new();
    pair.send(UnixEnd::A, b"reply").unwrap();
    pair.send(UnixEnd::B, b"unread").unwrap();
    pair.release_end(UnixEnd::A);
    assert!(pair.take_reset(UnixEnd::B));
    assert_eq!(pair.recv(UnixEnd::B, 64).unwrap(), b"reply");
    assert!(pair.is_eof(UnixEnd::B));
}

#[test]
fn seqpacket_reset_uses_endpoint_canonical_error() {
    let _serial = test_guard();
    let pair = UnixMsgPair::new();
    let error = Arc::new(crate::SocketError::new());
    pair.attach_end_error(UnixEnd::B, &error);
    pair.send(UnixEnd::A, b"reply").unwrap();
    pair.send(UnixEnd::B, b"unread").unwrap();

    pair.release_end(UnixEnd::A);

    assert!(error.has());
    assert_eq!(pair.recv(UnixEnd::B, 64).unwrap(), b"reply");
    assert!(pair.take_reset(UnixEnd::B));
    assert!(!error.has());
}

#[test]
fn datagram_pair_close_has_no_eof_or_reset_and_refuses_peer_send() {
    let _serial = test_guard();
    let pair = UnixMsgPair::new_datagram();
    pair.send(UnixEnd::A, b"reply").unwrap();
    pair.send(UnixEnd::B, b"discarded").unwrap();
    pair.release_end(UnixEnd::A);

    assert_eq!(pair.recv(UnixEnd::B, 64).unwrap(), b"reply");
    assert!(pair.recv(UnixEnd::B, 64).is_none());
    assert!(!pair.take_reset(UnixEnd::B));
    assert!(!pair.is_eof(UnixEnd::B));
    assert!(matches!(pair.send(UnixEnd::B, b"late"), Err(UnixMsgError::PeerRefused)));
    assert_eq!(pair.poll_mask(UnixEnd::B) & (vfs::POLL_HUP | vfs::POLL_RDHUP), 0);
}

#[test]
fn datagram_pair_shutdown_read_drains_without_permanent_eof() {
    let _serial = test_guard();
    let pair = UnixMsgPair::new_datagram();
    pair.send(UnixEnd::A, b"queued").unwrap();
    pair.shutdown_reader(UnixEnd::B);

    assert_eq!(pair.recv(UnixEnd::B, 64).unwrap(), b"queued");
    assert!(pair.recv(UnixEnd::B, 64).is_none());
    assert!(!pair.is_eof(UnixEnd::B));
    assert!(matches!(pair.send(UnixEnd::A, b"late"), Err(UnixMsgError::PeerClosed)));
}

#[test]
fn datagram_shutdown_read_drains_queue_then_rejects_senders() {
    let _serial = test_guard();
    let queue = UnixDgramQueue::new();
    queue.try_push(UnixDgram {
        payload: b"queued".to_vec(), creds: (1, 2, 3),
        fds: alloc::vec::Vec::new(),
    }).unwrap();
    queue.shutdown_reader();

    assert_eq!(queue.pop().unwrap().payload, b"queued");
    assert!(queue.pop().is_none());
    assert!(matches!(queue.try_push(UnixDgram {
        payload: b"late".to_vec(), creds: (1, 2, 3),
        fds: alloc::vec::Vec::new(),
    }), Err(crate::NetError::Epipe)));
}

#[test]
fn shutdown_direction_validation_is_typed() {
    let _serial = test_guard();
    assert_eq!(crate::uapi::ShutdownHow::try_from(0), Ok(crate::uapi::ShutdownHow::Read));
    assert_eq!(crate::uapi::ShutdownHow::try_from(1), Ok(crate::uapi::ShutdownHow::Write));
    assert_eq!(crate::uapi::ShutdownHow::try_from(2), Ok(crate::uapi::ShutdownHow::ReadWrite));
    assert_eq!(crate::uapi::ShutdownHow::try_from(3), Err(()));
}

#[test]
fn closed_listener_refuses_connect_and_accept() {
    let _serial = test_guard();
    let listener = UnixListener::new(UnixAddr::from_abstract_or_test_path("shutdown-listener".into()));
    listener.listen(4, 128);
    listener.close();

    assert!(!listener.is_listening());
    assert!(matches!(listener.connect_pair(UnixPair::new()), Err(UnixConnectError::Refused)));
    assert!(matches!(listener.accept(), Err(crate::NetError::Einval)));
}

#[test]
fn listener_shutdown_read_preserves_pending_accept_then_refuses_connect() {
    let _serial = test_guard();
    let listener = UnixListener::new(UnixAddr::from_abstract_or_test_path("shutdown-read-listener".into()));
    listener.listen(0, crate::sysctl::DEFAULT_SOMAXCONN);
    let queued = listener.connect_pair(UnixPair::new()).expect("queue before shutdown");

    listener.shutdown(crate::uapi::ShutdownHow::Read);

    assert!(listener.is_listening());
    assert!(matches!(listener.connect_pair(UnixPair::new()), Err(UnixConnectError::Refused)));
    assert!(Arc::ptr_eq(&listener.accept().expect("accept pre-shutdown queue").0, &queued));
    assert!(matches!(listener.accept(), Err(crate::NetError::Einval)));
    assert_eq!(listener.poll_mask() & (vfs::POLL_IN | vfs::POLL_RDHUP), vfs::POLL_IN | vfs::POLL_RDHUP);
}
