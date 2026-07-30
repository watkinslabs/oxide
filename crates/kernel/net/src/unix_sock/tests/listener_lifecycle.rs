use super::*;
use alloc::string::String;
use alloc::sync::Arc;

#[test]
fn listener_backlog_matches_linux_queue_capacity() {
    let _serial = test_guard();
    assert_eq!(crate::sysctl::normalize_listen_backlog(0, 4096), 0);
    assert_eq!(crate::sysctl::normalize_listen_backlog(1, 4096), 1);
    assert_eq!(crate::sysctl::normalize_listen_backlog(i32::MAX, 4096), 4096);
    assert_eq!(crate::sysctl::normalize_listen_backlog(-1, 4096), 4096);
    let registry = UnixRegistry::new();
    let listener = registry.bind(String::from("\0listener-backlog")).unwrap();
    listener.listen(0, crate::sysctl::DEFAULT_SOMAXCONN);
    assert_eq!(listener.backlog(), 0);
    assert!(registry.connect("\0listener-backlog").is_ok(), "Linux admits backlog + 1 clients");
    assert!(matches!(registry.connect("\0listener-backlog"), Err(UnixConnectError::Full)));
    assert!(listener.accept().is_ok(), "accept releases queue capacity");
    assert!(registry.connect("\0listener-backlog").is_ok());

    let capped = registry.bind(String::from("\0listener-backlog-cap")).unwrap();
    capped.listen(-7, crate::sysctl::DEFAULT_SOMAXCONN);
    assert_eq!(capped.backlog(), crate::sysctl::DEFAULT_SOMAXCONN);
}

#[test]
fn relisten_backlog_growth_preserves_queue_and_adds_capacity() {
    let _serial = test_guard();
    let registry = UnixRegistry::new();
    let path = "\0listener-relisten-growth";
    let listener = registry.bind(String::from(path)).unwrap();
    listener.listen(0, crate::sysctl::DEFAULT_SOMAXCONN);
    let first = registry.connect(path).unwrap();
    assert!(matches!(registry.connect(path), Err(UnixConnectError::Full)));
    assert_eq!(listener.pending_len(), 1, "full connect leaves the queue unchanged");

    listener.listen(2, crate::sysctl::DEFAULT_SOMAXCONN);
    assert_eq!(listener.backlog(), 2);
    assert_eq!(listener.pending_len(), 1, "relisten preserves pending connections");
    let second = registry.connect(path).unwrap();
    let third = registry.connect(path).unwrap();
    assert_eq!(listener.pending_len(), 3, "capacity grows to backlog + 1");
    assert!(matches!(registry.connect(path), Err(UnixConnectError::Full)));
    assert_eq!(listener.pending_len(), 3, "refused overflow does not consume capacity");

    for expected in [&first, &second, &third] {
        let (accepted, _pin) = listener.accept().expect("queued connection");
        assert!(Arc::ptr_eq(&accepted, expected), "relisten preserves FIFO order");
    }
    assert_eq!(listener.pending_len(), 0);
}

#[test]
fn listener_queue_and_refusal_invariants_hold_across_close() {
    let _serial = test_guard();
    let registry = UnixRegistry::new();
    let path = "\0listener-queue-refusal";
    let listener = registry.bind(String::from(path)).unwrap();
    assert!(matches!(registry.connect(path), Err(UnixConnectError::Refused)));
    assert_eq!(listener.pending_len(), 0, "pre-listen refusal does not queue");

    listener.listen(0, crate::sysctl::DEFAULT_SOMAXCONN);
    let accepted = registry.connect(path).unwrap();
    assert!(Arc::ptr_eq(&listener.accept().unwrap().0, &accepted));
    let pending = registry.connect(path).unwrap();
    assert_eq!(listener.pending_len(), 1);

    registry.unbind(path);

    assert_eq!(listener.pending_len(), 0, "close drains only the accept queue");
    assert!(matches!(registry.connect(path), Err(UnixConnectError::Refused)));
    assert!(!accepted.peer_gone(UnixEnd::B), "accepted connection survives listener close");
    assert!(!accepted.reset_pending(UnixEnd::B));
    assert!(pending.peer_gone(UnixEnd::B), "unaccepted connection is reset");
    assert!(pending.reset_pending(UnixEnd::B));
}

#[test]
fn pathname_unlink_removes_name_without_closing_listener() {
    let _serial = test_guard();
    let registry = UnixRegistry::new();
    let addr = UnixAddr::from_abstract_or_test_path(String::from("/run/unlinked-listener"));
    let listener = registry.bind_addr(addr.clone()).unwrap();
    listener.listen(0, crate::sysctl::DEFAULT_SOMAXCONN);
    let pending = registry.connect_addr(&addr).unwrap();

    registry.unlink_addr(&addr);

    assert!(matches!(registry.connect_addr(&addr), Err(UnixConnectError::Refused)));
    assert!(listener.is_listening());
    assert_eq!(listener.pending_len(), 1);
    assert!(Arc::ptr_eq(&listener.accept().unwrap().0, &pending));
    assert!(!pending.peer_gone(UnixEnd::B));
}

#[test]
fn accept_distinguishes_closed_listener_from_empty_queue() {
    let _serial = test_guard();
    let registry = UnixRegistry::new();
    let path = "\0listener-closed-accept";
    let listener = registry.bind(String::from(path)).unwrap();
    listener.listen(0, crate::sysctl::DEFAULT_SOMAXCONN);
    assert!(matches!(listener.accept(), Err(crate::NetError::Eagain)));
    registry.unbind(path);
    assert!(matches!(listener.accept(), Err(crate::NetError::Einval)));
}

#[test]
fn unaccepted_reset_stays_pending_until_consumed_once() {
    let _serial = test_guard();
    let registry = UnixRegistry::new();
    let path = "\0listener-reset-once";
    let listener = registry.bind(String::from(path)).unwrap();
    listener.listen(0, crate::sysctl::DEFAULT_SOMAXCONN);
    let client = registry.connect(path).unwrap();
    assert!(!client.reset_pending(UnixEnd::B));

    registry.unbind(path);

    assert!(client.reset_pending(UnixEnd::B));
    assert!(!client.is_eof(UnixEnd::B), "pending reset takes precedence over EOF");
    assert!(client.take_reset(UnixEnd::B), "first receive consumes ECONNRESET");
    assert!(!client.reset_pending(UnixEnd::B));
    assert!(!client.take_reset(UnixEnd::B), "ECONNRESET is reported only once");
    assert!(client.is_eof(UnixEnd::B), "reads after consumed reset observe EOF");
}

#[test]
fn unaccepted_reset_is_consumed_by_canonical_socket_error() {
    let _serial = test_guard();
    let registry = UnixRegistry::new();
    let path = "\0listener-reset-so-error";
    let listener = registry.bind(String::from(path)).unwrap();
    listener.listen(0, crate::sysctl::DEFAULT_SOMAXCONN);
    let client = registry.connect(path).unwrap();
    let error = client.end_error(UnixEnd::B);

    registry.unbind(path);

    assert_eq!(error.take(), syscall::errno::Errno::Econnreset as i32);
    assert!(!client.reset_pending(UnixEnd::B));
    assert!(!client.take_reset(UnixEnd::B), "receive cannot redeliver consumed SO_ERROR");
    assert!(client.is_eof(UnixEnd::B));
}

#[test]
fn listener_publishes_only_fully_initialized_pairs() {
    let _serial = test_guard();
    let registry = UnixRegistry::new();
    let path = "\0listener-initialized-pair";
    let addr = UnixAddr::from_abstract_or_test_path(String::from(path));
    let listener = registry.bind_addr(addr.clone()).unwrap();
    listener.listen_with_cred(0, crate::sysctl::DEFAULT_SOMAXCONN, Some((10, 20, 30)), None);
    let client = UnixPair::new();
    client.set_end_cred(UnixEnd::B, 40, 50, 60);

    registry.connect_pair_addr(&addr, client.clone()).unwrap();
    let (accepted, _pin) = listener.accept().unwrap();

    assert!(Arc::ptr_eq(&accepted, &client));
    assert_eq!(accepted.peer_cred(UnixEnd::A), (40, 50, 60));
    assert_eq!(accepted.peer_cred(UnixEnd::B), (10, 20, 30));

    listener.listen_with_cred(0, crate::sysctl::DEFAULT_SOMAXCONN, Some((11, 21, 31)), None);
    let next = UnixPair::new();
    next.set_end_cred(UnixEnd::B, 41, 51, 61);
    registry.connect_pair_addr(&addr, next).unwrap();
    let (accepted, _pin) = listener.accept().unwrap();
    assert_eq!(accepted.peer_cred(UnixEnd::A), (41, 51, 61));
    assert_eq!(accepted.peer_cred(UnixEnd::B), (11, 21, 31));
    accepted.write(UnixEnd::B, b"cred").unwrap();
    assert_eq!(accepted.peer_cred(UnixEnd::A), (41, 51, 61), "write does not mutate SO_PEERCRED");
    let (_, _, cred) = accepted.read_stream(UnixEnd::A, 16);
    assert_eq!(cred, Some((41, 51, 61)), "SCM_CREDENTIALS follows the write record");
}

#[test]
fn listener_close_resets_all_unaccepted_clients() {
    let _serial = test_guard();
    let registry = UnixRegistry::new();
    let path = "\0listener-close";
    let listener = registry.bind(String::from(path)).unwrap();
    listener.listen(1, crate::sysctl::DEFAULT_SOMAXCONN);
    let first = registry.connect(path).unwrap();
    let second = registry.connect(path).unwrap();
    let held = anon_file();
    first.write_with_fds(UnixEnd::B, b"queued", alloc::vec![held.clone()]).unwrap();
    second.write_with_fds(UnixEnd::B, b"queued", alloc::vec![held.clone()]).unwrap();
    assert_eq!(Arc::strong_count(&held), 3);
    assert_eq!(listener.pending_len(), 2);

    registry.unbind(path);

    assert_eq!(listener.pending_len(), 0, "close drains the accept queue");
    assert_eq!(Arc::strong_count(&held), 1, "close drops queued SCM_RIGHTS outside ring locks");
    assert!(matches!(registry.connect(path), Err(UnixConnectError::Refused)));
    for client in [&first, &second] {
        assert!(client.peer_gone(UnixEnd::B));
        assert!(client.reset_pending(UnixEnd::B));
        assert_eq!(client.write(UnixEnd::B, b"late"), Err(UnixStreamError::PeerClosed));
        client.abort_unaccepted();
        assert!(client.reset_pending(UnixEnd::B), "repeat close preserves pending reset");
    }
}

#[test]
fn accepted_pairs_carry_the_pinned_peer_identity_both_ways() {
    // SO_PEERPIDFD's whole point: the identity, not the number, is what the
    // pair retains, so a descriptor minted later still names the process that
    // actually connected even after its pid number has been recycled.
    let _serial = test_guard();
    let registry = UnixRegistry::new();
    let path = "\0listener-peer-identity";
    let addr = UnixAddr::from_abstract_or_test_path(String::from(path));
    let server = Arc::new(sched::pid::PidIdentity::new(10));
    let client_id = Arc::new(sched::pid::PidIdentity::new(40));
    let listener = registry.bind_addr(addr.clone()).unwrap();
    listener.listen_with_cred(0, crate::sysctl::DEFAULT_SOMAXCONN, Some((10, 20, 30)),
        Some(Arc::clone(&server)));
    let client = UnixPair::new();
    client.set_end_cred(UnixEnd::B, 40, 50, 60);
    client.set_end_identity(UnixEnd::B, Some(Arc::clone(&client_id)));

    registry.connect_pair_addr(&addr, client.clone()).unwrap();
    let (accepted, _pin) = listener.accept().unwrap();

    let seen_by_server = accepted.peer_identity(UnixEnd::A).expect("client identity");
    let seen_by_client = accepted.peer_identity(UnixEnd::B).expect("server identity");
    assert!(Arc::ptr_eq(&seen_by_server, &client_id));
    assert!(Arc::ptr_eq(&seen_by_client, &server));
    assert_eq!(accepted.peer_cred(UnixEnd::A).0, seen_by_server.tid);
}

#[test]
fn a_pair_with_no_snapshot_reports_no_peer_identity() {
    // The ENODATA case: nothing pinned the connection, so there is no identity
    // to hand out — distinct from handing out a stale pid number.
    let _serial = test_guard();
    let pair = UnixPair::new();
    pair.set_end_cred(UnixEnd::B, 40, 50, 60);
    assert!(pair.peer_identity(UnixEnd::A).is_none());
    assert!(pair.peer_identity(UnixEnd::B).is_none());
}
