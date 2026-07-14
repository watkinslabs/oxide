use super::*;

#[test]
fn listener_backlog_matches_linux_queue_capacity() {
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
    assert!(listener.accept().is_some(), "accept releases queue capacity");
    assert!(registry.connect("\0listener-backlog").is_ok());

    let capped = registry.bind(String::from("\0listener-backlog-cap")).unwrap();
    capped.listen(-7, crate::sysctl::DEFAULT_SOMAXCONN);
    assert_eq!(capped.backlog(), crate::sysctl::DEFAULT_SOMAXCONN);
}

#[test]
fn listener_close_resets_all_unaccepted_clients() {
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
        assert!(client.take_reset(UnixEnd::B), "recv observes one ECONNRESET");
        assert!(!client.take_reset(UnixEnd::B), "reset error is consumed once");
        assert!(client.is_eof(UnixEnd::B), "reads after reset observe EOF");
        assert_eq!(client.write(UnixEnd::B, b"late"), Err(UnixStreamError::PeerClosed));
        client.abort_unaccepted();
        assert!(!client.take_reset(UnixEnd::B), "repeat close is idempotent");
    }
}
