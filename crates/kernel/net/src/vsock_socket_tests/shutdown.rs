// AF_VSOCK `shutdown(2)`: security admission ordering, direction validation,
// half-close latching, and the `sock->state` -> ENOTCONN mapping. Split from
// `../vsock_socket_tests.rs` for the file-length cap (`08§7`); the fixtures
// (`connection`, `namespace`, `file`, the deny hooks) come from the parent.

use super::*;

#[test]
fn shutdown_is_net_owned_and_latches_both_directions_without_a_driver() {
    let _guard = vsock::tests::test_domain();
    let (key, conn) = connection(0x0a00_000d, 61_013);
    let sock = VsockSocket::new();
    *sock.kind.lock() = VsockKind::Conn(conn.clone());

    assert_eq!(sock.shutdown(crate::uapi::ShutdownHow::Write), Ok(()));
    assert!(conn.tx.lock().local_shut);
    assert_eq!(sock.write(0, b"blocked"), Err(vfs::VfsError::Epipe));
    assert_eq!(sock.write_nonblock(0, b"blocked"), Err(vfs::VfsError::Epipe));
    assert_eq!(sock.poll() & vfs::POLL_OUT, 0);

    assert_eq!(sock.shutdown(crate::uapi::ShutdownHow::Read), Ok(()));
    assert!(sock.read_shut.load(core::sync::atomic::Ordering::Acquire));
    assert_eq!(sock.read(0, &mut [0u8; 1]), Ok(0));
    assert_eq!(sock.poll() & (vfs::POLL_IN | vfs::POLL_RDHUP | vfs::POLL_HUP),
        vfs::POLL_IN | vfs::POLL_RDHUP | vfs::POLL_HUP);

    sock.release_file();
    assert_eq!(*conn.st.lock(), VsockState::Closed);
    assert!(vsock::TABLE.find(key).is_none());
}

#[test]
fn shutdown_admission_uses_socket_namespace_before_transport_mutation() {
    let _guard = vsock::tests::test_domain();
    let namespace = namespace();
    let id = crate::net_ns::namespace_id(&namespace);
    let (key, conn) = connection(0x0a00_0014, 61_014);
    let sock = VsockSocket::new_type_in(crate::socket_args::SOCK_STREAM, namespace);
    *sock.kind.lock() = VsockKind::Conn(conn.clone());
    assert_eq!(security::network::install(id, security::network::Operation::Shutdown,
        deny_vsock_shutdown), None);
    assert_eq!(sock.shutdown(crate::uapi::ShutdownHow::Write), Err(crate::NetError::Eacces));
    assert!(!conn.tx.lock().local_shut);
    assert_eq!(security::network::counters(id, security::network::Operation::Shutdown), Some((0, 1)));
    assert!(security::network::remove(id, security::network::Operation::Shutdown).is_some());
    sock.release_file();
    assert!(vsock::TABLE.find(key).is_none());
}

#[test]
fn shutdown_admission_precedes_vsock_direction_validation() {
    let namespace = namespace();
    let id = crate::net_ns::namespace_id(&namespace);
    let sock = VsockSocket::new_type_in(crate::socket_args::SOCK_STREAM, namespace);
    assert_eq!(security::network::install(id, security::network::Operation::Shutdown,
        deny_vsock_shutdown), None);
    assert_eq!(sock.shutdown_raw(INVALID_SHUTDOWN_DIRECTION), Err(crate::NetError::Eacces));
    assert_eq!(security::network::counters(id, security::network::Operation::Shutdown), Some((0, 1)));
    assert!(security::network::remove(id, security::network::Operation::Shutdown).is_some());
}

#[test]
fn pending_recv_error_overwrites_with_latest_positive_errno() {
    let sock = VsockSocket::new();
    assert_eq!(sock.take_pending_recv_error(), 0);
    assert!(!sock.set_pending_recv_error(0));
    assert!(!sock.set_pending_recv_error(-5));
    assert!(sock.set_pending_recv_error(111));
    assert!(sock.set_pending_recv_error(104));
    assert_eq!(sock.take_pending_recv_error(), 104);
    assert_eq!(sock.take_pending_recv_error(), 0);
}

// Linux `vsock_shutdown` returns ENOTCONN only for `SS_UNCONNECTED`, which for
// a connectible socket means a connect that never completed. A connection that
// WAS established and has since closed keeps `sock->state` at
// SS_CONNECTED/SS_DISCONNECTING, so its shutdown succeeds — and so does one
// still in SS_CONNECTING. Collapsing every non-Connected state to ENOTCONN
// made "shut the socket down, then close it" fail on a peer-closed connection.
#[test]
fn shutdown_state_mapping_matches_vsock_sock_state() {
    use core::sync::atomic::Ordering::Release;
    let _guard = vsock::tests::test_domain();

    let (_k, connecting) = connection(0x0a00_0021, 61_021);
    *connecting.st.lock() = VsockState::Connecting;
    connecting.ever_connected.store(false, Release);
    let sock = VsockSocket::new();
    *sock.kind.lock() = VsockKind::Conn(connecting.clone());
    assert_eq!(sock.shutdown(crate::uapi::ShutdownHow::Write), Ok(()),
        "SS_CONNECTING takes the else branch: shutdown applies and returns 0");
    assert!(connecting.tx.lock().local_shut);

    let (_k, closed) = connection(0x0a00_0022, 61_022);
    *closed.st.lock() = VsockState::Closed;
    let sock = VsockSocket::new();
    *sock.kind.lock() = VsockKind::Conn(closed.clone());
    assert_eq!(sock.shutdown(crate::uapi::ShutdownHow::Write), Ok(()),
        "an established-then-closed connection is still not SS_UNCONNECTED");

    let (_k, never) = connection(0x0a00_0023, 61_023);
    *never.st.lock() = VsockState::Closed;
    never.ever_connected.store(false, Release);
    let sock = VsockSocket::new();
    *sock.kind.lock() = VsockKind::Conn(never.clone());
    assert_eq!(sock.shutdown(crate::uapi::ShutdownHow::Write), Err(crate::NetError::Enotconn),
        "a connect that never completed is SS_UNCONNECTED");
    assert!(!never.tx.lock().local_shut, "and nothing is latched on that path");

    // An unconnected socket with no connection at all is ENOTCONN too.
    let bare = VsockSocket::new();
    assert_eq!(bare.shutdown(crate::uapi::ShutdownHow::ReadWrite), Err(crate::NetError::Enotconn));
}
