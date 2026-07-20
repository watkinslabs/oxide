use super::*;

fn owner(raw: u32) -> vsock::VsockOwner {
    vsock::VsockOwner::from_raw(raw).expect("nonzero owner")
}

fn tx_ok(_: vsock::VsockOwner, _: &[u8]) -> bool { true }
fn rx_noop(_: vsock::VsockOwner) -> usize { 0 }

fn immediate_reply(owner: vsock::VsockOwner, frame: &[u8], op: u16) -> bool {
    let request = vsock::VsockHdr::decode(frame).expect("connect request header");
    if request.op != vsock::VIRTIO_VSOCK_OP_REQUEST { return true; }
    let reply = vsock::VsockHdr {
        src_cid: request.dst_cid, dst_cid: request.src_cid,
        src_port: request.dst_port, dst_port: request.src_port,
        len: 0, typ: request.typ, op, flags: 0, buf_alloc: 8192, fwd_cnt: 0,
    };
    vsock::deliver_rx_from(owner, &reply, &[]);
    true
}

fn tx_immediate_response(owner: vsock::VsockOwner, frame: &[u8]) -> bool {
    immediate_reply(owner, frame, vsock::VIRTIO_VSOCK_OP_RESPONSE)
}

fn tx_immediate_rst(owner: vsock::VsockOwner, frame: &[u8]) -> bool {
    immediate_reply(owner, frame, vsock::VIRTIO_VSOCK_OP_RST)
}

fn tx_immediate_remove(owner: vsock::VsockOwner, _: &[u8]) -> bool {
    assert!(vsock::driver_uninstall(owner));
    true
}

fn observe_connect_wait(sock: &VsockSocket) {
    assert!(matches!(*sock.kind.lock(), VsockKind::Conn(ref conn)
        if *conn.st.lock() == VsockState::Connecting));
}

fn refuse_connect(sock: &VsockSocket) {
    let conn = sock.conn().expect("pending connection");
    assert!(vsock::fail_connect(&conn, crate::NetError::Econnrefused));
}

fn close_read_connection(sock: &VsockSocket) {
    let conn = sock.conn().expect("read connection");
    vsock::close(&conn);
}

#[test]
fn blocking_connect_releases_kind_before_wait() {
    let _guard = vsock::tests::test_domain();
    let transport = owner(0x0d00_0003);
    let cid = 0x5d00_0003;
    let _ = vsock::driver_uninstall(transport);
    assert!(vsock::driver_install(transport, cid, tx_ok, rx_noop));
    let sock = Arc::new(VsockSocket::new());
    *sock.connect_wait_hook.lock() = Some(observe_connect_wait);
    assert_eq!(sock.connect_transport(2, 1024, false), Ok(()));
    sock.disconnect().unwrap();
    sock.release_file();
    assert!(vsock::driver_uninstall(transport));
}

#[test]
fn explicit_bind_survives_connect_disconnect_and_releases_on_close() {
    let _guard = vsock::tests::test_domain();
    let transport = owner(0x0d00_0001);
    let cid = 0x5d00_0001;
    let port = 63_010;
    let _ = vsock::driver_uninstall(transport);
    assert!(vsock::driver_install(transport, cid, tx_ok, rx_noop));
    let sock = Arc::new(VsockSocket::new());
    sock.bind(crate::socket_args::AF_VSOCK as u16, port, cid).unwrap();
    sock.connect_transport(2, 1024, true).unwrap();
    sock.disconnect().unwrap();
    assert!(matches!(*sock.kind.lock(), VsockKind::Bound { port: p, .. } if p == port));
    let duplicate = VsockSocket::new();
    assert_eq!(duplicate.bind(crate::socket_args::AF_VSOCK as u16, port, cid),
        Err(crate::NetError::Eaddrinuse));
    sock.connect_transport(2, 1024, true).unwrap();
    sock.disconnect().unwrap();
    sock.release_file();
    assert_eq!(duplicate.bind(crate::socket_args::AF_VSOCK as u16, port, cid), Ok(()));
    duplicate.release_file();
    assert!(vsock::driver_uninstall(transport));
}

#[test]
fn auto_bind_is_released_by_disconnect_and_can_be_rebound() {
    let _guard = vsock::tests::test_domain();
    let transport = owner(0x0d00_0002);
    let cid = 0x5d00_0002;
    let _ = vsock::driver_uninstall(transport);
    assert!(vsock::driver_install(transport, cid, tx_ok, rx_noop));
    let sock = Arc::new(VsockSocket::new());
    sock.connect_transport(2, 1024, true).unwrap();
    let local_port = sock.conn().expect("connected socket").local_port;
    sock.disconnect().unwrap();
    assert!(matches!(*sock.kind.lock(), VsockKind::Init));
    assert_eq!(sock.bind(crate::socket_args::AF_VSOCK as u16, local_port, cid), Ok(()));
    sock.release_file();
    assert!(vsock::driver_uninstall(transport));
}


#[test]
fn nonblocking_rst_publishes_reset_poll_retains_port_and_reconnects() {
    use syscall::errno::Errno;
    let _guard = vsock::tests::test_domain();
    let transport = owner(0x0d00_0004);
    let cid = 0x5d00_0004;
    let _ = vsock::driver_uninstall(transport);
    assert!(vsock::driver_install(transport, cid, tx_ok, rx_noop));
    let sock = Arc::new(VsockSocket::new());
    sock.connect_transport(2, 1024, true).unwrap();
    let conn = sock.conn().expect("pending connection");
    let port = conn.local_port;
    let rst = vsock::VsockHdr {
        src_cid: conn.peer_cid, dst_cid: conn.local_cid,
        src_port: conn.peer_port, dst_port: conn.local_port,
        len: 0, typ: vsock::VIRTIO_VSOCK_TYPE_STREAM,
        op: vsock::VIRTIO_VSOCK_OP_RST, flags: 0, buf_alloc: 0, fwd_cnt: 0,
    };
    vsock::deliver_rx_from(transport, &rst, &[]);

    assert!(matches!(*sock.kind.lock(), VsockKind::Bound { port: p, .. } if p == port));
    assert!(vsock::TABLE.find(conn.key()).is_none());
    assert_eq!(sock.poll() & (vfs::POLL_ERR | vfs::POLL_OUT),
        vfs::POLL_ERR | vfs::POLL_OUT);
    assert_eq!(sock.take_pending_recv_error(), Errno::Econnreset as i32);
    assert_eq!(sock.take_pending_recv_error(), 0);
    assert_eq!(sock.poll() & vfs::POLL_ERR, 0);

    assert!(matches!(vsock::TABLE.reserve_bind(Some(transport), Some(port)),
        Err(crate::NetError::Eaddrinuse)));
    sock.connect_transport(2, 1025, true).unwrap();
    assert!(matches!(*sock.kind.lock(), VsockKind::Conn(_)));
    sock.disconnect().unwrap();
    sock.release_file();
    assert!(vsock::driver_uninstall(transport));
}

#[test]
fn failed_connect_preserves_explicit_bind_and_allows_reconnect() {
    use syscall::errno::Errno;
    let _guard = vsock::tests::test_domain();
    let transport = owner(0x0d00_0005);
    let cid = 0x5d00_0005;
    let port = 63_012;
    let _ = vsock::driver_uninstall(transport);
    assert!(vsock::driver_install(transport, cid, tx_ok, rx_noop));
    let sock = Arc::new(VsockSocket::new());
    sock.bind(crate::socket_args::AF_VSOCK as u16, port, cid).unwrap();
    sock.connect_transport(2, 1024, true).unwrap();
    let failed = sock.conn().expect("pending connection");
    assert!(vsock::fail_connect(&failed, crate::NetError::Etimedout));
    assert!(matches!(*sock.kind.lock(), VsockKind::Bound { port: p, .. } if p == port));
    assert_eq!(sock.take_pending_recv_error(), Errno::Etimedout as i32);
    let duplicate = VsockSocket::new();
    assert_eq!(duplicate.bind(crate::socket_args::AF_VSOCK as u16, port, cid),
        Err(crate::NetError::Eaddrinuse));
    sock.connect_transport(2, 1025, true).unwrap();
    sock.disconnect().unwrap();
    sock.release_file();
    assert_eq!(duplicate.bind(crate::socket_args::AF_VSOCK as u16, port, cid), Ok(()));
    duplicate.release_file();
    assert!(vsock::driver_uninstall(transport));
}

#[test]
fn driver_removal_completes_pending_connect_through_socket_owner() {
    use syscall::errno::Errno;
    let _guard = vsock::tests::test_domain();
    let transport = owner(0x0d00_0006);
    let cid = 0x5d00_0006;
    let _ = vsock::driver_uninstall(transport);
    assert!(vsock::driver_install(transport, cid, tx_ok, rx_noop));
    let sock = Arc::new(VsockSocket::new());
    sock.connect_transport(2, 1024, true).unwrap();
    assert!(vsock::driver_uninstall(transport));
    assert!(matches!(*sock.kind.lock(), VsockKind::Bound { .. }));
    assert_eq!(sock.take_pending_recv_error(), Errno::Enetunreach as i32);
    assert_eq!(sock.poll() & vfs::POLL_OUT, vfs::POLL_OUT);
    sock.release_file();
}

#[test]
fn blocking_failure_uses_same_consumable_completion() {
    use syscall::errno::Errno;
    let _guard = vsock::tests::test_domain();
    let transport = owner(0x0d00_0007);
    let cid = 0x5d00_0007;
    let _ = vsock::driver_uninstall(transport);
    assert!(vsock::driver_install(transport, cid, tx_ok, rx_noop));
    let sock = Arc::new(VsockSocket::new());
    *sock.connect_wait_hook.lock() = Some(refuse_connect);
    assert_eq!(sock.connect_transport(2, 1024, false), Err(crate::NetError::Econnrefused));
    assert!(matches!(*sock.kind.lock(), VsockKind::Bound { .. }));
    assert_eq!(sock.poll() & (vfs::POLL_ERR | vfs::POLL_OUT),
        vfs::POLL_ERR | vfs::POLL_OUT);
    assert_eq!(sock.take_pending_recv_error(), Errno::Econnrefused as i32);
    sock.connect_transport(2, 1025, true).unwrap();
    sock.disconnect().unwrap();
    sock.release_file();
    assert!(vsock::driver_uninstall(transport));
}

#[test]
fn pending_reentry_and_stale_failure_preserve_current_arc() {
    let _guard = vsock::tests::test_domain();
    let transport = owner(0x0d00_0008);
    let cid = 0x5d00_0008;
    let _ = vsock::driver_uninstall(transport);
    assert!(vsock::driver_install(transport, cid, tx_ok, rx_noop));
    let sock = Arc::new(VsockSocket::new());
    sock.connect_transport(2, 1024, true).unwrap();
    let old = sock.conn().expect("first pending connection");
    assert_eq!(sock.connect_transport(2, 1025, true), Err(crate::NetError::Ealready));
    sock.disconnect().unwrap();
    sock.connect_transport(2, 1025, true).unwrap();
    let current = sock.conn().expect("replacement pending connection");
    assert!(!Arc::ptr_eq(&old, &current));
    assert!(!vsock::fail_connect(&old, crate::NetError::Econnrefused));
    assert!(matches!(&*sock.kind.lock(), VsockKind::Conn(conn) if Arc::ptr_eq(conn, &current)));
    sock.disconnect().unwrap();
    sock.release_file();
    assert!(vsock::driver_uninstall(transport));
}

#[test]
fn nonblocking_deadline_completes_exact_arc_with_timeout_readiness() {
    use syscall::errno::Errno;
    let _guard = vsock::tests::test_domain();
    let transport = owner(0x0d00_0009);
    let cid = 0x5d00_0009;
    let _ = vsock::driver_uninstall(transport);
    assert!(vsock::driver_install(transport, cid, tx_ok, rx_noop));
    let sock = Arc::new(VsockSocket::new());
    sock.connect_transport(2, 1024, true).unwrap();
    let conn = sock.conn().expect("pending connection");
    let port = conn.local_port;
    vsock::cancel_connect_timeout(&conn);
    vsock::arm_connect_timeout(&conn, 1);
    timer::run_due(1);

    assert_eq!(*conn.st.lock(), VsockState::Closed);
    assert!(vsock::TABLE.find(conn.key()).is_none());
    assert!(matches!(*sock.kind.lock(), VsockKind::Bound { port: p, .. } if p == port));
    assert_eq!(sock.poll() & (vfs::POLL_ERR | vfs::POLL_OUT),
        vfs::POLL_ERR | vfs::POLL_OUT);
    assert_eq!(sock.take_pending_recv_error(), Errno::Etimedout as i32);
    assert_eq!(Arc::strong_count(&conn), 1);
    sock.release_file();
    assert!(vsock::driver_uninstall(transport));
}

#[test]
fn cancelled_connect_deadline_releases_both_timer_arc_owners() {
    let _guard = vsock::tests::test_domain();
    let transport = owner(0x0d00_000c);
    let cid = 0x5d00_000c;
    let _ = vsock::driver_uninstall(transport);
    assert!(vsock::driver_install(transport, cid, tx_ok, rx_noop));
    let sock = Arc::new(VsockSocket::new());
    sock.connect_transport(2, 1024, true).unwrap();
    let conn = sock.conn().expect("pending connection");
    let armed = Arc::strong_count(&conn);
    vsock::cancel_connect_timeout(&conn);
    assert_eq!(Arc::strong_count(&conn), armed - 1);
    timer::run_due(u64::MAX);
    assert_eq!(*conn.st.lock(), VsockState::Connecting);
    sock.disconnect().unwrap();
    sock.release_file();
    assert!(vsock::driver_uninstall(transport));
}

#[test]
fn immediate_response_during_start_sees_published_socket() {
    let _guard = vsock::tests::test_domain();
    let transport = owner(0x0d00_000d);
    let cid = 0x5d00_000d;
    let _ = vsock::driver_uninstall(transport);
    assert!(vsock::driver_install(transport, cid, tx_immediate_response, rx_noop));
    let sock = Arc::new(VsockSocket::new());
    sock.error.set(syscall::errno::Errno::Etimedout as i32);

    assert_eq!(sock.connect_transport(2, 1024, true), Ok(()));
    let conn = sock.conn().expect("synchronously connected socket");
    assert_eq!(*conn.st.lock(), VsockState::Connected);
    assert_eq!(Arc::strong_count(&conn), 3);
    assert_eq!(sock.take_pending_recv_error(), 0);
    sock.release_file();
    assert!(vsock::driver_uninstall(transport));
}

#[test]
fn immediate_rst_during_start_rolls_back_exact_published_socket() {
    use syscall::errno::Errno;
    let _guard = vsock::tests::test_domain();
    let transport = owner(0x0d00_000e);
    let cid = 0x5d00_000e;
    let _ = vsock::driver_uninstall(transport);
    assert!(vsock::driver_install(transport, cid, tx_immediate_rst, rx_noop));
    let sock = Arc::new(VsockSocket::new());

    assert_eq!(sock.connect_transport(2, 1024, true), Ok(()));
    assert!(matches!(*sock.kind.lock(), VsockKind::Bound { .. }));
    assert_eq!(sock.take_pending_recv_error(), Errno::Econnreset as i32);
    sock.release_file();
    assert!(vsock::driver_uninstall(transport));
}

#[test]
fn immediate_driver_removal_during_start_completes_published_socket() {
    use syscall::errno::Errno;
    let _guard = vsock::tests::test_domain();
    let transport = owner(0x0d00_000f);
    let cid = 0x5d00_000f;
    let _ = vsock::driver_uninstall(transport);
    assert!(vsock::driver_install(transport, cid, tx_immediate_remove, rx_noop));
    let sock = Arc::new(VsockSocket::new());

    assert_eq!(sock.connect_transport(2, 1024, true), Ok(()));
    assert!(matches!(*sock.kind.lock(), VsockKind::Bound { .. }));
    assert_eq!(sock.take_pending_recv_error(), Errno::Enetunreach as i32);
    sock.release_file();
}

#[test]
fn disconnect_releases_armed_timer_arc_immediately() {
    let _guard = vsock::tests::test_domain();
    let transport = owner(0x0d00_0010);
    let cid = 0x5d00_0010;
    let _ = vsock::driver_uninstall(transport);
    assert!(vsock::driver_install(transport, cid, tx_ok, rx_noop));
    let sock = Arc::new(VsockSocket::new());
    sock.connect_transport(2, 1024, true).unwrap();
    let conn = sock.conn().expect("armed connection");

    sock.disconnect().unwrap();
    assert_eq!(Arc::strong_count(&conn), 1);
    timer::run_due(u64::MAX);
    assert_eq!(*conn.st.lock(), VsockState::Closed);
    sock.release_file();
    assert!(vsock::driver_uninstall(transport));
}

#[test]
fn release_releases_armed_timer_arc_immediately() {
    let _guard = vsock::tests::test_domain();
    let transport = owner(0x0d00_0011);
    let cid = 0x5d00_0011;
    let _ = vsock::driver_uninstall(transport);
    assert!(vsock::driver_install(transport, cid, tx_ok, rx_noop));
    let sock = Arc::new(VsockSocket::new());
    sock.connect_transport(2, 1024, true).unwrap();
    let conn = sock.conn().expect("armed connection");

    sock.release_file();
    assert_eq!(Arc::strong_count(&conn), 1);
    timer::run_due(u64::MAX);
    assert_eq!(*conn.st.lock(), VsockState::Closed);
    assert!(vsock::driver_uninstall(transport));
}

#[test]
fn stale_so_error_survives_rejected_attempt_and_clears_after_publication() {
    let _guard = vsock::tests::test_domain();
    let transport = owner(0x0d00_000a);
    let cid = 0x5d00_000a;
    let _ = vsock::driver_uninstall(transport);
    assert!(vsock::driver_install(transport, cid, tx_ok, rx_noop));
    let sock = Arc::new(VsockSocket::new());
    sock.connect_transport(2, 1024, true).unwrap();
    let failed = sock.conn().expect("failed connection");
    let port = failed.local_port;
    assert!(vsock::fail_connect(&failed, crate::NetError::Etimedout));
    let collision = Arc::new(VsockConn::new(transport, cid, port, 2, 1025,
        VsockState::Connecting));
    assert!(vsock::TABLE.insert(collision.clone()));

    assert_eq!(sock.connect_transport(2, 1025, true), Err(crate::NetError::Eaddrinuse));
    assert_ne!(sock.poll() & vfs::POLL_ERR, 0);
    assert!(vsock::TABLE.remove_conn(&collision));
    sock.connect_transport(2, 1025, true).unwrap();
    assert_eq!(sock.take_pending_recv_error(), 0);
    sock.disconnect().unwrap();
    sock.release_file();
    assert!(vsock::driver_uninstall(transport));
}

#[test]
fn blocking_read_recheck_observes_terminal_close() {
    let conn = Arc::new(VsockConn::new(owner(0x0d00_000b), 3, 63_013, 2, 1024,
        VsockState::Connected));
    let sock = Arc::new(VsockSocket::new());
    *sock.kind.lock() = VsockKind::Conn(conn.clone());
    *sock.read_retry_hook.lock() = Some(close_read_connection);
    assert_eq!(sock.read(0, &mut [0u8; 1]), Ok(0));
    assert_eq!(*conn.st.lock(), VsockState::Closed);
}

#[test]
fn vsock_option_policy_is_typed_and_state_aware() {
    const UNKNOWN_SOCKET_LEVEL: u64 = 999;
    const UNKNOWN_SOCKET_OPTION: u64 = 999;
    const ZERO_BUFFER_SIZE: u64 = 0;
    const MAXIMUM_U64_BUFFER_SIZE: u64 = u64::MAX;
    const UNKNOWN_VSOCK_OPTION: u64 = 99;
    use crate::uapi::{SOL_SOCKET, SO_ACCEPTCONN, SO_DOMAIN, SO_PROTOCOL, SO_TYPE};
    let _guard = vsock::tests::test_domain();
    let sock = VsockSocket::new();
    assert_eq!(sock.get_socket_option(SOL_SOCKET, SO_TYPE),
        Ok(crate::socket_args::SOCK_STREAM as i32));
    assert_eq!(sock.get_socket_option(SOL_SOCKET, SO_DOMAIN),
        Ok(crate::socket_args::AF_VSOCK as i32));
    assert_eq!(sock.get_socket_option(SOL_SOCKET, SO_PROTOCOL), Ok(0));
    assert_eq!(sock.get_socket_option(SOL_SOCKET, SO_ACCEPTCONN), Ok(0));
    sock.bind(crate::socket_args::AF_VSOCK as u16, 63_011, vsock::VMADDR_CID_ANY).unwrap();
    sock.listen().unwrap();
    assert_eq!(sock.get_socket_option(SOL_SOCKET, SO_ACCEPTCONN), Ok(1));
    assert_eq!(sock.get_socket_option(UNKNOWN_SOCKET_LEVEL, SO_TYPE),
        Err(crate::NetError::Enoprotoopt));
    assert_eq!(sock.get_socket_option(SOL_SOCKET, UNKNOWN_SOCKET_OPTION),
        Err(crate::NetError::Enoprotoopt));
    assert_eq!(sock.set_vsock_buffer_option(crate::uapi::SO_VM_SOCKETS_BUFFER_SIZE,
        ZERO_BUFFER_SIZE), Ok(()));
    assert_eq!(sock.get_vsock_buffer_option(crate::uapi::SO_VM_SOCKETS_BUFFER_SIZE),
        Ok(crate::uapi::VSOCK_DEFAULT_BUFFER_MIN_SIZE));
    assert_eq!(sock.set_vsock_buffer_option(crate::uapi::SO_VM_SOCKETS_BUFFER_SIZE,
        MAXIMUM_U64_BUFFER_SIZE), Ok(()));
    assert_eq!(sock.get_vsock_buffer_option(crate::uapi::SO_VM_SOCKETS_BUFFER_SIZE),
        Ok(crate::uapi::VSOCK_DEFAULT_BUFFER_MAX_SIZE));
    assert_eq!(sock.set_vsock_buffer_option(UNKNOWN_VSOCK_OPTION, ZERO_BUFFER_SIZE),
        Err(crate::NetError::Enoprotoopt));
    const CONFIGURED_BUFFER_SIZE: u64 = 128 * 1024;
    assert_eq!(sock.set_vsock_buffer_option(crate::uapi::SO_VM_SOCKETS_BUFFER_SIZE,
        CONFIGURED_BUFFER_SIZE), Ok(()));
    assert_eq!(sock.get_vsock_buffer_option(crate::uapi::SO_VM_SOCKETS_BUFFER_SIZE),
        Ok(CONFIGURED_BUFFER_SIZE));
    sock.release_file();
}
