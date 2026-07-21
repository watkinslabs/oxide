use super::*;

fn connected() -> (Arc<net::vsock_socket::VsockSocket>, Arc<net::vsock::VsockConn>) {
    let owner = net::vsock::VsockOwner::from_raw(0x0b00_0010).expect("test owner is nonzero");
    let conn = Arc::new(net::vsock::VsockConn::new(owner, 3, 62_010, 2, 1024,
        net::vsock::VsockState::Connected));
    let sock = Arc::new(net::vsock_socket::VsockSocket::new());
    *sock.kind.lock() = net::vsock_socket::VsockKind::Conn(conn.clone());
    (sock, conn)
}

fn connected_type(typ: u32) -> (Arc<net::vsock_socket::VsockSocket>, Arc<net::vsock::VsockConn>) {
    let (_, conn) = connected();
    let sock = Arc::new(net::vsock_socket::VsockSocket::new_type(typ));
    *sock.kind.lock() = net::vsock_socket::VsockKind::Conn(conn.clone());
    (sock, conn)
}

#[test]
fn zero_length_recvmsg_checks_connection_before_returning() {
    for typ in [net::socket_args::SOCK_STREAM, net::socket_args::SOCK_SEQPACKET] {
        let sock = Arc::new(net::vsock_socket::VsockSocket::new_type(typ));
        assert!(matches!(recvmsg_preflight(&sock, 0, 0), Err(error) if error == err(Errno::Enotconn)));
    }
}

#[test]
fn recvmsg_checks_connection_before_oob() {
    let sock = Arc::new(net::vsock_socket::VsockSocket::new());
    assert!(matches!(recvmsg_preflight(&sock, 1, net::uapi::MSG_OOB), Err(error) if error == err(Errno::Enotconn)));
    let (sock, _) = connected();
    assert!(matches!(recvmsg_preflight(&sock, 1, net::uapi::MSG_OOB), Err(error) if error == err(Errno::Eopnotsupp)));
}

#[test]
fn zero_length_stream_recvmsg_leaves_rx_queue_untouched() {
    let (sock, conn) = connected();
    conn.rx.lock().extend([b'a']);
    assert!(matches!(recvmsg_preflight(&sock, 0, 0), Ok(RecvmsgState::Empty)));
    assert_eq!(conn.rx.lock().len(), 1);
}

#[test]
fn zero_length_seqpacket_recvmsg_leaves_record_and_credit_untouched() {
    let (sock, conn) = connected_type(net::socket_args::SOCK_SEQPACKET);
    conn.seq_rx.lock().push_fragment(b"record", net::vsock::VIRTIO_VSOCK_SEQ_EOM);
    let credit_before = conn.tx.lock().credit.fwd_cnt;
    assert!(matches!(recvmsg_preflight(&sock, 0, 0), Ok(RecvmsgState::Empty)));
    assert_eq!(conn.seq_rx.lock().ready_count(), 1);
    assert_eq!(conn.tx.lock().credit.fwd_cnt, credit_before);
}

#[test]
fn local_read_shutdown_precedes_zero_length_recvmsg_return() {
    let (sock, _) = connected();
    sock.shutdown(net::uapi::ShutdownHow::Read).expect("connected shutdown read");
    assert!(matches!(recvmsg_preflight(&sock, 0, 0), Ok(RecvmsgState::Empty)));
}

#[test]
fn zero_length_recvmsg_rejects_a_connecting_endpoint() {
    let (sock, conn) = connected();
    *conn.st.lock() = net::vsock::VsockState::Connecting;
    assert!(matches!(recvmsg_preflight(&sock, 0, 0), Err(error) if error == err(Errno::Enotconn)));
}

#[test]
fn terminal_vsock_state_precedes_oob_and_zero_length_checks() {
    let (sock, conn) = connected();
    *conn.st.lock() = net::vsock::VsockState::Closed;
    assert!(matches!(recvmsg_preflight(&sock, 0, net::uapi::MSG_OOB), Ok(RecvmsgState::Empty)));
}

#[test]
fn recvmsg_retry_observes_local_read_shutdown() {
    let (sock, _) = connected();
    let result = recv_with_copy_inner(&sock, 1, 0, false, |_, _| Ok(0), |sock| {
        sock.shutdown(net::uapi::ShutdownHow::Read).expect("connected shutdown read");
    });
    assert_eq!(result, Ok(0));
}

#[test]
fn waitall_returns_copied_prefix_when_shutdown_wakes_receiver() {
    let (sock, conn) = connected();
    conn.rx.lock().extend([b'a', b'b']);
    let mut copied = alloc::vec::Vec::new();
    let result = recv_with_copy_inner(&sock, 4, MSG_WAITALL, false, |_, bytes| {
        copied.extend_from_slice(bytes);
        Ok(bytes.len())
    }, |sock| {
        sock.shutdown(net::uapi::ShutdownHow::Read).expect("connected shutdown read");
    });
    assert_eq!(result, Ok(2));
    assert_eq!(copied, b"ab");
}

#[test]
fn recvmsg_retry_observes_terminal_close_before_wait_arm() {
    let (sock, conn) = connected();
    let result = recv_with_copy_inner(&sock, 1, 0, false, |_, _| Ok(0), |_| {
        net::vsock::close(&conn);
    });
    assert_eq!(result, Ok(0));
    assert_eq!(*conn.st.lock(), net::vsock::VsockState::Closed);
}

#[test]
fn vsock_epipe_uses_the_shared_sigpipe_completion_owner() {
    let work = include_str!("../../../socket/src/send.rs");
    let sendto = include_str!("../044_sendto.rs");
    let sendmsg = include_str!("../046_sendmsg.rs");
    let write = include_str!("../001_write.rs");
    let writev = include_str!("../020_writev.rs");
    assert!(work.contains("fn complete("));
    assert!(work.contains("MSG_NOSIGNAL"));
    assert!(sendto.contains("socket::send_io("));
    assert!(sendmsg.contains("socket::send_io("));
    assert!(write.contains("socket::write("));
    assert!(writev.contains("socket::writev("));
}

#[test]
fn vsock_bind_syscall_only_validates_copies_and_calls_endpoint_owner() {
    let bind = include_str!("../049_bind.rs");
    assert!(bind.contains("require_sockaddr_vm(addrlen as usize)"));
    assert!(bind.contains("vs.bind(family, port, cid)"));
    assert!(!bind.contains("*vs.kind.lock()"));
}
