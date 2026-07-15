use super::*;

fn connected() -> (Arc<net::vsock_socket::VsockSocket>, Arc<net::vsock::VsockConn>) {
    let owner = net::vsock::VsockOwner::from_raw(0x0b00_0010).expect("test owner is nonzero");
    let conn = Arc::new(net::vsock::VsockConn::new(owner, 3, 62_010, 2, 1024,
        net::vsock::VsockState::Connected));
    let sock = Arc::new(net::vsock_socket::VsockSocket::new());
    *sock.kind.lock() = net::vsock_socket::VsockKind::Conn(conn.clone());
    (sock, conn)
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
