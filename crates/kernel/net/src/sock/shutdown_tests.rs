use super::*;

const LISTENER_PORT: u16 = 41_010;

fn listener_socket() -> (InetSocket, alloc::sync::Arc<crate::stack::TcpListenEntry>) {
    let owner = crate::net_ns::test_support::allocate_namespace();
    let sock = InetSocket::new_tcp_in(owner.clone());
    let stack = crate::global_stack();
    let bind = stack.tcp_reserve_in(owner.id().as_u64(), crate::IpAddr::V4(crate::Ipv4Addr::LOOPBACK),
        LISTENER_PORT, None, false, false, sock.owner_uid, false).expect("reserve listener bind");
    let listener = stack.tcp_listen_reserved(&bind).expect("publish listener");
    *sock.kind.lock() = SockKind::TcpListener(listener.clone());
    (sock, listener)
}

#[test]
fn tcp_listener_shutdown_matches_linux_direction_semantics() {
    let (write_only, listener) = listener_socket();
    assert_eq!(shutdown(&write_only, ShutdownHow::Write), Ok(()));
    assert!(!listener.is_closed());
    assert!(matches!(*write_only.kind.lock(), SockKind::TcpListener(_)));
    drop(listener);

    let (read_close, listener) = listener_socket();
    assert_eq!(shutdown(&read_close, ShutdownHow::Read), Ok(()));
    assert!(listener.is_closed());
    assert!(matches!(*read_close.kind.lock(), SockKind::TcpInit));
}
