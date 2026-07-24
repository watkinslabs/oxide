use super::*;

const LISTENER_PORT: u16 = 41_010;
const PACKET_RAW: u8 = crate::socket_args::SOCK_RAW as u8;

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

fn packet_socket() -> InetSocket {
    InetSocket::new_packet_in(crate::eth_p::ALL, PACKET_RAW,
        crate::net_ns::test_support::allocate_namespace())
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

#[test]
fn packet_shutdown_is_linux_sock_no_shutdown_for_each_direction() {
    let sock = packet_socket();
    for how in [ShutdownHow::Read, ShutdownHow::Write, ShutdownHow::ReadWrite] {
        assert_eq!(shutdown(&sock, how), Err(NetError::Eopnotsupp));
        assert!(!sock.read_shut.load(core::sync::atomic::Ordering::Acquire));
        assert!(!sock.write_shut.load(core::sync::atomic::Ordering::Acquire));
    }
}

fn assert_latched_after_enotconn(sock: &InetSocket) {
    assert_eq!(shutdown(sock, ShutdownHow::ReadWrite), Err(NetError::Enotconn));
    assert!(sock.read_shut.load(core::sync::atomic::Ordering::Acquire));
    assert!(sock.write_shut.load(core::sync::atomic::Ordering::Acquire));
}

#[test]
fn unconnected_inet_protocols_latch_before_returning_enotconn() {
    let owner = crate::net_ns::test_support::allocate_namespace();
    assert_latched_after_enotconn(&InetSocket::new_udp_in(owner.clone()));
    assert_latched_after_enotconn(&InetSocket::new_tcp_in(owner.clone()));
    assert_latched_after_enotconn(&InetSocket::new_raw4_in(
        crate::addr::IpProto::Icmp as u8, owner.clone()));
    assert_latched_after_enotconn(&InetSocket::new_raw6_in(
        crate::addr::IpProto::Icmpv6 as u8, owner));
}

#[test]
fn unix_listener_shutdown_latches_without_closing_listener() {
    let owner = crate::net_ns::test_support::allocate_namespace();
    let sock = InetSocket::new_unix_in(owner);
    let listener = crate::UnixListener::new(
        crate::UnixAddr::from_abstract_or_test_path("shutdown-listener".into()));
    let backlog = crate::sysctl::DEFAULT_SOMAXCONN as i32;
    listener.listen(backlog, crate::sysctl::DEFAULT_SOMAXCONN);
    *sock.kind.lock() = SockKind::UnixListener(listener.clone());

    assert_eq!(shutdown(&sock, ShutdownHow::ReadWrite), Ok(()));
    assert_eq!(listener.poll_mask() & vfs::POLL_HUP, vfs::POLL_HUP);
    assert!(listener.is_listening());
}

const INVALID_SHUTDOWN_DIRECTION: u32 = u32::MAX;

fn deny_shutdown(_context: security::network::Context) -> security::network::Verdict {
    security::network::Verdict::Deny
}

#[test]
fn shutdown_security_precedes_raw_direction_validation() {
    let owner = crate::net_ns::test_support::allocate_namespace();
    let id = crate::net_ns::namespace_id(&owner);
    let sock = InetSocket::new_udp_in(owner);
    assert_eq!(security::network::install(id, security::network::Operation::Shutdown,
        deny_shutdown), None);
    assert_eq!(shutdown_raw(&sock, INVALID_SHUTDOWN_DIRECTION), Err(NetError::Eacces));
    assert_eq!(security::network::counters(id, security::network::Operation::Shutdown), Some((0, 1)));
    assert!(security::network::remove(id, security::network::Operation::Shutdown).is_some());
}

// Linux `__sys_shutdown_sock` maps any `how` outside {0,1,2} to EINVAL once
// security admission has passed (`t_shutdown` badhow cases). A datagram socket
// has no listener/connection state, isolating the direction check.
#[test]
fn invalid_shutdown_direction_returns_einval_after_admission() {
    let sock = InetSocket::new_udp_in(crate::net_ns::test_support::allocate_namespace());
    assert_eq!(shutdown_raw(&sock, 3), Err(NetError::Einval));
    assert_eq!(shutdown_raw(&sock, INVALID_SHUTDOWN_DIRECTION), Err(NetError::Einval));
    // A valid direction on the same unconnected datagram socket still reaches
    // its protocol arm and returns ENOTCONN, proving the EINVAL came from the
    // direction check rather than an earlier reject.
    assert_eq!(shutdown_raw(&sock, ShutdownHow::Read as u32), Err(NetError::Enotconn));
}

// A repeated write shutdown on an already-write-closed socket still succeeds
// (`t_shutdown` double_shut_wr) — the latch is idempotent, not an error.
#[test]
fn repeated_write_shutdown_is_idempotent() {
    let sock = InetSocket::new_udp_in(crate::net_ns::test_support::allocate_namespace());
    // Unconnected UDP latches the direction then reports ENOTCONN both times.
    assert_eq!(shutdown_raw(&sock, ShutdownHow::Write as u32), Err(NetError::Enotconn));
    assert!(sock.write_shut.load(core::sync::atomic::Ordering::Acquire));
    assert_eq!(shutdown_raw(&sock, ShutdownHow::Write as u32), Err(NetError::Enotconn));
    assert!(sock.write_shut.load(core::sync::atomic::Ordering::Acquire));
}
