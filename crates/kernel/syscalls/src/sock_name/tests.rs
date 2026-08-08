// Behaviour of the `*_getname` decisions, driven against real sockets: which
// bytes each family/state answers with, and which errno a socket that owns no
// such name reports. Every assertion here is on a returned value, never on the
// text of the shim that calls it.

use super::*;
use core::sync::atomic::Ordering;
use net::sock::{AF_INET, AF_INET6, AF_PACKET, AF_UNIX};

fn family_of(sa: &EncodedSockaddr) -> u16 {
    u16::from_ne_bytes([sa.as_bytes()[0], sa.as_bytes()[1]])
}

fn udp4() -> Arc<InetSocket> {
    let s = InetSocket::new_udp();
    s.family.store(AF_INET, Ordering::Release);
    Arc::new(s)
}

fn udp6() -> Arc<InetSocket> { Arc::new(InetSocket::new_udp6()) }

// --- peer name -----------------------------------------------------------

#[test]
fn packet_peername_reports_the_packet_owner_error_not_a_synthesized_tuple() {
    // `packet_getname(peer=1)` is EOPNOTSUPP. An AF_PACKET socket carrying a
    // stale generic peer tuple must still refuse rather than answer from it.
    let sock = Arc::new(InetSocket::new_packet(net::eth_p::ALL, 3));
    assert_eq!(sock.family.load(Ordering::Acquire), AF_PACKET);
    *sock.peer.lock() = Some((net::Ipv4Addr::from_u32(0x7f00_0001), 80));
    assert_eq!(peer_sockaddr(&sock).map(|_| ()), Err(Errno::Eopnotsupp));
    // The same tuple on a generic INET socket DOES answer — so the refusal is
    // the AF_PACKET rule, not an empty-state accident.
    let inet = udp4();
    *inet.peer.lock() = Some((net::Ipv4Addr::from_u32(0x7f00_0001), 80));
    assert_eq!(family_of(&peer_sockaddr(&inet).expect("inet peer answers")), AF_INET);
}

#[test]
fn unconnected_inet_peername_is_enotconn() {
    assert_eq!(peer_sockaddr(&udp4()).map(|_| ()), Err(Errno::Enotconn));
    assert_eq!(peer_sockaddr(&udp6()).map(|_| ()), Err(Errno::Enotconn));
}

#[test]
fn ipv6_peername_answers_from_the_native_v6_tuple() {
    let sock = udp6();
    let ip = net::Ipv6Addr([0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    *sock.peer6.lock() = Some((ip, 443));
    let sa = peer_sockaddr(&sock).expect("native v6 peer answers");
    assert_eq!(family_of(&sa), AF_INET6);
    assert_eq!(sa.len(), 28);
    assert_eq!(&sa.as_bytes()[2..4], &443u16.to_be_bytes());
    assert_eq!(&sa.as_bytes()[8..24], &ip.0);
}

/// `sin6_flowinfo` is inert in a reported name until the socket asked to send
/// one: a caller who never set `IPV6_FLOWINFO_SEND` sees zero however much
/// flow information the connection settled. With the option set, the peer name
/// carries exactly what was settled, and the LOCAL name still carries none —
/// the reference reports flow information in the peer branch alone.
#[test]
fn a_peer_name_carries_flow_information_only_for_a_socket_that_sends_one() {
    const SETTLED: u32 = 0x0abc_de12;
    let sock = udp6();
    let ip = net::Ipv6Addr([0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7]);
    *sock.peer6.lock() = Some((ip, 443));
    sock.opts.ipv6.set_flow_label(SETTLED);

    let quiet = peer_sockaddr(&sock).expect("peer answers");
    assert_eq!(&quiet.as_bytes()[4..8], &[0u8; 4]);

    sock.opts.ipv6.set_flag(net::sock_opts::sol_ipv6::flag::SNDFLOW, true);
    let flowed = peer_sockaddr(&sock).expect("peer answers");
    assert_eq!(&flowed.as_bytes()[4..8], &SETTLED.to_be_bytes());
    // The address and port the name reports are untouched by the word.
    assert_eq!(&flowed.as_bytes()[8..24], &ip.0);
    assert_eq!(&flowed.as_bytes()[2..4], &443u16.to_be_bytes());
    // A local name never carries it, whatever the option says.
    assert_eq!(&local_sockaddr(&sock).as_bytes()[4..8], &[0u8; 4]);
}

#[test]
fn ipv6_peername_falls_through_to_the_v4_mapped_tuple() {
    // A dual-stack socket that connected to an IPv4 peer holds its peer in
    // the IPv4 tuple only. `inet6_getname` still answers ::ffff:a.b.c.d — an
    // empty `peer6` must NOT short-circuit to ENOTCONN.
    let sock = udp6();
    assert!(sock.peer6.lock().is_none());
    *sock.peer.lock() = Some((net::Ipv4Addr::from_u32(0x7f00_0001), 8080));
    let sa = peer_sockaddr(&sock).expect("a v4-mapped peer is still a peer");
    assert_eq!(family_of(&sa), AF_INET6);
    assert_eq!(&sa.as_bytes()[2..4], &8080u16.to_be_bytes());
    assert_eq!(&sa.as_bytes()[8..24],
        &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1]);
}

#[test]
fn ipv6_peername_carries_the_link_local_scope_id() {
    let sock = udp6();
    let link_local = net::Ipv6Addr([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    sock.opts.base.bound_ifindex.store(7, Ordering::Release);
    *sock.peer6.lock() = Some((link_local, 22));
    let scoped = peer_sockaddr(&sock).expect("link-local peer answers");
    assert_eq!(&scoped.as_bytes()[24..28], &7u32.to_ne_bytes(),
        "a link-local peer name carries the bound ifindex as sin6_scope_id");
    // A global peer on the same socket carries no scope id.
    let global = net::Ipv6Addr([0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    *sock.peer6.lock() = Some((global, 22));
    let unscoped = peer_sockaddr(&sock).expect("global peer answers");
    assert_eq!(&unscoped.as_bytes()[24..28], &0u32.to_ne_bytes());
}

#[test]
fn tcp_peername_checks_transport_state_before_the_tuple() {
    // A half-open client already holds its destination tuple, so answering
    // from the tuple alone would name a peer that is not connected yet.
    // `inet_getname` demands an established transport first.
    let local = net::Endpoint { ip: net::IpAddr::V4(net::Ipv4Addr::LOOPBACK), port: 40006 };
    let remote = net::Endpoint { ip: net::IpAddr::V4(net::Ipv4Addr::LOOPBACK), port: 80 };
    let mut conn = net::TcpConn::new_client(local, remote, 5);
    conn.active_open().expect("a fresh client enters SYN-SENT");
    let entry = alloc::sync::Arc::new(net::stack::TcpEntry::new(conn));
    let sock = udp4();
    *sock.peer.lock() = Some((net::Ipv4Addr::LOOPBACK, 80));
    *sock.kind.lock() = net::sock::SockKind::TcpConn(entry.clone());
    assert_eq!(peer_sockaddr(&sock).map(|_| ()), Err(Errno::Enotconn),
        "a SYN-SENT socket has no peer name even with the tuple present");
    // The same socket, established, answers from that tuple.
    entry.conn.lock().state = net::tcp_state::TcpState::Established;
    let sa = peer_sockaddr(&sock).expect("an established peer has a name");
    assert_eq!(&sa.as_bytes()[2..4], &80u16.to_be_bytes());
    // A closed transport loses the name again.
    entry.conn.lock().state = net::tcp_state::TcpState::Closed;
    assert_eq!(peer_sockaddr(&sock).map(|_| ()), Err(Errno::Enotconn));
}

#[test]
fn unix_peername_reports_the_peer_path_and_unnamed_peers_are_family_only() {
    let pair = net::UnixPair::new();
    let a = InetSocket::new_unix();
    a.family.store(AF_UNIX, Ordering::Release);
    *a.kind.lock() = net::sock::SockKind::Unix(pair.clone(), net::UnixEnd::A);
    let a = Arc::new(a);
    // A socketpair-shaped connection has no bound name on either end, which
    // `unix_getname` reports as the bare family (addrlen == 2) — NOT ENOTCONN.
    let sa = peer_sockaddr(&a).expect("a connected AF_UNIX end is connected");
    assert_eq!(sa.len(), 2);
    assert_eq!(family_of(&sa), AF_UNIX);
    // An unconnected AF_UNIX socket is ENOTCONN.
    let lone = InetSocket::new_unix();
    lone.family.store(AF_UNIX, Ordering::Release);
    assert_eq!(peer_sockaddr(&Arc::new(lone)).map(|_| ()), Err(Errno::Enotconn));
}

// --- local name ----------------------------------------------------------

#[test]
fn packet_sockname_answers_with_sockaddr_ll_not_the_inet_tuple() {
    let sock = Arc::new(InetSocket::new_packet(net::eth_p::IPV4, 3));
    let sa = local_sockaddr(&sock);
    assert_eq!(family_of(&sa), AF_PACKET, "AF_PACKET names its link layer");
    // `packet_getname` returns offsetof(sockaddr_ll, sll_addr) + sll_halen;
    // an unbound socket has no hardware address, so exactly the 12-byte base.
    assert_eq!(sa.len(), 12);
    assert_eq!(&sa.as_bytes()[2..4], &net::eth_p::IPV4.to_be_bytes(),
        "sll_protocol is the bound protocol in network order");
}

#[test]
fn ipv4_sockname_reports_the_bound_tuple() {
    let sock = udp4();
    *sock.local_ip.lock() = net::Ipv4Addr::from_u32(0x7f00_0001);
    *sock.local_port.lock() = Some(1234);
    let sa = local_sockaddr(&sock);
    assert_eq!(family_of(&sa), AF_INET);
    assert_eq!(sa.len(), 16);
    assert_eq!(&sa.as_bytes()[2..4], &1234u16.to_be_bytes());
    assert_eq!(&sa.as_bytes()[4..8], &0x7f00_0001u32.to_be_bytes());
}

#[test]
fn unbound_inet_sockname_is_the_wildcard_tuple_not_an_error() {
    let sa = local_sockaddr(&udp4());
    assert_eq!(family_of(&sa), AF_INET);
    assert_eq!(&sa.as_bytes()[2..8], &[0u8; 6], "port 0, 0.0.0.0");
}

#[test]
fn ipv6_sockname_consults_the_v4_mapped_source() {
    // A dual-stack socket whose live local address is in the IPv4 tuple must
    // render ::ffff:a.b.c.d; reading `local_ip6` unconditionally reported
    // [::] for every such socket.
    let sock = udp6();
    assert!(sock.local_ip6.lock().is_unspecified());
    *sock.local_ip.lock() = net::Ipv4Addr::from_u32(0x0a00_0005);
    *sock.local_port.lock() = Some(4242);
    let sa = local_sockaddr(&sock);
    assert_eq!(family_of(&sa), AF_INET6);
    assert_eq!(&sa.as_bytes()[8..24],
        &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 5]);
    assert_eq!(&sa.as_bytes()[2..4], &4242u16.to_be_bytes());
    // A socket with a real v6 local address reports that instead.
    let native = net::Ipv6Addr([0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9]);
    *sock.local_ip6.lock() = native;
    assert_eq!(&local_sockaddr(&sock).as_bytes()[8..24], &native.0);
}

#[test]
fn ipv6_sockname_carries_the_link_local_scope_id() {
    let sock = udp6();
    let link_local = net::Ipv6Addr([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    *sock.local_ip6.lock() = link_local;
    sock.opts.base.bound_ifindex.store(3, Ordering::Release);
    assert_eq!(&local_sockaddr(&sock).as_bytes()[24..28], &3u32.to_ne_bytes());
    let global = net::Ipv6Addr([0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    *sock.local_ip6.lock() = global;
    assert_eq!(&local_sockaddr(&sock).as_bytes()[24..28], &0u32.to_ne_bytes());
}

#[test]
fn unix_sockname_reports_the_bound_path_with_its_trailing_nul() {
    let sock = InetSocket::new_unix();
    sock.family.store(AF_UNIX, Ordering::Release);
    *sock.unix_bound.lock() = Some(net::UnixListener::new(
        net::UnixAddr::from_abstract_or_test_path(alloc::string::String::from("/run/x"))));
    let sa = local_sockaddr(&Arc::new(sock));
    assert_eq!(family_of(&sa), AF_UNIX);
    assert_eq!(sa.len(), 2 + 6 + 1, "sun_path counts its terminator");
    assert_eq!(&sa.as_bytes()[2..8], b"/run/x");
}
