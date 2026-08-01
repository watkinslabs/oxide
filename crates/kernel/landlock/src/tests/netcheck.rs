// Socket-address admission. The failure mode these guard against is answering
// a permission error where the network stack owes an argument error, which
// makes a sandboxed program look broken rather than confined.

use super::*;

fn v4(port: u16) -> Addr {
    Addr { sa_family: AF_INET, addrlen: SOCKADDR_IN_LEN, port, v4_wildcard: false }
}
fn v6(port: u16) -> Addr {
    Addr { sa_family: AF_INET6, addrlen: SOCKADDR_IN6_LEN, port, v4_wildcard: false }
}

#[test]
fn each_transport_asks_for_its_own_rights() {
    assert_eq!(bind_request(Proto::Tcp), Some(ACCESS_NET_BIND_TCP));
    assert_eq!(connect_request(Proto::Tcp), Some(ACCESS_NET_CONNECT_TCP));
    assert_eq!(bind_request(Proto::Udp), Some(ACCESS_NET_BIND_UDP));
    assert_eq!(connect_request(Proto::Udp), Some(ACCESS_NET_CONNECT_SEND_UDP));
    // A transport with no port rights is never filtered; asking for a right on
    // it would confine traffic the policy never named.
    assert_eq!(bind_request(Proto::Other), None);
    assert_eq!(connect_request(Proto::Other), None);
}

#[test]
fn an_address_too_short_to_hold_a_family_is_an_argument_error() {
    let a = Addr { sa_family: AF_INET, addrlen: 1, port: 80, v4_wildcard: false };
    assert_eq!(classify(ACCESS_NET_BIND_TCP, Op::Bind, a, AF_INET), Verdict::Fail(Errno::Einval));
}

#[test]
fn a_truncated_internet_address_is_an_argument_error() {
    let a = Addr { sa_family: AF_INET, addrlen: SOCKADDR_IN_LEN - 1, port: 80, v4_wildcard: false };
    assert_eq!(classify(ACCESS_NET_BIND_TCP, Op::Bind, a, AF_INET), Verdict::Fail(Errno::Einval));
    let a = Addr { sa_family: AF_INET6, addrlen: SOCKADDR_IN6_LEN - 1, port: 80, v4_wildcard: false };
    assert_eq!(classify(ACCESS_NET_BIND_TCP, Op::Bind, a, AF_INET6), Verdict::Fail(Errno::Einval));
}

#[test]
fn a_well_formed_address_yields_its_port() {
    assert_eq!(classify(ACCESS_NET_BIND_TCP, Op::Bind, v4(443), AF_INET),
               Verdict::CheckPort(443));
    assert_eq!(classify(ACCESS_NET_CONNECT_TCP, Op::Connect, v6(443), AF_INET6),
               Verdict::CheckPort(443));
    assert_eq!(classify(ACCESS_NET_BIND_UDP, Op::Bind, v4(69), AF_INET),
               Verdict::CheckPort(69));
    assert_eq!(classify(ACCESS_NET_CONNECT_SEND_UDP, Op::Send, v4(53), AF_INET),
               Verdict::CheckPort(53));
}

#[test]
fn a_family_the_check_does_not_understand_is_not_filtered() {
    let a = Addr { sa_family: 1, addrlen: 110, port: 0, v4_wildcard: false };
    assert_eq!(classify(ACCESS_NET_BIND_TCP, Op::Bind, a, 1), Verdict::Allow);
}

#[test]
fn dropping_a_peer_association_is_always_allowed() {
    // Connecting to the unspecified family dissolves the association, which is
    // a privilege drop; refusing it would make a sandbox harder to tighten.
    let a = Addr { sa_family: AF_UNSPEC, addrlen: SOCKADDR_IN_LEN, port: 0, v4_wildcard: true };
    assert_eq!(classify(ACCESS_NET_CONNECT_TCP, Op::Connect, a, AF_INET), Verdict::Allow);
    assert_eq!(classify(ACCESS_NET_CONNECT_TCP, Op::Connect, a, AF_INET6), Verdict::Allow);
    // The same is true of a datagram socket dropping its preset peer.
    assert_eq!(classify(ACCESS_NET_CONNECT_SEND_UDP, Op::Connect, a, AF_INET), Verdict::Allow);
    assert_eq!(classify(ACCESS_NET_CONNECT_SEND_UDP, Op::Connect, a, AF_INET6), Verdict::Allow);
}

#[test]
fn sending_to_an_unspecified_family_is_denied_on_an_ipv6_socket() {
    // The socket's family can change under this check, and an IPv4 socket reads
    // the same address as a real destination — so the send cannot be waved
    // through the way a connect can.
    let a = Addr { sa_family: AF_UNSPEC, addrlen: SOCKADDR_IN_LEN, port: 0, v4_wildcard: true };
    assert_eq!(classify(ACCESS_NET_CONNECT_SEND_UDP, Op::Send, a, AF_INET6),
               Verdict::Fail(Errno::Eacces));
    // On an IPv4 socket it stands in for IPv4 and reaches the rule lookup.
    assert_eq!(classify(ACCESS_NET_CONNECT_SEND_UDP, Op::Send, a, AF_INET),
               Verdict::CheckPort(0));
}

#[test]
fn an_unspecified_bind_stands_in_for_a_wildcard_ipv4_bind_only() {
    let wild = Addr { sa_family: AF_UNSPEC, addrlen: SOCKADDR_IN_LEN, port: 8080, v4_wildcard: true };
    assert_eq!(classify(ACCESS_NET_BIND_TCP, Op::Bind, wild, AF_INET), Verdict::CheckPort(8080));
    assert_eq!(classify(ACCESS_NET_BIND_UDP, Op::Bind, wild, AF_INET), Verdict::CheckPort(8080));

    // A non-wildcard address with an unspecified family is not supported.
    let named = Addr { v4_wildcard: false, ..wild };
    assert_eq!(classify(ACCESS_NET_BIND_TCP, Op::Bind, named, AF_INET),
               Verdict::Fail(Errno::Eafnosupport));

    // An IPv6 socket never accepts it, and reports the length problem first.
    let short = Addr { sa_family: AF_UNSPEC, addrlen: SOCKADDR_IN_LEN, port: 0, v4_wildcard: true };
    assert_eq!(classify(ACCESS_NET_BIND_TCP, Op::Bind, short, AF_INET6), Verdict::Fail(Errno::Einval));
    let long = Addr { addrlen: SOCKADDR_IN6_LEN, ..short };
    assert_eq!(classify(ACCESS_NET_BIND_TCP, Op::Bind, long, AF_INET6),
               Verdict::Fail(Errno::Eafnosupport));
    assert_eq!(classify(ACCESS_NET_BIND_UDP, Op::Bind, long, AF_INET6),
               Verdict::Fail(Errno::Eafnosupport));
}

#[test]
fn a_family_that_disagrees_with_the_socket_still_reaches_the_port_rules() {
    // The network stack owes the family answer. Producing one here would change
    // a program's errno by the mere presence of a policy, and would hide a port
    // the policy was asked to filter.
    assert_eq!(classify(ACCESS_NET_CONNECT_TCP, Op::Connect, v4(80), AF_INET6),
               Verdict::CheckPort(80));
    assert_eq!(classify(ACCESS_NET_BIND_TCP, Op::Bind, v6(80), AF_INET),
               Verdict::CheckPort(80));
}

#[test]
fn port_zero_is_a_real_port_for_rule_purposes() {
    // Binding port 0 asks the kernel for an ephemeral port; a policy naming
    // port 0 is how that is permitted, so it must reach the rule lookup.
    assert_eq!(classify(ACCESS_NET_BIND_TCP, Op::Bind, v4(0), AF_INET), Verdict::CheckPort(0));
}

#[test]
fn an_address_is_read_family_first_then_a_network_order_port() {
    let mut b = [0u8; SOCKADDR_IN_LEN];
    b[0..2].copy_from_slice(&AF_INET.to_le_bytes());
    b[2..4].copy_from_slice(&443u16.to_be_bytes());
    let a = Addr::parse(&b);
    assert_eq!(a.sa_family, AF_INET);
    assert_eq!(a.port, 443);
    assert_eq!(a.addrlen, SOCKADDR_IN_LEN);
    // An all-zero IPv4 address is the wildcard.
    assert!(a.v4_wildcard);
    b[4] = 127;
    assert!(!Addr::parse(&b).v4_wildcard);
}

#[test]
fn a_buffer_too_short_for_a_field_reads_it_as_zero_and_is_then_rejected() {
    let a = Addr::parse(&[]);
    assert_eq!(a.addrlen, 0);
    assert_eq!(classify(ACCESS_NET_BIND_TCP, Op::Bind, a, AF_INET), Verdict::Fail(Errno::Einval));
}
