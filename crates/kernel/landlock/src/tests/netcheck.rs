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
fn only_stream_transports_carry_port_rules_at_this_abi_level() {
    assert_eq!(bind_request(Proto::Tcp), Some(ACCESS_NET_BIND_TCP));
    assert_eq!(connect_request(Proto::Tcp), Some(ACCESS_NET_CONNECT_TCP));
    // Datagram rights are a later ABI level; claiming them here would let a
    // caller believe its datagram traffic was confined.
    assert_eq!(bind_request(Proto::Udp), None);
    assert_eq!(connect_request(Proto::Udp), None);
    assert_eq!(bind_request(Proto::Other), None);
    assert_eq!(connect_request(Proto::Other), None);
}

#[test]
fn an_address_too_short_to_hold_a_family_is_an_argument_error() {
    let a = Addr { sa_family: AF_INET, addrlen: 1, port: 80, v4_wildcard: false };
    assert_eq!(classify(ACCESS_NET_BIND_TCP, false, a, AF_INET), Verdict::Fail(Errno::Einval));
}

#[test]
fn a_truncated_internet_address_is_an_argument_error() {
    let a = Addr { sa_family: AF_INET, addrlen: SOCKADDR_IN_LEN - 1, port: 80, v4_wildcard: false };
    assert_eq!(classify(ACCESS_NET_BIND_TCP, false, a, AF_INET), Verdict::Fail(Errno::Einval));
    let a = Addr { sa_family: AF_INET6, addrlen: SOCKADDR_IN6_LEN - 1, port: 80, v4_wildcard: false };
    assert_eq!(classify(ACCESS_NET_BIND_TCP, false, a, AF_INET6), Verdict::Fail(Errno::Einval));
}

#[test]
fn a_well_formed_address_yields_its_port() {
    assert_eq!(classify(ACCESS_NET_BIND_TCP, false, v4(443), AF_INET),
               Verdict::CheckPort(443));
    assert_eq!(classify(ACCESS_NET_CONNECT_TCP, true, v6(443), AF_INET6),
               Verdict::CheckPort(443));
}

#[test]
fn a_family_the_check_does_not_understand_is_not_filtered() {
    let a = Addr { sa_family: 1, addrlen: 110, port: 0, v4_wildcard: false };
    assert_eq!(classify(ACCESS_NET_BIND_TCP, false, a, 1), Verdict::Allow);
}

#[test]
fn dropping_a_peer_association_is_always_allowed() {
    // Connecting to the unspecified family dissolves the association, which is
    // a privilege drop; refusing it would make a sandbox harder to tighten.
    let a = Addr { sa_family: AF_UNSPEC, addrlen: SOCKADDR_IN_LEN, port: 0, v4_wildcard: true };
    assert_eq!(classify(ACCESS_NET_CONNECT_TCP, true, a, AF_INET), Verdict::Allow);
    assert_eq!(classify(ACCESS_NET_CONNECT_TCP, true, a, AF_INET6), Verdict::Allow);
}

#[test]
fn an_unspecified_bind_stands_in_for_a_wildcard_ipv4_bind_only() {
    let wild = Addr { sa_family: AF_UNSPEC, addrlen: SOCKADDR_IN_LEN, port: 8080, v4_wildcard: true };
    assert_eq!(classify(ACCESS_NET_BIND_TCP, false, wild, AF_INET), Verdict::CheckPort(8080));

    // A non-wildcard address with an unspecified family is not supported.
    let named = Addr { v4_wildcard: false, ..wild };
    assert_eq!(classify(ACCESS_NET_BIND_TCP, false, named, AF_INET),
               Verdict::Fail(Errno::Eafnosupport));

    // An IPv6 socket never accepts it, and reports the length problem first.
    let short = Addr { sa_family: AF_UNSPEC, addrlen: SOCKADDR_IN_LEN, port: 0, v4_wildcard: true };
    assert_eq!(classify(ACCESS_NET_BIND_TCP, false, short, AF_INET6), Verdict::Fail(Errno::Einval));
    let long = Addr { addrlen: SOCKADDR_IN6_LEN, ..short };
    assert_eq!(classify(ACCESS_NET_BIND_TCP, false, long, AF_INET6),
               Verdict::Fail(Errno::Eafnosupport));
}

#[test]
fn a_family_that_disagrees_with_the_socket_is_an_argument_error() {
    // Reporting a denial here would blame the sandbox for the caller's bug.
    assert_eq!(classify(ACCESS_NET_CONNECT_TCP, true, v4(80), AF_INET6),
               Verdict::Fail(Errno::Einval));
    assert_eq!(classify(ACCESS_NET_BIND_TCP, false, v6(80), AF_INET),
               Verdict::Fail(Errno::Einval));
}

#[test]
fn port_zero_is_a_real_port_for_rule_purposes() {
    // Binding port 0 asks the kernel for an ephemeral port; a policy naming
    // port 0 is how that is permitted, so it must reach the rule lookup.
    assert_eq!(classify(ACCESS_NET_BIND_TCP, false, v4(0), AF_INET), Verdict::CheckPort(0));
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
    assert_eq!(classify(ACCESS_NET_BIND_TCP, false, a, AF_INET), Verdict::Fail(Errno::Einval));
}
