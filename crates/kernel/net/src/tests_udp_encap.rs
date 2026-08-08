// `UDP_ENCAP` receive-side contract: which datagrams an encapsulation socket
// never sees, and which fall through to ordinary delivery.
//
// The decision lives in an ungated module, so the classification cases below
// call it directly; the last two tests drive the real IPv4 and IPv6 receive
// paths to prove the stack consults it before queueing.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicI32, Ordering};
use sync::{Socket as StackLockClass, Spinlock};

use crate::sock_opts::sol_udp::encap::{EncapConsumed, EncapVerdict, rx_verdict};
use crate::sock_opts::sol_udp::uapi::*;
use crate::{Ipv4Addr, Ipv6Addr, NetStack, SocketError};

const PORT: u16 = 4_500;
const SOURCE_PORT: u16 = 4_501;

/// Every datagram shape the classifier distinguishes, by name.
fn shapes() -> [(&'static str, alloc::vec::Vec<u8>); 7] {
    [
        ("empty", alloc::vec![]),
        ("keepalive", alloc::vec![0xff]),
        ("one-byte-not-keepalive", alloc::vec![0xfe]),
        ("short-control", alloc::vec![1, 2, 3, 4, 5, 6, 7, 8]),
        ("marked-control", { let mut v = alloc::vec![0u8; 4]; v.extend_from_slice(b"IKEBODY!!"); v }),
        ("security-payload", { let mut v = alloc::vec![0u8; 9]; v[0] = 0x11; v[3] = 0x22; v }),
        ("long-security-payload", alloc::vec![0xab; 128]),
    ]
}

#[test]
fn encap_disabled_delivers_every_datagram_shape() {
    for (name, body) in shapes() {
        assert_eq!(rx_verdict(UDP_ENCAP_NONE, &body), EncapVerdict::Deliver,
            "a socket with no encapsulation identity delivers {name}");
    }
}

#[test]
fn tunnel_identity_alone_installs_no_handler_and_delivers() {
    // The tunnel identity is a label a tunnel subsystem consults when it
    // installs its own receive handler. Set through the plain socket option
    // it installs nothing, so ordinary delivery is untouched — including for
    // bodies the security handler would have eaten.
    for (name, body) in shapes() {
        assert_eq!(rx_verdict(UDP_ENCAP_L2TPINUDP, &body), EncapVerdict::Deliver,
            "the tunnel identity has no handler and delivers {name}");
    }
}

#[test]
fn security_encap_eats_the_nat_keepalive() {
    assert_eq!(rx_verdict(UDP_ENCAP_ESPINUDP, &[0xff]),
        EncapVerdict::Consumed(EncapConsumed::Keepalive));
    // The keepalive is exactly one byte of exactly that value.
    assert_eq!(rx_verdict(UDP_ENCAP_ESPINUDP, &[0xfe]), EncapVerdict::Deliver);
    assert_eq!(rx_verdict(UDP_ENCAP_ESPINUDP, &[0xff, 0xff]), EncapVerdict::Deliver);
    assert_eq!(rx_verdict(UDP_ENCAP_ESPINUDP, &[]), EncapVerdict::Deliver);
}

#[test]
fn security_encap_passes_key_exchange_control_packets() {
    // Nothing longer than the payload header can be a payload.
    for len in 0..=8usize {
        let body = alloc::vec![0x5a; len];
        if len == 1 { continue; }
        assert_eq!(rx_verdict(UDP_ENCAP_ESPINUDP, &body), EncapVerdict::Deliver,
            "a {len}-byte body is a control packet");
    }
    // Longer than the header, but carrying the all-zero non-payload marker.
    let mut marked = alloc::vec![0u8; 4];
    marked.extend_from_slice(b"key exchange body");
    assert_eq!(rx_verdict(UDP_ENCAP_ESPINUDP, &marked), EncapVerdict::Deliver);
}

#[test]
fn security_encap_consumes_the_encapsulated_payload() {
    // Longer than the payload header and not marked: a payload. This tree has
    // no transform subsystem, so the handler consumes it and it goes no
    // further — the same outcome the reference reaches when no security
    // association matches.
    let mut payload = alloc::vec![0u8; 9];
    payload[0] = 0x11;
    assert_eq!(rx_verdict(UDP_ENCAP_ESPINUDP, &payload),
        EncapVerdict::Consumed(EncapConsumed::SecurityPayload));
    assert_eq!(rx_verdict(UDP_ENCAP_ESPINUDP, &[0xab; 128]),
        EncapVerdict::Consumed(EncapConsumed::SecurityPayload));
    // The length test is strict: a body exactly the header's length is a
    // control packet even with a non-zero marker word.
    assert_eq!(rx_verdict(UDP_ENCAP_ESPINUDP, &[0xab; 8]), EncapVerdict::Deliver);
    // The marker word is only the first four bytes.
    let mut marker_only = alloc::vec![0u8; 16];
    marker_only[4] = 0x99;
    assert_eq!(rx_verdict(UDP_ENCAP_ESPINUDP, &marker_only), EncapVerdict::Deliver);
}

#[test]
fn identities_the_option_rejects_install_no_handler() {
    for id in [UDP_ENCAP_ESPINUDP_NON_IKE, UDP_ENCAP_GTP0, UDP_ENCAP_GTP1U,
               UDP_ENCAP_RXRPC, TCP_ENCAP_ESPINTCP, UDP_ENCAP_OVPNINUDP, -1, 4_242] {
        assert_eq!(rx_verdict(id, &[0xab; 128]), EncapVerdict::Deliver,
            "identity {id} has no receive handler");
    }
}

#[test]
fn only_three_identities_are_accepted_by_the_option() {
    let opts = crate::sock_opts::sol_udp::UdpOpts::default();
    for id in [UDP_ENCAP_NONE, UDP_ENCAP_ESPINUDP, UDP_ENCAP_L2TPINUDP] {
        crate::sock_opts::sol_udp::set(&opts, UDP_ENCAP, id).unwrap();
        assert_eq!(crate::sock_opts::sol_udp::get(&opts, UDP_ENCAP).unwrap(), id);
    }
    for id in [UDP_ENCAP_ESPINUDP_NON_IKE, UDP_ENCAP_GTP0, UDP_ENCAP_GTP1U,
               UDP_ENCAP_RXRPC, TCP_ENCAP_ESPINTCP, UDP_ENCAP_OVPNINUDP, -1] {
        assert_eq!(crate::sock_opts::sol_udp::set(&opts, UDP_ENCAP, id),
            Err(crate::NetError::Enoprotoopt), "identity {id} is not an encapsulation the stack claims");
    }
}

fn flag(v: i32) -> Arc<AtomicI32> { Arc::new(AtomicI32::new(v)) }

#[test]
fn ipv4_receive_path_consumes_the_payload_and_delivers_the_control_packet() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, loopback) = stack.register_loopback();
    let endpoint = stack.bind_udp_socket(
        Ipv4Addr::LOOPBACK, PORT, None, Arc::new(SocketError::new()),
        flag(0), flag(0), flag(crate::uapi::IP_PMTUDISC_WANT), 0,
        Arc::new(Spinlock::<Option<(Ipv4Addr, u16)>, StackLockClass>::new(None)),
        Arc::new(crate::bpf_filter::SocketFilter::new()),
        Arc::new(crate::mcast_filter::SocketMcast::new()),
    ).unwrap();
    endpoint.encap_type.store(UDP_ENCAP_ESPINUDP, Ordering::Release);

    let mut payload = alloc::vec![0u8; 9];
    payload[0] = 0x11;
    stack.send_udp_to(Ipv4Addr::LOOPBACK, SOURCE_PORT, Ipv4Addr::LOOPBACK, PORT, &payload).unwrap();
    stack.drain_loopback(iface, &loopback);
    assert!(endpoint.recv(false).is_none(), "an encapsulated payload never reaches the socket");

    stack.send_udp_to(Ipv4Addr::LOOPBACK, SOURCE_PORT, Ipv4Addr::LOOPBACK, PORT, &[0xff]).unwrap();
    stack.drain_loopback(iface, &loopback);
    assert!(endpoint.recv(false).is_none(), "a NAT keepalive never reaches the socket");

    let mut control = alloc::vec![0u8; 4];
    control.extend_from_slice(b"key exchange");
    stack.send_udp_to(Ipv4Addr::LOOPBACK, SOURCE_PORT, Ipv4Addr::LOOPBACK, PORT, &control).unwrap();
    stack.drain_loopback(iface, &loopback);
    assert_eq!(endpoint.recv(false).expect("a control packet is delivered").payload, control);

    // The same payload reaches a socket that never selected an encapsulation.
    endpoint.encap_type.store(UDP_ENCAP_NONE, Ordering::Release);
    stack.send_udp_to(Ipv4Addr::LOOPBACK, SOURCE_PORT, Ipv4Addr::LOOPBACK, PORT, &payload).unwrap();
    stack.drain_loopback(iface, &loopback);
    assert_eq!(endpoint.recv(false).expect("no encapsulation, ordinary delivery").payload, payload);
}

#[test]
fn ipv6_receive_path_consumes_the_payload_and_delivers_the_control_packet() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, loopback) = stack.register_loopback();
    let endpoint = stack.bind_udp6_socket(
        Ipv6Addr::LOOPBACK, PORT, None, Arc::new(SocketError::new()),
        flag(0), flag(0), 0, flag(0),
        Arc::new(Spinlock::<Option<(Ipv6Addr, u16)>, StackLockClass>::new(None)),
        flag(crate::uapi::IP_PMTUDISC_WANT), flag(crate::uapi::IPV6_PMTUDISC_WANT),
        Arc::new(crate::bpf_filter::SocketFilter::new()),
        Arc::new(crate::mcast_filter::SocketMcast::new()),
    ).unwrap();
    endpoint.encap_type.store(UDP_ENCAP_ESPINUDP, Ordering::Release);

    let mut payload = alloc::vec![0u8; 9];
    payload[0] = 0x11;
    stack.send_udp6_to(Ipv6Addr::LOOPBACK, SOURCE_PORT, Ipv6Addr::LOOPBACK, PORT, &payload).unwrap();
    stack.drain_loopback(iface, &loopback);
    assert!(endpoint.recv(false).is_none(), "an encapsulated payload never reaches the socket");

    stack.send_udp6_to(Ipv6Addr::LOOPBACK, SOURCE_PORT, Ipv6Addr::LOOPBACK, PORT, &[0xff]).unwrap();
    stack.drain_loopback(iface, &loopback);
    assert!(endpoint.recv(false).is_none(), "a NAT keepalive never reaches the socket");

    let mut control = alloc::vec![0u8; 4];
    control.extend_from_slice(b"key exchange");
    stack.send_udp6_to(Ipv6Addr::LOOPBACK, SOURCE_PORT, Ipv6Addr::LOOPBACK, PORT, &control).unwrap();
    stack.drain_loopback(iface, &loopback);
    assert_eq!(endpoint.recv(false).expect("a control packet is delivered").payload, control);

    endpoint.encap_type.store(UDP_ENCAP_NONE, Ordering::Release);
    stack.send_udp6_to(Ipv6Addr::LOOPBACK, SOURCE_PORT, Ipv6Addr::LOOPBACK, PORT, &payload).unwrap();
    stack.drain_loopback(iface, &loopback);
    assert_eq!(endpoint.recv(false).expect("no encapsulation, ordinary delivery").payload, payload);
}
