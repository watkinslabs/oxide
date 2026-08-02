// End-to-end contract for the ICMP datagram endpoint class: kernel-owned
// identifier, identifier-keyed reply demultiplexing, echo-only transmit, the
// raw-only options it must refuse, and the group-membership admission ladder.

use alloc::sync::Arc;
use core::sync::atomic::AtomicI32;

use crate::addr::{Ipv4Addr, NetIfaceId};
use crate::ipv4::Ipv4Hdr;
use crate::netdev::NetError;
use crate::ping::group::{admits, CallerGroups};
use crate::ping::validate::identifier;
use crate::raw4::Raw4Endpoint;

const IFACE: u32 = 1;
const LOCAL: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const PEER: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

fn namespace() -> network_namespace::NetworkNamespaceRef {
    let namespace = crate::net_ns::test_support::allocate_namespace();
    crate::net_ns::materialize_state(&namespace);
    namespace
}

fn ping4(namespace: &network_namespace::NetworkNamespaceRef) -> Arc<Raw4Endpoint> {
    Raw4Endpoint::new_ping(crate::SocketOwner::root(namespace.clone(), 0),
        Arc::new(crate::bpf_filter::SocketFilter::new()),
        Arc::new(crate::mcast_filter::SocketMcast::new()),
        Arc::new(crate::SocketError::new()),
        Arc::new(AtomicI32::new(0)),
        Arc::new(AtomicI32::new(crate::uapi::IP_PMTUDISC_WANT)))
}

fn ping6(namespace: &network_namespace::NetworkNamespaceRef) -> Arc<crate::raw6::Raw6Endpoint> {
    Arc::new(crate::raw6::Raw6Endpoint::new_ping(
        crate::SocketOwner::root(namespace.clone(), 0),
        Arc::new(crate::bpf_filter::SocketFilter::new()),
        Arc::new(crate::mcast_filter::SocketMcast::new()),
        Arc::new(crate::SocketError::new()),
        Arc::new(AtomicI32::new(0))))
}

fn probe(seq: u16, caller_ident: u16) -> alloc::vec::Vec<u8> {
    let mut message = alloc::vec![8u8, 0, 0, 0, 0, 0, 0, 0];
    message[4..6].copy_from_slice(&caller_ident.to_be_bytes());
    message[6..8].copy_from_slice(&seq.to_be_bytes());
    message.extend_from_slice(b"payload-bytes");
    message
}

fn reply_for(probe: &[u8]) -> alloc::vec::Vec<u8> {
    let mut reply = probe.to_vec();
    reply[0] = crate::icmp::ICMP_TYPE_ECHO_REPLY;
    reply[2] = 0;
    reply[3] = 0;
    let checksum = crate::ipv4::ip_checksum(&reply);
    reply[2..4].copy_from_slice(&checksum.to_be_bytes());
    reply
}

fn header(src: Ipv4Addr, dst: Ipv4Addr, len: usize) -> Ipv4Hdr {
    let mut bytes = alloc::vec![0u8; crate::ipv4::IPV4_HDR_LEN + len];
    bytes[0] = 0x45;
    let total = bytes.len() as u16;
    bytes[2..4].copy_from_slice(&total.to_be_bytes());
    bytes[8] = 64;
    bytes[9] = crate::addr::IpProto::Icmp as u8;
    bytes[12..16].copy_from_slice(&src.octets());
    bytes[16..20].copy_from_slice(&dst.octets());
    let checksum = crate::ipv4::ip_checksum(&bytes[..crate::ipv4::IPV4_HDR_LEN]);
    bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
    Ipv4Hdr::parse(&bytes).expect("fixture header parses")
}

#[test]
fn a_reply_reaches_only_the_endpoint_whose_identifier_it_carries() {
    let owner = namespace();
    let stack = crate::global_stack();
    let mine = ping4(&owner);
    let other = ping4(&owner);
    let sent = crate::ping::prepare_v4(&mine, &probe(1, 0xffff), false).unwrap();
    let ident = mine.ping_ident();
    assert_ne!(ident, 0);
    // The caller wrote 0xffff; the wire carries the kernel's value instead.
    assert_eq!(identifier(&sent), ident);
    assert_ne!(identifier(&sent), 0xffff);
    let _ = crate::ping::prepare_v4(&other, &probe(1, 0xffff), false).unwrap();
    assert_ne!(other.ping_ident(), ident);

    let reply = reply_for(&sent);
    let hdr = header(PEER, LOCAL, reply.len());
    assert!(stack.deliver_ping_v4(owner.id().as_u64(), NetIfaceId::from_raw(IFACE), &hdr,
        &reply, &reply, 0, &Default::default()));
    let got = mine.recv(false).expect("the owning endpoint receives its reply");
    assert_eq!(got.packet, reply, "the record starts at the ICMP message, not the network header");
    assert_eq!(got.source, PEER);
    assert_eq!(got.ttl, 64);
    assert!(other.recv(false).is_none(), "a foreign identifier must not be delivered here");
}

#[test]
fn a_reply_for_an_unowned_identifier_is_dropped() {
    let owner = namespace();
    let stack = crate::global_stack();
    let endpoint = ping4(&owner);
    let sent = crate::ping::prepare_v4(&endpoint, &probe(1, 0), false).unwrap();
    let mut reply = reply_for(&sent);
    let stray = endpoint.ping_ident().wrapping_add(1).max(1);
    reply[4..6].copy_from_slice(&stray.to_be_bytes());
    let hdr = header(PEER, LOCAL, reply.len());
    assert!(!stack.deliver_ping_v4(owner.id().as_u64(), NetIfaceId::from_raw(IFACE), &hdr,
        &reply, &reply, 0, &Default::default()));
    assert!(endpoint.recv(false).is_none());
}

#[test]
fn an_echo_request_is_never_demultiplexed_as_a_reply() {
    let owner = namespace();
    let stack = crate::global_stack();
    let endpoint = ping4(&owner);
    let sent = crate::ping::prepare_v4(&endpoint, &probe(1, 0), false).unwrap();
    let hdr = header(PEER, LOCAL, sent.len());
    assert!(!stack.deliver_ping_v4(owner.id().as_u64(), NetIfaceId::from_raw(IFACE), &hdr,
        &sent, &sent, 0, &Default::default()), "a request carrying our identifier is not our reply");
    assert!(endpoint.recv(false).is_none());
}

#[test]
fn an_explicit_bind_fixes_the_identifier_the_probe_carries() {
    let owner = namespace();
    let endpoint = ping4(&owner);
    assert_eq!(crate::ping::bind_v4(&endpoint, 0x4d2), Ok(0x4d2));
    assert_eq!(endpoint.ping_ident(), 0x4d2);
    let sent = crate::ping::prepare_v4(&endpoint, &probe(9, 0x1111), false).unwrap();
    assert_eq!(identifier(&sent), 0x4d2);
    assert_eq!(&sent[6..8], &[0, 9], "the caller still owns the sequence");
    // A second bind on an endpoint that already owns an identifier is refused.
    assert_eq!(crate::ping::bind_v4(&endpoint, 0x4d3), Err(NetError::Einval));
}

#[test]
fn identifiers_are_private_to_their_network_namespace() {
    let first = namespace();
    let second = namespace();
    let stack = crate::global_stack();
    let mine = ping4(&first);
    let theirs = ping4(&second);
    crate::ping::bind_v4(&mine, 0x2222).unwrap();
    // The same identifier is free in a different namespace.
    assert_eq!(crate::ping::bind_v4(&theirs, 0x2222), Ok(0x2222));
    let sent = crate::ping::prepare_v4(&mine, &probe(1, 0), false).unwrap();
    let reply = reply_for(&sent);
    let hdr = header(PEER, LOCAL, reply.len());
    assert!(stack.deliver_ping_v4(first.id().as_u64(), NetIfaceId::from_raw(IFACE), &hdr,
        &reply, &reply, 0, &Default::default()));
    assert!(mine.recv(false).is_some());
    assert!(theirs.recv(false).is_none());
}

#[test]
fn a_quoted_probe_steers_its_error_to_the_originating_endpoint() {
    let owner = namespace();
    let stack = crate::global_stack();
    let endpoint = ping4(&owner);
    // Extended-error delivery is what an echo-probe tool enables; without it an
    // unconnected endpoint only latches a hard error, matching datagram rules.
    endpoint.error.set_recverr4(true);
    let sent = crate::ping::prepare_v4(&endpoint, &probe(4, 0), false).unwrap();
    let entry = crate::SocketErrorEntry {
        errno: syscall::errno::Errno::Ehostunreach as i32,
        origin: crate::socket_error::SO_EE_ORIGIN_ICMP,
        kind: crate::icmp::ICMP_TYPE_DEST_UNREACH, code: 1, info: 0, data: 0,
        offender: crate::addr::IpAddr::V4(PEER),
        destination: crate::addr::IpAddr::V4(PEER),
        destination_port: 0, ifindex: IFACE, payload: sent.clone(),
    };
    assert!(stack.report_ping_error_v4(owner.id().as_u64(), NetIfaceId::from_raw(IFACE), LOCAL,
        &sent, entry.clone(), true, &sent));
    assert_ne!(endpoint.error.take(), 0, "the error reaches the endpoint that sent the probe");
    // An error quoting something that is not an echo probe is not ours.
    let mut foreign = sent.clone();
    foreign[0] = crate::icmp::ICMP_TYPE_ECHO_REPLY;
    assert!(!stack.report_ping_error_v4(owner.id().as_u64(), NetIfaceId::from_raw(IFACE), LOCAL,
        &foreign, entry, true, &foreign));
}

#[test]
fn the_ipv6_endpoint_uses_the_same_identifier_contract() {
    let owner = namespace();
    let stack = crate::global_stack();
    let endpoint = ping6(&owner);
    let mut message = alloc::vec![128u8, 0, 0, 0, 0xff, 0xff, 0, 3];
    message.extend_from_slice(b"v6-probe");
    let sent = crate::ping::prepare_v6(&endpoint, &message, false).unwrap();
    let ident = endpoint.ping_ident();
    assert_ne!(ident, 0);
    assert_eq!(identifier(&sent), ident);
    let mut reply = sent.clone();
    reply[0] = crate::icmpv6::ICMPV6_TYPE_ECHO_REPLY;
    let src = crate::Ipv6Addr([0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    let dst = crate::Ipv6Addr([0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    assert!(stack.deliver_ping_v6(crate::ping::Reply6 {
        net_ns: owner.id().as_u64(), iface: NetIfaceId::from_raw(IFACE), src, dst,
        hop_limit: 64, traffic_class: 0, flow_label: 0, hatype: 0, message: &reply,
    }));
    let got = endpoint.recv(false).expect("the owning endpoint receives its reply");
    assert_eq!(got.payload, reply);
    assert_eq!(got.meta.source.addr, src);
    // A neighbour-discovery message carrying the same two bytes is not a reply.
    let mut nd = reply.clone();
    nd[0] = 136;
    assert!(!stack.deliver_ping_v6(crate::ping::Reply6 {
        net_ns: owner.id().as_u64(), iface: NetIfaceId::from_raw(IFACE), src, dst,
        hop_limit: 64, traffic_class: 0, flow_label: 0, hatype: 0, message: &nd,
    }));
}

#[test]
fn an_ipv6_error_quoting_a_probe_reaches_its_originating_endpoint() {
    let owner = namespace();
    let stack = crate::global_stack();
    let endpoint = ping6(&owner);
    endpoint.error.set_recverr6(true);
    let mut message = alloc::vec![128u8, 0, 0, 0, 0, 0, 0, 1];
    message.extend_from_slice(b"probe");
    let sent = crate::ping::prepare_v6(&endpoint, &message, false).unwrap();
    let local = crate::Ipv6Addr([0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    let entry = crate::SocketErrorEntry {
        errno: syscall::errno::Errno::Ehostunreach as i32,
        origin: crate::socket_error::SO_EE_ORIGIN_ICMP6,
        kind: 1, code: 3, info: 0, data: 0,
        offender: crate::addr::IpAddr::V6(local),
        destination: crate::addr::IpAddr::V6(local),
        destination_port: 0, ifindex: IFACE, payload: sent.clone(),
    };
    assert!(stack.report_ping_error_v6(owner.id().as_u64(), NetIfaceId::from_raw(IFACE), local,
        &sent, entry.clone(), true));
    assert_ne!(endpoint.error.take(), 0);
    // A quoted neighbour-discovery message is not an echo probe of ours.
    let mut foreign = sent.clone();
    foreign[0] = 135;
    assert!(!stack.report_ping_error_v6(owner.id().as_u64(), NetIfaceId::from_raw(IFACE), local,
        &foreign, entry, true));
}

#[test]
fn closing_an_endpoint_frees_its_identifier_for_the_next_caller() {
    let owner = namespace();
    let endpoint = ping4(&owner);
    crate::ping::bind_v4(&endpoint, 0x0abc).unwrap();
    let ident = Arc::clone(endpoint.ping.as_ref().unwrap());
    crate::ping::release(&ident, owner.id().as_u64());
    assert_eq!(endpoint.ping_ident(), 0);
    let next = ping4(&owner);
    assert_eq!(crate::ping::bind_v4(&next, 0x0abc), Ok(0x0abc));
}

#[test]
fn the_group_window_gates_creation_and_the_default_denies_everyone() {
    let owner = namespace();
    // The compiled default window admits nobody, including the superuser's group.
    assert_eq!(crate::ping::group_range_for(&owner), Some((1, 0)));
    assert!(!crate::ping::admits(&owner, CallerGroups { egid: 0, supplementary: &[] }));
    assert!(!crate::ping::admits(&owner, CallerGroups { egid: 1000, supplementary: &[0] }));
    // The window a distribution installs at boot admits every ordinary group.
    crate::ping::set_group_range_for(&owner, 0, 2_147_483_647).unwrap();
    assert!(crate::ping::admits(&owner, CallerGroups { egid: 1000, supplementary: &[] }));
    // A narrow window admits through the supplementary list as well.
    crate::ping::set_group_range_for(&owner, 100, 100).unwrap();
    assert!(!crate::ping::admits(&owner, CallerGroups { egid: 1000, supplementary: &[7] }));
    assert!(crate::ping::admits(&owner, CallerGroups { egid: 1000, supplementary: &[7, 100] }));
    assert!(crate::ping::admits(&owner, CallerGroups { egid: 100, supplementary: &[] }));
    // Windows are namespace-private.
    let other = namespace();
    assert_eq!(crate::ping::group_range_for(&other), Some((1, 0)));
    assert!(admits((100, 100), CallerGroups { egid: 100, supplementary: &[] }));
}
