// Hosted coverage for the router-alert chain: option recognition, chain
// membership, the admission both levels share, the IPv6 selector shape, and
// the delivery fan-out.

use super::*;
use crate::addr::IpProto;
use crate::{Ipv4Addr, Ipv6Addr};

const PROTO_UNDER_TEST: u8 = IpProto::Icmp as u8;
const OTHER_PROTO: u8 = IpProto::Tcp as u8;

/// One IPv4 header with a four-byte option area, so `ihl` is 6 words.
fn header(options: [u8; 4], proto: u8) -> alloc::vec::Vec<u8> {
    let mut l3 = alloc::vec![0u8; 24];
    l3[0] = 0x46;
    l3[2..4].copy_from_slice(&24u16.to_be_bytes());
    l3[8] = 64;
    l3[9] = proto;
    l3[12..16].copy_from_slice(&Ipv4Addr::new(192, 0, 2, 1).octets());
    l3[16..20].copy_from_slice(&Ipv4Addr::new(198, 51, 100, 1).octets());
    l3[20..24].copy_from_slice(&options);
    let csum = crate::ipv4::ip_checksum(&l3);
    l3[10..12].copy_from_slice(&csum.to_be_bytes());
    l3
}

fn alert(proto: u8) -> alloc::vec::Vec<u8> { header([IPOPT_RA, 4, 0, 0], proto) }

fn endpoint(ns: &network_namespace::NetworkNamespaceRef, proto: u8)
    -> alloc::sync::Arc<Raw4Endpoint>
{
    Raw4Endpoint::new(proto, ns.clone(),
        alloc::sync::Arc::new(crate::bpf_filter::SocketFilter::new()),
        alloc::sync::Arc::new(crate::mcast_filter::SocketMcast::new()),
        alloc::sync::Arc::new(crate::socket_error::SocketError::new()))
}

#[test]
fn the_alert_option_is_recognised_only_at_its_own_length_and_value() {
    assert!(v4_present(&alert(PROTO_UNDER_TEST)));
    // A reserved alert value leaves the packet on the forwarding path.
    assert!(!v4_present(&header([IPOPT_RA, 4, 0, 1], PROTO_UNDER_TEST)));
    // A wrong length is not the option.
    assert!(!v4_present(&header([IPOPT_RA, 3, 0, 0], PROTO_UNDER_TEST)));
    // An option area that ends the walk before the alert.
    assert!(!v4_present(&header([IPOPT_END, IPOPT_RA, 4, 0], PROTO_UNDER_TEST)));
    // A header with no option area at all.
    let mut bare = alert(PROTO_UNDER_TEST);
    bare[0] = 0x45;
    assert!(!v4_present(&bare));
}

#[test]
fn a_no_op_pad_does_not_hide_the_option_behind_it() {
    // The pad is one byte, so the alert that follows it runs to the end of the
    // area: type, length, and the two value bytes the area cannot hold.
    let mut l3 = alert(PROTO_UNDER_TEST);
    l3[20] = IPOPT_NOOP;
    l3[21..24].copy_from_slice(&[IPOPT_RA, 4, 0]);
    assert!(!v4_present(&l3), "an option running past its area is not the option");
}

#[test]
fn a_truncated_option_length_stops_the_walk_rather_than_running_off() {
    // A length byte longer than the area it sits in must not be trusted.
    assert!(!v4_present(&header([IPOPT_RA, 40, 0, 0], PROTO_UNDER_TEST)));
    // A zero-length option would never advance.
    assert!(!v4_present(&header([IPOPT_RA, 0, 0, 0], PROTO_UNDER_TEST)));
}

#[test]
fn the_admission_answers_a_double_join_and_an_unjoined_leave() {
    assert_eq!(admit(true, false), Ok(()));
    assert_eq!(admit(true, true), Err(Errno::Eaddrinuse));
    assert_eq!(admit(false, true), Ok(()));
    assert_eq!(admit(false, false), Err(Errno::Enobufs));
}

#[test]
fn the_v6_operand_is_a_selector_and_only_a_negative_value_releases_a_slot() {
    // Zero takes a slot matching alert value zero — it is not "off".
    assert_eq!(v6_selector(0), Some(0));
    assert_eq!(v6_selector(1), Some(1));
    assert_eq!(v6_selector(-1), None);
    assert_eq!(v6_selector(i32::MIN), None);
}

#[test]
fn v6_packet_selector_accepts_one_well_formed_hop_by_hop_alert() {
    let payload = [IpProto::Udp as u8, 0, 5, 2, 0, 7, 0, 0];
    assert_eq!(v6_packet_selector(0, &payload), Some(7));
    assert_eq!(v6_packet_selector(IpProto::Udp as u8, &payload), None);
    assert_eq!(v6_packet_selector(0, &payload[..7]), None);
}

#[test]
fn v6_delivery_uses_the_raw_table_and_shared_socket_option_state() {
    let ns = network_namespace::initial();
    let stack = crate::stack::NetStack::new();
    let options = crate::sock_opts::sol_ipv6::Ipv6Opts::default();
    options.set_ra_selector(7);
    let endpoint = alloc::sync::Arc::new(crate::raw6::Raw6Endpoint::new_owned(
        crate::SocketOwner::root(ns.clone(), 0), IpProto::Raw as u8,
        alloc::sync::Arc::new(crate::bpf_filter::SocketFilter::new()),
        alloc::sync::Arc::new(crate::mcast_filter::SocketMcast::new()),
        alloc::sync::Arc::new(crate::socket_error::SocketError::new()),
        Some(options.router_alert()),
    ));
    stack.register_raw6(&endpoint);
    let src = Ipv6Addr::from_segments([0x2001, 0xdb8, 0, 1, 0, 0, 0, 1]);
    let dst = Ipv6Addr::from_segments([0x2001, 0xdb8, 0, 1, 0, 0, 0, 2]);
    let mut packet = alloc::vec![0u8; crate::ipv6::IPV6_HDR_LEN + 8];
    let mut header = crate::ipv6::Ipv6Hdr::build(src, dst, IpProto::Udp, 8);
    header.next_header = 0;
    header.write_to(&mut packet);
    packet[crate::ipv6::IPV6_HDR_LEN..].copy_from_slice(&[IpProto::Udp as u8, 0, 5, 2, 0, 7, 0, 0]);

    assert!(v6_deliver(&stack, ns.id().as_u64(), crate::NetIfaceId::from_raw(1), &packet));
    assert_eq!(endpoint.recv(false).unwrap().payload, b"");
}

#[test]
fn v6_isolate_excludes_a_receiver_owned_by_another_namespace() {
    let ingress = network_namespace::initial();
    let receiver = crate::net_ns::test_support::allocate_namespace();
    crate::net_ns::materialize_state(&receiver);
    let stack = crate::stack::NetStack::new();
    let options = crate::sock_opts::sol_ipv6::Ipv6Opts::default();
    options.set_ra_selector(7);
    let endpoint = alloc::sync::Arc::new(crate::raw6::Raw6Endpoint::new_owned(
        crate::SocketOwner::root(receiver, 0), IpProto::Raw as u8,
        alloc::sync::Arc::new(crate::bpf_filter::SocketFilter::new()),
        alloc::sync::Arc::new(crate::mcast_filter::SocketMcast::new()),
        alloc::sync::Arc::new(crate::socket_error::SocketError::new()),
        Some(options.router_alert()),
    ));
    stack.register_raw6(&endpoint);
    let src = Ipv6Addr::from_segments([0x2001, 0xdb8, 0, 1, 0, 0, 0, 1]);
    let dst = Ipv6Addr::from_segments([0x2001, 0xdb8, 0, 1, 0, 0, 0, 2]);
    let mut packet = alloc::vec![0u8; crate::ipv6::IPV6_HDR_LEN + 8];
    let mut header = crate::ipv6::Ipv6Hdr::build(src, dst, IpProto::Udp, 8);
    header.next_header = 0;
    header.write_to(&mut packet);
    packet[crate::ipv6::IPV6_HDR_LEN..].copy_from_slice(&[IpProto::Udp as u8, 0, 5, 2, 0, 7, 0, 0]);
    let iface = crate::NetIfaceId::from_raw(1);

    assert!(v6_deliver(&stack, ingress.id().as_u64(), iface, &packet));
    assert!(endpoint.recv(false).is_some());
    options.set_router_alert_isolate(true);
    assert!(!v6_deliver(&stack, ingress.id().as_u64(), iface, &packet));
    assert!(endpoint.recv(false).is_none());
}

#[test]
fn a_slot_is_taken_once_released_once_and_reports_its_own_membership() {
    let ns = crate::net_ns::test_support::allocate_namespace();
    let endpoint = endpoint(&ns, PROTO_UNDER_TEST);
    assert!(!v4_joined(&endpoint));
    assert_eq!(v4_join(&endpoint), Ok(()));
    assert!(v4_joined(&endpoint));
    assert_eq!(v4_join(&endpoint), Err(Errno::Eaddrinuse));
    assert_eq!(v4_leave(&endpoint), Ok(()));
    assert!(!v4_joined(&endpoint));
    assert_eq!(v4_leave(&endpoint), Err(Errno::Enobufs));
}

#[test]
fn a_dropped_endpoint_leaves_no_slot_behind() {
    let ns = crate::net_ns::test_support::allocate_namespace();
    let endpoint = endpoint(&ns, PROTO_UNDER_TEST);
    v4_join(&endpoint).unwrap();
    v4_forget(&endpoint);
    assert!(!v4_joined(&endpoint));
}

#[test]
fn every_member_watching_the_protocol_gets_its_own_copy() {
    let ns = crate::net_ns::test_support::allocate_namespace();
    let net_ns = ns.id().as_u64();
    let iface = crate::NetIfaceId::from_raw(1);
    let first = endpoint(&ns, PROTO_UNDER_TEST);
    let second = endpoint(&ns, PROTO_UNDER_TEST);
    let other = endpoint(&ns, OTHER_PROTO);
    for member in [&first, &second, &other] { v4_join(member).unwrap(); }

    let packet = alert(PROTO_UNDER_TEST);
    assert!(v4_deliver(net_ns, iface, &packet));

    for member in [&first, &second] {
        let queued = member.snapshot().queued_bytes;
        assert_eq!(queued, packet.len(), "each member holds its own whole copy");
    }
    assert_eq!(other.snapshot().queued_bytes, 0, "a member on another protocol sees nothing");
    for member in [&first, &second, &other] { v4_forget(member); }
}

#[test]
fn a_member_bound_to_a_device_sees_only_that_devices_packets() {
    let ns = crate::net_ns::test_support::allocate_namespace();
    let net_ns = ns.id().as_u64();
    let (bound_iface, other_iface) =
        (crate::NetIfaceId::from_raw(7), crate::NetIfaceId::from_raw(8));
    let member = endpoint(&ns, PROTO_UNDER_TEST);
    member.set_bound_iface(Some(bound_iface)).unwrap();
    v4_join(&member).unwrap();

    let packet = alert(PROTO_UNDER_TEST);
    assert!(!v4_deliver(net_ns, other_iface, &packet), "nothing took the packet");
    assert_eq!(member.snapshot().queued_bytes, 0);
    assert!(v4_deliver(net_ns, bound_iface, &packet));
    assert_eq!(member.snapshot().queued_bytes, packet.len());
    v4_forget(&member);
}

#[test]
fn a_member_in_another_namespace_is_not_on_this_namespaces_chain() {
    let ns = crate::net_ns::test_support::allocate_namespace();
    let elsewhere = crate::net_ns::test_support::allocate_namespace();
    let member = endpoint(&elsewhere, PROTO_UNDER_TEST);
    v4_join(&member).unwrap();

    let packet = alert(PROTO_UNDER_TEST);
    assert!(!v4_deliver(ns.id().as_u64(), crate::NetIfaceId::from_raw(1), &packet));
    assert_eq!(member.snapshot().queued_bytes, 0);
    v4_forget(&member);
}

#[test]
fn an_empty_chain_never_consumes_the_packet() {
    let ns = crate::net_ns::test_support::allocate_namespace();
    assert!(!v4_deliver(ns.id().as_u64(), crate::NetIfaceId::from_raw(1),
        &alert(PROTO_UNDER_TEST)));
}
