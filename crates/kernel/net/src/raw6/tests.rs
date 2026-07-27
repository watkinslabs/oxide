use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::addr::{Ipv6Addr, NetIfaceId};
use crate::bpf_filter::{install_bpf_filter_context_runner, FilterContext, FilterKind, FilterProgram};

use super::*;

const NET_NS: u64 = 0;
const PROTOCOL: u8 = 253;
const IFACE: NetIfaceId = NetIfaceId(7);
const NO_POLL_EVENTS: u32 = 0;
const LOCAL: Ipv6Addr = Ipv6Addr([0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
const REMOTE: Ipv6Addr = Ipv6Addr([0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
const LINK_LOCAL: Ipv6Addr = Ipv6Addr([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

#[test]
fn namespace_teardown_closes_raw6_endpoint_and_publishes_terminal_poll_state() {
    let _guard = crate::net_ns::test_support::LIFETIME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let stack = crate::NetStack::new();
    let owner = crate::net_ns::test_support::allocate_namespace();
    let id = owner.id();
    let endpoint = Arc::new(Raw6Endpoint::standalone(owner.clone(), PROTOCOL));
    stack.register_raw6(&endpoint);

    assert!(endpoint.is_accepting());
    assert_eq!(endpoint.poll_mask() & vfs::POLL_OUT, vfs::POLL_OUT);
    assert!(crate::net_ns::destroy_namespace_into(&stack, id.as_u64()));
    assert!(!endpoint.is_accepting());
    assert_eq!(endpoint.poll_mask() & vfs::POLL_OUT, NO_POLL_EVENTS);
    assert_eq!(endpoint.poll_mask() & vfs::POLL_HUP, vfs::POLL_HUP);

    drop(endpoint);
    drop(owner);
    let claimed = network_namespace::take_dead_namespace_ids();
    assert!(claimed.contains(&id));
    crate::net_ns::test_support::finish_claimed(&stack, &claimed);
}

fn verdict(_kind: FilterKind, insns: &[u8], ctx: FilterContext<'_>) -> u32 {
    let _ = ctx;
    u32::from_ne_bytes(insns.try_into().unwrap())
}

fn packet<'a>(protocol: u8, src: Ipv6Addr, dst: Ipv6Addr, payload: &'a [u8]) -> Raw6RxPacket<'a> {
    Raw6RxPacket {
        net_ns: NET_NS, protocol, src, dst, iface: IFACE, hop_limit: 63,
        traffic_class: 0x2e, flow_label: 0x12345, hatype: 1, payload,
    }
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = bytes.chunks_exact(2);
    for word in &mut chunks {
        sum += u32::from(u16::from_be_bytes([word[0], word[1]]));
    }
    if let Some(byte) = chunks.remainder().first() { sum += u32::from(*byte) << 8; }
    while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16); }
    !(sum as u16)
}

fn ipv6_packet(protocol: u8, src: Ipv6Addr, dst: Ipv6Addr, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0u8; crate::ipv6::IPV6_HDR_LEN + payload.len()];
    crate::ipv6::Ipv6Hdr {
        flow_label: 0, traffic_class: 0, payload_length: payload.len() as u16,
        next_header: protocol, hop_limit: 64, src, dst,
    }.write_to(&mut bytes);
    bytes[crate::ipv6::IPV6_HDR_LEN..].copy_from_slice(payload);
    bytes
}

fn raw6_icmp_error(local: Ipv6Addr, remote: Ipv6Addr, protocol: u8,
                   kind: u8, code: u8, info: u32) -> Vec<u8> {
    let invoking = ipv6_packet(protocol, local, remote, &[0; 8]);
    let mut message = vec![0u8; crate::icmpv6::ICMPV6_HDR_LEN + invoking.len()];
    message[0] = kind;
    message[1] = code;
    message[4..8].copy_from_slice(&info.to_be_bytes());
    message[crate::icmpv6::ICMPV6_HDR_LEN..].copy_from_slice(&invoking);
    let mut pseudo = vec![0u8; 40 + message.len()];
    pseudo[..16].copy_from_slice(&remote.0);
    pseudo[16..32].copy_from_slice(&local.0);
    pseudo[32..36].copy_from_slice(&(message.len() as u32).to_be_bytes());
    pseudo[39] = crate::addr::IpProto::Icmpv6 as u8;
    pseudo[40..].copy_from_slice(&message);
    message[2..4].copy_from_slice(&checksum(&pseudo).to_be_bytes());
    ipv6_packet(crate::icmpv6::IPPROTO_ICMPV6, remote, local, &message)
}

#[test]
fn exact_tuple_device_namespace_and_link_local_source_scope() {
    let endpoint = Raw6Endpoint::standalone(network_namespace::initial(), PROTOCOL);
    endpoint.bind(Raw6Address::new(LOCAL, IFACE.raw()), Some(IFACE));
    endpoint.connect(Raw6Address::new(LINK_LOCAL, IFACE.raw()));
    assert_eq!(endpoint.receive(packet(PROTOCOL, LINK_LOCAL, LOCAL, b"payload")), Raw6RxDisposition::Queued);
    let datagram = endpoint.recv(false).unwrap();
    assert_eq!(datagram.payload, b"payload");
    assert_eq!(datagram.meta.source, Raw6Address::new(LINK_LOCAL, IFACE.raw()));
    assert_eq!(datagram.meta.source_port, 0);

    assert_eq!(endpoint.receive(packet(PROTOCOL - 1, LINK_LOCAL, LOCAL, b"x")), Raw6RxDisposition::NoMatch);
    let mut wrong_ns = packet(PROTOCOL, LINK_LOCAL, LOCAL, b"x");
    wrong_ns.net_ns += 1;
    assert_eq!(endpoint.receive(wrong_ns), Raw6RxDisposition::NoMatch);
    let mut wrong_iface = packet(PROTOCOL, LINK_LOCAL, LOCAL, b"x");
    wrong_iface.iface = NetIfaceId(8);
    assert_eq!(endpoint.receive(wrong_iface), Raw6RxDisposition::NoMatch);
}

#[test]
fn checked_bind_rejects_ipv4_mapped_address() {
    let endpoint = Raw6Endpoint::standalone(network_namespace::initial(), PROTOCOL);
    let mapped = Ipv6Addr::from_v4_mapped(crate::Ipv4Addr::new(192, 0, 2, 1));
    assert_eq!(endpoint.bind_checked(Raw6Address::new(mapped, 0), None),
        Err(crate::NetError::Eaddrnotavail));
}

#[test]
fn icmp_filter_runs_before_bpf_and_icmp_checksum_defaults_to_two() {
    install_bpf_filter_context_runner(verdict);
    let endpoint = Raw6Endpoint::standalone(network_namespace::initial(), crate::icmpv6::IPPROTO_ICMPV6);
    endpoint.bpf_filter.attach(FilterProgram {
        kind: FilterKind::Ebpf, insns: u32::MAX.to_ne_bytes().to_vec(),
    }).unwrap();
    let mut words = [0u32; 8];
    words[(128u8 >> 5) as usize] = 1 << (128u8 & 31);
    endpoint.set_icmp_filter(Icmp6Filter::from_words(words));
    assert_eq!(endpoint.checksum(), Raw6Checksum::Offset(2));
    assert_eq!(endpoint.receive(packet(crate::icmpv6::IPPROTO_ICMPV6, REMOTE, LOCAL,
        &[128, 0, 0, 0])), Raw6RxDisposition::PolicyDrop);
    assert_eq!(endpoint.queue_usage(), (0, 0));
    assert_eq!(endpoint.receive(packet(crate::icmpv6::IPPROTO_ICMPV6, REMOTE, LOCAL,
        &[129, 0, 0, 0])), Raw6RxDisposition::Queued);
    assert_eq!(endpoint.queue_usage(), (1, 4));
}

#[test]
fn bpf_positive_verdict_truncates_upper_layer_packet_and_zero_drops() {
    install_bpf_filter_context_runner(verdict);
    let filter = Arc::new(crate::bpf_filter::SocketFilter::new());
    filter.attach(FilterProgram { kind: FilterKind::Classic, insns: 3u32.to_ne_bytes().to_vec() }).unwrap();
    let endpoint = Raw6Endpoint::new(network_namespace::initial(), PROTOCOL, filter.clone(),
        Arc::new(crate::mcast_filter::SocketMcast::new()), Arc::new(crate::SocketError::new()));
    assert_eq!(endpoint.receive(packet(PROTOCOL, REMOTE, LOCAL, b"abcdef")), Raw6RxDisposition::Queued);
    assert_eq!(endpoint.recv(false).unwrap().payload, b"abc");
    filter.attach(FilterProgram { kind: FilterKind::Classic, insns: 0u32.to_ne_bytes().to_vec() }).unwrap();
    assert_eq!(endpoint.receive(packet(PROTOCOL, REMOTE, LOCAL, b"abcdef")), Raw6RxDisposition::PolicyDrop);
}

#[test]
fn queue_limit_and_close_are_admission_boundaries() {
    let endpoint = Raw6Endpoint::standalone(network_namespace::initial(), PROTOCOL);
    endpoint.set_rcvbuf(3);
    assert_eq!(endpoint.receive(packet(PROTOCOL, REMOTE, LOCAL, b"abc")), Raw6RxDisposition::Queued);
    assert_eq!(endpoint.receive(packet(PROTOCOL, REMOTE, LOCAL, b"d")), Raw6RxDisposition::QueueFull);
    assert_eq!(endpoint.queue_usage(), (1, 3));
    assert_eq!(endpoint.recv(false).unwrap().payload, b"abc");
    endpoint.deactivate();
    assert_eq!(endpoint.receive(packet(PROTOCOL, REMOTE, LOCAL, b"x")), Raw6RxDisposition::NoMatch);
}

#[test]
fn multicast_requires_socket_membership_before_queue_admission() {
    let endpoint = Raw6Endpoint::standalone(network_namespace::initial(), PROTOCOL);
    let group = Ipv6Addr([0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9]);
    assert_eq!(endpoint.receive(packet(PROTOCOL, LINK_LOCAL, group, b"group")),
        Raw6RxDisposition::PolicyDrop);
    assert_eq!(endpoint.queue_usage(), (0, 0));
}

#[test]
fn checksum_validation_and_kernel_header_send_preparation() {
    let endpoint = Raw6Endpoint::standalone(network_namespace::initial(), crate::icmpv6::IPPROTO_ICMPV6);
    assert_eq!(endpoint.set_checksum(3), Err(crate::NetError::Einval));
    endpoint.set_checksum(2).unwrap();
    let prepared = endpoint.prepare_send(LOCAL, REMOTE, None, &[128, 0, 0, 0, 1, 2, 3, 4]).unwrap();
    assert_eq!(prepared.mode, Raw6SendMode::KernelHeader);
    assert_ne!(&prepared.bytes[2..4], &[0, 0]);
    assert_eq!(prepared.next_header, crate::icmpv6::IPPROTO_ICMPV6);
    endpoint.set_checksum(16).unwrap();
    assert_eq!(endpoint.prepare_send(LOCAL, REMOTE, None, &[0; 8]), Err(crate::NetError::Einval));
}

#[test]
fn caller_header_send_preserves_bytes_and_protocol_raw_requires_override_otherwise() {
    let endpoint = Raw6Endpoint::standalone(network_namespace::initial(), crate::addr::IpProto::Raw as u8);
    endpoint.set_header_included(false);
    assert_eq!(endpoint.prepare_send(LOCAL, REMOTE, None, b"body"), Err(crate::NetError::Einval));
    assert_eq!(endpoint.prepare_send(LOCAL, REMOTE, Some(PROTOCOL), b"body").unwrap().next_header, PROTOCOL);

    endpoint.set_header_included(true);
    let mut bytes = vec![0u8; crate::ipv6::IPV6_HDR_LEN + 4];
    let header = crate::ipv6::Ipv6Hdr {
        flow_label: 0, traffic_class: 0, payload_length: 4,
        next_header: PROTOCOL, hop_limit: 64, src: LOCAL, dst: REMOTE,
    };
    header.write_to(&mut bytes);
    let prepared = endpoint.prepare_send(Ipv6Addr::ANY, Ipv6Addr::ANY, None, &bytes).unwrap();
    assert_eq!(prepared.mode, Raw6SendMode::CallerHeader);
    assert_eq!(prepared.src, Ipv6Addr::ANY);
    assert_eq!(prepared.dst, Ipv6Addr::ANY);
    bytes.pop();
    assert_eq!(endpoint.prepare_send(LOCAL, REMOTE, None, &bytes).unwrap().bytes, bytes);
}

#[test]
fn registry_is_exact_protocol_idempotent_and_weak() {
    let table = Raw6Table::new();
    let endpoint = Arc::new(Raw6Endpoint::standalone(network_namespace::initial(), PROTOCOL));
    table.register(&endpoint);
    table.register(&endpoint);
    assert_eq!(table.endpoint_count(PROTOCOL), 1);
    assert_eq!(table.endpoint_count(PROTOCOL - 1), 0);
    table.unregister(&endpoint);
    assert_eq!(table.endpoint_count(PROTOCOL), 0);
}

#[test]
fn raw6_hardness_matching_and_recverr_follow_linux() {
    let stack = crate::NetStack::new();
    let (iface, _) = stack.register_loopback_in(NET_NS);
    let (other_iface, _) = stack.register_loopback_in(NET_NS);
    let local = Ipv6Addr::LOOPBACK;
    let remote = REMOTE;
    let matching_a = Arc::new(Raw6Endpoint::standalone(network_namespace::initial(), PROTOCOL));
    let matching_b = Arc::new(Raw6Endpoint::standalone(network_namespace::initial(), PROTOCOL));
    for raw in [&matching_a, &matching_b] {
        raw.bind(Raw6Address::new(local, 0), Some(iface));
        raw.connect(Raw6Address::new(remote, 0));
        stack.register_raw6(raw);
    }
    let wrong_protocol = Arc::new(Raw6Endpoint::standalone(network_namespace::initial(), PROTOCOL - 1));
    wrong_protocol.bind(Raw6Address::new(local, 0), Some(iface));
    wrong_protocol.connect(Raw6Address::new(remote, 0));
    stack.register_raw6(&wrong_protocol);
    let wrong_peer = Arc::new(Raw6Endpoint::standalone(network_namespace::initial(), PROTOCOL));
    wrong_peer.bind(Raw6Address::new(local, 0), Some(iface));
    wrong_peer.connect(Raw6Address::new(LINK_LOCAL, iface.raw()));
    stack.register_raw6(&wrong_peer);
    let wrong_iface = Arc::new(Raw6Endpoint::standalone(network_namespace::initial(), PROTOCOL));
    wrong_iface.bind(Raw6Address::new(local, 0), Some(other_iface));
    wrong_iface.connect(Raw6Address::new(remote, 0));
    stack.register_raw6(&wrong_iface);
    let unconnected = Arc::new(Raw6Endpoint::standalone(network_namespace::initial(), PROTOCOL));
    unconnected.bind(Raw6Address::new(local, 0), Some(iface));
    stack.register_raw6(&unconnected);

    stack.deliver_rx_ipv6(iface, &raw6_icmp_error(local, remote, PROTOCOL, 1, 0, 0)).unwrap();
    assert_eq!(matching_a.error.take(), 0);
    assert_eq!(matching_b.error.take(), 0);
    stack.deliver_rx_ipv6(iface, &raw6_icmp_error(local, remote, PROTOCOL, 2, 0, 1_280)).unwrap();
    assert_eq!(matching_a.error.take(), 0);
    assert_eq!(matching_b.error.take(), 0);
    matching_a.error.set_recverr6(true);
    stack.deliver_rx_ipv6(iface, &raw6_icmp_error(local, remote, PROTOCOL, 2, 0, 1_280)).unwrap();
    assert_eq!(matching_a.error.take(), syscall::errno::Errno::Emsgsize as i32);
    assert_eq!(matching_a.error.take_extended().unwrap().info, 1_280);
    matching_a.error.set_recverr6(false);
    stack.deliver_rx_ipv6(iface, &raw6_icmp_error(local, remote, PROTOCOL, 1, 4, 0)).unwrap();

    let expected = syscall::errno::Errno::Econnrefused as i32;
    assert_eq!(matching_a.error.take(), expected);
    assert_eq!(matching_b.error.take(), expected);
    assert_eq!(wrong_protocol.error.take(), 0);
    assert_eq!(wrong_peer.error.take(), 0);
    assert_eq!(wrong_iface.error.take(), 0);
    assert_eq!(unconnected.error.take(), 0);

    unconnected.error.set_recverr6(true);
    stack.deliver_rx_ipv6(iface, &raw6_icmp_error(local, remote, PROTOCOL, 1, 0, 0)).unwrap();
    assert_eq!(unconnected.error.take(), syscall::errno::Errno::Enetunreach as i32);
    assert_eq!(unconnected.error.take_extended().unwrap().destination_port, 0);
}
