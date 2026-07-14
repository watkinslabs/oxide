use alloc::sync::Arc;
use alloc::vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::addr::{Ipv6Addr, NetIfaceId};
use crate::bpf_filter::{install_bpf_filter_context_runner, FilterContext, FilterKind, FilterProgram};

use super::*;

const NET_NS: u64 = 19;
const PROTOCOL: u8 = 253;
const IFACE: NetIfaceId = NetIfaceId(7);
const LOCAL: Ipv6Addr = Ipv6Addr([0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
const REMOTE: Ipv6Addr = Ipv6Addr([0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
const LINK_LOCAL: Ipv6Addr = Ipv6Addr([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

static FILTER_CALLS: AtomicUsize = AtomicUsize::new(0);

fn verdict(_kind: FilterKind, insns: &[u8], ctx: FilterContext<'_>) -> u32 {
    FILTER_CALLS.fetch_add(1, Ordering::Relaxed);
    assert_eq!(ctx.protocol, crate::addr::eth_p::IPV6);
    assert_eq!(ctx.pay_offset, 0);
    u32::from_ne_bytes(insns.try_into().unwrap())
}

fn packet<'a>(protocol: u8, src: Ipv6Addr, dst: Ipv6Addr, payload: &'a [u8]) -> Raw6RxPacket<'a> {
    Raw6RxPacket {
        net_ns: NET_NS, protocol, src, dst, iface: IFACE, hop_limit: 63,
        traffic_class: 0x2e, flow_label: 0x12345, hatype: 1, payload,
    }
}

#[test]
fn exact_tuple_device_namespace_and_link_local_source_scope() {
    let endpoint = Raw6Endpoint::standalone(NET_NS, PROTOCOL);
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
fn icmp_filter_runs_before_bpf_and_icmp_checksum_defaults_to_two() {
    install_bpf_filter_context_runner(verdict);
    FILTER_CALLS.store(0, Ordering::Relaxed);
    let endpoint = Raw6Endpoint::standalone(NET_NS, crate::icmpv6::IPPROTO_ICMPV6);
    endpoint.bpf_filter.attach(FilterProgram {
        kind: FilterKind::Ebpf, insns: u32::MAX.to_ne_bytes().to_vec(),
    }).unwrap();
    let mut words = [0u32; 8];
    words[(128u8 >> 5) as usize] = 1 << (128u8 & 31);
    endpoint.set_icmp_filter(Icmp6Filter::from_words(words));
    assert_eq!(endpoint.checksum(), Raw6Checksum::Offset(2));
    assert_eq!(endpoint.receive(packet(crate::icmpv6::IPPROTO_ICMPV6, REMOTE, LOCAL,
        &[128, 0, 0, 0])), Raw6RxDisposition::PolicyDrop);
    assert_eq!(FILTER_CALLS.load(Ordering::Relaxed), 0);
    assert_eq!(endpoint.receive(packet(crate::icmpv6::IPPROTO_ICMPV6, REMOTE, LOCAL,
        &[129, 0, 0, 0])), Raw6RxDisposition::Queued);
    assert_eq!(FILTER_CALLS.load(Ordering::Relaxed), 1);
}

#[test]
fn bpf_positive_verdict_truncates_upper_layer_packet_and_zero_drops() {
    install_bpf_filter_context_runner(verdict);
    let filter = Arc::new(crate::bpf_filter::SocketFilter::new());
    filter.attach(FilterProgram { kind: FilterKind::Classic, insns: 3u32.to_ne_bytes().to_vec() }).unwrap();
    let endpoint = Raw6Endpoint::new(NET_NS, PROTOCOL, filter.clone(),
        Arc::new(crate::mcast_filter::SocketMcast::new()), Arc::new(crate::SocketError::new()));
    assert_eq!(endpoint.receive(packet(PROTOCOL, REMOTE, LOCAL, b"abcdef")), Raw6RxDisposition::Queued);
    assert_eq!(endpoint.recv(false).unwrap().payload, b"abc");
    filter.attach(FilterProgram { kind: FilterKind::Classic, insns: 0u32.to_ne_bytes().to_vec() }).unwrap();
    assert_eq!(endpoint.receive(packet(PROTOCOL, REMOTE, LOCAL, b"abcdef")), Raw6RxDisposition::PolicyDrop);
}

#[test]
fn queue_limit_and_close_are_admission_boundaries() {
    let endpoint = Raw6Endpoint::standalone(NET_NS, PROTOCOL);
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
    let endpoint = Raw6Endpoint::standalone(NET_NS, PROTOCOL);
    let group = Ipv6Addr([0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9]);
    assert_eq!(endpoint.receive(packet(PROTOCOL, LINK_LOCAL, group, b"group")),
        Raw6RxDisposition::PolicyDrop);
    assert_eq!(endpoint.queue_usage(), (0, 0));
}

#[test]
fn checksum_validation_and_kernel_header_send_preparation() {
    let endpoint = Raw6Endpoint::standalone(NET_NS, crate::icmpv6::IPPROTO_ICMPV6);
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
fn caller_header_send_is_validated_and_protocol_raw_requires_override_otherwise() {
    let endpoint = Raw6Endpoint::standalone(NET_NS, crate::addr::IpProto::Raw as u8);
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
    assert_eq!(prepared.src, LOCAL);
    assert_eq!(prepared.dst, REMOTE);
    bytes.pop();
    assert_eq!(endpoint.prepare_send(LOCAL, REMOTE, None, &bytes), Err(crate::NetError::Einval));
}

#[test]
fn registry_is_exact_protocol_idempotent_and_weak() {
    let table = Raw6Table::new();
    let endpoint = Arc::new(Raw6Endpoint::standalone(NET_NS, PROTOCOL));
    table.register(&endpoint);
    table.register(&endpoint);
    assert_eq!(table.endpoint_count(PROTOCOL), 1);
    assert_eq!(table.endpoint_count(PROTOCOL - 1), 0);
    table.unregister(&endpoint);
    assert_eq!(table.endpoint_count(PROTOCOL), 0);
}
