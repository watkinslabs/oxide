use alloc::sync::Arc;
use alloc::vec::Vec;

use sync::{Spinlock, Socket as LockClass};

use super::{Raw4Endpoint, Raw4TxOptions};
use crate::addr::{IpProto, Ipv4Addr, MacAddr};
use crate::bpf_filter::{install_bpf_filter_context_runner, FilterContext, FilterKind,
    FilterProgram, SocketFilter};
use crate::ipv4::{ip_checksum, Ipv4Hdr, IPV4_HDR_LEN};
use crate::mcast_filter::SocketMcast;
use crate::netdev::{NetDev, NetError, NetResult};
use crate::pkt::Pkt;
use crate::route::RouteEntry;
use crate::stack::NetStack;

// The transmit half, split out at the per-file size cutoff.
mod transmit;

const PROTOCOL: u8 = 143;
const OTHER_PROTOCOL: u8 = 144;
const FRAGMENT_ID: u16 = 0x4A21;
const MORE_FRAGMENTS: u16 = 0x2000;
const FINAL_FRAGMENT_OFFSET: u16 = 1;
const REASSEMBLY_NOW_NS: u64 = 1;
const FIRST_FRAGMENT_PAYLOAD: &[u8] = b"fragment";
const FINAL_FRAGMENT_PAYLOAD: &[u8] = b"tail";
fn endpoint(protocol: u8, net_namespace: network_namespace::NetworkNamespaceRef) -> Arc<Raw4Endpoint> {
    Raw4Endpoint::new(protocol, net_namespace, Arc::new(SocketFilter::new()),
        Arc::new(SocketMcast::new()), Arc::new(crate::SocketError::new()))
}

fn initial_endpoint(protocol: u8) -> Arc<Raw4Endpoint> {
    endpoint(protocol, network_namespace::initial())
}

#[test]
fn namespace_teardown_closes_live_raw_endpoint() {
    let _guard = crate::net_ns::test_support::LIFETIME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let stack = NetStack::new();
    let owner = crate::net_ns::test_support::allocate_namespace();
    let id = owner.id();
    let endpoint = endpoint(PROTOCOL, owner.clone());
    stack.register_raw4(&endpoint);
    assert!(endpoint.snapshot().accepting);
    assert!(crate::net_ns::destroy_namespace_into(&stack, id.as_u64()));
    assert!(!endpoint.snapshot().accepting);
    drop(endpoint);
    drop(owner);
    let claimed = network_namespace::take_dead_namespace_ids();
    assert!(claimed.contains(&id));
    crate::net_ns::test_support::finish_claimed(&stack, &claimed);
}

#[test]
fn namespace_teardown_drops_raw4_fragment_queue_without_cross_namespace_delivery() {
    let _guard = crate::net_ns::test_support::LIFETIME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let stack = NetStack::new();
    let owner_a = crate::net_ns::test_support::allocate_namespace();
    let owner_b = crate::net_ns::test_support::allocate_namespace();
    let ns_a = owner_a.id();
    let ns_b = owner_b.id();
    let (iface_a, _) = stack.register_loopback_in(ns_a.as_u64());
    let (iface_b, _) = stack.register_loopback_in(ns_b.as_u64());
    let raw_a = endpoint(PROTOCOL, owner_a.clone());
    let raw_b = endpoint(PROTOCOL, owner_b.clone());
    stack.register_raw4(&raw_a);
    stack.register_raw4(&raw_b);
    let first = packet(PROTOCOL, Ipv4Addr::LOOPBACK, Ipv4Addr::LOOPBACK, FRAGMENT_ID,
        MORE_FRAGMENTS, &[], FIRST_FRAGMENT_PAYLOAD);
    let final_fragment = packet(PROTOCOL, Ipv4Addr::LOOPBACK, Ipv4Addr::LOOPBACK, FRAGMENT_ID,
        FINAL_FRAGMENT_OFFSET, &[], FINAL_FRAGMENT_PAYLOAD);

    stack.deliver_raw4(ns_a.as_u64(), iface_a, &first, Ipv4Hdr::parse(&first).unwrap(), REASSEMBLY_NOW_NS, &Default::default());
    stack.deliver_raw4(ns_b.as_u64(), iface_b, &final_fragment, Ipv4Hdr::parse(&final_fragment).unwrap(), REASSEMBLY_NOW_NS, &Default::default());
    assert!(raw_a.recv(false).is_none());
    assert!(raw_b.recv(false).is_none());
    assert!(crate::net_ns::destroy_namespace_into(&stack, ns_a.as_u64()));
    assert!(!raw_a.snapshot().accepting);

    stack.deliver_raw4(ns_b.as_u64(), iface_b, &first, Ipv4Hdr::parse(&first).unwrap(), REASSEMBLY_NOW_NS, &Default::default());
    let reassembled = raw_b.recv(false).expect("namespace-local fragments complete only in namespace B");
    assert_eq!(&reassembled.packet[IPV4_HDR_LEN..], b"fragmenttail");
    drop(raw_a);
    drop(raw_b);
    drop(owner_a);
    drop(owner_b);
    let claimed = network_namespace::take_dead_namespace_ids();
    assert!(claimed.contains(&ns_a));
    assert!(claimed.contains(&ns_b));
    crate::net_ns::test_support::finish_claimed(&stack, &claimed);
}

#[test]
fn endpoint_retains_concrete_namespace_owner() {
    let owner = crate::net_ns::test_support::allocate_namespace();
    let id = owner.id();
    let endpoint = endpoint(PROTOCOL, owner.clone());
    drop(owner);
    assert!(network_namespace::lookup(id).is_some(), "raw endpoint pins namespace lifetime");
    drop(endpoint);
    assert!(network_namespace::lookup(id).is_none(), "last endpoint drop releases namespace");
}

fn packet(protocol: u8, src: Ipv4Addr, dst: Ipv4Addr, id: u16, flags: u16,
          options: &[u8], payload: &[u8]) -> Vec<u8> {
    assert_eq!(options.len() % 4, 0);
    let ihl = IPV4_HDR_LEN + options.len();
    let mut bytes = alloc::vec![0u8; ihl + payload.len()];
    bytes[0] = (4 << 4) | (ihl as u8 / 4);
    let total = bytes.len() as u16;
    bytes[2..4].copy_from_slice(&total.to_be_bytes());
    bytes[4..6].copy_from_slice(&id.to_be_bytes());
    bytes[6..8].copy_from_slice(&flags.to_be_bytes());
    bytes[8] = 64;
    bytes[9] = protocol;
    bytes[12..16].copy_from_slice(&src.octets());
    bytes[16..20].copy_from_slice(&dst.octets());
    bytes[IPV4_HDR_LEN..ihl].copy_from_slice(options);
    bytes[ihl..].copy_from_slice(payload);
    let checksum = ip_checksum(&bytes[..ihl]);
    bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
    bytes
}

fn error_quote(protocol: u8, local: Ipv4Addr, remote: Ipv4Addr) -> Vec<u8> {
    let mut quote = alloc::vec![0u8; crate::icmp::ICMP_HDR_LEN];
    quote.extend_from_slice(&packet(protocol, local, remote, 1, 0, &[], &[0; 8]));
    quote
}

fn filter_runner(_kind: FilterKind, insns: &[u8], _ctx: FilterContext<'_>) -> u32 {
    u32::from_ne_bytes(insns.try_into().unwrap())
}

#[test]
fn exact_protocol_fanout_is_namespace_local() {
    let stack = NetStack::new();
    let owner_a = crate::net_ns::test_support::allocate_namespace();
    let owner_b = crate::net_ns::test_support::allocate_namespace();
    let net_a = owner_a.id().as_u64();
    let net_b = owner_b.id().as_u64();
    let (iface_a, _) = stack.register_loopback_in(net_a);
    let (_iface_b, _) = stack.register_loopback_in(net_b);
    let exact_a = endpoint(PROTOCOL, owner_a.clone());
    let exact_b = endpoint(PROTOCOL, owner_b);
    let wrong = endpoint(OTHER_PROTOCOL, owner_a);
    stack.register_raw4(&exact_a);
    stack.register_raw4(&exact_b);
    stack.register_raw4(&wrong);

    let bytes = packet(PROTOCOL, Ipv4Addr::new(127, 0, 0, 2), Ipv4Addr::LOOPBACK,
        1, 0, &[], b"raw");
    stack.deliver_rx(iface_a, &bytes).unwrap();

    assert_eq!(exact_a.recv(false).unwrap().packet, bytes);
    assert!(exact_b.recv(false).is_none());
    assert!(wrong.recv(false).is_none());
}

#[test]
fn local_peer_and_bound_device_are_all_required_for_receive_match() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (wrong_iface, _) = stack.register_loopback();
    let (right_iface, _) = stack.register_loopback();
    let expected_peer = Ipv4Addr::new(127, 0, 0, 2);
    let raw = initial_endpoint(PROTOCOL);
    raw.bind(Ipv4Addr::LOOPBACK, Some(right_iface)).unwrap();
    raw.connect(expected_peer, None).unwrap();
    stack.register_raw4(&raw);
    let matching = packet(PROTOCOL, expected_peer, Ipv4Addr::LOOPBACK, 10, 0, &[], b"ok");

    stack.deliver_rx(wrong_iface, &matching).unwrap();
    let wrong_peer = packet(PROTOCOL, Ipv4Addr::new(127, 0, 0, 3),
        Ipv4Addr::LOOPBACK, 11, 0, &[], b"peer");
    stack.deliver_rx(right_iface, &wrong_peer).unwrap();
    let wrong_local = packet(PROTOCOL, expected_peer, Ipv4Addr::new(127, 0, 0, 4),
        12, 0, &[], b"local");
    stack.deliver_rx(right_iface, &wrong_local).unwrap();
    assert!(raw.recv(false).is_none());

    stack.deliver_rx(right_iface, &matching).unwrap();
    assert_eq!(raw.recv(false).unwrap().packet, matching);
}

#[test]
fn full_packet_bpf_drops_zero_and_truncates_positive_verdict() {
    let _domain = crate::hosted_fixture::init_net_domain();
    install_bpf_filter_context_runner(filter_runner);
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();
    let dropped = initial_endpoint(PROTOCOL);
    dropped.bpf_filter.attach(FilterProgram {
        kind: FilterKind::Ebpf, insns: 0u32.to_ne_bytes().to_vec(),
    }).unwrap();
    let truncated = initial_endpoint(PROTOCOL);
    truncated.bpf_filter.attach(FilterProgram {
        kind: FilterKind::Classic, insns: 22u32.to_ne_bytes().to_vec(),
    }).unwrap();
    stack.register_raw4(&dropped);
    stack.register_raw4(&truncated);
    let bytes = packet(PROTOCOL, Ipv4Addr::new(127, 0, 0, 2), Ipv4Addr::LOOPBACK,
        2, 0, &[], b"abcdef");

    stack.deliver_rx(iface, &bytes).unwrap();

    assert!(dropped.recv(false).is_none());
    let datagram = truncated.recv(false).unwrap();
    assert_eq!(datagram.packet, bytes[..22]);
    assert_eq!(datagram.source, Ipv4Addr::new(127, 0, 0, 2));
    assert_eq!(datagram.destination, Ipv4Addr::LOOPBACK);
}

#[test]
fn receive_limit_accounts_bytes_and_reports_drops() {
    let raw = initial_endpoint(PROTOCOL);
    raw.set_rcvbuf(3);
    assert!(raw.enqueue(super::Raw4Datagram { packet: b"abc".to_vec(),
        source: Ipv4Addr::LOOPBACK, destination: Ipv4Addr::LOOPBACK,
        iface: crate::NetIfaceId::from_raw(1), ttl: 64 , options: Default::default() }));
    assert!(!raw.enqueue(super::Raw4Datagram { packet: b"d".to_vec(),
        source: Ipv4Addr::LOOPBACK, destination: Ipv4Addr::LOOPBACK,
        iface: crate::NetIfaceId::from_raw(1), ttl: 64 , options: Default::default() }));
    assert_eq!((raw.snapshot().queued_bytes, raw.snapshot().drops), (3, 1));
    assert_eq!(raw.recv(false).unwrap().packet, b"abc");
    assert_eq!(raw.snapshot().queued_bytes, 0);
}

#[test]
fn raw_udp_clone_does_not_interfere_with_transport_delivery() {
    let _domain = crate::hosted_fixture::init_net_domain();
    const PORT: u16 = 43_210;
    let stack = NetStack::new();
    let (iface, loopback) = stack.register_loopback();
    let raw = initial_endpoint(IpProto::Udp as u8);
    stack.register_raw4(&raw);
    let udp = stack.bind_udp(Ipv4Addr::LOOPBACK, PORT).unwrap();

    stack.send_udp_to(Ipv4Addr::LOOPBACK, 40_000, Ipv4Addr::LOOPBACK, PORT, b"payload").unwrap();
    stack.drain_loopback(iface, &loopback);

    let raw_packet = raw.recv(false).unwrap().packet;
    assert_eq!(Ipv4Hdr::parse(&raw_packet).unwrap().proto, IpProto::Udp as u8);
    assert_eq!(udp.recv(false).unwrap().payload, b"payload");
}

#[test]
fn reassembly_preserves_first_header_options_and_normalizes_fragment_fields() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();
    let raw = initial_endpoint(PROTOCOL);
    stack.register_raw4(&raw);
    let src = Ipv4Addr::new(127, 0, 0, 2);
    let options = [0x94, 4, 0, 0];
    let first = packet(PROTOCOL, src, Ipv4Addr::LOOPBACK, 77, 0x2000,
        &options, b"abcdefgh");
    let last = packet(PROTOCOL, src, Ipv4Addr::LOOPBACK, 77, 1,
        &[], b"ijklmnop");

    stack.deliver_rx(iface, &last).unwrap();
    assert!(raw.recv(false).is_none());
    stack.deliver_rx(iface, &first).unwrap();

    let assembled = raw.recv(false).unwrap().packet;
    let hdr = Ipv4Hdr::parse(&assembled).unwrap();
    assert_eq!(hdr.ihl_bytes(), 24);
    assert_eq!(hdr.flags_frag, 0);
    assert_eq!(&assembled[20..24], &options);
    assert_eq!(&assembled[24..], b"abcdefghijklmnop");
    assert_eq!(hdr.total_len as usize, assembled.len());
}

#[test]
fn multicast_membership_filters_each_raw_endpoint() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, loopback) = stack.register_loopback();
    let joined = initial_endpoint(PROTOCOL);
    let unjoined = initial_endpoint(PROTOCOL);
    stack.register_raw4(&joined);
    stack.register_raw4(&unjoined);
    let group = Ipv4Addr::new(239, 1, 2, 3);
    // Unconditional multicast delivery is on at creation, so membership only
    // gates a raw socket that cleared it.
    unjoined.mcast.set_multicast_all_v4(false);
    joined.mcast.change_v4(&stack, iface, group, Ipv4Addr::LOOPBACK, true).unwrap();
    while loopback.rx_pop().is_some() {}
    let bytes = packet(PROTOCOL, Ipv4Addr::new(192, 0, 2, 1), group, 5, 0, &[], b"group");

    stack.deliver_rx(iface, &bytes).unwrap();

    assert!(joined.recv(false).is_some());
    assert!(unjoined.recv(false).is_none());
}

struct CaptureDev {
    mtu: u32,
    packets: Spinlock<Vec<Vec<u8>>, LockClass>,
    /// The transmit metadata each captured packet arrived with.
    metas: Spinlock<Vec<crate::TxMeta>, LockClass>,
}

impl CaptureDev {
    fn new(mtu: u32) -> Self {
        Self { mtu, packets: Spinlock::new(Vec::new()), metas: Spinlock::new(Vec::new()) }
    }
}

impl NetDev for CaptureDev {
    fn name(&self) -> &str { "rawtest0" }
    fn mac(&self) -> MacAddr { MacAddr::ZERO }
    fn mtu(&self) -> u32 { self.mtu }
    fn retire_namespace(&self) {}
    fn namespace_drop_action(&self) -> crate::NamespaceDropAction {
        crate::NamespaceDropAction::Destroy
    }
    fn xmit(&self, packet: Pkt) -> NetResult<()> {
        self.metas.lock().push(packet.tx);
        self.packets.lock().push(packet.data().to_vec());
        Ok(())
    }
}
