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

const PROTOCOL: u8 = 143;
const OTHER_PROTOCOL: u8 = 144;
fn endpoint(protocol: u8, net_namespace: network_namespace::NetworkNamespaceRef) -> Arc<Raw4Endpoint> {
    Raw4Endpoint::new(protocol, net_namespace, Arc::new(SocketFilter::new()),
        Arc::new(SocketMcast::new()), Arc::new(crate::SocketError::new()))
}

fn initial_endpoint(protocol: u8) -> Arc<Raw4Endpoint> {
    endpoint(protocol, network_namespace::initial())
}

#[test]
fn namespace_teardown_closes_live_raw_endpoint() {
    let _guard = crate::net_ns::test_support::LIFETIME_LOCK.lock().unwrap();
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
        iface: crate::NetIfaceId::from_raw(1), ttl: 64 }));
    assert!(!raw.enqueue(super::Raw4Datagram { packet: b"d".to_vec(),
        source: Ipv4Addr::LOOPBACK, destination: Ipv4Addr::LOOPBACK,
        iface: crate::NetIfaceId::from_raw(1), ttl: 64 }));
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
    assert_eq!(udp.recv(false).unwrap().5, b"payload");
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
}

impl CaptureDev {
    fn new(mtu: u32) -> Self { Self { mtu, packets: Spinlock::new(Vec::new()) } }
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
        self.packets.lock().push(packet.data().to_vec());
        Ok(())
    }
}

fn routed_capture(stack: &NetStack, mtu: u32, dst: Ipv4Addr)
    -> (crate::NetIfaceId, Arc<CaptureDev>) {
    let dev = Arc::new(CaptureDev::new(mtu));
    let iface = stack.ifaces.register(dev.clone() as Arc<dyn NetDev>);
    stack.routes.add(RouteEntry::main(dst, 32, iface, None,
        Some(Ipv4Addr::new(192, 0, 2, 10))));
    (iface, dev)
}

#[test]
fn non_hdrincl_transmit_supports_arbitrary_protocol_and_fragments() {
    let stack = NetStack::new();
    let dst = Ipv4Addr::new(198, 51, 100, 20);
    let (_iface, dev) = routed_capture(&stack, 68, dst);
    let raw = initial_endpoint(PROTOCOL);
    let options = Raw4TxOptions { pmtudisc: crate::uapi::IP_PMTUDISC_DONT,
        ..Raw4TxOptions::default() };

    stack.send_raw4(&raw, dst, &[0x5a; 100], options,
        &crate::send_control::Raw4Control::default()).unwrap();

    let packets = dev.packets.lock();
    assert_eq!(packets.len(), 3);
    let headers: Vec<_> = packets.iter().map(|packet| Ipv4Hdr::parse(packet).unwrap()).collect();
    assert!(headers.iter().all(|hdr| hdr.proto == PROTOCOL && hdr.id == headers[0].id));
    assert_ne!(headers[0].flags_frag & 0x2000, 0);
    assert_eq!(headers[1].flags_frag & 0x1fff, 6);
    assert_eq!(headers[2].flags_frag & 0x1fff, 12);
    assert_eq!(headers[2].flags_frag & 0x2000, 0);
}

#[test]
fn want_small_packet_clears_df_on_locked_pmtu_route() {
    let stack = NetStack::new();
    let dst = Ipv4Addr::new(198, 51, 100, 21);
    let (iface, dev) = routed_capture(&stack, 1_500, dst);
    let raw = initial_endpoint(PROTOCOL);
    stack.inet_tables(0).pmtu.update(
        iface, crate::IpAddr::V4(dst), 296, 1_500, crate::stack::IPV4_MIN_PMTU,
    );
    let options = Raw4TxOptions { pmtudisc: crate::uapi::IP_PMTUDISC_WANT,
        ..Raw4TxOptions::default() };

    stack.send_raw4(&raw, dst, b"small", options,
        &crate::send_control::Raw4Control::default()).unwrap();

    let packets = dev.packets.lock();
    assert_eq!(packets.len(), 1);
    assert_eq!(Ipv4Hdr::parse(&packets[0]).unwrap().flags_frag & 0x4000, 0);
}

#[test]
fn broadcast_transmit_requires_permission() {
    let stack = NetStack::new();
    let (_iface, dev) = routed_capture(&stack, 1_500, Ipv4Addr::BROADCAST);
    let raw = initial_endpoint(PROTOCOL);
    assert_eq!(stack.send_raw4(&raw, Ipv4Addr::BROADCAST, b"x",
        Raw4TxOptions::default(), &crate::send_control::Raw4Control::default()), Err(NetError::Eacces));
    stack.send_raw4(&raw, Ipv4Addr::BROADCAST, b"x", Raw4TxOptions {
        broadcast: true, ..Raw4TxOptions::default()
    }, &crate::send_control::Raw4Control::default()).unwrap();
    assert_eq!(dev.packets.lock().len(), 1);
}

#[test]
fn hdrincl_rewrites_kernel_fields_preserves_user_header_and_never_fragments() {
    let stack = NetStack::new();
    let dst = Ipv4Addr::new(203, 0, 113, 9);
    let (_iface, dev) = routed_capture(&stack, 80, dst);
    let raw = initial_endpoint(PROTOCOL);
    raw.set_hdrincl(true);
    let mut user = packet(OTHER_PROTOCOL, Ipv4Addr::ANY, dst, 0, 0, &[], b"body");
    user[1] = 0x2e;
    user[8] = 31;
    user[2..4].copy_from_slice(&0u16.to_be_bytes());
    user[10..12].copy_from_slice(&0xdead_u16.to_be_bytes());

    stack.send_raw4(&raw, dst, &user, Raw4TxOptions::default(),
        &crate::send_control::Raw4Control::default()).unwrap();

    let packets = dev.packets.lock();
    assert_eq!(packets.len(), 1);
    let hdr = Ipv4Hdr::parse(&packets[0]).unwrap();
    assert_eq!(hdr.proto, OTHER_PROTOCOL);
    assert_eq!(hdr.tos, 0x2e);
    assert_eq!(hdr.ttl, 31);
    assert_ne!(hdr.id, 0);
    assert_eq!(hdr.src, Ipv4Addr::new(192, 0, 2, 10));
    assert_eq!(hdr.total_len as usize, user.len());
    drop(packets);

    let oversized = alloc::vec![0u8; 81];
    assert_eq!(stack.send_raw4(&raw, dst, &oversized, Raw4TxOptions::default(),
        &crate::send_control::Raw4Control::default()),
        Err(NetError::Einval));
    let valid_oversized = packet(PROTOCOL, Ipv4Addr::ANY, dst, 0, 0, &[], &[0; 61]);
    assert_eq!(stack.send_raw4(&raw, dst, &valid_oversized, Raw4TxOptions::default(),
        &crate::send_control::Raw4Control::default()),
        Err(NetError::Emsgsize));
    assert_eq!(dev.packets.lock().len(), 1);
}

#[test]
fn unregister_is_exact_and_close_blocks_late_receive_publication() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();
    let removed = initial_endpoint(PROTOCOL);
    let live = initial_endpoint(PROTOCOL);
    stack.register_raw4(&removed);
    stack.register_raw4(&live);
    stack.unregister_raw4(&removed);
    let bytes = packet(PROTOCOL, Ipv4Addr::new(127, 0, 0, 2), Ipv4Addr::LOOPBACK,
        9, 0, &[], b"late");

    stack.deliver_rx(iface, &bytes).unwrap();

    assert!(removed.recv(false).is_none());
    assert!(live.recv(false).is_some());
    assert_eq!(stack.inet_tables(0).raw4.endpoint_count(PROTOCOL), 1);
}

#[test]
fn connected_raw4_publishes_hard_not_soft_matching_errors() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();
    let (other_iface, _) = stack.register_loopback();
    let local = Ipv4Addr::LOOPBACK;
    let remote = Ipv4Addr::new(192, 0, 2, 44);
    let matching_a = initial_endpoint(PROTOCOL);
    let matching_b = initial_endpoint(PROTOCOL);
    for raw in [&matching_a, &matching_b] {
        raw.bind(local, Some(iface)).unwrap();
        raw.connect(remote, None).unwrap();
        stack.register_raw4(raw);
    }
    let wrong_protocol = initial_endpoint(OTHER_PROTOCOL);
    wrong_protocol.bind(local, Some(iface)).unwrap();
    wrong_protocol.connect(remote, None).unwrap();
    stack.register_raw4(&wrong_protocol);
    let wrong_peer = initial_endpoint(PROTOCOL);
    wrong_peer.bind(local, Some(iface)).unwrap();
    wrong_peer.connect(Ipv4Addr::new(192, 0, 2, 45), None).unwrap();
    stack.register_raw4(&wrong_peer);
    let wrong_iface = initial_endpoint(PROTOCOL);
    wrong_iface.bind(local, Some(other_iface)).unwrap();
    wrong_iface.connect(remote, None).unwrap();
    stack.register_raw4(&wrong_iface);

    crate::stack_icmp::handle_error(&stack, iface, remote,
        crate::icmp::ICMP_TYPE_DEST_UNREACH, 0, &error_quote(PROTOCOL, local, remote));
    assert_eq!(matching_a.error.take(), 0);
    assert_eq!(matching_b.error.take(), 0);
    crate::stack_icmp::handle_error(&stack, iface, remote,
        crate::icmp::ICMP_TYPE_DEST_UNREACH, 3, &error_quote(PROTOCOL, local, remote));

    let expected = syscall::errno::Errno::Econnrefused as i32;
    assert_eq!(matching_a.error.take(), expected);
    assert_eq!(matching_b.error.take(), expected);
    assert_eq!(wrong_protocol.error.take(), 0);
    assert_eq!(wrong_peer.error.take(), 0);
    assert_eq!(wrong_iface.error.take(), 0);
}

#[test]
fn unconnected_raw4_error_requires_recverr() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();
    let remote = Ipv4Addr::new(198, 51, 100, 9);
    let raw = initial_endpoint(PROTOCOL);
    raw.bind(Ipv4Addr::LOOPBACK, Some(iface)).unwrap();
    stack.register_raw4(&raw);
    let quote = error_quote(PROTOCOL, Ipv4Addr::LOOPBACK, remote);

    crate::stack_icmp::handle_error(&stack, iface, remote,
        crate::icmp::ICMP_TYPE_DEST_UNREACH, 3, &quote);
    assert_eq!(raw.error.take(), 0);
    raw.error.set_recverr4(true);
    crate::stack_icmp::handle_error(&stack, iface, remote,
        crate::icmp::ICMP_TYPE_DEST_UNREACH, 3, &quote);
    assert_eq!(raw.error.take(), syscall::errno::Errno::Econnrefused as i32);
    assert_eq!(raw.error.take_extended().unwrap().destination_port, 0);
}
