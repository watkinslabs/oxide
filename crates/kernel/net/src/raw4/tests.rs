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
const NET_A: u64 = 8_320_001;
const NET_B: u64 = 8_320_002;

fn endpoint(protocol: u8, net_ns: u64) -> Arc<Raw4Endpoint> {
    Raw4Endpoint::new(protocol, net_ns, Arc::new(SocketFilter::new()),
        Arc::new(SocketMcast::new()))
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

fn filter_runner(_kind: FilterKind, insns: &[u8], _ctx: FilterContext<'_>) -> u32 {
    u32::from_ne_bytes(insns.try_into().unwrap())
}

#[test]
fn exact_protocol_fanout_is_namespace_local() {
    let stack = NetStack::new();
    let (iface_a, _) = stack.register_loopback_in(NET_A);
    let (_iface_b, _) = stack.register_loopback_in(NET_B);
    let exact_a = endpoint(PROTOCOL, NET_A);
    let exact_b = endpoint(PROTOCOL, NET_B);
    let wrong = endpoint(OTHER_PROTOCOL, NET_A);
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
    let stack = NetStack::new();
    let (wrong_iface, _) = stack.register_loopback();
    let (right_iface, _) = stack.register_loopback();
    let expected_peer = Ipv4Addr::new(127, 0, 0, 2);
    let raw = endpoint(PROTOCOL, 0);
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
    install_bpf_filter_context_runner(filter_runner);
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();
    let dropped = endpoint(PROTOCOL, 0);
    dropped.bpf_filter.attach(FilterProgram {
        kind: FilterKind::Ebpf, insns: 0u32.to_ne_bytes().to_vec(),
    }).unwrap();
    let truncated = endpoint(PROTOCOL, 0);
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
fn raw_udp_clone_does_not_interfere_with_transport_delivery() {
    const PORT: u16 = 43_210;
    let stack = NetStack::new();
    let (iface, loopback) = stack.register_loopback();
    let raw = endpoint(IpProto::Udp as u8, 0);
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
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();
    let raw = endpoint(PROTOCOL, 0);
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
    let stack = NetStack::new();
    let (iface, loopback) = stack.register_loopback();
    let joined = endpoint(PROTOCOL, 0);
    let unjoined = endpoint(PROTOCOL, 0);
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
    let raw = endpoint(PROTOCOL, 0);
    let options = Raw4TxOptions { pmtudisc: crate::uapi::IP_PMTUDISC_DONT,
        ..Raw4TxOptions::default() };

    stack.send_raw4(&raw, dst, &[0x5a; 100], options).unwrap();

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
fn hdrincl_rewrites_kernel_fields_preserves_user_header_and_never_fragments() {
    let stack = NetStack::new();
    let dst = Ipv4Addr::new(203, 0, 113, 9);
    let (_iface, dev) = routed_capture(&stack, 80, dst);
    let raw = endpoint(PROTOCOL, 0);
    raw.set_hdrincl(true);
    let mut user = packet(OTHER_PROTOCOL, Ipv4Addr::ANY, dst, 0, 0, &[], b"body");
    user[1] = 0x2e;
    user[8] = 31;
    user[2..4].copy_from_slice(&0u16.to_be_bytes());
    user[10..12].copy_from_slice(&0xdead_u16.to_be_bytes());

    stack.send_raw4(&raw, dst, &user, Raw4TxOptions::default()).unwrap();

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
    assert_eq!(stack.send_raw4(&raw, dst, &oversized, Raw4TxOptions::default()),
        Err(NetError::Einval));
    let valid_oversized = packet(PROTOCOL, Ipv4Addr::ANY, dst, 0, 0, &[], &[0; 61]);
    assert_eq!(stack.send_raw4(&raw, dst, &valid_oversized, Raw4TxOptions::default()),
        Err(NetError::Emsgsize));
    assert_eq!(dev.packets.lock().len(), 1);
}

#[test]
fn unregister_is_exact_and_close_blocks_late_receive_publication() {
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();
    let removed = endpoint(PROTOCOL, 0);
    let live = endpoint(PROTOCOL, 0);
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
