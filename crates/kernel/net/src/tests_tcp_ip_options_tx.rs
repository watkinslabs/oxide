// Transmit-path coverage for a TCP connection's sticky IPv4 option area: the
// segments it emits carry the area, a source route retargets the wire
// destination WITHOUT moving the segment's own checksum, and the area is
// charged against the MSS the connection sends at.

use alloc::sync::Arc;
use alloc::vec::Vec;

use sync::{Socket as LockClass, Spinlock};

use crate::iface_addr::{Ipv4AddrCacheInfo, Ipv4IfaceAddr};
use crate::ipv4::{ip_checksum, IPV4_HDR_LEN};
use crate::ipv4_options::uapi::{IPOPT_END, IPOPT_LSRR, IPOPT_RR};
use crate::route::RouteEntry;
use crate::sock_opts::sol_ip::IpOpts;
use crate::stack::{NetStack, TcpEntry};
use crate::tcp_conn::TcpConn;
use crate::{Endpoint, IpAddr, Ipv4Addr, MacAddr, NetDev, NetIfaceId, NetResult, Pkt};

const SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 44);
const DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 8);
const HOP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const SPORT: u16 = 4001;
const DPORT: u16 = 443;
/// A four-byte-aligned record-route area: kind, length, pointer, two slots.
const RR_AREA: [u8; 12] = [IPOPT_RR, 11, 4, 0, 0, 0, 0, 0, 0, 0, 0, IPOPT_END];

struct Capture { packets: Spinlock<Vec<Vec<u8>>, LockClass> }
impl NetDev for Capture {
    fn name(&self) -> &str { "topt0" }
    fn mac(&self) -> MacAddr { MacAddr::ZERO }
    fn mtu(&self) -> u32 { 1500 }
    fn retire_namespace(&self) {}
    fn namespace_drop_action(&self) -> crate::NamespaceDropAction {
        crate::NamespaceDropAction::Destroy
    }
    fn xmit(&self, packet: Pkt) -> NetResult<()> {
        self.packets.lock().push(packet.data().to_vec());
        Ok(())
    }
}

fn device(stack: &NetStack, addr: Ipv4Addr) -> (Arc<Capture>, NetIfaceId) {
    let dev = Arc::new(Capture { packets: Spinlock::new(Vec::new()) });
    let iface = stack.ifaces.register(dev.clone() as Arc<dyn NetDev>);
    crate::iface_addr::insert(Ipv4IfaceAddr { ns: 0, iface, addr, peer: None, prefixlen: 24,
        mask: 0xffff_ff00, broadcast: None, scope: 0, flags: 0, proto: 0, rt_priority: 0,
        cacheinfo: Ipv4AddrCacheInfo::PERMANENT });
    (dev, iface)
}

fn resolve(stack: &NetStack, iface: NetIfaceId, hop: Ipv4Addr) {
    if let Some(cache) = stack.ifaces.arp_cache_in_ns(iface, 0) {
        cache.insert(hop, MacAddr([2, 0, 0, 0, 0, 2]));
    }
}

/// An established entry whose sticky option area is `area`, empty when `None`.
fn entry(area: Option<&[u8]>) -> TcpEntry {
    let mut conn = TcpConn::new_client(
        Endpoint { ip: IpAddr::V4(SRC), port: SPORT },
        Endpoint { ip: IpAddr::V4(DST), port: DPORT }, 1);
    conn.state = crate::tcp_state::TcpState::Established;
    let opts = Arc::new(IpOpts::default());
    if let Some(area) = area {
        opts.set_options(crate::ipv4_options::build_in(area, true, 0).unwrap());
    }
    TcpEntry::new_bound_ip_opts(conn, Arc::new(crate::SocketError::new()), None,
        Arc::new(crate::bpf_filter::SocketFilter::new()),
        Arc::new(::core::sync::atomic::AtomicI32::new(crate::uapi::IP_PMTUDISC_DONT)),
        Arc::new(::core::sync::atomic::AtomicI32::new(crate::uapi::IPV6_PMTUDISC_DONT)),
        Arc::new(::core::sync::atomic::AtomicI32::new(0)),
        None, Arc::new(crate::min_hop::MinHop::new()), opts)
}

/// Without an option area a segment leaves on the minimum header, so the
/// widened header in the next test is the option area's doing.
#[test]
fn a_connection_without_sticky_options_emits_the_minimum_header() {
    let stack = NetStack::new();
    let (dev, iface) = device(&stack, SRC);
    stack.routes.add(RouteEntry::main(DST, 32, iface, None, Some(SRC)));
    resolve(&stack, iface, DST);

    stack.send_tcp_entry_segment_in(&entry(None), IpAddr::V4(SRC), IpAddr::V4(DST),
        b"segment-bytes", 0).unwrap();

    let packets = dev.packets.lock();
    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0][0], 0x45);
    assert_eq!(packets[0].len(), IPV4_HDR_LEN + 13);
}

/// The socket's sticky area rides ahead of every TCP segment: the header
/// widens, its length field and checksum cover the options, and the fill pass
/// stamps the outgoing address into the record-route slot.
#[test]
fn a_tcp_segment_carries_the_sockets_sticky_option_area() {
    let stack = NetStack::new();
    let (dev, iface) = device(&stack, SRC);
    stack.routes.add(RouteEntry::main(DST, 32, iface, None, Some(SRC)));
    resolve(&stack, iface, DST);

    stack.send_tcp_entry_segment_in(&entry(Some(&RR_AREA)), IpAddr::V4(SRC), IpAddr::V4(DST),
        b"segment-bytes", 0).unwrap();

    let packets = dev.packets.lock();
    assert_eq!(packets.len(), 1);
    let packet = &packets[0];
    let hdr = IPV4_HDR_LEN + 12;
    assert_eq!(packet[0], 0x48);
    assert_eq!(packet.len(), hdr + 13);
    assert_eq!(&packet[2..4], &(packet.len() as u16).to_be_bytes());
    assert_eq!(ip_checksum(&packet[..hdr]), 0);
    assert_eq!(&packet[IPV4_HDR_LEN..IPV4_HDR_LEN + 3], &[IPOPT_RR, 11, 8]);
    assert_eq!(&packet[IPV4_HDR_LEN + 3..IPV4_HDR_LEN + 7], &SRC.octets());
    assert_eq!(&packet[hdr..], b"segment-bytes");
}

/// A loose source route sends the segment to its first hop and records the
/// real destination in the option. Unlike a datagram socket, the segment's own
/// checksum was computed against the FINAL destination before the option area
/// was known, so the source route must not disturb the segment bytes.
#[test]
fn a_tcp_source_route_retargets_the_wire_destination_only() {
    let stack = NetStack::new();
    let (direct, direct_iface) = device(&stack, SRC);
    let (hop_dev, hop_iface) = device(&stack, Ipv4Addr::new(192, 0, 2, 45));
    stack.routes.add(RouteEntry::main(DST, 32, direct_iface, None, Some(SRC)));
    stack.routes.add(RouteEntry::main(HOP, 32, hop_iface, None, Some(SRC)));
    resolve(&stack, direct_iface, DST);
    resolve(&stack, hop_iface, HOP);
    let mut area = alloc::vec![IPOPT_LSRR, 7, 4];
    area.extend_from_slice(&HOP.octets());
    area.push(IPOPT_END);

    stack.send_tcp_entry_segment_in(&entry(Some(&area)), IpAddr::V4(SRC), IpAddr::V4(DST),
        b"segment-bytes", 0).unwrap();

    assert!(direct.packets.lock().is_empty());
    let packets = hop_dev.packets.lock();
    assert_eq!(packets.len(), 1);
    let packet = &packets[0];
    assert_eq!(&packet[16..20], &HOP.octets());
    assert_eq!(&packet[IPV4_HDR_LEN + 3..IPV4_HDR_LEN + 7], &DST.octets());
    assert_eq!(&packet[IPV4_HDR_LEN + 8..], b"segment-bytes");
}

/// Re-deriving the MSS charges the option area against the path MTU, so the
/// segments the connection emits still fit once the wider header is prepended.
#[test]
fn the_sticky_option_area_is_charged_against_the_connections_mss() {
    let stack = NetStack::new();
    let (_dev, iface) = device(&stack, SRC);
    stack.routes.add(RouteEntry::main(DST, 32, iface, None, Some(SRC)));
    resolve(&stack, iface, DST);

    let bare = entry(None);
    stack.tcp_sync_mss(&bare);
    let without = bare.conn.lock().own_mss;
    assert!(without > 0);

    let routed = entry(Some(&RR_AREA));
    stack.tcp_sync_mss(&routed);
    assert_eq!(routed.conn.lock().own_mss, without - RR_AREA.len() as u16);
}
