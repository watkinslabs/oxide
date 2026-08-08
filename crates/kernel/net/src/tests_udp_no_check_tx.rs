// `SO_NO_CHECK` on the IPv4 UDP transmit path: the datagram that reaches the
// device carries a zero checksum field, and nothing else about it changes.

use alloc::sync::Arc;
use alloc::vec::Vec;

use sync::{Socket as LockClass, Spinlock};

use crate::iface_addr::{Ipv4AddrCacheInfo, Ipv4IfaceAddr};
use crate::ipv4::IPV4_HDR_LEN;
use crate::route::RouteEntry;
use crate::stack::NetStack;
use crate::{Ipv4Addr, MacAddr, NetDev, NetResult, Pkt};

const SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 44);
const DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 8);
const SPORT: u16 = 4001;
const DPORT: u16 = 4002;
const BODY: &[u8] = b"payload-bytes";

struct Capture { packets: Spinlock<Vec<Vec<u8>>, LockClass> }
impl NetDev for Capture {
    fn name(&self) -> &str { "nck0" }
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

/// One datagram on the wire, with `no_check` as given.
fn emit(no_check: bool) -> Vec<u8> {
    let stack = NetStack::new();
    let dev = Arc::new(Capture { packets: Spinlock::new(Vec::new()) });
    let iface = stack.ifaces.register(dev.clone() as Arc<dyn NetDev>);
    crate::iface_addr::insert(Ipv4IfaceAddr { ns: 0, iface, addr: SRC, peer: None, prefixlen: 24,
        mask: 0xffff_ff00, broadcast: None, scope: 0, flags: 0, proto: 0, rt_priority: 0,
        cacheinfo: Ipv4AddrCacheInfo::PERMANENT });
    stack.routes.add(RouteEntry::main(DST, 32, iface, None, Some(SRC)));
    if let Some(cache) = stack.ifaces.arp_cache_in_ns(iface, 0) {
        cache.insert(DST, MacAddr([2, 0, 0, 0, 0, 2]));
    }
    let owner = crate::SocketOwner::root(network_namespace::initial(), 0);
    stack.send_udp_pmtu_to_bound_opts_owned(&owner, SRC, SPORT, DST, DPORT, BODY,
        Some(iface), 0, 0, crate::uapi::IP_PMTUDISC_DONT, None, no_check, crate::TxMeta::NONE).unwrap();
    let packets = dev.packets.lock();
    assert_eq!(packets.len(), 1);
    packets[0].clone()
}

/// The suppressed checksum reaches the wire as the reserved zero, and the
/// datagram is otherwise byte-identical to the checksummed one.
#[test]
fn so_no_check_zeroes_the_transmitted_udp_checksum() {
    let _initial_net = crate::hosted_fixture::init_net_domain();
    let suppressed = emit(true);
    let checked = emit(false);
    let field = IPV4_HDR_LEN + 6;

    assert_eq!(&suppressed[field..field + 2], &[0, 0]);
    assert_ne!(&checked[field..field + 2], &[0, 0]);
    assert_eq!(suppressed.len(), checked.len());
    assert_eq!(&suppressed[..field], &checked[..field]);
    assert_eq!(&suppressed[field + 2..], &checked[field + 2..]);
    assert_eq!(&suppressed[IPV4_HDR_LEN + crate::udp::UDP_HDR_LEN..], BODY);
}

/// A receiver takes the suppressed datagram: a zero checksum field means "not
/// computed" on IPv4 and is never validated.
#[test]
fn a_suppressed_checksum_datagram_still_parses_at_the_receiver() {
    let _initial_net = crate::hosted_fixture::init_net_domain();
    let packet = emit(true);
    let header = crate::udp::UdpHdr::parse(&packet[IPV4_HDR_LEN..], SRC, DST).unwrap();
    assert_eq!(header.checksum, 0);
    assert_eq!((header.src_port, header.dst_port), (SPORT, DPORT));
}

/// Segmentation offload and checksum suppression are mutually exclusive: a
/// socket asking for both is refused rather than emitting segments whose
/// checksums nobody computed.
#[test]
fn segmentation_offload_refuses_a_socket_that_suppressed_its_checksum() {
    use crate::sock_opts::sol_udp::segment::plan_v4;
    assert!(plan_v4(3_000, 1_000, 1_500, false).is_ok());
    assert_eq!(plan_v4(3_000, 1_000, 1_500, true), Err(crate::NetError::Einval));
}
