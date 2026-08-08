// Transmit-path coverage for the IPv4 header option area: variable header
// length through routing, fragmentation and checksum, and the source route's
// retarget of the route lookup at its first hop.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use sync::{Socket as LockClass, Spinlock};

use crate::iface_addr::{Ipv4AddrCacheInfo, Ipv4IfaceAddr};
use crate::ipv4::{ip_checksum, IPV4_HDR_LEN};
use crate::route::RouteEntry;
use crate::ipv4_options::Compiled;
use crate::ipv4_options::uapi::{IPOPT_END, IPOPT_LSRR, IPOPT_NOOP, IPOPT_RA, IPOPT_RR};
use crate::stack::NetStack;
use crate::{Ipv4Addr, MacAddr, NetDev, NetIfaceId, NetResult, Pkt};

const SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 44);
const DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 8);
const HOP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const SPORT: u16 = 4001;
const DPORT: u16 = 4002;

struct Capture { mtu: u32, packets: Spinlock<Vec<Vec<u8>>, LockClass> }
impl NetDev for Capture {
    fn name(&self) -> &str { "opt0" }
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

fn device(stack: &NetStack, mtu: u32, addr: Ipv4Addr) -> (Arc<Capture>, NetIfaceId) {
    let dev = Arc::new(Capture { mtu, packets: Spinlock::new(Vec::new()) });
    let iface = stack.ifaces.register(dev.clone() as Arc<dyn NetDev>);
    crate::iface_addr::insert(Ipv4IfaceAddr { ns: 0, iface, addr, peer: None, prefixlen: 24,
        mask: 0xffff_ff00, broadcast: None, scope: 0, flags: 0, proto: 0, rt_priority: 0,
        cacheinfo: Ipv4AddrCacheInfo::PERMANENT });
    (dev, iface)
}

struct OutcomeCapture { fail: AtomicBool }
impl NetDev for OutcomeCapture {
    fn name(&self) -> &str { "mib0" }
    fn mac(&self) -> MacAddr { MacAddr::ZERO }
    fn mtu(&self) -> u32 { 68 }
    fn retire_namespace(&self) {}
    fn namespace_drop_action(&self) -> crate::NamespaceDropAction {
        crate::NamespaceDropAction::Destroy
    }
    fn xmit(&self, _packet: Pkt) -> NetResult<()> {
        if self.fail.load(Ordering::Acquire) { Err(crate::NetError::Eio) } else { Ok(()) }
    }
}

#[test]
fn ipv4_fragment_counters_follow_output_outcomes() {
    let ns_owner = crate::net_ns::test_support::allocate_namespace();
    let net_ns = ns_owner.id().as_u64();
    let stack = NetStack::new();
    let dev = Arc::new(OutcomeCapture { fail: AtomicBool::new(false) });
    let iface = stack.ifaces.register_in_ns(dev.clone() as Arc<dyn NetDev>, net_ns);
    stack.ifaces.arp_cache_in_ns(iface, net_ns).unwrap().insert(
        DST, MacAddr([2, 0, 0, 0, 0, 2]),
    );
    let lease = stack.ifaces.acquire_egress_in_ns(iface, net_ns).unwrap();
    let owner = crate::SocketOwner::root(ns_owner, 0);
    let before_created = crate::mib::get(net_ns, crate::mib::Mib::IpFragCreates);
    let before_oks = crate::mib::get(net_ns, crate::mib::Mib::IpFragOks);
    let before_fails = crate::mib::get(net_ns, crate::mib::Mib::IpFragFails);

    stack.xmit_ipv4_l4_with_policy(iface, lease.clone(), DST, SRC, DST, crate::IpProto::Udp,
        &[0u8; 100], 0, crate::ipv4::IPV4_DEFAULT_TTL, 1, 68, false, true,
        Some(&owner), None).unwrap();
    assert_eq!(crate::mib::get(net_ns, crate::mib::Mib::IpFragCreates), before_created + 3);
    assert_eq!(crate::mib::get(net_ns, crate::mib::Mib::IpFragOks), before_oks + 1);
    assert_eq!(crate::mib::get(net_ns, crate::mib::Mib::IpFragFails), before_fails);

    dev.fail.store(true, Ordering::Release);
    assert_eq!(stack.xmit_ipv4_l4_with_policy(iface, lease, DST, SRC, DST, crate::IpProto::Udp,
        &[0u8; 100], 0, crate::ipv4::IPV4_DEFAULT_TTL, 2, 68, false, true,
        Some(&owner), None), Err(crate::NetError::Eio));
    assert_eq!(crate::mib::get(net_ns, crate::mib::Mib::IpFragCreates), before_created + 3);
    assert_eq!(crate::mib::get(net_ns, crate::mib::Mib::IpFragOks), before_oks + 1);
    assert_eq!(crate::mib::get(net_ns, crate::mib::Mib::IpFragFails), before_fails + 1);
    crate::mib::forget(net_ns);
}

fn resolve(stack: &NetStack, iface: NetIfaceId, hop: Ipv4Addr) {
    if let Some(cache) = stack.ifaces.arp_cache_in_ns(iface, 0) {
        cache.insert(hop, MacAddr([2, 0, 0, 0, 0, 2]));
    }
}

fn owner() -> Arc<crate::SocketOwner> {
    crate::SocketOwner::root(network_namespace::initial(), 0)
}

fn compiled(bytes: &[u8]) -> Compiled { crate::ipv4_options::build_in(bytes, true, 0).unwrap() }

/// A record-route area widens every datagram's header, and the header
/// checksum covers the options.
#[test]
fn sticky_options_widen_the_udp_header() {
    let _initial_net = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (dev, iface) = device(&stack, 1500, SRC);
    stack.routes.add(RouteEntry::main(DST, 32, iface, None, Some(SRC)));
    resolve(&stack, iface, DST);
    let opts = compiled(&[IPOPT_RR, 11, 4, 0, 0, 0, 0, 0, 0, 0, 0, IPOPT_END]);

    stack.send_udp_pmtu_to_bound_opts_owned(&owner(), SRC, SPORT, DST, DPORT, b"body",
        Some(iface), 0, 0, crate::uapi::IP_PMTUDISC_DONT, Some(&opts), false).unwrap();

    let packets = dev.packets.lock();
    assert_eq!(packets.len(), 1);
    let packet = &packets[0];
    assert_eq!(packet[0], 0x48);
    assert_eq!(packet.len(), 32 + crate::udp::UDP_HDR_LEN + 4);
    assert_eq!(&packet[2..4], &(packet.len() as u16).to_be_bytes());
    assert_eq!(ip_checksum(&packet[..32]), 0);
    // The pointer advanced past the slot the fill pass wrote.
    assert_eq!(&packet[IPV4_HDR_LEN..IPV4_HDR_LEN + 3], &[IPOPT_RR, 11, 8]);
    assert_eq!(&packet[IPV4_HDR_LEN + 3..IPV4_HDR_LEN + 7], &SRC.octets());
    assert_eq!(&packet[IPV4_HDR_LEN + 7..IPV4_HDR_LEN + 11], &[0; 4]);
}

/// The option area is part of the header on EVERY fragment: it comes out of
/// the fragmentable payload budget, and the uncopied record route survives
/// only on the fragment carrying the first octet.
#[test]
fn fragmentation_accounts_for_the_option_area() {
    let _initial_net = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (dev, iface) = device(&stack, 68, SRC);
    stack.routes.add(RouteEntry::main(DST, 32, iface, None, Some(SRC)));
    resolve(&stack, iface, DST);
    let opts = compiled(&[IPOPT_RR, 7, 4, 0, 0, 0, 0, IPOPT_RA, 4, 0, 0, IPOPT_END]);
    let payload = [0x5au8; 120];

    stack.send_udp_pmtu_to_bound_opts_owned(&owner(), SRC, SPORT, DST, DPORT, &payload,
        Some(iface), 0, 0, crate::uapi::IP_PMTUDISC_DONT, Some(&opts), false).unwrap();

    let packets = dev.packets.lock();
    let hdr = IPV4_HDR_LEN + 12;
    // 68 - 32 = 36, rounded down to an eight-byte multiple.
    assert!(packets.len() > 1);
    assert_eq!(packets[0].len(), hdr + 32);
    for (index, packet) in packets.iter().enumerate() {
        assert_eq!(packet[0], 0x48, "fragment {index} header length");
        assert_eq!(ip_checksum(&packet[..hdr]), 0);
        let offset = u16::from_be_bytes([packet[6], packet[7]]) & 0x1fff;
        assert_eq!(offset as usize * 8, if index == 0 { 0 } else { index * 32 });
        // The router alert is copied to every fragment; the record route is not.
        assert_eq!(&packet[IPV4_HDR_LEN + 7..IPV4_HDR_LEN + 11], &[IPOPT_RA, 4, 0, 0]);
        if index == 0 {
            assert_eq!(&packet[IPV4_HDR_LEN..IPV4_HDR_LEN + 3], &[IPOPT_RR, 7, 8]);
            assert_eq!(&packet[IPV4_HDR_LEN + 3..IPV4_HDR_LEN + 7], &SRC.octets());
        } else {
            assert_eq!(&packet[IPV4_HDR_LEN..IPV4_HDR_LEN + 7], &[IPOPT_NOOP; 7]);
        }
    }
    let last = packets.len() - 1;
    assert_eq!(u16::from_be_bytes([packets[last][6], packets[last][7]]) & 0x2000, 0);
    for packet in &packets[..last] {
        assert_eq!(u16::from_be_bytes([packet[6], packet[7]]) & 0x2000, 0x2000);
    }
}

/// A loose source route sends the datagram to its first hop — the route
/// lookup, the interface, the header destination and the UDP checksum all
/// follow that hop, while the option area carries the real destination.
#[test]
fn source_route_retargets_the_route_lookup_at_the_first_hop() {
    let _initial_net = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (direct, direct_iface) = device(&stack, 1500, SRC);
    let (hop_dev, hop_iface) = device(&stack, 1500, Ipv4Addr::new(192, 0, 2, 45));
    stack.routes.add(RouteEntry::main(DST, 32, direct_iface, None, Some(SRC)));
    stack.routes.add(RouteEntry::main(HOP, 32, hop_iface, None, Some(SRC)));
    resolve(&stack, direct_iface, DST);
    resolve(&stack, hop_iface, HOP);
    let mut area = alloc::vec![IPOPT_LSRR, 7, 4];
    area.extend_from_slice(&HOP.octets());
    area.push(IPOPT_END);
    let opts = compiled(&area);

    stack.send_udp_pmtu_to_bound_opts_owned(&owner(), SRC, SPORT, DST, DPORT, b"body",
        None, 0, 0, crate::uapi::IP_PMTUDISC_DONT, Some(&opts), false).unwrap();

    assert!(direct.packets.lock().is_empty());
    let packets = hop_dev.packets.lock();
    assert_eq!(packets.len(), 1);
    let packet = &packets[0];
    assert_eq!(&packet[16..20], &HOP.octets());
    assert_eq!(&packet[IPV4_HDR_LEN + 3..IPV4_HDR_LEN + 7], &DST.octets());
    // The transport checksum is computed over the address the header carries.
    let udp = &packet[IPV4_HDR_LEN + 8..];
    assert!(crate::udp::UdpHdr::parse(udp, SRC, HOP).is_ok());
}
