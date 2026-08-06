use super::*;

// ----- F180c: NDP cache + NS/NA dispatch ----------------------------

#[test]
fn f180c_na_populates_ndp_cache() {
    let _domain = crate::hosted_fixture::init_net_domain();
    use crate::addr::{Ipv6Addr, MacAddr};
    use crate::ipv6::{Ipv6Hdr, IPV6_HDR_LEN};
    use crate::ndp::NdpMsg;
    let stack = NetStack::new();
    let (id, _lo) = stack.register_loopback();
    let target = Ipv6Addr::from_segments([0xFE80,0,0,0,0,0,0,2]);
    let neighbor_mac = MacAddr([0xde, 0xad, 0xbe, 0xef, 0, 1]);
    let na = NdpMsg::build_na(target, Ipv6Addr::LOOPBACK, neighbor_mac, target, 0);
    let total = IPV6_HDR_LEN + na.len();
    let mut frame = alloc::vec![0u8; total];
    let mut h = Ipv6Hdr::build(target, Ipv6Addr::LOOPBACK, IpProto::Icmpv6, na.len() as u16);
    h.hop_limit = u8::MAX;
    h.write_to(&mut frame[..IPV6_HDR_LEN]);
    frame[IPV6_HDR_LEN..].copy_from_slice(&na);
    stack.deliver_rx_ipv6(id, &frame).unwrap();
    assert_eq!(stack.ndp_lookup(id, target), Some(neighbor_mac),
        "NA target_lladdr must populate the iface-scoped NDP cache");
}

#[test]
fn f180c_ndp_cache_is_scoped_by_iface() {
    let _domain = crate::hosted_fixture::init_net_domain();
    use crate::addr::{Ipv6Addr, MacAddr};
    use crate::ipv6::{Ipv6Hdr, IPV6_HDR_LEN};
    use crate::ndp::NdpMsg;

    let stack = NetStack::new();
    let (id1, _lo1) = stack.register_loopback();
    let (id2, _lo2) = stack.register_loopback();
    let target = Ipv6Addr::from_segments([0xFE80,0,0,0,0,0,0,2]);
    let dst = Ipv6Addr::LOOPBACK;
    let mac1 = MacAddr([0x02,0,0,0,0,1]);
    let mac2 = MacAddr([0x02,0,0,0,0,2]);

    for (id, mac) in [(id1, mac1), (id2, mac2)] {
        let na = NdpMsg::build_na(target, dst, mac, target, 0);
        let mut frame = alloc::vec![0u8; IPV6_HDR_LEN + na.len()];
        let mut hdr = Ipv6Hdr::build(target, dst, IpProto::Icmpv6, na.len() as u16);
        hdr.hop_limit = u8::MAX;
        hdr.write_to(&mut frame[..IPV6_HDR_LEN]);
        frame[IPV6_HDR_LEN..].copy_from_slice(&na);
        stack.deliver_rx_ipv6(id, &frame).unwrap();
    }

    assert_eq!(stack.ndp_lookup(id1, target), Some(mac1));
    assert_eq!(stack.ndp_lookup(id2, target), Some(mac2));
}

#[test]
fn f180c_unregister_iface_drops_only_its_ndp_entries() {
    let _domain = crate::hosted_fixture::init_net_domain();
    use crate::addr::{Ipv6Addr, MacAddr};
    let stack = NetStack::new();
    let (id1, _lo1) = stack.register_loopback();
    let (id2, _lo2) = stack.register_loopback();
    let target = Ipv6Addr::from_segments([0xFE80,0,0,0,0,0,0,2]);
    let mac1 = MacAddr([0x02,0,0,0,0,1]);
    let mac2 = MacAddr([0x02,0,0,0,0,2]);
    let retired_cache = stack.ifaces.ndp_cache_for(id1).unwrap();

    stack.ndp_insert(id1, target, mac1);
    stack.ndp_insert(id2, target, mac2);
    assert_eq!(retired_cache.lookup(target), Some(mac1));
    assert!(stack.unregister_iface(id1));

    assert_eq!(retired_cache.lookup(target), None,
        "a retained handle to the retired generation must be closed and empty");
    assert_eq!(stack.ndp_lookup(id1, target), None);
    assert_eq!(stack.ndp_lookup(id2, target), Some(mac2));
}

#[test]
fn f180c_ns_for_owned_addr_emits_na() {
    let _domain = crate::hosted_fixture::init_net_domain();
    use crate::addr::{Ipv6Addr, MacAddr};
    use crate::ipv6::{Ipv6Hdr, IPV6_HDR_LEN};
    use crate::ndp::{NdpMsg, NDP_NA};
    let stack = NetStack::new();
    let (id, lo) = stack.register_loopback();
    let our_addr = Ipv6Addr::from_segments([0xFE80,0,0,0,0,0,0,1]);
    stack.add_v6_addr(id, our_addr);
    let peer = Ipv6Addr::from_segments([0xFE80,0,0,0,0,0,0,2]);
    let peer_mac = MacAddr([1,2,3,4,5,6]);
    let ns = NdpMsg::build_ns(peer, our_addr, peer_mac, our_addr);
    let total = IPV6_HDR_LEN + ns.len();
    let mut frame = alloc::vec![0u8; total];
    let mut h = Ipv6Hdr::build(peer, our_addr, IpProto::Icmpv6, ns.len() as u16);
    h.hop_limit = u8::MAX;
    h.write_to(&mut frame[..IPV6_HDR_LEN]);
    frame[IPV6_HDR_LEN..].copy_from_slice(&ns);
    stack.deliver_rx_ipv6(id, &frame).unwrap();
    // Source-lladdr from the NS should land in the cache.
    assert_eq!(stack.ndp_lookup(id, peer), Some(peer_mac));
    // And lo should have a frame queued — the NA reply.
    let reply = lo.rx_pop().expect("NS for owned addr must produce NA");
    let parsed = Ipv6Hdr::parse(reply.data()).unwrap();
    let body = &reply.data()[IPV6_HDR_LEN..];
    assert_eq!(body[0], NDP_NA, "reply must be NDP NA (136)");
    let _ = parsed;
}

#[test]
fn f180c_ns_for_unowned_addr_silent() {
    let _domain = crate::hosted_fixture::init_net_domain();
    use crate::addr::{Ipv6Addr, MacAddr};
    use crate::ipv6::{Ipv6Hdr, IPV6_HDR_LEN};
    use crate::ndp::NdpMsg;
    let stack = NetStack::new();
    let (id, lo) = stack.register_loopback();
    let unowned = Ipv6Addr::from_segments([0xFE80,0,0,0,0,0,0,9]);
    let peer = Ipv6Addr::LOOPBACK;
    let ns = NdpMsg::build_ns(peer, unowned, MacAddr::ZERO, unowned);
    let total = IPV6_HDR_LEN + ns.len();
    let mut frame = alloc::vec![0u8; total];
    let h = Ipv6Hdr::build(peer, unowned, IpProto::Icmpv6, ns.len() as u16);
    h.write_to(&mut frame[..IPV6_HDR_LEN]);
    frame[IPV6_HDR_LEN..].copy_from_slice(&ns);
    stack.deliver_rx_ipv6(id, &frame).unwrap();
    assert!(lo.rx_pop().is_none(), "NS for unowned addr must not reply");
}

#[test]
fn ipv6_router_solicitation_emits_to_all_routers() {
    let _domain = crate::hosted_fixture::init_net_domain();
    use crate::ipv6::{Ipv6Hdr, IPV6_HDR_LEN};
    use crate::ndp::{IPV6_ALL_ROUTERS, NDP_RS, NDP_RS_FIXED};
    let stack = NetStack::new();
    let (id, lo) = stack.register_loopback();

    stack.send_router_solicitation(id, Ipv6Addr::ANY).unwrap();

    let pkt = lo.rx_pop().expect("RS should be transmitted");
    let hdr = Ipv6Hdr::parse(pkt.data()).unwrap();
    assert_eq!(hdr.src, Ipv6Addr::ANY);
    assert_eq!(hdr.dst, IPV6_ALL_ROUTERS);
    assert_eq!(hdr.next_header, IpProto::Icmpv6 as u8);
    let body = &pkt.data()[IPV6_HDR_LEN..];
    assert_eq!(body.len(), NDP_RS_FIXED);
    assert_eq!(body[0], NDP_RS);
}

#[test]
fn ipv6_router_advertisement_installs_slaac_addr_and_routes() {
    let _domain = crate::hosted_fixture::init_net_domain();
    use crate::addr::{IpProto, Ipv6Addr, MacAddr};
    use crate::ipv6::{Ipv6Hdr, IPV6_HDR_LEN};

    let stack = NetStack::new();
    let (id, _lo) = stack.register_loopback();
    let router = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,1]);
    let all_nodes = Ipv6Addr::from_segments([0xff02,0,0,0,0,0,0,1]);
    let prefix = Ipv6Addr::from_segments([0x2001,0xdb8,0x77,0,0,0,0,0]);
    let router_mac = MacAddr([0x02,0xaa,0xbb,0xcc,0xdd,0xee]);
    let ra = crate::ndp::RouterAdvertisement::build_one_prefix(
        router,
        all_nodes,
        router_mac,
        1800,
        prefix,
        64,
        crate::ndp::NDP_PIO_FLAG_ONLINK | crate::ndp::NDP_PIO_FLAG_AUTO,
    );
    let mut frame = alloc::vec![0u8; IPV6_HDR_LEN + ra.len()];
    let mut hdr = Ipv6Hdr::build(router, all_nodes, IpProto::Icmpv6, ra.len() as u16);
    hdr.hop_limit = u8::MAX;
    hdr.write_to(&mut frame[..IPV6_HDR_LEN]);
    frame[IPV6_HDR_LEN..].copy_from_slice(&ra);

    stack.deliver_rx_ipv6(id, &frame).unwrap();

    let expected = Ipv6Addr::from_segments([0x2001,0xdb8,0x77,0,0x0200,0x00ff,0xfe00,0x0000]);
    assert!(!stack.v6_addr_owned_by(id, expected), "SLAAC address must remain tentative during DAD");
    stack.ipv6_control_tick(0);
    stack.ipv6_control_tick(crate::stack_ipv6::DAD_DELAY_NS);
    assert!(stack.v6_addr_owned_by(id, expected), "SLAAC address should be bound after DAD");
    assert_eq!(stack.ndp_lookup(id, router), Some(router_mac));

    let onlink = stack.routes6.lookup(expected).expect("on-link prefix route");
    assert_eq!(onlink.iface, id);
    assert_eq!(onlink.prefix_len, 64);
    assert_eq!(onlink.src_hint, Some(expected));

    let outside = Ipv6Addr::from_segments([0x2001,0xdb8,0x99,0,0,0,0,1]);
    let default = stack.routes6.lookup(outside).expect("default route from RA");
    assert_eq!(default.iface, id);
    assert_eq!(default.prefix_len, 0);
    assert_eq!(default.gateway, Some(router));
}
