use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::addr::{IpProto, Ipv6Addr, MacAddr};
use crate::ipv6::{Ipv6Hdr, IPV6_HDR_LEN};
use crate::stack::NetStack;
use crate::NetDev;

const SEC: u64 = 1_000_000_000;

struct FailProbeDev { attempts: AtomicUsize }

impl crate::NetDev for FailProbeDev {
    fn name(&self) -> &str { "dadfail0" }
    fn mac(&self) -> MacAddr { MacAddr([2,3,4,5,6,7]) }
    fn mtu(&self) -> u32 { 1500 }
    fn retire_namespace(&self) {}
    fn namespace_drop_action(&self) -> crate::NamespaceDropAction {
        crate::NamespaceDropAction::Destroy
    }
    fn xmit(&self, _packet: crate::Pkt) -> crate::NetResult<()> {
        self.attempts.fetch_add(1, Ordering::Relaxed);
        Err(crate::NetError::Enobufs)
    }
}

struct PersistentFailProbeDev { attempts: AtomicUsize }

impl crate::NetDev for PersistentFailProbeDev {
    fn name(&self) -> &str { "dadmove0" }
    fn mac(&self) -> MacAddr { MacAddr([2,3,4,5,6,8]) }
    fn mtu(&self) -> u32 { 1500 }
    fn retire_namespace(&self) {}
    fn namespace_drop_action(&self) -> crate::NamespaceDropAction {
        crate::NamespaceDropAction::MoveToInitial
    }
    fn xmit(&self, _packet: crate::Pkt) -> crate::NetResult<()> {
        self.attempts.fetch_add(1, Ordering::Relaxed);
        Err(crate::NetError::Enobufs)
    }
}

fn advertisement(prefix: Ipv6Addr) -> crate::ndp::RouterAdvertisement {
    crate::ndp::RouterAdvertisement {
        hop_limit: 64, flags: 0, router_lifetime: 0,
        reachable_time: 0, retrans_timer: 0, source_lladdr: None,
        prefixes: alloc::vec![crate::ndp::PrefixInfo {
            prefix_len: 64,
            flags: crate::ndp::NDP_PIO_FLAG_ONLINK | crate::ndp::NDP_PIO_FLAG_AUTO,
            valid_lifetime: 60, preferred_lifetime: 30, prefix,
        }],
    }
}

fn deliver_ndp(stack: &NetStack, iface: crate::NetIfaceId, src: Ipv6Addr,
               dst: Ipv6Addr, payload: &[u8]) {
    let mut packet = alloc::vec![0; IPV6_HDR_LEN + payload.len()];
    let mut hdr = Ipv6Hdr::build(src, dst, IpProto::Icmpv6, payload.len() as u16);
    hdr.hop_limit = u8::MAX;
    hdr.write_to(&mut packet[..IPV6_HDR_LEN]);
    packet[IPV6_HDR_LEN..].copy_from_slice(payload);
    stack.deliver_rx_ipv6(iface, &packet).unwrap();
}

#[test]
fn slaac_is_tentative_until_dad_timer_and_emits_correct_solicitation() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, loopback) = stack.register_loopback();
    let router = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,1]);
    let prefix = Ipv6Addr::from_segments([0x2001,0xdb8,0x844,1,0,0,0,0]);
    let target = super::ra::slaac_eui64_addr(prefix, MacAddr::ZERO);

    stack.apply_router_advertisement(0, iface, router, &advertisement(prefix));
    let row = stack.v6_addr_snapshot().into_iter()
        .find(|(_, row)| row.addr == target).unwrap().1;
    assert!(matches!(row.state, super::Ipv6AddrState::Tentative { .. }));
    assert_ne!(row.flags() & crate::iface_addr::IFA_F_TENTATIVE, 0);
    assert!(!stack.v6_addr_owned_by(iface, target));
    assert_ne!(stack.v6_select_source(iface, target, None), Some(target));

    let packet = loopback.rx_pop().unwrap();
    let hdr = Ipv6Hdr::parse(packet.data()).unwrap();
    assert_eq!((hdr.src, hdr.dst),
        (Ipv6Addr::ANY, crate::ndp::solicited_node_multicast(target)));
    let msg = crate::ndp::NdpMsg::parse(&packet.data()[IPV6_HDR_LEN..], hdr.src, hdr.dst).unwrap();
    assert_eq!((msg.typ, msg.target, msg.lladdr), (crate::ndp::NDP_NS, target, None));

    stack.ipv6_control_tick(SEC - 1);
    assert!(!stack.v6_addr_owned_by(iface, target));
    stack.ipv6_control_tick(SEC);
    assert!(stack.v6_addr_owned_by(iface, target));
    let row = stack.v6_addr_snapshot().into_iter()
        .find(|(_, row)| row.addr == target).unwrap().1;
    assert_eq!(row.state, super::Ipv6AddrState::Assigned);
}

#[test]
fn matching_ns_or_na_fails_dad_and_address_stays_unusable() {
    let _domain = crate::hosted_fixture::init_net_domain();
    for advertisement_kind in [crate::ndp::NDP_NS, crate::ndp::NDP_NA] {
        let stack = NetStack::new();
        let (iface, _) = stack.register_loopback();
        let router = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,2]);
        let peer = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,3]);
        let prefix = Ipv6Addr::from_segments([0x2001,0xdb8,0x844,2,0,0,0,0]);
        let target = super::ra::slaac_eui64_addr(prefix, MacAddr::ZERO);
        stack.apply_router_advertisement(0, iface, router, &advertisement(prefix));
        let dst = crate::ndp::solicited_node_multicast(target);
        let payload = if advertisement_kind == crate::ndp::NDP_NS {
            crate::ndp::NdpMsg::build_ns(peer, dst, MacAddr([2,3,4,5,6,7]), target)
        } else {
            crate::ndp::NdpMsg::build_dad_defense_na(peer,
                MacAddr([2,3,4,5,6,7]), target)
        };
        let packet_dst = if advertisement_kind == crate::ndp::NDP_NS {
            dst
        } else { crate::ndp::IPV6_ALL_NODES };
        let rtnl_before = stack.rtnl.acquisition_count();
        deliver_ndp(&stack, iface, peer, packet_dst, &payload);
        assert_eq!(stack.rtnl.acquisition_count(), rtnl_before,
            "NDP ingress must not acquire RTNL");
        let ingress_row = stack.v6_addr_snapshot().into_iter()
            .find(|(_, row)| row.addr == target).unwrap().1;
        assert_eq!(ingress_row.state, super::Ipv6AddrState::DadFailed,
            "validated NDP type {advertisement_kind} must fail DAD before timer publication");
        stack.ipv6_control_tick(SEC);
        let row = stack.v6_addr_snapshot().into_iter()
            .find(|(_, row)| row.addr == target).unwrap().1;
        assert_eq!(row.state, super::Ipv6AddrState::DadFailed);
        assert_ne!(row.flags() & crate::iface_addr::IFA_F_DADFAILED, 0);
        assert!(!stack.v6_addr_owned_by(iface, target));
    }
}

#[test]
fn failed_dad_probe_retries_without_arming_success() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let dev = Arc::new(FailProbeDev { attempts: AtomicUsize::new(0) });
    let iface = stack.ifaces.register(dev.clone() as Arc<dyn crate::NetDev>);
    let router = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,4]);
    let prefix = Ipv6Addr::from_segments([0x2001,0xdb8,0x844,4,0,0,0,0]);
    let target = super::ra::slaac_eui64_addr(prefix, dev.mac());

    stack.apply_router_advertisement(0, iface, router, &advertisement(prefix));
    assert_eq!(dev.attempts.load(Ordering::Relaxed), 1);
    let row = stack.v6_addr_snapshot().into_iter()
        .find(|(_, row)| row.addr == target).unwrap().1;
    assert!(matches!(row.state, super::Ipv6AddrState::Tentative {
        dad_until_ns: None, retry_at_ns: SEC, .. }));
    stack.ipv6_control_tick(SEC - 1);
    assert_eq!(dev.attempts.load(Ordering::Relaxed), 1);
    stack.ipv6_control_tick(SEC);
    assert_eq!(dev.attempts.load(Ordering::Relaxed), 2);
    assert!(!stack.v6_addr_owned_by(iface, target));
}

#[test]
fn stale_dad_retry_cannot_probe_replacement_generation() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let owner = crate::net_ns::test_support::allocate_namespace();
    let net_ns = owner.id().as_u64();
    let stack = NetStack::new();
    let dev = Arc::new(PersistentFailProbeDev { attempts: AtomicUsize::new(0) });
    let iface = stack.ifaces.register_in_ns(dev.clone() as Arc<dyn crate::NetDev>, net_ns);
    let router = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,8]);
    let prefix = Ipv6Addr::from_segments([0x2001,0xdb8,0x844,8,0,0,0,0]);
    let target = super::ra::slaac_eui64_addr(prefix, dev.mac());
    stack.apply_router_advertisement(net_ns, iface, router, &advertisement(prefix));
    let old = {
        let lease = stack.ifaces.acquire_ingress(iface).unwrap();
        stack.dad_probe_for(&lease, target).unwrap()
    };
    assert_eq!(dev.attempts.load(Ordering::Relaxed), 1);

    assert!(stack.teardown_iface_in(net_ns, iface));
    stack.apply_router_advertisement(0, iface, router, &advertisement(prefix));
    assert_eq!(dev.attempts.load(Ordering::Relaxed), 2);
    assert_ne!(stack.ifaces.acquire_ingress(iface).unwrap().generation(), old.generation);

    stack.try_dad_retry(&old, SEC);
    assert_eq!(dev.attempts.load(Ordering::Relaxed), 2);
    stack.ipv6_control_tick(SEC);
    assert_eq!(dev.attempts.load(Ordering::Relaxed), 3);
}

#[test]
fn dad_promotion_reannounces_joined_groups_with_link_local_source() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, lo) = stack.register_loopback();
    let link = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,0x844]);
    let group = Ipv6Addr::from_segments([0xff02,0,0,0,0,0,0,0x844]);
    stack.v6_addrs.lock().entry(iface).or_default().push(super::Ipv6IfaceAddr {
        addr: link, prefixlen: 64, preferred: u32::MAX, valid: u32::MAX,
        origin: super::Ipv6AddrOrigin::Static,
        state: super::Ipv6AddrState::Tentative {
            dad_until_ns: Some(1), retry_at_ns: 0, retrans_timer_ns: SEC,
        },
        deprecated: false, notify_pending: false,
    });
    stack.join_ipv6_multicast(iface, group, Ipv6Addr::ANY).unwrap();
    let initial = lo.rx_pop().unwrap();
    assert_eq!(Ipv6Hdr::parse(initial.data()).unwrap().src, Ipv6Addr::ANY);

    stack.ipv6_control_tick(1);

    let fresh = lo.rx_pop().unwrap();
    assert_eq!(Ipv6Hdr::parse(fresh.data()).unwrap().src, link);
}

#[test]
fn ra_retrans_timer_controls_dad_probe_deadline() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();
    let router = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,6]);
    let prefix = Ipv6Addr::from_segments([0x2001,0xdb8,0x844,6,0,0,0,0]);
    let target = super::ra::slaac_eui64_addr(prefix, MacAddr::ZERO);
    let mut advertised = advertisement(prefix);
    advertised.retrans_timer = 250;

    stack.apply_router_advertisement(0, iface, router, &advertised);
    let row = stack.v6_addr_snapshot().into_iter()
        .find(|(_, row)| row.addr == target).unwrap().1;
    assert!(matches!(row.state, super::Ipv6AddrState::Tentative {
        dad_until_ns: Some(250_000_000), retrans_timer_ns: 250_000_000, .. }));
    stack.ipv6_control_tick(249_999_999);
    assert!(!stack.v6_addr_owned_by(iface, target));
    stack.ipv6_control_tick(250_000_000);
    assert!(stack.v6_addr_owned_by(iface, target));
}

#[test]
fn ra_retrans_timer_controls_failed_probe_retry() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let dev = Arc::new(FailProbeDev { attempts: AtomicUsize::new(0) });
    let iface = stack.ifaces.register(dev.clone() as Arc<dyn crate::NetDev>);
    let router = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,7]);
    let prefix = Ipv6Addr::from_segments([0x2001,0xdb8,0x844,7,0,0,0,0]);
    let mut advertised = advertisement(prefix);
    advertised.retrans_timer = 250;

    stack.apply_router_advertisement(0, iface, router, &advertised);
    assert_eq!(dev.attempts.load(Ordering::Relaxed), 1);
    stack.ipv6_control_tick(249_999_999);
    assert_eq!(dev.attempts.load(Ordering::Relaxed), 1);
    stack.ipv6_control_tick(250_000_000);
    assert_eq!(dev.attempts.load(Ordering::Relaxed), 2);
}

#[test]
fn dad_defense_na_is_unsolicited_to_all_nodes() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, loopback) = stack.register_loopback();
    let target = Ipv6Addr::from_segments([0x2001,0xdb8,0x844,5,0,0,0,1]);
    stack.add_v6_addr(iface, target);
    let dst = crate::ndp::solicited_node_multicast(target);
    let solicitation = crate::ndp::NdpMsg::build_dad_ns(target);
    deliver_ndp(&stack, iface, Ipv6Addr::ANY, dst, &solicitation);

    let packet = loopback.rx_pop().unwrap();
    let hdr = Ipv6Hdr::parse(packet.data()).unwrap();
    assert_eq!((hdr.src, hdr.dst), (target, crate::ndp::IPV6_ALL_NODES));
    let msg = crate::ndp::NdpMsg::parse(&packet.data()[IPV6_HDR_LEN..], hdr.src, hdr.dst).unwrap();
    assert_eq!(msg.typ, crate::ndp::NDP_NA);
    assert_eq!(msg.flags & crate::ndp::NDP_NA_FLAG_SOLICITED, 0);
    assert_ne!(msg.flags & crate::ndp::NDP_NA_FLAG_OVERRIDE, 0);
}

#[test]
fn source_selection_uses_destination_scope_and_longest_prefix() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();
    let link = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,10]);
    let near = Ipv6Addr::from_segments([0x2001,0xdb8,0x1234,0,0,0,0,10]);
    let far = Ipv6Addr::from_segments([0x2001,0xdb8,0x9999,0,0,0,0,10]);
    stack.add_v6_addr_meta(iface, link, 64, u32::MAX, u32::MAX);
    stack.add_v6_addr_meta(iface, far, 64, u32::MAX, u32::MAX);
    stack.add_v6_addr_meta(iface, near, 64, u32::MAX, u32::MAX);

    let link_dst = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,20]);
    let global_dst = Ipv6Addr::from_segments([0x2001,0xdb8,0x1234,0,0,0,0,20]);
    assert_eq!(stack.v6_select_source(iface, link_dst, None), Some(link));
    assert_eq!(stack.v6_select_source(iface, global_dst, None), Some(near));
}

#[test]
fn ordinary_transmit_rejects_unspecified_source_when_none_is_usable() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let dev = Arc::new(FailProbeDev { attempts: AtomicUsize::new(0) });
    let iface = stack.ifaces.register(dev.clone() as Arc<dyn crate::NetDev>);
    let dst = Ipv6Addr::from_segments([0x2001,0xdb8,0x844,7,0,0,0,1]);
    stack.routes6.add(crate::route6::Route6Entry {
        table: crate::policy_rule::RT_TABLE_MAIN, dst, prefix_len: 128, iface,
        gateway: None, src_hint: None, origin: crate::route6::Route6Origin::Static,
    });

    assert_eq!(stack.send_udp6_to_in(0, Ipv6Addr::ANY, 1000, dst, 1001, b"udp"),
        Err(crate::NetError::Eaddrnotavail));
    assert_eq!(stack.send_l4_over_ipv6_in(0, Ipv6Addr::ANY, dst, IpProto::Udp, b"l4"),
        Err(crate::NetError::Eaddrnotavail));
    assert_eq!(dev.attempts.load(Ordering::Relaxed), 0);
}

#[test]
fn wildcard_pmtu_udp6_checksum_uses_route_selected_source() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, lo) = stack.register_loopback();
    let src = Ipv6Addr::from_segments([0x2001,0xdb8,0x844,9,0,0,0,1]);
    let dst = Ipv6Addr::from_segments([0x2001,0xdb8,0x844,10,0,0,0,1]);
    stack.add_v6_addr(iface, src);
    stack.routes6.add(crate::route6::Route6Entry {
        table: crate::policy_rule::RT_TABLE_MAIN, dst, prefix_len: 128, iface,
        gateway: None, src_hint: None, origin: crate::route6::Route6Origin::Static,
    });

    stack.send_udp6_pmtu_to_bound_opts(Ipv6Addr::ANY, 1000, dst, 2000, b"pmtu",
        Some(iface), crate::ipv6::IPV6_DEFAULT_HOP_LIMIT, 0,
        crate::uapi::IPV6_PMTUDISC_WANT).unwrap();

    let packet = lo.rx_pop().unwrap();
    let header = Ipv6Hdr::parse(packet.data()).unwrap();
    assert_eq!(header.src, src);
    assert!(crate::udp::udp_checksum_v6_ok(
        &packet.data()[IPV6_HDR_LEN..], src, dst));
}
