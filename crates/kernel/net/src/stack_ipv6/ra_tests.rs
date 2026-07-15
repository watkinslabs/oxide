use alloc::sync::Arc;
use core::time::Duration;
use std::sync::mpsc;

use crate::addr::{IpProto, Ipv6Addr, MacAddr};
use crate::stack::NetStack;

use super::ra::slaac_eui64_addr;

const SEC: u64 = 1_000_000_000;

struct PersistentRaDev;

impl crate::NetDev for PersistentRaDev {
    fn name(&self) -> &str { "ra-persist0" }
    fn mac(&self) -> MacAddr { MacAddr::ZERO }
    fn mtu(&self) -> u32 { 1500 }
    fn retire_namespace(&self) {}
    fn namespace_drop_action(&self) -> crate::NamespaceDropAction {
        crate::NamespaceDropAction::MoveToInitial
    }
    fn xmit(&self, _packet: crate::Pkt) -> crate::NetResult<()> { Ok(()) }
}

fn ra(prefix: Ipv6Addr, valid: u32, preferred: u32,
      router_lifetime: u16) -> crate::ndp::RouterAdvertisement {
    crate::ndp::RouterAdvertisement {
        hop_limit: 64, flags: 0, router_lifetime, reachable_time: 0, retrans_timer: 0,
        source_lladdr: None,
        prefixes: alloc::vec![crate::ndp::PrefixInfo {
            prefix_len: 64,
            flags: crate::ndp::NDP_PIO_FLAG_ONLINK | crate::ndp::NDP_PIO_FLAG_AUTO,
            valid_lifetime: valid, preferred_lifetime: preferred, prefix,
        }],
    }
}

fn namespace_loopback(stack: &NetStack)
    -> (network_namespace::NetworkNamespaceRef, crate::NetIfaceId, Arc<crate::LoopbackDev>)
{
    let owner = crate::net_ns::test_support::allocate_namespace();
    let (iface, dev) = stack.register_loopback_for(&owner);
    (owner, iface, dev)
}

fn complete_dad(stack: &NetStack) {
    stack.ipv6_control_tick(0);
    stack.ipv6_control_tick(super::ra::DAD_DELAY_NS);
    stack.set_ra_now_ns(0);
}

#[test]
fn router_advertisement_mutations_are_namespace_scoped() {
    let stack = NetStack::new();
    let (owner_a, iface_a, _) = namespace_loopback(&stack);
    let (owner_b, iface_b, _) = namespace_loopback(&stack);
    let ns_a = owner_a.id().as_u64();
    let ns_b = owner_b.id().as_u64();
    let router_a = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,1]);
    let router_b = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,2]);
    let prefix = Ipv6Addr::from_segments([0x2001,0xdb8,0x825,0,0,0,0,0]);
    let outside = Ipv6Addr::from_segments([0x2001,0xdb8,0x999,0,0,0,0,1]);
    stack.apply_router_advertisement(ns_a, iface_a, router_a, &ra(prefix, 300, 300, 60));
    stack.apply_router_advertisement(ns_b, iface_b, router_b, &ra(prefix, 300, 300, 60));
    assert_eq!(stack.routes6.lookup_in(ns_a, outside).and_then(|r| r.gateway), Some(router_a));
    assert_eq!(stack.routes6.lookup_in(ns_b, outside).and_then(|r| r.gateway), Some(router_b));
    stack.apply_router_advertisement(ns_a, iface_a, router_a, &ra(prefix, 0, 0, 0));
    assert!(stack.routes6.snapshot_in(ns_a).iter().all(|r| r.prefix_len == 128));
    assert!(stack.routes6.snapshot_in(ns_b).iter().any(|r| r.prefix_len == 64));
    assert_eq!(stack.routes6.lookup_in(ns_b, outside).and_then(|r| r.gateway), Some(router_b));
    let before = stack.routes6.snapshot_in(ns_a);
    stack.apply_router_advertisement(ns_a, iface_b, router_b, &ra(prefix, 300, 300, 60));
    assert_eq!(stack.routes6.snapshot_in(ns_a), before);
}

#[test]
fn queued_ra_cannot_configure_moved_interface_generation() {
    let stack = NetStack::new();
    let owner = crate::net_ns::test_support::allocate_namespace();
    let net_ns = owner.id().as_u64();
    let iface = stack.ifaces.register_in_ns(Arc::new(PersistentRaDev), net_ns);
    let old_generation = stack.ifaces.acquire_ingress(iface).unwrap().generation();
    let router = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,0x844]);
    let prefix = Ipv6Addr::from_segments([0x2001,0xdb8,0x844,1,0,0,0,0]);

    stack.queue_router_advertisement_ingress(
        net_ns, iface, router, ra(prefix, 300, 300, 60));
    {
        let pending = stack.v6_ra_pending.lock();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].generation, old_generation);
        assert!(Arc::ptr_eq(&pending[0].namespace, &owner));
    }
    assert!(stack.teardown_iface_in(net_ns, iface));
    let moved = stack.ifaces.acquire_ingress(iface).unwrap();
    assert_eq!((moved.net_ns(), moved.generation()), (0, old_generation + 1));
    drop(moved);

    stack.ipv6_control_tick(0);
    assert!(stack.v6_addr_snapshot().iter().all(|(id, _)| *id != iface));
    assert!(stack.routes6.snapshot().iter().all(|route| route.iface != iface));
}

#[test]
fn router_withdrawal_removes_routes_but_preserves_guarded_slaac() {
    let stack = NetStack::new();
    let (owner, iface, _) = namespace_loopback(&stack);
    let net_ns = owner.id().as_u64();
    let router = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,3]);
    let dynamic_prefix = Ipv6Addr::from_segments([0x2001,0xdb8,0x826,0,0,0,0,0]);
    let static_prefix = Ipv6Addr::from_segments([0x2001,0xdb8,0x827,0,0,0,0,0]);
    let static_addr = slaac_eui64_addr(static_prefix, crate::addr::MacAddr::ZERO);
    stack.add_v6_addr_meta(iface, static_addr, 64, u32::MAX, u32::MAX);
    stack.routes6.add_in(net_ns, crate::route6::Route6Entry {
        table: crate::policy_rule::RT_TABLE_MAIN,
        dst: static_prefix, prefix_len: 64, iface, gateway: None,
        src_hint: Some(static_addr), origin: crate::route6::Route6Origin::Static,
    });
    stack.routes6.add_in(net_ns, crate::route6::Route6Entry {
        table: crate::policy_rule::RT_TABLE_MAIN,
        dst: Ipv6Addr::ANY, prefix_len: 0, iface, gateway: Some(router),
        src_hint: Some(static_addr), origin: crate::route6::Route6Origin::Static,
    });
    let mut advertised = ra(dynamic_prefix, 300, 300, 60);
    advertised.prefixes.push(ra(static_prefix, 300, 300, 0).prefixes[0]);
    stack.apply_router_advertisement(net_ns, iface, router, &advertised);
    complete_dad(&stack);
    let dynamic_addr = slaac_eui64_addr(dynamic_prefix, crate::addr::MacAddr::ZERO);
    assert!(stack.v6_addr_owned_by(iface, dynamic_addr));
    let static_row = stack.v6_addr_snapshot_in(net_ns).into_iter()
        .find(|(_, row)| row.addr == static_addr).unwrap().1;
    assert_eq!(static_row.origin, super::Ipv6AddrOrigin::Static);
    let mut withdrawn = ra(dynamic_prefix, 0, 0, 0);
    withdrawn.prefixes.push(ra(static_prefix, 0, 0, 0).prefixes[0]);
    stack.apply_router_advertisement(net_ns, iface, router, &withdrawn);
    assert!(stack.v6_addr_owned_by(iface, dynamic_addr));
    assert!(stack.v6_addr_owned_by(iface, static_addr));
    let routes = stack.routes6.snapshot_in(net_ns);
    assert!(routes.iter().any(|row| row.origin == crate::route6::Route6Origin::Static
        && row.prefix_len == 64 && row.dst == static_prefix));
    assert!(routes.iter().any(|row| row.origin == crate::route6::Route6Origin::Static
        && row.prefix_len == 0));
    assert!(routes.iter().all(|row| row.origin.ra_router() != Some(router)));
}

#[test]
fn prefix_and_slaac_state_are_updated_by_any_router() {
    let stack = NetStack::new();
    let (owner, iface, _) = namespace_loopback(&stack);
    let net_ns = owner.id().as_u64();
    let router_a = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,4]);
    let router_b = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,5]);
    let prefix = Ipv6Addr::from_segments([0x2001,0xdb8,0x828,0,0,0,0,0]);
    let addr = slaac_eui64_addr(prefix, crate::addr::MacAddr::ZERO);
    stack.apply_router_advertisement(net_ns, iface, router_a, &ra(prefix, 10_000, 5_000, 200));
    stack.set_ra_now_ns(100 * SEC);
    stack.apply_router_advertisement(net_ns, iface, router_b, &ra(prefix, 20_000, 15_000, 1_000));
    let row = stack.v6_addr_snapshot_in(net_ns).into_iter()
        .find(|(_, row)| row.addr == addr).unwrap().1;
    let super::Ipv6AddrOrigin::Slaac { prefix: owner, .. } = &row.origin else {
        panic!("expected SLAAC address");
    };
    assert_eq!(*owner, prefix);
    assert_eq!((row.valid, row.preferred), (20_000, 15_000));
    assert_eq!(stack.routes6.snapshot_in(net_ns).iter()
        .filter(|route| route.origin.is_ra_prefix()).count(), 1);

    stack.set_ra_now_ns(250 * SEC);
    let routes = stack.routes6.snapshot_in(net_ns);
    assert!(routes.iter().all(|route| route.origin.ra_router() != Some(router_a)
        || route.prefix_len != 0));
    assert!(routes.iter().any(|route| route.origin.ra_router() == Some(router_b)
        && route.prefix_len == 0));
    stack.apply_router_advertisement(net_ns, iface, router_a, &ra(prefix, 0, 0, 0));
    let row = stack.v6_addr_snapshot_in(net_ns).into_iter()
        .find(|(_, row)| row.addr == addr).unwrap().1;
    assert_eq!((row.valid, row.preferred), (super::ra::TWO_HOURS_SECS, 0));
    assert!(stack.routes6.snapshot_in(net_ns).iter().all(|route| !route.origin.is_ra_prefix()));
}

#[test]
fn route_hints_remain_owned_during_ra_replacement() {
    let stack = Arc::new(NetStack::new());
    let (owner, iface, _) = namespace_loopback(&stack);
    let net_ns = owner.id().as_u64();
    let router = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,6]);
    let old_prefix = Ipv6Addr::from_segments([0x2001,0xdb8,0x829,0,0,0,0,0]);
    let new_prefix = Ipv6Addr::from_segments([0x2001,0xdb8,0x82a,0,0,0,0,0]);
    let old_addr = slaac_eui64_addr(old_prefix, crate::addr::MacAddr::ZERO);
    let new_addr = slaac_eui64_addr(new_prefix, crate::addr::MacAddr::ZERO);
    stack.apply_router_advertisement(net_ns, iface, router, &ra(old_prefix, 300, 300, 60));
    complete_dad(&stack);
    let mut replacement = ra(old_prefix, 0, 0, 60);
    replacement.prefixes.push(ra(new_prefix, 300, 300, 0).prefixes[0]);
    let (published_tx, published_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let applying = Arc::clone(&stack);
    let apply = std::thread::spawn(move || applying.apply_router_advertisement_ordered(
        net_ns, iface, router, &replacement, || {
            published_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        },
    ));
    published_rx.recv().unwrap();
    let (checked_tx, checked_rx) = mpsc::channel();
    let reading = Arc::clone(&stack);
    let reader = std::thread::spawn(move || {
        let routes = reading.routes6.snapshot_in(net_ns);
        assert!(routes.iter().filter_map(|route| route.src_hint)
            .all(|hint| reading.v6_addr_owned_by(iface, hint)));
        assert!(routes.iter().all(|route| route.src_hint != Some(new_addr)));
        assert!(reading.v6_addr_owned_by(iface, old_addr));
        checked_tx.send(()).unwrap();
    });
    checked_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    release_tx.send(()).unwrap();
    apply.join().unwrap();
    reader.join().unwrap();
    assert!(stack.v6_addr_owned_by(iface, old_addr));
    assert!(!stack.v6_addr_owned_by(iface, new_addr));
    complete_dad(&stack);
    assert!(stack.v6_addr_owned_by(iface, new_addr));
}

#[test]
fn unauthenticated_short_valid_lifetime_obeys_two_hour_rule() {
    let stack = NetStack::new();
    let (owner, iface, _) = namespace_loopback(&stack);
    let net_ns = owner.id().as_u64();
    let router = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,7]);
    let prefix = Ipv6Addr::from_segments([0x2001,0xdb8,0x82b,0,0,0,0,0]);
    let addr = slaac_eui64_addr(prefix, MacAddr::ZERO);
    stack.apply_router_advertisement(net_ns, iface, router, &ra(prefix, 10_000, 5_000, 0));

    stack.set_ra_now_ns(100 * SEC);
    stack.apply_router_advertisement(net_ns, iface, router, &ra(prefix, 60, 60, 0));
    let row = stack.v6_addr_snapshot_in(net_ns).into_iter()
        .find(|(_, row)| row.addr == addr).unwrap().1;
    assert_eq!((row.valid, row.preferred), (super::ra::TWO_HOURS_SECS, 60));

    stack.set_ra_now_ns(200 * SEC);
    stack.apply_router_advertisement(net_ns, iface, router, &ra(prefix, 0, 0, 0));
    let row = stack.v6_addr_snapshot_in(net_ns).into_iter()
        .find(|(_, row)| row.addr == addr).unwrap().1;
    assert_eq!((row.valid, row.preferred), (7_100, 0));
}

#[test]
fn invalid_pio_is_ignored_without_mutating_existing_state() {
    let stack = NetStack::new();
    let (owner, iface, _) = namespace_loopback(&stack);
    let net_ns = owner.id().as_u64();
    let router = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,8]);
    let prefix = Ipv6Addr::from_segments([0x2001,0xdb8,0x82c,0,0,0,0,0]);
    stack.apply_router_advertisement(net_ns, iface, router, &ra(prefix, 400, 300, 0));
    let before_addr = stack.v6_addr_snapshot_in(net_ns);
    let before_routes = stack.routes6.snapshot_in(net_ns);
    stack.apply_router_advertisement(net_ns, iface, router, &ra(prefix, 100, 101, 0));
    assert_eq!(stack.v6_addr_snapshot_in(net_ns), before_addr);
    assert_eq!(stack.routes6.snapshot_in(net_ns), before_routes);
}

#[test]
fn pio_prefixes_are_canonical_and_link_local_prefixes_are_ignored() {
    let stack = NetStack::new();
    let (owner, iface, _) = namespace_loopback(&stack);
    let net_ns = owner.id().as_u64();
    let router = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,10]);
    let dirty = Ipv6Addr::from_segments([0x2001,0xdb8,0x82e,0,0xaaaa,0xbbbb,0xcccc,0xdddd]);
    let canonical = super::ra::canonical_prefix(dirty, 64);
    let link_local = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,0x1234]);
    let mut advertised = ra(dirty, 400, 300, 0);
    advertised.prefixes.push(ra(link_local, 400, 300, 0).prefixes[0]);
    stack.apply_router_advertisement(net_ns, iface, router, &advertised);

    let addr = slaac_eui64_addr(canonical, MacAddr::ZERO);
    let rows = stack.v6_addr_snapshot_in(net_ns);
    assert!(rows.iter().any(|(_, row)| row.addr == addr));
    assert!(rows.iter().all(|(_, row)| !row.addr.is_link_local()));
    let routes = stack.routes6.snapshot_in(net_ns);
    assert!(routes.iter().any(|route| route.origin.is_ra_prefix()
        && route.dst == canonical && route.prefix_len == 64));
    assert!(routes.iter().all(|route| !route.dst.is_link_local()));

    stack.apply_router_advertisement(net_ns, iface, router, &ra(canonical, 500, 0, 0));
    assert_eq!(stack.v6_addr_snapshot_in(net_ns).iter()
        .filter(|(_, row)| row.addr == addr).count(), 1);
    assert_eq!(stack.routes6.snapshot_in(net_ns).iter()
        .filter(|route| route.origin.is_ra_prefix()).count(), 1);
}

#[test]
fn source_selection_rejects_deprecated_and_stale_route_hints() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, lo) = stack.register_loopback();
    let router = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,11]);
    let deprecated_prefix = Ipv6Addr::from_segments([0x2001,0xdb8,0x82f,0,0,0,0,0]);
    let preferred_prefix = Ipv6Addr::from_segments([0x2001,0xdb8,0x830,0,0,0,0,0]);
    let deprecated = slaac_eui64_addr(deprecated_prefix, MacAddr::ZERO);
    let preferred = slaac_eui64_addr(preferred_prefix, MacAddr::ZERO);
    stack.apply_router_advertisement(0, iface, router, &ra(deprecated_prefix, 100, 0, 0));
    stack.apply_router_advertisement(0, iface, router, &ra(preferred_prefix, 100, 80, 0));
    let selected = stack.v6_select_source(iface, preferred, Some(deprecated)).unwrap();
    assert_ne!(selected, deprecated);
    assert!(selected == preferred || selected == Ipv6Addr::LOOPBACK);

    let dst = Ipv6Addr::from_segments([0x2001,0xdb8,0x831,0,0,0,0,1]);
    stack.routes6.add(crate::route6::Route6Entry {
        table: crate::policy_rule::RT_TABLE_MAIN, dst, prefix_len: 128, iface,
        gateway: None, src_hint: Some(deprecated), origin: crate::route6::Route6Origin::Static });
    stack.send_udp6_to_in(0, Ipv6Addr::ANY, 1000, dst, 1001, b"source").unwrap();
    let packet = lo.rx_pop().unwrap();
    let hdr = crate::ipv6::Ipv6Hdr::parse(packet.data()).unwrap();
    assert_ne!(hdr.src, deprecated);

    stack.set_ra_now_ns(101 * SEC);
    assert_ne!(stack.v6_select_source(iface, dst, Some(deprecated)), Some(deprecated));
    stack.ipv6_control_tick(101 * SEC);
    assert!(stack.routes6.snapshot().iter()
        .find(|route| route.dst == dst).is_some_and(|route| route.src_hint.is_none()));
}

#[test]
fn two_hour_comparison_uses_exact_deadlines() {
    let stack = NetStack::new();
    let (owner, iface, _) = namespace_loopback(&stack);
    let net_ns = owner.id().as_u64();
    let router = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,12]);
    let prefix = Ipv6Addr::from_segments([0x2001,0xdb8,0x832,0,0,0,0,0]);
    let addr = slaac_eui64_addr(prefix, MacAddr::ZERO);
    stack.apply_router_advertisement(net_ns, iface, router, &ra(prefix, 7_201, 0, 0));
    stack.set_ra_now_ns(SEC / 2);
    stack.apply_router_advertisement(net_ns, iface, router, &ra(prefix, 7_200, 0, 0));
    let row = stack.v6_addr_snapshot_in(net_ns).into_iter()
        .find(|(_, row)| row.addr == addr).unwrap().1;
    let super::Ipv6AddrOrigin::Slaac { valid_until_ns, .. } = row.origin else {
        panic!("expected SLAAC address");
    };
    assert_eq!(valid_until_ns, SEC / 2 + super::ra::TWO_HOURS_SECS as u64 * SEC);
    stack.set_ra_now_ns(valid_until_ns);
    assert!(!stack.v6_addr_owned_by(iface, addr));
}

#[test]
fn finite_deadline_overflow_never_becomes_protocol_infinity() {
    let stack = NetStack::new();
    let (owner, iface, _) = namespace_loopback(&stack);
    let net_ns = owner.id().as_u64();
    let router = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,13]);
    let prefix = Ipv6Addr::from_segments([0x2001,0xdb8,0x833,0,0,0,0,0]);
    let addr = slaac_eui64_addr(prefix, MacAddr::ZERO);
    let now_ns = u64::MAX - 100;
    stack.set_ra_now_ns(now_ns);
    stack.apply_router_advertisement(net_ns, iface, router, &ra(prefix, 1, 1, 1));
    let row = stack.v6_addr_snapshot_in(net_ns).into_iter()
        .find(|(_, row)| row.addr == addr).unwrap().1;
    let super::Ipv6AddrOrigin::Slaac { valid_until_ns, .. } = row.origin else {
        panic!("expected SLAAC address");
    };
    assert_eq!(valid_until_ns, u64::MAX - 1);
    assert_ne!(valid_until_ns, u64::MAX);
    assert!(!stack.v6_addr_owned_by(iface, addr));
    stack.set_ra_now_ns(u64::MAX - 1);
    assert!(!stack.v6_addr_owned_by(iface, addr));
    assert!(stack.routes6.snapshot_in(net_ns).iter().all(|route| route.origin.ra_router().is_none()));
}

#[test]
fn receive_path_requires_link_local_source_and_hop_limit_255() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();
    let link_local = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,9]);
    let global = Ipv6Addr::from_segments([0x2001,0xdb8,0,0,0,0,0,9]);
    let dst = crate::ndp::IPV6_ALL_NODES;
    let prefix = Ipv6Addr::from_segments([0x2001,0xdb8,0x82d,0,0,0,0,0]);
    let addr = slaac_eui64_addr(prefix, MacAddr::ZERO);

    deliver_wire_ra(&stack, iface, link_local, dst, prefix, 64);
    deliver_wire_ra(&stack, iface, global, dst, prefix, u8::MAX);
    assert!(!stack.v6_addr_owned_by(iface, addr));
    deliver_wire_ra(&stack, iface, link_local, dst, prefix, u8::MAX);
    complete_dad(&stack);
    assert!(stack.v6_addr_owned_by(iface, addr));
}

fn deliver_wire_ra(stack: &NetStack, iface: crate::addr::NetIfaceId, src: Ipv6Addr,
                   dst: Ipv6Addr, prefix: Ipv6Addr, hop_limit: u8) {
    let payload = crate::ndp::RouterAdvertisement::build_one_prefix(
        src, dst, MacAddr::ZERO, 60, prefix, 64,
        crate::ndp::NDP_PIO_FLAG_ONLINK | crate::ndp::NDP_PIO_FLAG_AUTO,
    );
    let mut frame = alloc::vec![0; crate::ipv6::IPV6_HDR_LEN + payload.len()];
    let mut hdr = crate::ipv6::Ipv6Hdr::build(src, dst, IpProto::Icmpv6, payload.len() as u16);
    hdr.hop_limit = hop_limit;
    hdr.write_to(&mut frame[..crate::ipv6::IPV6_HDR_LEN]);
    frame[crate::ipv6::IPV6_HDR_LEN..].copy_from_slice(&payload);
    stack.deliver_rx_ipv6(iface, &frame).unwrap();
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct RecordedEvent {
    addr: bool,
    kind: crate::control_event::EventKind,
    ns: u64,
    iface: crate::NetIfaceId,
    generation: u64,
    flags: u32,
}

static RECORDED_EVENTS: std::sync::Mutex<alloc::vec::Vec<RecordedEvent>> =
    std::sync::Mutex::new(alloc::vec::Vec::new());

fn record_control_event(event: &crate::control_event::ControlEvent) {
    let row = match event {
        crate::control_event::ControlEvent::Addr6(event) => Some(RecordedEvent {
            addr: true, kind: event.kind, ns: event.namespace.id(), iface: event.owner.iface,
            generation: event.owner.generation, flags: event.row.flags(),
        }),
        crate::control_event::ControlEvent::Route6(event) => event.owners.first().map(|owner| {
            RecordedEvent { addr: false, kind: event.kind, ns: event.namespace.id(),
                iface: owner.iface, generation: owner.generation, flags: 0 }
        }),
        _ => None,
    };
    if let Some(row) = row { RECORDED_EVENTS.lock().unwrap().push(row); }
}

#[test]
fn slaac_expiry_stages_addr_before_route_for_exact_generation() {
    let domain = crate::hosted_fixture::init_net_domain();
    let stack = crate::NetStack::new();
    domain.set_notifier(record_control_event);
    stack.set_ra_now_ns(0);
    let iface = stack.ifaces.register(Arc::new(crate::LoopbackDev::new()));
    let generation = stack.ifaces.acquire_ingress(iface).unwrap().generation();
    let router = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,0x844]);
    let prefix = Ipv6Addr::from_segments([0x2001,0xdb8,0x844,0,0,0,0,0]);
    stack.apply_router_advertisement(0, iface, router, &ra(prefix, 1, 1, 1));
    RECORDED_EVENTS.lock().unwrap().clear();

    stack.set_ra_now_ns(SEC);
    stack.ipv6_control_tick(SEC);
    let events: alloc::vec::Vec<_> = RECORDED_EVENTS.lock().unwrap().iter().copied()
        .filter(|event| event.ns == 0 && event.iface == iface).collect();
    assert_eq!(events, alloc::vec![
        RecordedEvent { addr: true, kind: crate::control_event::EventKind::Delete,
            ns: 0, iface, generation, flags: crate::iface_addr::IFA_F_TENTATIVE },
        RecordedEvent { addr: false, kind: crate::control_event::EventKind::Delete,
            ns: 0, iface, generation, flags: 0 },
    ]);
    let _ = stack.unregister_iface(iface);
    stack.set_ra_now_ns(0);
    RECORDED_EVENTS.lock().unwrap().clear();
}

#[test]
fn control_tick_publishes_preferred_lifetime_deprecation() {
    let domain = crate::hosted_fixture::init_net_domain();
    let stack = crate::NetStack::new();
    domain.set_notifier(record_control_event);
    stack.set_ra_now_ns(0);
    let iface = stack.ifaces.register(Arc::new(crate::LoopbackDev::new()));
    let router = Ipv6Addr::from_segments([0xfe80,0,0,0,0,0,0,0x845]);
    let prefix = Ipv6Addr::from_segments([0x2001,0xdb8,0x845,0,0,0,0,0]);
    stack.apply_router_advertisement(0, iface, router, &ra(prefix, 10, 2, 0));
    stack.ipv6_control_tick(SEC);
    RECORDED_EVENTS.lock().unwrap().clear();

    stack.ipv6_control_tick(2 * SEC);
    let events: alloc::vec::Vec<_> = RECORDED_EVENTS.lock().unwrap().iter().copied()
        .filter(|event| event.ns == 0 && event.iface == iface && event.addr).collect();
    assert!(events.iter().any(|event| event.kind == crate::control_event::EventKind::New
        && event.flags & crate::iface_addr::IFA_F_DEPRECATED != 0
        && event.flags & crate::iface_addr::IFA_F_TENTATIVE == 0));
    let row = stack.v6_addr_snapshot().into_iter()
        .find(|(id, row)| *id == iface && row.addr == slaac_eui64_addr(prefix, MacAddr::ZERO))
        .unwrap().1;
    assert_eq!((row.preferred, row.deprecated), (0, true));
    let _ = stack.unregister_iface(iface);
    stack.set_ra_now_ns(0);
    RECORDED_EVENTS.lock().unwrap().clear();
}
