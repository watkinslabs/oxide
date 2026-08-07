use super::*;

struct ForwardingFixture {
    stack: NetStack,
    namespace: Option<network_namespace::NetworkNamespaceRef>,
    _lifetime: std::sync::MutexGuard<'static, ()>,
}

impl ForwardingFixture {
    fn new() -> Self {
        let lifetime = crate::net_ns::test_support::LIFETIME_LOCK
            .lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let namespace = crate::net_ns::test_support::allocate_namespace();
        crate::net_ns::materialize_state(&namespace);
        Self { stack: NetStack::new(), namespace: Some(namespace), _lifetime: lifetime }
    }

    fn namespace(&self) -> &network_namespace::NetworkNamespaceRef {
        self.namespace.as_ref().expect("live forwarding namespace")
    }

    fn net_ns(&self) -> u64 { crate::net_ns::namespace_id(self.namespace()) }

    fn teardown(&mut self, check: bool) {
        let Some(namespace) = self.namespace.take() else { return; };
        let id = namespace.id();
        drop(namespace);
        let claimed = network_namespace::take_dead_namespace_ids();
        if check {
            assert!(claimed.contains(&id), "forwarding namespace reaches final-drop teardown");
        }
        crate::net_ns::test_support::finish_claimed(&self.stack, &claimed);
        if check { crate::net_ns::test_support::assert_finished(&self.stack, id); }
    }

    fn finish(mut self) { self.teardown(true); }
}

impl Drop for ForwardingFixture {
    fn drop(&mut self) {
        self.teardown(!std::thread::panicking());
    }
}

fn transit_ipv4(src: Ipv4Addr, dst: Ipv4Addr, ttl: u8) -> alloc::vec::Vec<u8> {
    let mut frame = alloc::vec![0u8; IPV4_HDR_LEN];
    let mut ip = Ipv4Hdr::build(src, dst, IpProto::Udp, 0, 55);
    ip.ttl = ttl;
    ip.checksum = 0;
    ip.write_to(&mut frame[..IPV4_HDR_LEN]);
    ip.checksum = crate::ipv4::ip_checksum(&frame[..IPV4_HDR_LEN]);
    ip.write_to(&mut frame[..IPV4_HDR_LEN]);
    frame
}

fn transit_ipv6(src: Ipv6Addr, dst: Ipv6Addr, hop_limit: u8) -> alloc::vec::Vec<u8> {
    let mut frame = alloc::vec![0u8; IPV6_HDR_LEN];
    let mut ip = Ipv6Hdr::build(src, dst, IpProto::Udp, 0);
    ip.hop_limit = hop_limit;
    ip.write_to(&mut frame);
    frame
}

fn mark_transparent_packet(_namespace: u64, _hook: u32, _packet: &[u8], _family: u8)
    -> crate::netfilter_hook::NfHookResult
{
    crate::netfilter_hook::NfHookResult { verdict: 1, mark: 0x20 }
}

#[test]
fn ipv4_forwarding_sysctl_gates_transit_packets() {
    let fixture = ForwardingFixture::new();
    crate::forwarding::set_ipv4_enabled_for(fixture.namespace(), false).unwrap();
    let net_ns = fixture.net_ns();
    let in_dev = Arc::new(CountDev::new());
    let out_dev = Arc::new(CountDev::new());
    let in_id = fixture.stack.ifaces.register_in_ns(in_dev, net_ns);
    let out_id = fixture.stack.ifaces.register_in_ns(out_dev.clone(), net_ns);
    fixture.stack.routes.add_in(net_ns, RouteEntry {
        table: crate::policy_rule::RT_TABLE_MAIN,
        dst: Ipv4Addr::new(198, 51, 100, 0),
        prefix_len: 24,
        iface: out_id,
        gateway: None,
        src_hint: None,
    });
    super::resolve_neighbour(&fixture.stack, out_id, net_ns, Ipv4Addr::new(198, 51, 100, 20));
    let frame = transit_ipv4(
        Ipv4Addr::new(192, 0, 2, 10),
        Ipv4Addr::new(198, 51, 100, 20),
        9,
    );

    fixture.stack.deliver_rx(in_id, &frame).unwrap();
    assert_eq!(out_dev.tx.load(Ordering::Relaxed), 0);

    crate::forwarding::set_ipv4_enabled_for(fixture.namespace(), true).unwrap();
    fixture.stack.deliver_rx(in_id, &frame).unwrap();
    assert_eq!(out_dev.tx.load(Ordering::Relaxed), 1);
    assert_eq!(out_dev.ttl0.load(Ordering::Relaxed), 8);
    fixture.finish();
}

#[test]
fn ipv4_ingress_mib_names_unforwardable_and_unknown_packets() {
    let stack = NetStack::new();
    let (in_id, _) = stack.register_loopback();

    let transit = transit_ipv4(Ipv4Addr::new(192, 0, 2, 10), Ipv4Addr::new(198, 51, 100, 20), 9);
    let addr_before = crate::mib::get(0, crate::mib::Mib::IpInAddrErrors);
    stack.forward_ipv4_mark_in(0, in_id, &transit, 0).unwrap();
    assert_eq!(crate::mib::get(0, crate::mib::Mib::IpInAddrErrors), addr_before + 1);

    let mut unknown = transit_ipv4(Ipv4Addr::new(192, 0, 2, 10), Ipv4Addr::LOOPBACK, 9);
    unknown[9] = 253;
    unknown[10..12].fill(0);
    let checksum = crate::ipv4::ip_checksum(&unknown).to_be_bytes();
    unknown[10..12].copy_from_slice(&checksum);
    let unknown_before = crate::mib::get(0, crate::mib::Mib::IpInUnknownProtos);
    let delivered_before = crate::mib::get(0, crate::mib::Mib::IpInDelivers);
    stack.deliver_rx(in_id, &unknown).unwrap();
    assert_eq!(crate::mib::get(0, crate::mib::Mib::IpInUnknownProtos), unknown_before + 1);
    assert_eq!(crate::mib::get(0, crate::mib::Mib::IpInDelivers), delivered_before);
}

#[test]
fn a_policy_selected_local_route_delivers_nonlocal_ipv4_instead_of_forwarding_it() {
    let fixture = ForwardingFixture::new();
    let net_ns = fixture.net_ns();
    let in_id = fixture.stack.ifaces.register_in_ns(Arc::new(CountDev::new()), net_ns);
    let dst = Ipv4Addr::new(198, 51, 100, 20);
    // This is the route half of transparent proxying: ordinary address
    // ownership does not include `dst`, but policy selected an RTN_LOCAL
    // record for it, so ingress must take LOCAL_IN rather than FORWARD.
    fixture.stack.routes.add_record_in(net_ns, crate::RouteRecord {
        route: RouteEntry { table: 100, dst: Ipv4Addr::ANY, prefix_len: 0,
            iface: in_id, gateway: None, src_hint: None },
        kind: crate::route::RTN_LOCAL,
        ..crate::RouteRecord::kernel(RouteEntry::main(
            Ipv4Addr::ANY, 0, in_id, None, None))
    });
    let rule = crate::policy_rule::PolicyRule { ns: net_ns, family: crate::policy_rule::AF_INET,
        priority: 100, table: 100, action: crate::policy_rule::FR_ACT_TO_TBL,
        dst_len: 0, src_len: 0, tos: 0, flags: 0, fwmark: 0, fwmask: 0 };
    { let rtnl = fixture.stack.rtnl_lock(); fixture.stack.policy_rules().insert_rtnl(&rtnl, rule); }
    let before = crate::mib::get(net_ns, crate::mib::Mib::IpForwDatagrams);
    // The intentionally header-only UDP packet fails L4 validation after the
    // route decision.  That makes the test prove classification without
    // needing an unrelated bound UDP socket.
    assert_eq!(fixture.stack.deliver_rx(in_id,
        &transit_ipv4(Ipv4Addr::new(192, 0, 2, 10), dst, 9)), Err(NetError::Einval));
    assert_eq!(crate::mib::get(net_ns, crate::mib::Mib::IpForwDatagrams), before);
    fixture.finish();
}

#[test]
fn prerouting_packet_mark_selects_transparent_local_delivery() {
    let domain = crate::hosted_fixture::init_net_domain();
    domain.set_nf_hook(mark_transparent_packet);
    let stack = NetStack::new();
    let (in_id, _) = stack.register_loopback();
    let dst = Ipv4Addr::new(198, 51, 100, 21);
    stack.routes.add_record_in(0, crate::RouteRecord {
        route: RouteEntry { table: 101, dst: Ipv4Addr::ANY, prefix_len: 0,
            iface: in_id, gateway: None, src_hint: None },
        kind: crate::route::RTN_LOCAL,
        ..crate::RouteRecord::kernel(RouteEntry::main(
            Ipv4Addr::ANY, 0, in_id, None, None))
    });
    let rule = crate::policy_rule::PolicyRule { ns: 0, family: crate::policy_rule::AF_INET,
        priority: 101, table: 101, action: crate::policy_rule::FR_ACT_TO_TBL,
        dst_len: 0, src_len: 0, tos: 0, flags: 0, fwmark: 0x20, fwmask: u32::MAX };
    { let rtnl = stack.rtnl_lock(); stack.policy_rules().insert_rtnl(&rtnl, rule); }
    let before = crate::mib::get(0, crate::mib::Mib::IpForwDatagrams);
    assert_eq!(stack.deliver_rx(in_id,
        &transit_ipv4(Ipv4Addr::new(192, 0, 2, 10), dst, 9)), Err(NetError::Einval));
    assert_eq!(crate::mib::get(0, crate::mib::Mib::IpForwDatagrams), before);
}

#[test]
fn ipv4_forwarding_ttl_expired_emits_time_exceeded() {
    let fixture = ForwardingFixture::new();
    crate::forwarding::set_ipv4_enabled_for(fixture.namespace(), true).unwrap();
    let net_ns = fixture.net_ns();
    let in_dev = Arc::new(CountDev::new());
    let out_dev = Arc::new(CountDev::new());
    let in_id = fixture.stack.ifaces.register_in_ns(in_dev.clone(), net_ns);
    let out_id = fixture.stack.ifaces.register_in_ns(out_dev.clone(), net_ns);
    crate::iface_addr::set_primary_addr(net_ns, in_id, Ipv4Addr::new(192, 0, 2, 1), 0);
    fixture.stack.routes.add_in(net_ns, RouteEntry {
        table: crate::policy_rule::RT_TABLE_MAIN,
        dst: Ipv4Addr::new(198, 51, 100, 0),
        prefix_len: 24,
        iface: out_id,
        gateway: None,
        src_hint: None,
    });
    super::resolve_neighbour(&fixture.stack, in_id, net_ns, Ipv4Addr::new(192, 0, 2, 10));

    let frame = transit_ipv4(
        Ipv4Addr::new(192, 0, 2, 10),
        Ipv4Addr::new(198, 51, 100, 20),
        1,
    );
    fixture.stack.deliver_rx(in_id, &frame).unwrap();

    assert_eq!(out_dev.tx.load(Ordering::Relaxed), 0);
    assert_eq!(in_dev.tx.load(Ordering::Relaxed), 1);
    assert_eq!(in_dev.icmp_type0.load(Ordering::Relaxed), icmp::ICMP_TYPE_TIME_EXC as usize);
    assert_eq!(in_dev.icmp_code0.load(Ordering::Relaxed), icmp::time_exceeded_code::TTL as usize);
    fixture.finish();
}

#[test]
fn ipv4_forwarding_no_route_emits_net_unreachable() {
    let fixture = ForwardingFixture::new();
    crate::forwarding::set_ipv4_enabled_for(fixture.namespace(), true).unwrap();
    let net_ns = fixture.net_ns();
    let in_dev = Arc::new(CountDev::new());
    let in_id = fixture.stack.ifaces.register_in_ns(in_dev.clone(), net_ns);
    crate::iface_addr::set_primary_addr(net_ns, in_id, Ipv4Addr::new(192, 0, 2, 1), 0);
    super::resolve_neighbour(&fixture.stack, in_id, net_ns, Ipv4Addr::new(192, 0, 2, 10));

    let frame = transit_ipv4(
        Ipv4Addr::new(192, 0, 2, 10),
        Ipv4Addr::new(198, 51, 100, 20),
        9,
    );
    fixture.stack.deliver_rx(in_id, &frame).unwrap();

    assert_eq!(in_dev.tx.load(Ordering::Relaxed), 1);
    assert_eq!(in_dev.icmp_type0.load(Ordering::Relaxed), icmp::ICMP_TYPE_DEST_UNREACH as usize);
    assert_eq!(in_dev.icmp_code0.load(Ordering::Relaxed), icmp::unreach_code::NET as usize);
    fixture.finish();
}

#[test]
fn ipv6_forwarding_is_gated_and_decrements_hop_limit() {
    let fixture = ForwardingFixture::new();
    let net_ns = fixture.net_ns();
    let in_dev = Arc::new(CountDev::new());
    let out_dev = Arc::new(CountDev::new());
    let in_id = fixture.stack.ifaces.register_in_ns(in_dev, net_ns);
    let out_id = fixture.stack.ifaces.register_in_ns(out_dev.clone(), net_ns);
    let dst = Ipv6Addr::from_segments([0x2001, 0xdb8, 0x820, 0, 0, 0, 0, 2]);
    fixture.stack.routes6.add_in(net_ns, Route6Entry {
        table: crate::policy_rule::RT_TABLE_MAIN, dst, prefix_len: 128, iface: out_id,
        gateway: None, src_hint: None, origin: crate::route6::Route6Origin::Static,
    });
    let frame = transit_ipv6(Ipv6Addr::from_segments([0x2001, 0xdb8, 0x820, 0, 0, 0, 0, 1]),
        dst, 9);

    fixture.stack.deliver_rx_ipv6(in_id, &frame).unwrap();
    assert_eq!(out_dev.tx.load(Ordering::Relaxed), 0);

    crate::forwarding::set_ipv6_enabled_for(fixture.namespace(), true).unwrap();
    fixture.stack.deliver_rx_ipv6(in_id, &frame).unwrap();
    assert_eq!(out_dev.tx.load(Ordering::Relaxed), 1);
    assert_eq!(out_dev.hop_limit0.load(Ordering::Relaxed), 8);
    fixture.finish();
}
