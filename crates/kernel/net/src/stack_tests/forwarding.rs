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
