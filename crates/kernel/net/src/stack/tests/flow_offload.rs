use super::*;

#[test]
fn tuple_parser_uses_wire_addresses_and_ports() {
    let mut packet = [0u8; 28];
    packet[0] = 0x45;
    packet[9] = IPPROTO_UDP;
    packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
    packet[16..20].copy_from_slice(&[10, 0, 0, 2]);
    packet[20..22].copy_from_slice(&1234u16.to_be_bytes());
    packet[22..24].copy_from_slice(&5353u16.to_be_bytes());
    let tuple = flow_tuple(&packet, NFPROTO_IPV4).expect("flow tuple");
    assert_eq!(tuple.src.addr, InetAddr::v4([10, 0, 0, 1]));
    assert_eq!(tuple.dst.addr, InetAddr::v4([10, 0, 0, 2]));
    assert_eq!(tuple.src.proto.port, 1234);
    assert_eq!(tuple.dst.proto.port, 5353);
}

#[test]
fn flowtable_registration_is_namespace_scoped_and_dumpable() {
    let stack = NetStack::new();
    let handle = stack.register_flowtable_in(7, 2, "filter", "ft", 0, -256,
        alloc::vec![FlowtableDevice::Name(String::from("eth0"))], 0).expect("first registration");
    assert!(stack.register_flowtable_in(7, 2, "filter", "ft", 0, -256,
        alloc::vec![FlowtableDevice::Name(String::from("eth0"))], 0).is_none());
    assert!(stack.register_flowtable_in(7, 2, "nat", "ft", 0, -256,
        alloc::vec![FlowtableDevice::Name(String::from("eth0"))], 0).is_some());
    let snapshot = stack.flowtables_snapshot_in(7, 2);
    assert_eq!(snapshot.len(), 2);
    let filter = snapshot.iter().find(|config| config.table == "filter").unwrap();
    assert_eq!((filter.table.as_str(), filter.name.as_str(),
        filter.hook_num, filter.priority, filter.handle),
        ("filter", "ft", 0, -256, handle));
    assert!(stack.unregister_flowtable_in(7, 2, "filter", "ft"));
    assert_eq!(stack.flowtables_snapshot_in(7, 2).len(), 1);
}

#[test]
fn exact_flowtable_device_follows_interface_rename() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();
    stack.register_flowtable_in(0, NFPROTO_IPV4, "filter", "ft", 0, -256,
        alloc::vec![FlowtableDevice::Name(String::from("lo"))], 0)
        .expect("flowtable registration");
    assert!(stack.flowtable_applies(0, NFPROTO_IPV4, "filter", "ft", iface));
    let rtnl = stack.rtnl_lock();
    assert_eq!(stack.ifaces.rename_in_ns(&rtnl, iface, 0, "renamed0"),
        Ok(String::from("lo")));
    stack.flowtable_device_event_in(0, iface, true);
    assert!(!stack.flowtable_applies(0, NFPROTO_IPV4, "filter", "ft", iface));
    assert_eq!(stack.ifaces.rename_in_ns(&rtnl, iface, 0, "lo"),
        Ok(String::from("renamed0")));
    stack.flowtable_device_event_in(0, iface, true);
    assert!(stack.flowtable_applies(0, NFPROTO_IPV4, "filter", "ft", iface));
}

#[test]
fn flowtable_hook_priorities_are_sorted_for_one_device() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();
    for (name, priority) in [("early", -300), ("late", 100), ("middle", -100)] {
        stack.register_flowtable_in(0, NFPROTO_IPV4, "filter", name, 0, priority,
            alloc::vec![FlowtableDevice::Name(String::from("lo"))], 0)
            .expect("flowtable registration");
    }
    assert_eq!(stack.flowtable_priorities_in(0, NFPROTO_IPV4, iface),
        alloc::vec![-300, -100, 100]);
}

#[test]
fn device_down_cleans_both_flow_directions_and_status() {
    let stack = NetStack::new();
    let iface = NetIfaceId::from_raw(41);
    let other = NetIfaceId::from_raw(42);
    let tuple = Tuple {
        src: TupleEnd { addr: InetAddr::v4([10, 0, 0, 1]), proto: ProtoPart::port(1234) },
        dst: TupleEnd { addr: InetAddr::v4([10, 0, 0, 2]), proto: ProtoPart::port(5353) },
        l3num: NFPROTO_IPV4, protonum: IPPROTO_UDP, zone: 0,
    };
    let conn = Arc::new(conntrack::Conn::new(1, tuple, tuple.invert().unwrap(), 9));
    conn.status.fetch_or(IPS_OFFLOAD, core::sync::atomic::Ordering::AcqRel);
    let entry = Arc::new(FlowEntry { conn: conn.clone(), routes: [
        FlowRoute::V4 { iface, next_hop: Ipv4Addr::ANY },
        FlowRoute::V4 { iface: other, next_hop: Ipv4Addr::ANY },
    ]});
    let mut flows = stack.flow_offload.lock();
    flows.insert((9, String::from("filter"), String::from("ft"), tuple), entry.clone());
    flows.insert((9, String::from("filter"), String::from("ft"), tuple.invert().unwrap()), entry);
    drop(flows);

    stack.flowtable_device_down_in(9, iface);

    assert!(stack.flow_offload.lock().is_empty());
    assert_eq!(conn.status() & IPS_OFFLOAD, 0);
}
