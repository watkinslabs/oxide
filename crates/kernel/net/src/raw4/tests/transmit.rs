// Raw IPv4 transmit, and the error reporting a connected endpoint does.
// Split out of `raw4::tests` at the per-file size cutoff; the receive,
// membership and namespace coverage stays in the parent.

use super::*;

fn routed_capture(stack: &NetStack, mtu: u32, dst: Ipv4Addr)
    -> (crate::NetIfaceId, Arc<CaptureDev>) {
    let dev = Arc::new(CaptureDev::new(mtu));
    let iface = stack.ifaces.register(dev.clone() as Arc<dyn NetDev>);
    stack.routes.add(RouteEntry::main(dst, 32, iface, None,
        Some(Ipv4Addr::new(192, 0, 2, 10))));
    // These cases assert transmit behaviour, so the next hop is already
    // resolved. Without it Linux queues the packet on the neighbour and emits
    // only an ARP request.
    if let Some(cache) = stack.ifaces.arp_cache_in_ns(iface, 0) {
        cache.insert(dst, crate::MacAddr([2, 0, 0, 0, 0, 2]));
    }
    (iface, dev)
}

#[test]
fn non_hdrincl_transmit_supports_arbitrary_protocol_and_fragments() {
    let _initial_net = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let dst = Ipv4Addr::new(198, 51, 100, 20);
    let (_iface, dev) = routed_capture(&stack, 68, dst);
    let raw = initial_endpoint(PROTOCOL);
    let options = Raw4TxOptions { pmtudisc: crate::uapi::IP_PMTUDISC_DONT,
        ..Raw4TxOptions::default() };

    stack.send_raw4(&raw, dst, &[0x5a; 100], options,
        &crate::send_control::Raw4Control::default(), crate::TxMeta::NONE).unwrap();

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
fn want_small_packet_clears_df_on_locked_pmtu_route() {
    let _initial_net = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let dst = Ipv4Addr::new(198, 51, 100, 21);
    let (iface, dev) = routed_capture(&stack, 1_500, dst);
    let raw = initial_endpoint(PROTOCOL);
    stack.inet_tables(0).pmtu.update(
        iface, crate::IpAddr::V4(dst), 296, 1_500, crate::stack::IPV4_MIN_PMTU,
    );
    let options = Raw4TxOptions { pmtudisc: crate::uapi::IP_PMTUDISC_WANT,
        ..Raw4TxOptions::default() };

    stack.send_raw4(&raw, dst, b"small", options,
        &crate::send_control::Raw4Control::default(), crate::TxMeta::NONE).unwrap();

    let packets = dev.packets.lock();
    assert_eq!(packets.len(), 1);
    assert_eq!(Ipv4Hdr::parse(&packets[0]).unwrap().flags_frag & 0x4000, 0);
}

#[test]
fn broadcast_transmit_requires_permission() {
    let _initial_net = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (_iface, dev) = routed_capture(&stack, 1_500, Ipv4Addr::BROADCAST);
    let raw = initial_endpoint(PROTOCOL);
    assert_eq!(stack.send_raw4(&raw, Ipv4Addr::BROADCAST, b"x",
        Raw4TxOptions::default(), &crate::send_control::Raw4Control::default(), crate::TxMeta::NONE), Err(NetError::Eacces));
    stack.send_raw4(&raw, Ipv4Addr::BROADCAST, b"x", Raw4TxOptions {
        broadcast: true, ..Raw4TxOptions::default()
    }, &crate::send_control::Raw4Control::default(), crate::TxMeta::NONE).unwrap();
    assert_eq!(dev.packets.lock().len(), 1);
}

#[test]
fn hdrincl_rewrites_kernel_fields_preserves_user_header_and_never_fragments() {
    let _initial_net = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let dst = Ipv4Addr::new(203, 0, 113, 9);
    let (_iface, dev) = routed_capture(&stack, 80, dst);
    let raw = initial_endpoint(PROTOCOL);
    raw.set_hdrincl(true);
    let mut user = packet(OTHER_PROTOCOL, Ipv4Addr::ANY, dst, 0, 0, &[], b"body");
    user[1] = 0x2e;
    user[8] = 31;
    user[2..4].copy_from_slice(&0u16.to_be_bytes());
    user[10..12].copy_from_slice(&0xdead_u16.to_be_bytes());

    stack.send_raw4(&raw, dst, &user, Raw4TxOptions::default(),
        &crate::send_control::Raw4Control::default(), crate::TxMeta::NONE).unwrap();

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
    assert_eq!(stack.send_raw4(&raw, dst, &oversized, Raw4TxOptions::default(),
        &crate::send_control::Raw4Control::default(), crate::TxMeta::NONE),
        Err(NetError::Einval));
    let valid_oversized = packet(PROTOCOL, Ipv4Addr::ANY, dst, 0, 0, &[], &[0; 61]);
    assert_eq!(stack.send_raw4(&raw, dst, &valid_oversized, Raw4TxOptions::default(),
        &crate::send_control::Raw4Control::default(), crate::TxMeta::NONE),
        Err(NetError::Emsgsize));
    assert_eq!(dev.packets.lock().len(), 1);
}

#[test]
fn unregister_is_exact_and_close_blocks_late_receive_publication() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();
    let removed = initial_endpoint(PROTOCOL);
    let live = initial_endpoint(PROTOCOL);
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

#[test]
fn connected_raw4_publishes_hard_not_soft_matching_errors() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();
    let (other_iface, _) = stack.register_loopback();
    let local = Ipv4Addr::LOOPBACK;
    let remote = Ipv4Addr::new(192, 0, 2, 44);
    let matching_a = initial_endpoint(PROTOCOL);
    let matching_b = initial_endpoint(PROTOCOL);
    for raw in [&matching_a, &matching_b] {
        raw.bind(local, Some(iface)).unwrap();
        raw.connect(remote, None).unwrap();
        stack.register_raw4(raw);
    }
    let wrong_protocol = initial_endpoint(OTHER_PROTOCOL);
    wrong_protocol.bind(local, Some(iface)).unwrap();
    wrong_protocol.connect(remote, None).unwrap();
    stack.register_raw4(&wrong_protocol);
    let wrong_peer = initial_endpoint(PROTOCOL);
    wrong_peer.bind(local, Some(iface)).unwrap();
    wrong_peer.connect(Ipv4Addr::new(192, 0, 2, 45), None).unwrap();
    stack.register_raw4(&wrong_peer);
    let wrong_iface = initial_endpoint(PROTOCOL);
    wrong_iface.bind(local, Some(other_iface)).unwrap();
    wrong_iface.connect(remote, None).unwrap();
    stack.register_raw4(&wrong_iface);

    crate::stack_icmp::handle_error(&stack, iface, remote,
        crate::icmp::ICMP_TYPE_DEST_UNREACH, 0, &error_quote(PROTOCOL, local, remote));
    assert_eq!(matching_a.error.take(), 0);
    assert_eq!(matching_b.error.take(), 0);
    crate::stack_icmp::handle_error(&stack, iface, remote,
        crate::icmp::ICMP_TYPE_DEST_UNREACH, 3, &error_quote(PROTOCOL, local, remote));

    let expected = syscall::errno::Errno::Econnrefused as i32;
    assert_eq!(matching_a.error.take(), expected);
    assert_eq!(matching_b.error.take(), expected);
    assert_eq!(wrong_protocol.error.take(), 0);
    assert_eq!(wrong_peer.error.take(), 0);
    assert_eq!(wrong_iface.error.take(), 0);
}

#[test]
fn unconnected_raw4_error_requires_recverr() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();
    let remote = Ipv4Addr::new(198, 51, 100, 9);
    let raw = initial_endpoint(PROTOCOL);
    raw.bind(Ipv4Addr::LOOPBACK, Some(iface)).unwrap();
    stack.register_raw4(&raw);
    let quote = error_quote(PROTOCOL, Ipv4Addr::LOOPBACK, remote);

    crate::stack_icmp::handle_error(&stack, iface, remote,
        crate::icmp::ICMP_TYPE_DEST_UNREACH, 3, &quote);
    assert_eq!(raw.error.take(), 0);
    raw.error.set_recverr4(true);
    crate::stack_icmp::handle_error(&stack, iface, remote,
        crate::icmp::ICMP_TYPE_DEST_UNREACH, 3, &quote);
    assert_eq!(raw.error.take(), syscall::errno::Errno::Econnrefused as i32);
    assert_eq!(raw.error.take_extended().unwrap().destination_port, 0);
}

/// The mark, the transmit band and the departure time a send settles reach the
/// packet. Before this every one of them was admitted by the ancillary rule
/// and by the option table and then dropped: nothing downstream could see any
/// of the three.
#[test]
fn a_sends_mark_band_and_departure_time_reach_the_packet() {
    let _initial_net = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let dst = Ipv4Addr::new(198, 51, 100, 62);
    let (_iface, dev) = routed_capture(&stack, 1_500, dst);
    let raw = initial_endpoint(PROTOCOL);
    let settled = crate::TxMeta { mark: 0x5a5a, priority: 6, transmit_time: 0x1234_5678 };

    stack.send_raw4(&raw, dst, b"marked", Raw4TxOptions::default(),
        &crate::send_control::Raw4Control::default(), settled).unwrap();

    assert_eq!(*dev.metas.lock(), alloc::vec![settled]);
}
