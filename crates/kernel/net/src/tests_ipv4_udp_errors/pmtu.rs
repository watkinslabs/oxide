// Path-MTU discovery over IPv4: `IP_PMTUDISC_*` mode behaviour, the
// FRAG_NEEDED route-cache update, and which sockets may write that cache.

use super::*;
use crate::policy_rule::{AF_INET, FR_ACT_TO_TBL, PolicyRule};
use crate::route::{RouteEntry, RouteRecord};

const MARK: u32 = 0x21;
const MARK_TABLE: u32 = 101;

/// Two output routes to the same peer: the main table uses `main_iface`, while
/// an fwmark rule selects `marked_iface`. Distinct PMTU cache keys make a write
/// to the wrong route observable rather than merely proving argument plumbing.
fn marked_pmtu_stack() -> (NetStack, crate::NetIfaceId, crate::NetIfaceId) {
    let stack = NetStack::new();
    let main_iface = stack.ifaces.register(Arc::new(PmtuDev {
        tx: AtomicUsize::new(0), flags: AtomicUsize::new(0),
    }));
    let marked_iface = stack.ifaces.register(Arc::new(PmtuDev {
        tx: AtomicUsize::new(0), flags: AtomicUsize::new(0),
    }));
    stack.routes.add(RouteEntry::main(REMOTE, 32, main_iface, None, Some(LOCAL)));
    stack.routes.add_record_in(0, RouteRecord::kernel(RouteEntry {
        table: MARK_TABLE, dst: REMOTE, prefix_len: 32, iface: marked_iface,
        gateway: None, src_hint: Some(LOCAL),
    }));
    let rtnl = stack.rtnl_lock();
    stack.policy_rules().insert_rtnl(&rtnl, PolicyRule {
        ns: 0, family: AF_INET, priority: 100, table: MARK_TABLE,
        action: FR_ACT_TO_TBL, dst_len: 0, src_len: 0, tos: 0, flags: 0,
        fwmark: 0x20, fwmask: 0xf0,
    });
    drop(rtnl);
    (stack, main_iface, marked_iface)
}

fn assert_only_marked_route_learned(stack: &NetStack, main: crate::NetIfaceId,
                                    marked: crate::NetIfaceId) {
    let dst = crate::IpAddr::V4(REMOTE);
    assert_eq!(stack.path_mtu_mark_in(0, dst, None, false, MARK), Ok(1_200));
    assert_eq!(stack.path_mtu_mark_in(0, dst, None, false, 0), Ok(1_500));
    assert_eq!(stack.path_mtu_mark_in(0, dst, Some(marked), false, MARK), Ok(1_200));
    assert_eq!(stack.path_mtu_mark_in(0, dst, Some(main), false, 0), Ok(1_500));
}

#[test]
fn udp_frag_needed_uses_the_live_socket_mark_route() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let (stack, main, marked) = marked_pmtu_stack();
    let mark = Arc::new(AtomicI32::new(0));
    stack.bind_udp_socket_owned(
        crate::SocketOwner::root(network_namespace::initial(), 1_000),
        LOCAL, LOCAL_PORT, None, Arc::new(SocketError::new()), flag(), flag(),
        Arc::new(AtomicI32::new(crate::uapi::IP_PMTUDISC_WANT)), mark.clone(), flag(), flag(),
        Arc::new(Spinlock::<_, StackLockClass>::new(Some((REMOTE, REMOTE_PORT)))),
        Arc::new(crate::bpf_filter::SocketFilter::new()),
        Arc::new(crate::mcast_filter::SocketMcast::new()),
    ).unwrap();
    // This is deliberately after bind: Linux reads `sk_mark` from the matched
    // socket when the error arrives rather than snapshotting it at bind.
    mark.store(MARK as i32, Ordering::Release);

    crate::stack_icmp::handle_error(
        &stack, main, REMOTE, crate::icmp::ICMP_TYPE_DEST_UNREACH, 4,
        &frag_needed_quote(1_500, 1_200),
    );
    assert_only_marked_route_learned(&stack, main, marked);
}

#[test]
fn mapped_udp_frag_needed_uses_the_live_dual_stack_socket_mark_route() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let (stack, main, marked) = marked_pmtu_stack();
    let mark = Arc::new(AtomicI32::new(0));
    stack.bind_udp6_socket_owned(
        crate::SocketOwner::root(network_namespace::initial(), 1_000),
        crate::Ipv6Addr::ANY, LOCAL_PORT, None, Arc::new(SocketError::new()), flag(), flag(),
        flag(), Arc::new(Spinlock::new(Some((
            crate::Ipv6Addr::from_v4_mapped(REMOTE), REMOTE_PORT,
        )))), Arc::new(AtomicI32::new(crate::uapi::IP_PMTUDISC_WANT)), mark.clone(),
        Arc::new(AtomicI32::new(crate::uapi::IPV6_PMTUDISC_WANT)), flag(), flag(), flag(),
        Arc::new(crate::bpf_filter::SocketFilter::new()),
        Arc::new(crate::mcast_filter::SocketMcast::new()),
    ).unwrap();
    mark.store(MARK as i32, Ordering::Release);

    crate::stack_icmp::handle_error(
        &stack, main, REMOTE, crate::icmp::ICMP_TYPE_DEST_UNREACH, 4,
        &frag_needed_quote(1_500, 1_200),
    );
    assert_only_marked_route_learned(&stack, main, marked);
}

#[test]
fn raw_frag_needed_uses_the_live_socket_mark_route() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let (stack, main, marked) = marked_pmtu_stack();
    let mark = Arc::new(AtomicI32::new(0));
    let endpoint = crate::raw4::Raw4Endpoint::new_owned_with_pmtudisc(
        crate::addr::IpProto::Icmp as u8,
        crate::SocketOwner::root(network_namespace::initial(), 0),
        Arc::new(crate::bpf_filter::SocketFilter::new()),
        Arc::new(crate::mcast_filter::SocketMcast::new()), Arc::new(SocketError::new()),
        Arc::new(AtomicI32::new(crate::uapi::IP_PMTUDISC_WANT)),
        Arc::new(crate::sock_opts::sol_ip::IpOpts::default()), mark.clone(),
    );
    endpoint.bind(LOCAL, None).unwrap();
    endpoint.connect(REMOTE, None).unwrap();
    stack.register_raw4(&endpoint);
    mark.store(MARK as i32, Ordering::Release);
    let mut quote = alloc::vec![0u8; 8 + crate::ipv4::IPV4_HDR_LEN + 8];
    quote[6..8].copy_from_slice(&1_200u16.to_be_bytes());
    crate::Ipv4Hdr::build(LOCAL, REMOTE, crate::addr::IpProto::Icmp, 8, 1)
        .write_to(&mut quote[8..8 + crate::ipv4::IPV4_HDR_LEN]);

    crate::stack_icmp::handle_error(
        &stack, main, REMOTE, crate::icmp::ICMP_TYPE_DEST_UNREACH, 4, &quote,
    );
    assert_only_marked_route_learned(&stack, main, marked);
}

#[test]
fn pmtudisc_dont_suppresses_frag_needed_pending_and_extended_errors() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();
    let error = Arc::new(SocketError::new());
    let pmtu = Arc::new(AtomicI32::new(crate::uapi::IP_PMTUDISC_WANT));
    error.set_recverr4(true);
    stack.bind_udp_socket(
        LOCAL, LOCAL_PORT, None, error.clone(), flag(), flag(), pmtu.clone(), 1_000,
        Arc::new(Spinlock::new(Some((REMOTE, REMOTE_PORT)))),
        Arc::new(crate::bpf_filter::SocketFilter::new()),
        Arc::new(crate::mcast_filter::SocketMcast::new()),
    ).unwrap();

    crate::stack_icmp::handle_error(
        &stack, iface, REMOTE, crate::icmp::ICMP_TYPE_DEST_UNREACH, 4, &quote(),
    );
    assert_eq!(error.take(), syscall::errno::Errno::Emsgsize as i32);
    assert_eq!(error.take_extended().unwrap().info, 0);

    pmtu.store(crate::uapi::IP_PMTUDISC_DONT, core::sync::atomic::Ordering::Release);
    crate::stack_icmp::handle_error(
        &stack, iface, REMOTE, crate::icmp::ICMP_TYPE_DEST_UNREACH, 4, &quote(),
    );
    assert!(!error.has());
    assert!(!error.has_extended());
}

#[test]
fn frag_needed_zero_mtu_locks_linux_minimum_until_expiry() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();
    stack.routes.add(crate::RouteEntry::main(
        REMOTE, 32, iface, None, Some(LOCAL),
    ));
    bind(&stack, Arc::new(SocketError::new()), true, crate::uapi::IP_PMTUDISC_WANT);
    crate::stack_icmp::handle_error(
        &stack, iface, REMOTE, crate::icmp::ICMP_TYPE_DEST_UNREACH, 4,
        &frag_needed_quote(1_500, 0),
    );

    assert_eq!(stack.path_mtu(crate::IpAddr::V4(REMOTE), Some(iface), false), Ok(552));
    let payload = alloc::vec![0u8; 1_465];
    assert_eq!(stack.send_udp_pmtu_to_bound_opts(
        LOCAL, LOCAL_PORT, REMOTE, REMOTE_PORT, &payload, Some(iface), 0,
        crate::ipv4::IPV4_DEFAULT_TTL, crate::uapi::IP_PMTUDISC_DO,
    ), Err(crate::NetError::Emsgsize));
    assert_eq!(stack.path_mtu(crate::IpAddr::V4(REMOTE), Some(iface), true), Ok(65_535));

    crate::stack_icmp::handle_error(
        &stack, iface, REMOTE, crate::icmp::ICMP_TYPE_DEST_UNREACH, 4,
        &frag_needed_quote(1_492, 1_200),
    );
    assert_eq!(stack.path_mtu(crate::IpAddr::V4(REMOTE), Some(iface), false), Ok(552));
}

#[test]
fn udp_pmtudisc_modes_use_cache_fragment_and_probe_as_linux() {
    let _initial_net = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let remote = Ipv4Addr::new(192, 0, 2, 44);
    let dev = Arc::new(PmtuDev { tx: AtomicUsize::new(0), flags: AtomicUsize::new(0) });
    let iface = stack.ifaces.register(dev.clone());
    stack.routes.add(crate::RouteEntry::main(
        remote, 32, iface, None, Some(LOCAL),
    ));
    resolve_udp_neighbour(&stack, iface, remote);
    bind_to(&stack, Arc::new(SocketError::new()), true,
        crate::uapi::IP_PMTUDISC_WANT, remote);
    crate::stack_icmp::handle_error(
        &stack, iface, REMOTE, crate::icmp::ICMP_TYPE_DEST_UNREACH, 4,
        &frag_needed_quote_to(remote, 1_500, 1_200),
    );
    let large = alloc::vec![0u8; 1_200];
    let send = |mode, payload: &[u8]| stack.send_udp_pmtu_to_bound_opts(
        LOCAL, LOCAL_PORT, remote, REMOTE_PORT, payload, Some(iface), 0,
        crate::ipv4::IPV4_DEFAULT_TTL, mode,
    );

    assert_eq!(send(crate::uapi::IP_PMTUDISC_DONT, &large), Ok(()));
    assert_eq!(dev.tx.load(Ordering::Relaxed), 2);
    assert_eq!(send(crate::uapi::IP_PMTUDISC_WANT, b"small"), Ok(()));
    assert_eq!(dev.flags.load(Ordering::Relaxed), 0x4000);
    assert_eq!(send(crate::uapi::IP_PMTUDISC_WANT, &large), Ok(()));
    assert_eq!(dev.tx.load(Ordering::Relaxed), 5);
    assert_eq!(send(crate::uapi::IP_PMTUDISC_DO, &large), Err(crate::NetError::Emsgsize));
    assert_eq!(dev.tx.load(Ordering::Relaxed), 5);
    assert_eq!(send(crate::uapi::IP_PMTUDISC_PROBE, &large), Ok(()));
    assert_eq!(dev.tx.load(Ordering::Relaxed), 6);
    assert_eq!(dev.flags.load(Ordering::Relaxed), 0x4000);
    let over_iface = alloc::vec![0u8; 1_500];
    assert_eq!(send(crate::uapi::IP_PMTUDISC_INTERFACE, &over_iface),
        Err(crate::NetError::Emsgsize));
    assert_eq!(dev.tx.load(Ordering::Relaxed), 6);
    assert_eq!(send(crate::uapi::IP_PMTUDISC_OMIT, &over_iface), Ok(()));
    assert_eq!(dev.tx.load(Ordering::Relaxed), 8);
    let last_fragment = dev.flags.load(Ordering::Relaxed);
    assert_eq!(last_fragment & 0xe000, 0);
    assert_ne!(last_fragment & 0x1fff, 0);
}

#[test]
fn udp_want_small_packet_clears_df_on_locked_pmtu_route() {
    let _initial_net = crate::hosted_fixture::init_net_domain();
    let _net_ns = network_namespace::initial();
    let stack = NetStack::new();
    let remote = Ipv4Addr::new(192, 0, 2, 45);
    let dev = Arc::new(PmtuDev { tx: AtomicUsize::new(0), flags: AtomicUsize::new(0) });
    let iface = stack.ifaces.register(dev.clone());
    stack.routes.add(crate::RouteEntry::main(remote, 32, iface, None, Some(LOCAL)));
    resolve_udp_neighbour(&stack, iface, remote);
    bind_to(&stack, Arc::new(SocketError::new()), true,
        crate::uapi::IP_PMTUDISC_WANT, remote);
    crate::stack_icmp::handle_error(
        &stack, iface, REMOTE, crate::icmp::ICMP_TYPE_DEST_UNREACH, 4,
        &frag_needed_quote_to(remote, 1_500, 0),
    );
    assert_eq!(stack.ipv4_pmtu_policy(
        0, iface, remote, 1_500, crate::uapi::IP_PMTUDISC_WANT,
    ), (crate::stack::IPV4_MIN_PMTU as usize, false, true));

    assert_eq!(stack.send_udp_pmtu_to_bound_opts(
        LOCAL, LOCAL_PORT, remote, REMOTE_PORT, b"small", Some(iface), 0,
        crate::ipv4::IPV4_DEFAULT_TTL, crate::uapi::IP_PMTUDISC_WANT,
    ), Ok(()));
    assert_eq!(dev.tx.load(Ordering::Relaxed), 1);
    assert_eq!(dev.flags.load(Ordering::Relaxed) & 0x4000, 0);
}

#[test]
fn frag_needed_cache_and_error_follow_each_linux_pmtudisc_mode() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let cases = [
        (crate::uapi::IP_PMTUDISC_DONT, true, false),
        (crate::uapi::IP_PMTUDISC_WANT, true, true),
        (crate::uapi::IP_PMTUDISC_DO, true, true),
        (crate::uapi::IP_PMTUDISC_PROBE, true, true),
        (crate::uapi::IP_PMTUDISC_INTERFACE, false, true),
        (crate::uapi::IP_PMTUDISC_OMIT, false, true),
    ];
    for (mode, caches, reports) in cases {
        let stack = NetStack::new();
        let (iface, _) = stack.register_loopback();
        stack.routes.add(crate::RouteEntry::main(
            REMOTE, 32, iface, None, Some(LOCAL),
        ));
        let error = Arc::new(SocketError::new());
        error.set_recverr4(true);
        bind(&stack, error.clone(), true, mode);
        crate::stack_icmp::handle_error(
            &stack, iface, REMOTE, crate::icmp::ICMP_TYPE_DEST_UNREACH, 4,
            &frag_needed_quote(1_500, 1_200),
        );
        assert_eq!(
            stack.path_mtu(crate::IpAddr::V4(REMOTE), Some(iface), false),
            Ok(if caches { 1_200 } else { 65_535 }),
            "mode {mode}",
        );
        assert_eq!(error.take(), if reports {
            syscall::errno::Errno::Emsgsize as i32
        } else { 0 }, "mode {mode}");
        assert_eq!(error.has_extended(), reports, "mode {mode}");
    }
}

#[test]
fn frag_needed_without_matching_protocol_socket_does_not_pollute_cache() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();
    stack.routes.add(crate::RouteEntry::main(
        REMOTE, 32, iface, None, Some(LOCAL),
    ));
    crate::stack_icmp::handle_error(
        &stack, iface, REMOTE, crate::icmp::ICMP_TYPE_DEST_UNREACH, 4,
        &frag_needed_quote(1_500, 1_200),
    );
    assert_eq!(stack.path_mtu(crate::IpAddr::V4(REMOTE), Some(iface), false), Ok(65_535));
}

#[test]
fn frag_needed_updates_output_route_not_icmp_ingress_interface() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (ingress, _) = stack.register_loopback();
    let dev = Arc::new(PmtuDev { tx: AtomicUsize::new(0), flags: AtomicUsize::new(0) });
    let output = stack.ifaces.register(dev);
    stack.routes.add(crate::RouteEntry::main(
        REMOTE, 32, output, None, Some(LOCAL),
    ));
    bind(&stack, Arc::new(SocketError::new()), true, crate::uapi::IP_PMTUDISC_WANT);
    crate::stack_icmp::handle_error(
        &stack, ingress, REMOTE, crate::icmp::ICMP_TYPE_DEST_UNREACH, 4,
        &frag_needed_quote(1_500, 1_200),
    );
    assert_eq!(stack.path_mtu(crate::IpAddr::V4(REMOTE), Some(output), false), Ok(1_200));
    assert_eq!(stack.path_mtu(crate::IpAddr::V4(REMOTE), Some(ingress), false), Ok(65_535));
}

#[test]
fn tcp_interface_and_omit_modes_cannot_update_shared_route_pmtu() {
    let _domain = crate::hosted_fixture::init_net_domain();
    use crate::stack::{TcpEntry, TcpKey};
    use crate::tcp_conn::{Endpoint, TcpConn};
    for mode in [crate::uapi::IP_PMTUDISC_INTERFACE, crate::uapi::IP_PMTUDISC_OMIT] {
        let stack = NetStack::new();
        let (iface, _) = stack.register_loopback();
        stack.routes.add(crate::RouteEntry::main(REMOTE, 32, iface, None, Some(LOCAL)));
        let local = Endpoint { ip: crate::IpAddr::V4(LOCAL), port: LOCAL_PORT };
        let remote = Endpoint { ip: crate::IpAddr::V4(REMOTE), port: REMOTE_PORT };
        let mut conn = TcpConn::new_client(local, remote, 10);
        conn.snd_una = 10;
        conn.snd_nxt = 20;
        conn.own_mss = 1_460;
        let entry = Arc::new(TcpEntry::new_bound_with_filter_pmtu(
            conn, Arc::new(SocketError::new()), None,
            Arc::new(crate::bpf_filter::SocketFilter::new()),
            Arc::new(AtomicI32::new(mode)),
        ));
        stack.inet_tables(0).tcp_conns.lock().insert(TcpKey {
            local_ip: local.ip, local_port: local.port,
            remote_ip: remote.ip, remote_port: remote.port,
        }, crate::stack::TcpSlot::Sock(entry.clone()));

        crate::stack_icmp::handle_error(
            &stack, iface, REMOTE, crate::icmp::ICMP_TYPE_DEST_UNREACH, 4,
            &tcp_frag_needed_quote(15, 1_200),
        );

        assert_eq!(stack.path_mtu(crate::IpAddr::V4(REMOTE), Some(iface), false),
            Ok(65_535), "mode {mode}");
        assert_eq!(entry.conn.lock().own_mss, 1_460, "mode {mode}");
    }
}
