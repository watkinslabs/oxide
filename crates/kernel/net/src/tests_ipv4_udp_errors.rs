use alloc::sync::Arc;
use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use sync::{Socket as StackLockClass, Spinlock};

use crate::{IpProto, Ipv4Addr, NetStack, SocketError};

struct PmtuDev { tx: AtomicUsize, flags: AtomicUsize }

impl crate::NetDev for PmtuDev {
    fn name(&self) -> &str { "pmtu0" }
    fn mac(&self) -> crate::MacAddr { crate::MacAddr::ZERO }
    fn mtu(&self) -> u32 { 1_500 }
    fn retire_namespace(&self) {}
    fn namespace_drop_action(&self) -> crate::NamespaceDropAction {
        crate::NamespaceDropAction::Destroy
    }
    fn xmit(&self, packet: crate::Pkt) -> crate::NetResult<()> {
        let hdr = crate::Ipv4Hdr::parse(packet.data()).unwrap();
        self.flags.store(hdr.flags_frag as usize, Ordering::Relaxed);
        self.tx.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

const LOCAL: Ipv4Addr = Ipv4Addr::LOOPBACK;
const REMOTE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const LOCAL_PORT: u16 = 43_210;
const REMOTE_PORT: u16 = 53;

/// Seed one resolved neighbour so a PMTU case exercises transmit instead of
/// the ARP request Linux emits while the neighbour is incomplete. # C: O(log N)
fn resolve_udp_neighbour(stack: &NetStack, iface: crate::NetIfaceId, hop: Ipv4Addr) {
    if let Some(cache) = stack.ifaces.arp_cache_in_ns(iface, 0) {
        cache.insert(hop, crate::MacAddr([2, 0, 0, 0, 0, 2]));
    }
}

fn flag() -> Arc<AtomicI32> { Arc::new(AtomicI32::new(0)) }

fn bind(stack: &NetStack, error: Arc<SocketError>, connected: bool, pmtu: i32) {
    bind_to(stack, error, connected, pmtu, REMOTE)
}

fn bind_to(stack: &NetStack, error: Arc<SocketError>, connected: bool, pmtu: i32,
           remote: Ipv4Addr) {
    stack.bind_udp_socket(
        LOCAL, LOCAL_PORT, None, error, flag(), flag(), Arc::new(AtomicI32::new(pmtu)), 1_000,
        Arc::new(Spinlock::<_, StackLockClass>::new(
            if connected { Some((remote, REMOTE_PORT)) } else { None },
        )), Arc::new(crate::bpf_filter::SocketFilter::new()),
        Arc::new(crate::mcast_filter::SocketMcast::new()),
    ).unwrap();
}

fn quote() -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec![0u8; 8 + crate::ipv4::IPV4_HDR_LEN + crate::udp::UDP_HDR_LEN];
    let hdr = crate::Ipv4Hdr::build(LOCAL, REMOTE, IpProto::Udp, crate::udp::UDP_HDR_LEN as u16, 1);
    hdr.write_to(&mut out[8..8 + crate::ipv4::IPV4_HDR_LEN]);
    let udp = 8 + crate::ipv4::IPV4_HDR_LEN;
    out[udp..udp + 2].copy_from_slice(&LOCAL_PORT.to_be_bytes());
    out[udp + 2..udp + 4].copy_from_slice(&REMOTE_PORT.to_be_bytes());
    out[udp + 4..udp + 6].copy_from_slice(&(crate::udp::UDP_HDR_LEN as u16).to_be_bytes());
    out
}

fn frag_needed_quote(total_len: u16, mtu: u16) -> alloc::vec::Vec<u8> {
    frag_needed_quote_to(REMOTE, total_len, mtu)
}

fn frag_needed_quote_to(remote: Ipv4Addr, total_len: u16, mtu: u16) -> alloc::vec::Vec<u8> {
    let mut out = quote();
    out[6..8].copy_from_slice(&mtu.to_be_bytes());
    let hdr = crate::Ipv4Hdr::build(
        LOCAL, remote, IpProto::Udp,
        total_len.saturating_sub(crate::ipv4::IPV4_HDR_LEN as u16), 1,
    );
    hdr.write_to(&mut out[8..8 + crate::ipv4::IPV4_HDR_LEN]);
    out
}

fn tcp_frag_needed_quote(seq: u32, mtu: u16) -> alloc::vec::Vec<u8> {
    let tcp_len = crate::tcp_hdr::TCP_HDR_MIN_LEN;
    let mut out = alloc::vec![0u8; 8 + crate::ipv4::IPV4_HDR_LEN + tcp_len];
    out[6..8].copy_from_slice(&mtu.to_be_bytes());
    let hdr = crate::Ipv4Hdr::build(LOCAL, REMOTE, IpProto::Tcp, tcp_len as u16, 1);
    hdr.write_to(&mut out[8..8 + crate::ipv4::IPV4_HDR_LEN]);
    let tcp = 8 + crate::ipv4::IPV4_HDR_LEN;
    out[tcp..tcp + 2].copy_from_slice(&LOCAL_PORT.to_be_bytes());
    out[tcp + 2..tcp + 4].copy_from_slice(&REMOTE_PORT.to_be_bytes());
    out[tcp + 4..tcp + 8].copy_from_slice(&seq.to_be_bytes());
    out
}

#[test]
fn icmp4_unreachable_errno_and_fatality_match_linux() {
    let _domain = crate::hosted_fixture::init_net_domain();
    use syscall::errno::Errno;
    let cases = [
        (0, Errno::Enetunreach, false), (1, Errno::Ehostunreach, false),
        (2, Errno::Enoprotoopt, true), (3, Errno::Econnrefused, true),
        (4, Errno::Emsgsize, true), (5, Errno::Eopnotsupp, false),
        (6, Errno::Enetunreach, true), (7, Errno::Ehostdown, true),
        (8, Errno::Enonet, true), (9, Errno::Enetunreach, true),
        (10, Errno::Ehostunreach, true), (11, Errno::Enetunreach, false),
        (12, Errno::Ehostunreach, false), (13, Errno::Ehostunreach, true),
        (14, Errno::Ehostunreach, true), (15, Errno::Ehostunreach, true),
    ];
    for (code, expected, hard) in cases {
        let stack = NetStack::new();
        let (iface, _) = stack.register_loopback();
        let error = Arc::new(SocketError::new());
        bind(&stack, error.clone(), true, crate::uapi::IP_PMTUDISC_WANT);
        crate::stack_icmp::handle_error(
            &stack, iface, REMOTE, crate::icmp::ICMP_TYPE_DEST_UNREACH, code, &quote(),
        );
        assert_eq!(error.take(), if hard { expected as i32 } else { 0 }, "code {code}");

        error.set_recverr4(true);
        crate::stack_icmp::handle_error(
            &stack, iface, REMOTE, crate::icmp::ICMP_TYPE_DEST_UNREACH, code, &quote(),
        );
        assert_eq!(error.take(), expected as i32, "RECVERR code {code}");
        let queued = error.take_extended().unwrap();
        assert_eq!((queued.errno, queued.code), (expected as i32, code));
    }
}

#[test]
fn unconnected_udp_requires_recverr_for_hard_icmp() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();
    let error = Arc::new(SocketError::new());
    bind(&stack, error.clone(), false, crate::uapi::IP_PMTUDISC_WANT);
    crate::stack_icmp::handle_error(
        &stack, iface, REMOTE, crate::icmp::ICMP_TYPE_DEST_UNREACH, 3, &quote(),
    );
    assert!(!error.has());
    error.set_recverr4(true);
    crate::stack_icmp::handle_error(
        &stack, iface, REMOTE, crate::icmp::ICMP_TYPE_DEST_UNREACH, 3, &quote(),
    );
    assert_eq!(error.take(), syscall::errno::Errno::Econnrefused as i32);
    assert!(error.take_extended().is_some());
}

#[test]
fn connected_dual_stack_endpoint_beats_unconnected_ipv4_candidate() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();
    let v4_error = Arc::new(SocketError::new());
    let v6_error = Arc::new(SocketError::new());
    let reuse = || Arc::new(AtomicI32::new(1));
    stack.bind_udp_socket(
        LOCAL, LOCAL_PORT, None, v4_error.clone(), reuse(), flag(),
        Arc::new(AtomicI32::new(crate::uapi::IP_PMTUDISC_WANT)), 1_000,
        Arc::new(Spinlock::<Option<(Ipv4Addr, u16)>, StackLockClass>::new(None)),
        Arc::new(crate::bpf_filter::SocketFilter::new()),
        Arc::new(crate::mcast_filter::SocketMcast::new()),
    ).unwrap();
    stack.bind_udp6_socket(
        crate::Ipv6Addr::ANY, LOCAL_PORT, None, v6_error.clone(), reuse(), flag(), 1_000,
        flag(), Arc::new(Spinlock::new(Some((
            crate::Ipv6Addr::from_v4_mapped(REMOTE), REMOTE_PORT,
        )))), Arc::new(AtomicI32::new(crate::uapi::IP_PMTUDISC_WANT)),
        Arc::new(AtomicI32::new(crate::uapi::IPV6_PMTUDISC_WANT)),
        Arc::new(crate::bpf_filter::SocketFilter::new()),
        Arc::new(crate::mcast_filter::SocketMcast::new()),
    ).unwrap();

    crate::stack_icmp::handle_error(
        &stack, iface, REMOTE, crate::icmp::ICMP_TYPE_DEST_UNREACH, 3, &quote(),
    );
    assert_eq!(v4_error.take(), 0);
    assert_eq!(v6_error.take(), syscall::errno::Errno::Econnrefused as i32);
}

#[test]
fn dual_stack_ipv4_frag_needed_uses_ip_not_ipv6_pmtudisc() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let cases = [
        (crate::uapi::IP_PMTUDISC_DONT, true, false),
        (crate::uapi::IP_PMTUDISC_WANT, true, true),
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
        let ipv6_mode = if mode == crate::uapi::IP_PMTUDISC_DONT {
            crate::uapi::IPV6_PMTUDISC_WANT
        } else { crate::uapi::IPV6_PMTUDISC_DONT };
        stack.bind_udp6_socket(
            crate::Ipv6Addr::ANY, LOCAL_PORT, None, error.clone(), flag(), flag(), 1_000,
            flag(), Arc::new(Spinlock::new(Some((
                crate::Ipv6Addr::from_v4_mapped(REMOTE), REMOTE_PORT,
            )))), Arc::new(AtomicI32::new(mode)), Arc::new(AtomicI32::new(ipv6_mode)),
            Arc::new(crate::bpf_filter::SocketFilter::new()),
            Arc::new(crate::mcast_filter::SocketMcast::new()),
        ).unwrap();
        crate::stack_icmp::handle_error(
            &stack, iface, REMOTE, crate::icmp::ICMP_TYPE_DEST_UNREACH, 4,
            &frag_needed_quote(1_500, 1_200),
        );
        assert_eq!(
            stack.path_mtu(crate::IpAddr::V4(REMOTE), Some(iface), false),
            Ok(if caches { 1_200 } else { 65_535 }), "mode {mode}",
        );
        assert_eq!(error.has_extended(), reports, "mode {mode}");
    }
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
        }, entry.clone());

        crate::stack_icmp::handle_error(
            &stack, iface, REMOTE, crate::icmp::ICMP_TYPE_DEST_UNREACH, 4,
            &tcp_frag_needed_quote(15, 1_200),
        );

        assert_eq!(stack.path_mtu(crate::IpAddr::V4(REMOTE), Some(iface), false),
            Ok(65_535), "mode {mode}");
        assert_eq!(entry.conn.lock().own_mss, 1_460, "mode {mode}");
    }
}
