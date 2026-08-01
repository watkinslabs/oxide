use crate::addr::{IpAddr, Ipv4Addr};
use crate::route_metrics::{RTAX_CC_ALGO, RTAX_CWND, RTAX_MTU};
use crate::stack::TcpKey;
use crate::tcp_conn::{Endpoint, TcpCongestionControl, TcpConn};
use crate::{Ipv4Hdr, NetStack, RouteEntry, RouteMetrics, RouteRecord};

const LOCAL: Ipv4Addr = Ipv4Addr::LOOPBACK;
const REMOTE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 151);

fn install_route(stack: &NetStack, iface: crate::NetIfaceId, metrics: RouteMetrics) {
    stack.routes.add_record_in(0, RouteRecord {
        metric: 42,
        metrics,
        ..RouteRecord::kernel(RouteEntry::main(REMOTE, 32, iface, None, Some(LOCAL)))
    });
}

#[test]
fn resolved_route_retains_priority_and_complete_metrics() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();
    let metrics = RouteMetrics {
        mtu: 1_300,
        hoplimit: 37,
        quickack: 1,
        ..RouteMetrics::NONE
    };
    install_route(&stack, iface, metrics);

    let route = stack.routes.lookup_result_in(0, REMOTE).unwrap();
    assert_eq!((route.iface, route.priority, route.metrics), (iface, 42, metrics));
}

#[test]
fn configured_mtu_lock_and_hoplimit_reach_ipv4_output() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, lo) = stack.register_loopback();
    let metrics = RouteMetrics {
        lock: 1 << RTAX_MTU,
        mtu: 68,
        hoplimit: 37,
        ..RouteMetrics::NONE
    };
    install_route(&stack, iface, metrics);
    let route = stack.routes.lookup_result_in(0, REMOTE).unwrap();
    assert_eq!(stack.ipv4_route_pmtu_policy(
        0, route, REMOTE, 1_500, crate::uapi::IP_PMTUDISC_WANT,
    ), (68, false, true));

    stack.send_udp_to_bound(LOCAL, 40_000, REMOTE, 53, &[0u8; 64], None).unwrap();
    let packet = lo.rx_pop().unwrap();
    let header = Ipv4Hdr::parse(packet.data()).unwrap();
    assert_eq!(header.ttl, 37);
    assert!(usize::from(header.total_len) <= 68);
}

#[test]
fn active_and_passive_tcp_consume_the_selected_metrics() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();
    let metrics = RouteMetrics {
        lock: (1 << RTAX_CWND) | (1 << RTAX_CC_ALGO),
        advmss: 1_200,
        initcwnd: 8,
        cwnd: 6,
        reordering: 5,
        quickack: 1,
        cc_algo: Some(TcpCongestionControl::Reno),
        fastopen_no_cookie: 1,
        ..RouteMetrics::NONE
    };
    install_route(&stack, iface, metrics);

    let active = stack.tcp_connect(LOCAL, 41_000, REMOTE, 80).unwrap();
    {
        let conn = active.conn.lock();
        assert_eq!((conn.own_mss, conn.congestion, conn.cwnd), (
            1_200, TcpCongestionControl::Reno, 7_200,
        ));
        assert!(conn.cc_locked && conn.quickack && conn.fastopen_no_cookie);
        assert_eq!(conn.reordering, 5);
    }

    let _listener = stack.tcp_listen(LOCAL, 8_080, false).unwrap();
    let mut peer = TcpConn::new_client(
        Endpoint { ip: IpAddr::V4(REMOTE), port: 42_000 },
        Endpoint { ip: IpAddr::V4(LOCAL), port: 8_080 },
        0x1512_0000,
    );
    let syn = peer.active_open().unwrap();
    stack.deliver_tcp(0, iface, IpAddr::V4(REMOTE), IpAddr::V4(LOCAL), &syn).unwrap();
    let key = TcpKey {
        local_ip: IpAddr::V4(LOCAL),
        local_port: 8_080,
        remote_ip: IpAddr::V4(REMOTE),
        remote_port: 42_000,
    };
    let child = stack.tcp_conns_map().lock().get(&key).cloned().unwrap();
    let conn = child.conn.lock();
    assert_eq!((conn.own_mss, conn.congestion, conn.cwnd), (
        1_200, TcpCongestionControl::Reno, 7_200,
    ));
    assert!(conn.cc_locked && conn.quickack && conn.fastopen_no_cookie);
}
