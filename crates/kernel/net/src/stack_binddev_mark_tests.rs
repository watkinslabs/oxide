// `SO_MARK` reaching the route lookups a TCP connection makes.
//
// Every case is built on a real fwmark policy rule selecting a second routing
// table, so what is checked is the route the stack actually chose — not that a
// parameter was passed along.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicI32, Ordering};

use super::*;
use crate::policy_rule::{AF_INET, FR_ACT_TO_TBL, PolicyRule};
use crate::route::{RouteEntry, RouteRecord};
use crate::route_metrics::{RTAX_MTU, RouteMetrics};
use crate::stack::{TcpEntry, TcpKey};
use crate::tcp_conn::{Endpoint, TcpConn};

/// The mark the marked routing table is reached by, and one that is not it.
const MARK: u32 = 0x21;
const OTHER_MARK: u32 = 0x11;
const MARK_MASK: u32 = 0xf0;
const MARK_TABLE: u32 = 101;
const RULE_PRIORITY: u32 = 100;

/// Metrics that make the marked route tell itself apart from the unmarked one
/// at every point a socket can observe a route.
const MARKED_HOPLIMIT: u32 = 77;
const MARKED_ADVMSS: u32 = 1_000;
const MARKED_MTU: u32 = 1_300;
const MARKED_RTT_MS: u32 = 33;
const SERVER_PORT: u16 = 8_080;
/// A destination outside the local table, so the policy rules — not the
/// local-table lookup that precedes them — decide which route answers.
const REMOTE: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 8);

fn marked_metrics() -> RouteMetrics {
    RouteMetrics {
        lock: 1u32 << RTAX_MTU,
        mtu: MARKED_MTU,
        advmss: MARKED_ADVMSS,
        hoplimit: MARKED_HOPLIMIT,
        rtt_ms: MARKED_RTT_MS,
        ..RouteMetrics::NONE
    }
}

/// A stack with loopback up, plus a second routing table reached only through
/// an `ip rule fwmark` match, whose route to the same destination carries
/// metrics of its own.
fn marked_stack() -> (NetStack, crate::NetIfaceId, Arc<crate::LoopbackDev>) {
    let stack = NetStack::new();
    let (iface, dev) = stack.register_loopback();
    stack.routes.add_in(0, RouteEntry::main(REMOTE, 24, iface, None, None));
    stack.routes.add_record_in(0, RouteRecord {
        metrics: marked_metrics(),
        ..RouteRecord::kernel(RouteEntry {
            table: MARK_TABLE, dst: Ipv4Addr::ANY, prefix_len: 0,
            iface, gateway: None, src_hint: None,
        })
    });
    let rtnl = stack.rtnl_lock();
    stack.policy_rules().insert_rtnl(&rtnl, PolicyRule {
        ns: 0, family: AF_INET, priority: RULE_PRIORITY, table: MARK_TABLE,
        action: FR_ACT_TO_TBL, dst_len: 0, src_len: 0, tos: 0, flags: 0,
        fwmark: 0x20, fwmask: MARK_MASK,
    });
    drop(rtnl);
    (stack, iface, dev)
}

/// A TCP entry that resolves its routes under `mark`, sharing the cell so a
/// later write to it is what a `setsockopt` would do.
fn entry_with_mark(local: u16, mark: &Arc<AtomicI32>) -> Arc<TcpEntry> {
    let mut conn = TcpConn::new_client(
        Endpoint { ip: IpAddr::V4(Ipv4Addr::LOOPBACK), port: local },
        Endpoint { ip: IpAddr::V4(REMOTE), port: SERVER_PORT }, 1);
    conn.state = crate::tcp_state::TcpState::Established;
    Arc::new(TcpEntry::new_bound_ip_opts_pacing_ipv6_mark(
        conn, Arc::new(crate::SocketError::new()), None,
        Arc::new(crate::bpf_filter::SocketFilter::new()),
        Arc::new(AtomicI32::new(crate::uapi::IP_PMTUDISC_WANT)),
        Arc::new(AtomicI32::new(crate::uapi::IPV6_PMTUDISC_WANT)),
        Arc::new(AtomicI32::new(0)), None,
        Arc::new(crate::min_hop::MinHop::new()),
        Arc::new(crate::sock_opts::sol_ip::IpOpts::default()),
        Arc::new(crate::sock_opts::sol_ipv6::Ipv6Opts::default()),
        Arc::new(::core::sync::atomic::AtomicU64::new(u64::MAX)),
        mark.clone(),
    ))
}

/// Emit one segment from `entry` and report the TTL the IPv4 header left
/// with — which is the hop limit of the route the transmit selected.
fn transmitted_ttl(stack: &NetStack, dev: &Arc<crate::LoopbackDev>, entry: &Arc<TcpEntry>) -> u8 {
    while dev.rx_pop().is_some() {}
    let segment = entry.conn.lock().build_segment(crate::tcp_hdr::flags::ACK, b"x");
    stack.send_tcp_entry_segment_in(entry, IpAddr::V4(Ipv4Addr::LOOPBACK),
        IpAddr::V4(REMOTE), &segment, 0).expect("segment leaves the stack");
    let packet = dev.rx_pop().expect("loopback holds the transmitted packet");
    crate::Ipv4Hdr::parse(packet.data()).expect("transmitted IPv4 header").ttl
}

#[test]
fn route_metrics_come_from_the_route_the_socket_mark_selects() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let (stack, _iface, _dev) = marked_stack();
    let dst = IpAddr::V4(REMOTE);

    assert_eq!(stack.route_metrics_for_dst_mark_in(0, dst, None, MARK).advmss, MARKED_ADVMSS);
    // A mark the rule's mask rejects lands in the main table, whose route to
    // the same destination carries none of these metrics.
    assert_eq!(stack.route_metrics_for_dst_mark_in(0, dst, None, OTHER_MARK).advmss, 0);
    assert_eq!(stack.route_metrics_for_dst_mark_in(0, dst, None, UNMARKED).advmss, 0);
}

#[test]
fn tcp_mss_comes_from_the_route_the_socket_mark_selects() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let (stack, _iface, _dev) = marked_stack();
    let dst = IpAddr::V4(REMOTE);
    let want = crate::uapi::IP_PMTUDISC_WANT;

    // The marked route caps both the path MTU and the advertised MSS; the
    // unmarked one caps neither, so loopback's own MTU is what answers.
    let marked = stack.mss_for_dst_on_iface_pmtu_modes_in(0, dst, None, want, want, MARK);
    let unmarked = stack.mss_for_dst_on_iface_pmtu_modes_in(0, dst, None, want, want, UNMARKED);
    assert_eq!(marked, MARKED_ADVMSS as u16);
    assert_eq!(unmarked, u16::MAX - IPV4_TCP_OVERHEAD as u16);
}

#[test]
fn path_mtu_comes_from_the_route_the_socket_mark_selects() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let (stack, iface, _dev) = marked_stack();
    let dst = IpAddr::V4(REMOTE);

    assert_eq!(stack.path_mtu_mark_in(0, dst, None, false, MARK), Ok(MARKED_MTU));
    assert_eq!(stack.path_mtu_mark_in(0, dst, None, false, UNMARKED), Ok(65_535));
    // The bound-interface branch consults the same table the mark names.
    assert_eq!(stack.path_mtu_mark_in(0, dst, Some(iface), false, MARK), Ok(MARKED_MTU));
    assert_eq!(stack.path_mtu_mark_in(0, dst, Some(iface), false, UNMARKED), Ok(65_535));
}

#[test]
fn a_marked_tcp_connection_transmits_over_the_route_its_mark_selects() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let (stack, _iface, dev) = marked_stack();

    let marked = entry_with_mark(51_001, &Arc::new(AtomicI32::new(MARK as i32)));
    let unmarked = entry_with_mark(51_002, &Arc::new(AtomicI32::new(UNMARKED as i32)));

    assert_eq!(transmitted_ttl(&stack, &dev, &marked), MARKED_HOPLIMIT as u8);
    assert_eq!(transmitted_ttl(&stack, &dev, &unmarked), crate::ipv4::IPV4_DEFAULT_TTL);
}

#[test]
fn a_mark_written_after_connect_reaches_the_next_segment() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let (stack, _iface, dev) = marked_stack();

    // The cell is the socket's: the connection holds it rather than a value
    // copied at connect time, so a later write is observed by the output path
    // with no second lookup anywhere.
    let cell = Arc::new(AtomicI32::new(UNMARKED as i32));
    let entry = entry_with_mark(51_003, &cell);
    assert_eq!(transmitted_ttl(&stack, &dev, &entry), crate::ipv4::IPV4_DEFAULT_TTL);
    cell.store(MARK as i32, Ordering::Release);
    assert_eq!(transmitted_ttl(&stack, &dev, &entry), MARKED_HOPLIMIT as u8);
}

#[test]
fn a_passive_child_takes_the_listening_socket_mark_as_its_own() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let (stack, iface, _dev) = marked_stack();
    let listen_port = SERVER_PORT + 30;
    let client_port = 51_010;

    let bind = stack.tcp_reserve(
        IpAddr::V4(Ipv4Addr::LOOPBACK), listen_port, None, false, false, 1_000, false).unwrap();
    let listener_mark = Arc::new(AtomicI32::new(MARK as i32));
    stack.tcp_listen_reserved_fastopen_frag_pacing_ipv6_mark(
        &bind, Arc::new(crate::bpf_filter::SocketFilter::new()),
        Arc::new(AtomicI32::new(crate::uapi::IP_PMTUDISC_WANT)),
        Arc::new(AtomicI32::new(crate::uapi::IPV6_PMTUDISC_WANT)),
        Arc::new(AtomicI32::new(0)),
        Arc::new(crate::sock_opts::sol_ipv6::Ipv6Opts::default()),
        Arc::new(crate::min_hop::MinHop::new()),
        Arc::new(crate::tcp_fastopen::FastOpenQueue::new()),
        Arc::new(::core::sync::atomic::AtomicU64::new(u64::MAX)),
        listener_mark.clone(),
    ).unwrap();

    let mut client = TcpConn::new_client(
        Endpoint { ip: IpAddr::V4(REMOTE), port: client_port },
        Endpoint { ip: IpAddr::V4(Ipv4Addr::LOOPBACK), port: listen_port }, 0x3000_0000);
    let syn = client.active_open().unwrap();
    stack.deliver_tcp(0, iface, IpAddr::V4(REMOTE),
        IpAddr::V4(Ipv4Addr::LOOPBACK), &syn).unwrap();

    let child = stack.inet_tables(0).tcp_conns.lock().get(&TcpKey {
        local_ip: IpAddr::V4(Ipv4Addr::LOOPBACK), local_port: listen_port,
        remote_ip: IpAddr::V4(REMOTE), remote_port: client_port,
    }).cloned().expect("the SYN opened a passive child");

    assert_eq!(child.mark(), MARK);
    // The request answered under the listener's mark, so the MSS it advertised
    // and the initial RTT it started from are the marked route's, not the ones
    // an unmarked lookup would have found. The RTT is the sharper of the two:
    // only the metrics query the delivery path makes can have supplied it.
    assert_eq!(child.conn.lock().own_mss, MARKED_ADVMSS as u16);
    assert_eq!(child.conn.lock().srtt_ns, u64::from(MARKED_RTT_MS) * 1_000_000);
    // The child owns the value from here: the listening socket's later writes
    // are its own, the way an accepted connection's mark is its own.
    listener_mark.store(OTHER_MARK as i32, Ordering::Release);
    assert_eq!(child.mark(), MARK);
}
