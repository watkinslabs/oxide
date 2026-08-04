use alloc::sync::Arc;
use core::sync::atomic::AtomicI32;

use super::*;
use crate::stack::{TcpKey, TcpBindReservation};
use crate::tcp_conn::{Endpoint, TcpConn};

const CLIENT_PORT: u16 = 51_000;
const SEED_PORT: u16 = 50_000;
const SERVER_PORT: u16 = 8_080;
const LEARNED_PMTU: u16 = 1_200;
const LEARNED_MSS: u16 = 1_160;
const LOOPBACK_MSS: u16 = u16::MAX - IPV4_TCP_OVERHEAD as u16;
const IPV6_LEARNED_PMTU: u32 = 1_280;
const IPV6_LEARNED_MSS: u16 = 1_220;
const IPV6_LOOPBACK_MSS: u16 = u16::MAX - IPV6_TCP_OVERHEAD as u16;

fn endpoint(ip: Ipv4Addr, port: u16) -> Endpoint {
    Endpoint { ip: IpAddr::V4(ip), port }
}

fn reserve(stack: &NetStack, port: u16) -> Arc<TcpBindReservation> {
    stack.tcp_reserve(
        IpAddr::V4(Ipv4Addr::LOOPBACK), port, None, false, false, 1_000, false,
    ).unwrap()
}

fn learn_tcp_pmtu(stack: &NetStack, iface: NetIfaceId) {
    let seed = stack.tcp_connect(
        Ipv4Addr::LOOPBACK, SEED_PORT, Ipv4Addr::LOOPBACK, SERVER_PORT,
    ).unwrap();
    let seq = seed.conn.lock().snd_una;
    let mut quote = alloc::vec![0u8; 8 + IPV4_HDR_LEN + 8];
    quote[6..8].copy_from_slice(&LEARNED_PMTU.to_be_bytes());
    let hdr = crate::Ipv4Hdr::build(
        Ipv4Addr::LOOPBACK, Ipv4Addr::LOOPBACK, IpProto::Tcp, 8, 1,
    );
    hdr.write_to(&mut quote[8..8 + IPV4_HDR_LEN]);
    let tcp = 8 + IPV4_HDR_LEN;
    quote[tcp..tcp + 2].copy_from_slice(&SEED_PORT.to_be_bytes());
    quote[tcp + 2..tcp + 4].copy_from_slice(&SERVER_PORT.to_be_bytes());
    quote[tcp + 4..tcp + 8].copy_from_slice(&seq.to_be_bytes());
    crate::stack_icmp::handle_error(
        stack, iface, Ipv4Addr::LOOPBACK,
        crate::icmp::ICMP_TYPE_DEST_UNREACH, 4, &quote,
    );
    assert_eq!(stack.path_mtu(
        IpAddr::V4(Ipv4Addr::LOOPBACK), Some(iface), false,
    ), Ok(u32::from(LEARNED_PMTU)));
}

fn connect_with_mode(stack: &NetStack, port: u16, mode: i32) -> Arc<TcpEntry> {
    let bind = reserve(stack, port);
    stack.tcp_connect_reserved_filter_pmtu(
        &bind, IpAddr::V4(Ipv4Addr::LOOPBACK), IpAddr::V4(Ipv4Addr::LOOPBACK),
        SERVER_PORT, Arc::new(crate::SocketError::new()),
        Arc::new(crate::bpf_filter::SocketFilter::new()), Arc::new(AtomicI32::new(mode)),
    ).unwrap()
}

#[test]
fn active_open_uses_learned_pmtu_unless_mode_uses_interface() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();
    learn_tcp_pmtu(&stack, iface);

    let cached = connect_with_mode(&stack, CLIENT_PORT, crate::uapi::IP_PMTUDISC_WANT);
    let probe = connect_with_mode(&stack, CLIENT_PORT + 1, crate::uapi::IP_PMTUDISC_PROBE);
    assert_eq!(cached.conn.lock().own_mss, LEARNED_MSS);
    assert_eq!(probe.conn.lock().own_mss, LOOPBACK_MSS);
    assert_eq!(cached.conn.lock().path_mtu, u32::from(LEARNED_PMTU));
    assert_eq!(probe.conn.lock().path_mtu, 65_535);
    cached.conn.lock().path_mtu = 0;
    stack.tcp_sync_mss(&cached);
    assert_eq!(cached.conn.lock().path_mtu, u32::from(LEARNED_PMTU));
}

#[test]
fn passive_child_uses_learned_pmtu_unless_listener_uses_interface() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();
    learn_tcp_pmtu(&stack, iface);

    for (offset, mode, expected) in [
        (0, crate::uapi::IP_PMTUDISC_WANT, LEARNED_MSS),
        (1, crate::uapi::IP_PMTUDISC_PROBE, LOOPBACK_MSS),
    ] {
        let listen_port = SERVER_PORT + 1 + offset;
        let bind = reserve(&stack, listen_port);
        stack.tcp_listen_reserved_filter_pmtu(
            &bind, Arc::new(crate::bpf_filter::SocketFilter::new()),
            Arc::new(AtomicI32::new(mode)),
        ).unwrap();
        let client_port = CLIENT_PORT + 10 + offset;
        let mut client = TcpConn::new_client(
            endpoint(Ipv4Addr::LOOPBACK, client_port),
            endpoint(Ipv4Addr::LOOPBACK, listen_port), 0x2000_0000 + u32::from(offset),
        );
        let syn = client.active_open().unwrap();
        stack.deliver_tcp(
            0, iface, IpAddr::V4(Ipv4Addr::LOOPBACK),
            IpAddr::V4(Ipv4Addr::LOOPBACK), &syn,
        ).unwrap();
        let key = TcpKey {
            local_ip: IpAddr::V4(Ipv4Addr::LOOPBACK), local_port: listen_port,
            remote_ip: IpAddr::V4(Ipv4Addr::LOOPBACK), remote_port: client_port,
        };
        let child = stack.inet_tables(0).tcp_conns.lock().get(&key).cloned().unwrap();
        assert_eq!(child.conn.lock().own_mss, expected, "mode={mode}");
        let expected_pmtu = if mode == crate::uapi::IP_PMTUDISC_PROBE {
            65_535
        } else { u32::from(LEARNED_PMTU) };
        assert_eq!(child.conn.lock().path_mtu, expected_pmtu, "mode={mode}");
    }
}

#[test]
fn tcp_mss_selects_pmtu_mode_by_destination_family() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();
    learn_tcp_pmtu(&stack, iface);
    stack.update_pmtu_v6(iface, Ipv6Addr::LOOPBACK, IPV6_LEARNED_PMTU);

    assert_eq!(stack.mss_for_dst_on_iface_pmtu_modes_in(
        0, IpAddr::V6(Ipv6Addr::LOOPBACK), Some(iface),
        crate::uapi::IP_PMTUDISC_PROBE, crate::uapi::IPV6_PMTUDISC_WANT,
    ), IPV6_LEARNED_MSS);
    assert_eq!(stack.mss_for_dst_on_iface_pmtu_modes_in(
        0, IpAddr::V6(Ipv6Addr::LOOPBACK), Some(iface),
        crate::uapi::IP_PMTUDISC_WANT, crate::uapi::IPV6_PMTUDISC_PROBE,
    ), IPV6_LOOPBACK_MSS);
    assert_eq!(stack.mss_for_dst_on_iface_pmtu_modes_in(
        0, IpAddr::V4(Ipv4Addr::LOOPBACK), Some(iface),
        crate::uapi::IP_PMTUDISC_WANT, crate::uapi::IPV6_PMTUDISC_PROBE,
    ), LEARNED_MSS);
    assert_eq!(stack.mss_for_dst_on_iface_pmtu_modes_in(
        0, IpAddr::V4(Ipv4Addr::LOOPBACK), Some(iface),
        crate::uapi::IP_PMTUDISC_PROBE, crate::uapi::IPV6_PMTUDISC_WANT,
    ), LOOPBACK_MSS);
}

#[test]
fn tcp_listener_and_active_entry_own_distinct_shared_pmtu_modes() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    stack.register_loopback();
    let listener_bind = stack.tcp_reserve(
        IpAddr::V6(Ipv6Addr::LOOPBACK), SERVER_PORT + 20, None,
        false, false, 1_000, true,
    ).unwrap();
    let listener_ip = Arc::new(AtomicI32::new(crate::uapi::IP_PMTUDISC_PROBE));
    let listener_ipv6 = Arc::new(AtomicI32::new(crate::uapi::IPV6_PMTUDISC_DONT));
    let listener = stack.tcp_listen_reserved_filter_pmtu_modes(
        &listener_bind, Arc::new(crate::bpf_filter::SocketFilter::new()),
        listener_ip.clone(), listener_ipv6.clone(),
    ).unwrap();
    assert!(Arc::ptr_eq(&listener.ip_mtu_discover, &listener_ip));
    assert!(Arc::ptr_eq(&listener.ipv6_mtu_discover, &listener_ipv6));

    let active_bind = stack.tcp_reserve(
        IpAddr::V6(Ipv6Addr::LOOPBACK), CLIENT_PORT + 20, None,
        false, false, 1_000, true,
    ).unwrap();
    let active_ip = Arc::new(AtomicI32::new(crate::uapi::IP_PMTUDISC_DONT));
    let active_ipv6 = Arc::new(AtomicI32::new(crate::uapi::IPV6_PMTUDISC_PROBE));
    let entry = stack.tcp_connect_reserved_filter_pmtu_modes(
        &active_bind, IpAddr::V6(Ipv6Addr::LOOPBACK), IpAddr::V6(Ipv6Addr::LOOPBACK),
        SERVER_PORT + 21, Arc::new(crate::SocketError::new()),
        Arc::new(crate::bpf_filter::SocketFilter::new()),
        active_ip.clone(), active_ipv6.clone(),
    ).unwrap();
    assert!(Arc::ptr_eq(&entry.ip_mtu_discover, &active_ip));
    assert!(Arc::ptr_eq(&entry.ipv6_mtu_discover, &active_ipv6));
}
