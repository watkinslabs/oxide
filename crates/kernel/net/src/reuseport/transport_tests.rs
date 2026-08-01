// Verified group join and program selection on the IPv6 datagram and TCP
// listener bind keys, not just the IPv4 datagram one.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::AtomicI32;

use super::slot::{self, ReuseportSlot};
use crate::bpf_filter::{install_bpf_filter_runner, FilterKind, FilterProgram, SocketFilter};
use crate::stack::{TcpListenEntry, tcp_listener};
use crate::stack_ipv6::Udp6RxQueue;
use crate::{IpAddr, Ipv4Addr, Ipv6Addr, NetStack, SocketError};

const PORT: u16 = 49_411;
const OTHER_PORT: u16 = 49_412;
const SOURCE_PORT: u16 = 41_888;

fn index_runner(_kind: FilterKind, insns: &[u8], _packet: &[u8]) -> u32 {
    u32::from_ne_bytes(insns.try_into().expect("index program is one u32"))
}

fn prog(index: u32) -> FilterProgram {
    FilterProgram { kind: FilterKind::Ebpf, insns: index.to_ne_bytes().to_vec() }
}

fn bind6(stack: &NetStack, port: u16, reuseport: bool, v6only: bool) -> Arc<Udp6RxQueue> {
    stack.bind_udp6_socket(
        Ipv6Addr::LOOPBACK, port, None, Arc::new(SocketError::new()),
        Arc::new(AtomicI32::new(0)), Arc::new(AtomicI32::new(i32::from(reuseport))), 0,
        Arc::new(AtomicI32::new(i32::from(v6only))),
        Arc::new(sync::Spinlock::new(None)),
        Arc::new(AtomicI32::new(crate::uapi::IP_PMTUDISC_WANT)),
        Arc::new(AtomicI32::new(crate::uapi::IPV6_PMTUDISC_WANT)),
        Arc::new(SocketFilter::new()), Arc::new(crate::mcast_filter::SocketMcast::new()),
    ).expect("reuseport bind shares the key")
}

fn join6(stack: &NetStack, endpoint: &Arc<Udp6RxQueue>) -> ReuseportSlot {
    let member = slot::new_slot();
    stack.join_udp6_reuseport(endpoint, &member);
    member
}

fn listen(stack: &NetStack, port: u16, reuseport: bool) -> Arc<TcpListenEntry> {
    stack.tcp_listen_ip_with(IpAddr::V4(Ipv4Addr::LOOPBACK), port, false, reuseport)
        .expect("reuseport listeners share the key")
}

fn join_tcp(stack: &NetStack, listener: &Arc<TcpListenEntry>) -> ReuseportSlot {
    let member = slot::new_slot();
    stack.join_tcp_reuseport(listener, &member);
    member
}

#[test]
fn ipv6_datagram_sockets_join_one_group_per_bind_key() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let first = bind6(&stack, PORT, true, true);
    let first_member = join6(&stack, &first);
    let second = bind6(&stack, PORT, true, true);
    let second_member = join6(&stack, &second);

    let group = slot::group(&first_member).expect("the bind key allocated one group");
    assert!(Arc::ptr_eq(&slot::group(&second_member).unwrap(), &group));
    assert!(Arc::ptr_eq(&slot::group(&second.reuseport_group).unwrap(), &group));
    assert_eq!(group.num_socks(), 2);

    let elsewhere = bind6(&stack, OTHER_PORT, true, true);
    assert!(!Arc::ptr_eq(&slot::group(&join6(&stack, &elsewhere)).unwrap(), &group));

    let plain = bind6(&stack, OTHER_PORT + 1, false, true);
    assert!(slot::group(&join6(&stack, &plain)).is_none());
}

#[test]
fn an_ipv6_program_names_the_member_and_an_out_of_range_result_keeps_the_hash() {
    let _domain = crate::hosted_fixture::init_net_domain();
    install_bpf_filter_runner(index_runner);
    let stack = NetStack::new();
    let (iface, _loopback) = stack.register_loopback();
    let endpoints = [bind6(&stack, PORT, true, true), bind6(&stack, PORT, true, true),
                     bind6(&stack, PORT, true, true)];
    let members: Vec<ReuseportSlot> = endpoints.iter().map(|e| join6(&stack, e)).collect();
    let group = slot::group(&members[0]).expect("the bind key allocated one group");

    let select = |payload: &[u8]| -> Arc<Udp6RxQueue> {
        let chosen = stack.udp6_demux_in(0, Ipv6Addr::LOOPBACK, SOURCE_PORT, Ipv6Addr::LOOPBACK,
            PORT, iface, payload);
        assert_eq!(chosen.len(), 1);
        chosen[0].clone()
    };

    let hashed = select(b"body");
    for index in 0..endpoints.len() {
        group.attach_prog(prog(index as u32));
        assert!(Arc::ptr_eq(&select(b"body"), &endpoints[index]), "program index {index}");
    }
    group.attach_prog(prog(endpoints.len() as u32));
    assert!(Arc::ptr_eq(&select(b"body"), &hashed));
    group.detach_prog().unwrap();
    assert!(Arc::ptr_eq(&select(b"body"), &hashed));
}

#[test]
fn tcp_listeners_on_one_key_share_a_group_whose_program_picks_the_listener() {
    let _domain = crate::hosted_fixture::init_net_domain();
    install_bpf_filter_runner(index_runner);
    let stack = NetStack::new();
    let bucket: Vec<Arc<TcpListenEntry>> =
        (0..3).map(|_| listen(&stack, PORT, true)).collect();
    let members: Vec<ReuseportSlot> = bucket.iter().map(|l| join_tcp(&stack, l)).collect();
    let group = slot::group(&members[0]).expect("the listen key allocated one group");
    assert_eq!(group.num_socks(), 3);
    for member in &members { assert!(Arc::ptr_eq(&slot::group(member).unwrap(), &group)); }

    let src = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
    let hashed = tcp_listener::select_listener_index(&bucket, src, SOURCE_PORT, PORT, b"seg");
    for index in 0..bucket.len() {
        group.attach_prog(prog(index as u32));
        assert_eq!(tcp_listener::select_listener_index(&bucket, src, SOURCE_PORT, PORT, b"seg"),
            index);
    }
    group.attach_prog(prog(bucket.len() as u32));
    assert_eq!(tcp_listener::select_listener_index(&bucket, src, SOURCE_PORT, PORT, b"seg"),
        hashed);
    group.detach_prog().unwrap();
    assert_eq!(tcp_listener::select_listener_index(&bucket, src, SOURCE_PORT, PORT, b"seg"),
        hashed);

    let plain = listen(&stack, OTHER_PORT, false);
    assert!(slot::group(&join_tcp(&stack, &plain)).is_none());
}
