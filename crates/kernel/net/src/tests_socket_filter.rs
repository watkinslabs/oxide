use alloc::sync::Arc;
use core::sync::atomic::AtomicI32;
use sync::{Spinlock, Socket as StackLockClass};

use crate::bpf_filter::{FilterKind, FilterProgram, SocketFilter, install_bpf_filter_runner};
use crate::{Ipv4Addr, NetStack, SocketError};

const PORT: u16 = 49_071;
const SOURCE_PORT: u16 = 41_000;

fn verdict_runner(_kind: FilterKind, insns: &[u8], _packet: &[u8]) -> u32 {
    u32::from_ne_bytes(insns.try_into().unwrap())
}

fn filter(verdict: u32) -> Arc<SocketFilter> {
    let filter = Arc::new(SocketFilter::new());
    filter.attach(FilterProgram {
        kind: FilterKind::Ebpf, insns: verdict.to_ne_bytes().to_vec(),
    }).unwrap();
    filter
}

fn endpoint(stack: &NetStack, port: u16, filter: Arc<SocketFilter>)
    -> Arc<crate::UdpRxQueue>
{
    stack.bind_udp_socket(
        Ipv4Addr::LOOPBACK, port, None, Arc::new(SocketError::new()),
        Arc::new(AtomicI32::new(0)), Arc::new(AtomicI32::new(0)),
        Arc::new(AtomicI32::new(crate::uapi::IP_PMTUDISC_WANT)), 0,
        Arc::new(Spinlock::<Option<(Ipv4Addr, u16)>, StackLockClass>::new(None)),
        filter, Arc::new(crate::mcast_filter::SocketMcast::new()),
    ).unwrap()
}

fn deliver_one(stack: &NetStack, iface: crate::NetIfaceId, loopback: &crate::LoopbackDev) {
    let packet = loopback.rx_pop().expect("queued loopback packet");
    stack.deliver_rx(iface, packet.data()).unwrap();
}

#[test]
fn udp_socket_filter_sees_header_drops_zero_and_truncates_positive_verdict() {
    let _domain = crate::hosted_fixture::init_net_domain();
    install_bpf_filter_runner(verdict_runner);
    let stack = NetStack::new();
    let (iface, loopback) = stack.register_loopback();
    let truncated = endpoint(&stack, PORT, filter(11));

    stack.send_udp_to(
        Ipv4Addr::LOOPBACK, SOURCE_PORT, Ipv4Addr::LOOPBACK, PORT, b"abcdef",
    ).unwrap();
    stack.drain_loopback(iface, &loopback);
    assert_eq!(truncated.recv(false).unwrap().5, b"abc");

    stack.unbind_udp_endpoint(&truncated);
    let dropped = endpoint(&stack, PORT, filter(0));
    stack.send_udp_to(
        Ipv4Addr::LOOPBACK, SOURCE_PORT, Ipv4Addr::LOOPBACK, PORT, b"abcdef",
    ).unwrap();
    stack.drain_loopback(iface, &loopback);
    assert!(dropped.recv(false).is_none());
}

#[test]
fn tcp_listener_filter_drops_syn_before_passive_open() {
    let _domain = crate::hosted_fixture::init_net_domain();
    install_bpf_filter_runner(verdict_runner);
    let stack = NetStack::new();
    let (iface, loopback) = stack.register_loopback();
    let listener = stack.tcp_listen(Ipv4Addr::LOOPBACK, PORT, true).unwrap();
    listener.bpf_filter.attach(FilterProgram {
        kind: FilterKind::Ebpf, insns: 0u32.to_ne_bytes().to_vec(),
    }).unwrap();
    stack.tcp_connect(Ipv4Addr::LOOPBACK, SOURCE_PORT, Ipv4Addr::LOOPBACK, PORT).unwrap();
    stack.drain_loopback(iface, &loopback);
    assert!(stack.tcp_accept(&listener).is_none());
}

#[test]
fn tcp_filter_truncates_to_header_without_delivering_payload() {
    let _domain = crate::hosted_fixture::init_net_domain();
    install_bpf_filter_runner(verdict_runner);
    let stack = NetStack::new();
    let (iface, loopback) = stack.register_loopback();
    let listener = stack.tcp_listen(Ipv4Addr::LOOPBACK, PORT, true).unwrap();
    let client = stack.tcp_connect(
        Ipv4Addr::LOOPBACK, SOURCE_PORT, Ipv4Addr::LOOPBACK, PORT,
    ).unwrap();
    for _ in 0..3 { stack.drain_loopback(iface, &loopback); }
    let server = stack.tcp_accept(&listener).unwrap();
    server.bpf_filter.attach(FilterProgram {
        kind: FilterKind::Ebpf,
        insns: (crate::tcp_hdr::TCP_HDR_MIN_LEN as u32).to_ne_bytes().to_vec(),
    }).unwrap();
    stack.tcp_send(&client, b"filtered", 65_536, true, false).unwrap();
    for _ in 0..3 { stack.drain_loopback(iface, &loopback); }
    assert!(stack.tcp_recv(&server, 64).is_empty());
}

#[test]
fn tcp_passive_filter_is_live_until_final_ack_and_partial_payload_progresses() {
    let _domain = crate::hosted_fixture::init_net_domain();
    install_bpf_filter_runner(verdict_runner);
    let stack = NetStack::new();
    let (iface, loopback) = stack.register_loopback();
    let listener = stack.tcp_listen(Ipv4Addr::LOOPBACK, PORT, true).unwrap();
    let client = stack.tcp_connect(
        Ipv4Addr::LOOPBACK, SOURCE_PORT, Ipv4Addr::LOOPBACK, PORT,
    ).unwrap();

    deliver_one(&stack, iface, &loopback);
    assert!(stack.tcp_accept(&listener).is_none());
    listener.bpf_filter.attach(FilterProgram {
        kind: FilterKind::Ebpf, insns: 0u32.to_ne_bytes().to_vec(),
    }).unwrap();
    deliver_one(&stack, iface, &loopback);
    let final_ack = loopback.rx_pop().expect("final ACK");
    stack.deliver_rx(iface, final_ack.data()).unwrap();
    assert!(stack.tcp_accept(&listener).is_none());

    let partial = crate::tcp_hdr::TCP_HDR_MIN_LEN as u32 + 12 + 3;
    listener.bpf_filter.attach(FilterProgram {
        kind: FilterKind::Ebpf, insns: partial.to_ne_bytes().to_vec(),
    }).unwrap();
    stack.deliver_rx(iface, final_ack.data()).unwrap();
    let server = stack.tcp_accept(&listener).expect("completed passive child");
    listener.bpf_filter.attach(FilterProgram {
        kind: FilterKind::Ebpf, insns: u32::MAX.to_ne_bytes().to_vec(),
    }).unwrap();

    stack.tcp_send(&client, b"abcdefgh", 65_536, true, false).unwrap();
    stack.drain_loopback(iface, &loopback);
    assert_eq!(stack.tcp_recv(&server, 64), b"abc");
    assert_eq!(client.conn.lock().retx_q.front().unwrap().payload, b"defgh");

    stack.tcp_retx_tick(60_000_000_000);
    assert_eq!(client.conn.lock().retx_q.front().unwrap().retries, 1);
    assert_eq!(loopback.rx_len(), 1);
    stack.drain_loopback(iface, &loopback);
    assert_eq!(stack.tcp_recv(&server, 64), b"def");
    assert_eq!(client.conn.lock().retx_q.front().unwrap().payload, b"gh");

    stack.tcp_retx_tick(120_000_000_000);
    assert_eq!(loopback.rx_len(), 1);
    stack.drain_loopback(iface, &loopback);
    assert_eq!(stack.tcp_recv(&server, 64), b"gh");
    assert!(client.conn.lock().retx_q.is_empty());
}
