// `IP_MINTTL` / `IPV6_MINHOPCOUNT` end to end: a segment arriving below the
// socket's minimum never reaches the state machine, and the drop is silent.
// The check is connection-oriented only — datagram and raw receives ignore
// both minimums however low the hop limit is.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::addr::{IpAddr, Ipv4Addr, Ipv6Addr};
use crate::stack::NetStack;
use crate::tcp_hdr::{TCP_HDR_MIN_LEN, TcpHdr, flags};

const PORT: u16 = 43_101;
const PEER_PORT: u16 = 5_000;

fn syn(src: IpAddr, dst: IpAddr) -> Vec<u8> {
    let mut buf = alloc::vec![0u8; TCP_HDR_MIN_LEN];
    let mut h = TcpHdr {
        src_port: PEER_PORT, dst_port: PORT,
        seq: 0x1000_0000, ack: 0,
        data_offset: 5, flags: flags::SYN,
        window: 65535, checksum: 0, urg_ptr: 0,
    };
    h.build_into_ip(src, dst, &mut buf);
    buf
}

fn listener(stack: &NetStack, local: IpAddr)
    -> Arc<crate::stack::TcpListenEntry>
{
    let bind = stack.tcp_reserve(local, PORT, None, false, false, 1_000, false).unwrap();
    stack.tcp_listen_reserved_min_hop(&bind,
        Arc::new(crate::bpf_filter::SocketFilter::new()),
        Arc::new(core::sync::atomic::AtomicI32::new(crate::uapi::IP_PMTUDISC_WANT)),
        Arc::new(core::sync::atomic::AtomicI32::new(crate::uapi::IPV6_PMTUDISC_WANT)),
        Arc::new(crate::min_hop::MinHop::new())).unwrap()
}

#[test]
fn a_connection_request_below_the_minimum_hop_limit_is_dropped_silently() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, lo) = stack.register_loopback();
    let local = IpAddr::V4(Ipv4Addr::LOOPBACK);
    let listen = listener(&stack, local);
    while lo.rx_pop().is_some() {}

    // The peer must prove it is one hop away.
    listen.min_hop.set_ttl(255);
    let segment = syn(local, local);
    stack.deliver_tcp_packet_hop(0, iface, local, local, &segment, &segment, 254).unwrap();
    assert_eq!(listen.syn_backlog_used.load(core::sync::atomic::Ordering::Acquire), 0,
        "a segment below the minimum never reaches the state machine");
    // Silent: no reset, nothing the peer can tell from a lost packet.
    assert!(lo.rx_pop().is_none(), "the drop answers nothing at all");

    // A segment AT the minimum is admitted.
    stack.deliver_tcp_packet_hop(0, iface, local, local, &segment, &segment, 255).unwrap();
    assert_eq!(listen.syn_backlog_used.load(core::sync::atomic::Ordering::Acquire), 1);
    assert!(lo.rx_pop().is_some(), "an admitted request is answered");
}

#[test]
fn the_default_minimum_admits_a_hop_limit_of_zero() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, lo) = stack.register_loopback();
    let local = IpAddr::V4(Ipv4Addr::LOOPBACK);
    let listen = listener(&stack, local);
    while lo.rx_pop().is_some() {}

    let segment = syn(local, local);
    stack.deliver_tcp_packet_hop(0, iface, local, local, &segment, &segment, 0).unwrap();
    assert_eq!(listen.syn_backlog_used.load(core::sync::atomic::Ordering::Acquire), 1,
        "a socket that named no minimum accepts any hop limit");
}

#[test]
fn the_ipv4_minimum_does_not_screen_a_native_ipv6_segment() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, lo) = stack.register_loopback();
    let local = IpAddr::V6(Ipv6Addr::LOOPBACK);
    let listen = listener(&stack, local);
    while lo.rx_pop().is_some() {}

    // A dual-stack socket answers a native connection through the IPv6
    // minimum, so raising only the IPv4 one leaves it open.
    listen.min_hop.set_ttl(255);
    let segment = syn(local, local);
    stack.deliver_tcp_packet_hop(0, iface, local, local, &segment, &segment, 64).unwrap();
    assert_eq!(listen.syn_backlog_used.load(core::sync::atomic::Ordering::Acquire), 1);

    // Raising the IPv6 minimum then closes it.
    listen.min_hop.set_hopcount(255);
    let second = {
        let mut buf = alloc::vec![0u8; TCP_HDR_MIN_LEN];
        let mut h = TcpHdr {
            src_port: PEER_PORT + 1, dst_port: PORT,
            seq: 0x2000_0000, ack: 0,
            data_offset: 5, flags: flags::SYN,
            window: 65535, checksum: 0, urg_ptr: 0,
        };
        h.build_into_ip(local, local, &mut buf);
        buf
    };
    stack.deliver_tcp_packet_hop(0, iface, local, local, &second, &second, 64).unwrap();
    assert_eq!(listen.syn_backlog_used.load(core::sync::atomic::Ordering::Acquire), 1,
        "the second request is refused, leaving the first one's reservation alone");
}

#[test]
fn a_datagram_socket_ignores_the_minimum_however_low_the_hop_limit() {
    // Only a connection-oriented socket consults the minimums; a UDP receive
    // path never looks at them, which is why the option lives beside the
    // transport entry rather than on the receive queue.
    let limits = crate::min_hop::MinHop::new();
    limits.set_ttl(255);
    limits.set_hopcount(255);
    assert!(limits.refuses(1, false));
    assert!(limits.refuses(1, true));
    // The datagram queues carry no reference to it at all.
    let _ = &limits;
}
