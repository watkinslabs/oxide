use alloc::sync::Arc;
use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

use sync::{Socket as StackLockClass, Spinlock};

use crate::{IpAddr, IpProto, Ipv6Addr, NetIfaceId, NetStack, SocketError};

const LOCAL_PORT: u16 = 43_000;
const REMOTE_PORT: u16 = 53;
const OWNER_UID: u32 = 1_000;
const ICMPV6_DEST_UNREACHABLE: u8 = 1;
const ICMPV6_TIME_EXCEEDED: u8 = 3;
const ICMPV6_PARAMETER_PROBLEM: u8 = 4;
const ICMPV6_DEST_PORT_UNREACHABLE: u8 = 4;

struct Pmtu6Dev { tx: AtomicUsize, fragments: AtomicUsize }

impl crate::NetDev for Pmtu6Dev {
    fn name(&self) -> &str { "pmtu6" }
    fn mac(&self) -> crate::MacAddr { crate::MacAddr::ZERO }
    fn mtu(&self) -> u32 { 1_500 }
    fn retire_namespace(&self) {}
    fn namespace_drop_action(&self) -> crate::NamespaceDropAction {
        crate::NamespaceDropAction::Destroy
    }
    fn xmit(&self, packet: crate::Pkt) -> crate::NetResult<()> {
        let hdr = crate::ipv6::Ipv6Hdr::parse(packet.data()).unwrap();
        if hdr.next_header == IpProto::Fragment as u8 {
            self.fragments.fetch_add(1, Ordering::Relaxed);
        }
        self.tx.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

fn flag(value: i32) -> Arc<AtomicI32> { Arc::new(AtomicI32::new(value)) }

#[test]
fn ipv6_pmtudisc_uapi_modes_match_linux() {
    for mode in crate::uapi::IPV6_PMTUDISC_DONT..=crate::uapi::IPV6_PMTUDISC_OMIT {
        assert!(crate::uapi::valid_ipv6_pmtudisc(mode));
    }
    assert!(!crate::uapi::valid_ipv6_pmtudisc(-1));
    assert!(!crate::uapi::valid_ipv6_pmtudisc(crate::uapi::IPV6_PMTUDISC_OMIT + 1));
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = bytes.chunks_exact(2);
    for word in &mut chunks {
        sum += u32::from(u16::from_be_bytes([word[0], word[1]]));
    }
    if let Some(byte) = chunks.remainder().first() { sum += u32::from(*byte) << 8; }
    while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16); }
    !(sum as u16)
}

fn set_icmpv6_checksum(message: &mut [u8], src: Ipv6Addr, dst: Ipv6Addr) {
    message[2] = 0;
    message[3] = 0;
    let mut pseudo = alloc::vec![0u8; 40 + message.len()];
    pseudo[0..16].copy_from_slice(&src.0);
    pseudo[16..32].copy_from_slice(&dst.0);
    pseudo[32..36].copy_from_slice(&(message.len() as u32).to_be_bytes());
    pseudo[39] = IpProto::Icmpv6 as u8;
    pseudo[40..].copy_from_slice(message);
    message[2..4].copy_from_slice(&checksum(&pseudo).to_be_bytes());
}

fn ipv6_packet(src: Ipv6Addr, dst: Ipv6Addr, proto: IpProto, payload: &[u8]) -> alloc::vec::Vec<u8> {
    let mut packet = alloc::vec![0u8; crate::ipv6::IPV6_HDR_LEN + payload.len()];
    crate::ipv6::Ipv6Hdr::build(src, dst, proto, payload.len() as u16)
        .write_to(&mut packet[..crate::ipv6::IPV6_HDR_LEN]);
    packet[crate::ipv6::IPV6_HDR_LEN..].copy_from_slice(payload);
    packet
}

fn dest_unreachable(src: Ipv6Addr, dst: Ipv6Addr, code: u8,
                    invoking: &[u8]) -> alloc::vec::Vec<u8> {
    icmp_error(src, dst, ICMPV6_DEST_UNREACHABLE, code, invoking)
}

fn icmp_error(src: Ipv6Addr, dst: Ipv6Addr, kind: u8, code: u8,
              invoking: &[u8]) -> alloc::vec::Vec<u8> {
    let mut message = alloc::vec![0u8; crate::icmpv6::ICMPV6_HDR_LEN + invoking.len()];
    message[0] = kind;
    message[1] = code;
    message[crate::icmpv6::ICMPV6_HDR_LEN..].copy_from_slice(invoking);
    set_icmpv6_checksum(&mut message, src, dst);
    ipv6_packet(src, dst, IpProto::Icmpv6, &message)
}

fn bind_connected(stack: &NetStack, iface: NetIfaceId, local: Ipv6Addr,
                  remote: Ipv6Addr, error: Arc<SocketError>) {
    bind_connected_mode(stack, iface, local, remote, error, crate::uapi::IPV6_PMTUDISC_WANT);
}

fn bind_connected_mode(stack: &NetStack, iface: NetIfaceId, local: Ipv6Addr,
                       remote: Ipv6Addr, error: Arc<SocketError>, mode: i32) {
    stack.bind_udp6_socket(
        local, LOCAL_PORT, Some(iface), error, flag(0), flag(1), OWNER_UID, flag(0),
        Arc::new(Spinlock::<Option<(Ipv6Addr, u16)>, StackLockClass>::new(
            Some((remote, REMOTE_PORT)),
        )), flag(crate::uapi::IP_PMTUDISC_WANT), flag(mode),
        Arc::new(crate::bpf_filter::SocketFilter::new()),
        Arc::new(crate::mcast_filter::SocketMcast::new()),
    ).unwrap();
}

fn quoted_udp(local: Ipv6Addr, remote: Ipv6Addr) -> alloc::vec::Vec<u8> {
    let mut udp = [0u8; crate::udp::UDP_HDR_LEN];
    crate::udp::build_into_v6(LOCAL_PORT, REMOTE_PORT, local, remote, &[], &mut udp);
    ipv6_packet(local, remote, IpProto::Udp, &udp)
}

fn packet_too_big(src: Ipv6Addr, dst: Ipv6Addr, mtu: u32,
                  invoking: &[u8]) -> alloc::vec::Vec<u8> {
    let mut message = alloc::vec![0u8; crate::icmpv6::ICMPV6_HDR_LEN + invoking.len()];
    message[0] = crate::icmpv6::ICMPV6_TYPE_PACKET_TOO_BIG;
    message[4..8].copy_from_slice(&mtu.to_be_bytes());
    message[crate::icmpv6::ICMPV6_HDR_LEN..].copy_from_slice(invoking);
    set_icmpv6_checksum(&mut message, src, dst);
    ipv6_packet(src, dst, IpProto::Icmpv6, &message)
}

#[test]
fn destination_unreachable_targets_exact_grouped_udp6_endpoint() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();
    let local = Ipv6Addr::LOOPBACK;
    let remote_a = Ipv6Addr::from_segments([0x2001, 0xdb8, 1, 0, 0, 0, 0, 1]);
    let remote_b = Ipv6Addr::from_segments([0x2001, 0xdb8, 1, 0, 0, 0, 0, 2]);
    let error_a = Arc::new(SocketError::new());
    let error_b = Arc::new(SocketError::new());
    bind_connected(&stack, iface, local, remote_a, error_a.clone());
    bind_connected(&stack, iface, local, remote_b, error_b.clone());

    let packet = dest_unreachable(
        remote_b, local, ICMPV6_DEST_PORT_UNREACHABLE, &quoted_udp(local, remote_b),
    );
    stack.deliver_rx_ipv6(iface, &packet).unwrap();

    assert_eq!(error_a.take(), 0);
    assert_eq!(error_b.take(), syscall::errno::Errno::Econnrefused as i32);
}

#[test]
fn bad_icmpv6_checksum_does_not_publish_udp_error() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();
    let local = Ipv6Addr::LOOPBACK;
    let remote = Ipv6Addr::from_segments([0x2001, 0xdb8, 2, 0, 0, 0, 0, 1]);
    let error = Arc::new(SocketError::new());
    bind_connected(&stack, iface, local, remote, error.clone());
    let mut packet = dest_unreachable(
        remote, local, ICMPV6_DEST_PORT_UNREACHABLE, &quoted_udp(local, remote),
    );
    let last = packet.len() - 1;
    packet[last] ^= 1;

    stack.deliver_rx_ipv6(iface, &packet).unwrap();

    assert_eq!(error.take(), 0);
}

#[test]
fn address_unreachable_maps_to_ehostunreach() {
    let _domain = crate::hosted_fixture::init_net_domain();
    const ICMPV6_DEST_ADDR_UNREACHABLE: u8 = 3;
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();
    let local = Ipv6Addr::LOOPBACK;
    let remote = Ipv6Addr::from_segments([0x2001, 0xdb8, 4, 0, 0, 0, 0, 1]);
    let error = Arc::new(SocketError::new());
    error.set_recverr6(true);
    bind_connected(&stack, iface, local, remote, error.clone());
    let packet = dest_unreachable(
        remote, local, ICMPV6_DEST_ADDR_UNREACHABLE, &quoted_udp(local, remote),
    );

    stack.deliver_rx_ipv6(iface, &packet).unwrap();

    assert_eq!(error.take(), syscall::errno::Errno::Ehostunreach as i32);
}

#[test]
fn icmpv6_error_conversion_matches_linux_table() {
    let _domain = crate::hosted_fixture::init_net_domain();
    use syscall::errno::Errno;
    let cases = [
        (ICMPV6_DEST_UNREACHABLE, 0, Errno::Enetunreach),
        (ICMPV6_DEST_UNREACHABLE, 1, Errno::Eacces),
        (ICMPV6_DEST_UNREACHABLE, 2, Errno::Ehostunreach),
        (ICMPV6_DEST_UNREACHABLE, 3, Errno::Ehostunreach),
        (ICMPV6_DEST_UNREACHABLE, 4, Errno::Econnrefused),
        (ICMPV6_DEST_UNREACHABLE, 5, Errno::Eacces),
        (ICMPV6_DEST_UNREACHABLE, 6, Errno::Eacces),
        (ICMPV6_DEST_UNREACHABLE, 255, Errno::Eproto),
        (ICMPV6_TIME_EXCEEDED, 0, Errno::Ehostunreach),
        (ICMPV6_TIME_EXCEEDED, 1, Errno::Ehostunreach),
        (ICMPV6_PARAMETER_PROBLEM, 0, Errno::Eproto),
        (ICMPV6_PARAMETER_PROBLEM, 2, Errno::Eproto),
    ];
    for (kind, code, expected) in cases {
        let stack = NetStack::new();
        let (iface, _) = stack.register_loopback();
        let local = Ipv6Addr::LOOPBACK;
        let remote = Ipv6Addr::from_segments([0x2001, 0xdb8, kind as u16, code as u16, 0, 0, 0, 1]);
        let error = Arc::new(SocketError::new());
        error.set_recverr6(true);
        bind_connected(&stack, iface, local, remote, error.clone());

        let packet = icmp_error(remote, local, kind, code, &quoted_udp(local, remote));
        stack.deliver_rx_ipv6(iface, &packet).unwrap();

        assert_eq!(error.take(), expected as i32, "kind={kind} code={code}");
        let extended = error.take_extended().expect("RECVERR must queue converted error");
        assert_eq!((extended.kind, extended.code, extended.errno),
                   (kind, code, expected as i32));
    }
}

#[test]
fn icmpv6_hardness_controls_connected_error_without_recverr() {
    let _domain = crate::hosted_fixture::init_net_domain();
    use syscall::errno::Errno;
    let cases = [
        (ICMPV6_DEST_UNREACHABLE, 0, 0),
        (ICMPV6_DEST_UNREACHABLE, 1, Errno::Eacces as i32),
        (ICMPV6_DEST_UNREACHABLE, 4, Errno::Econnrefused as i32),
        (ICMPV6_DEST_UNREACHABLE, 255, Errno::Eproto as i32),
        (ICMPV6_TIME_EXCEEDED, 0, 0),
        (ICMPV6_PARAMETER_PROBLEM, 0, Errno::Eproto as i32),
    ];
    for (kind, code, expected) in cases {
        let stack = NetStack::new();
        let (iface, _) = stack.register_loopback();
        let local = Ipv6Addr::LOOPBACK;
        let remote = Ipv6Addr::from_segments([0x2001, 0xdb8, kind as u16, code as u16, 0, 0, 0, 2]);
        let error = Arc::new(SocketError::new());
        bind_connected(&stack, iface, local, remote, error.clone());

        let packet = icmp_error(remote, local, kind, code, &quoted_udp(local, remote));
        stack.deliver_rx_ipv6(iface, &packet).unwrap();

        assert_eq!(error.take(), expected, "kind={kind} code={code}");
    }
}

#[test]
fn packet_too_big_respects_all_linux_pmtudisc_modes() {
    use syscall::errno::Errno;
    const PATH_MTU: u32 = 1_280;
    for (mode, accepted, hard) in [
        (crate::uapi::IPV6_PMTUDISC_DONT, true, false),
        (crate::uapi::IPV6_PMTUDISC_WANT, true, true),
        (crate::uapi::IPV6_PMTUDISC_DO, true, true),
        (crate::uapi::IPV6_PMTUDISC_PROBE, true, true),
        (crate::uapi::IPV6_PMTUDISC_INTERFACE, false, false),
        (crate::uapi::IPV6_PMTUDISC_OMIT, false, false),
    ] {
        let stack = NetStack::new();
        let dev = Arc::new(Pmtu6Dev {
            tx: AtomicUsize::new(0), fragments: AtomicUsize::new(0),
        });
        let iface = stack.ifaces.register(dev);
        let local = Ipv6Addr::LOOPBACK;
        stack.add_v6_addr(iface, local);
        let remote = Ipv6Addr::from_segments([0x2001, 0xdb8, 8, mode as u16, 0, 0, 0, 1]);
        let error = Arc::new(SocketError::new());
        bind_connected_mode(&stack, iface, local, remote, error.clone(), mode);
        let packet = packet_too_big(remote, local, PATH_MTU, &quoted_udp(local, remote));

        stack.deliver_rx_ipv6(iface, &packet).unwrap();
        assert_eq!(error.take(), if hard { Errno::Emsgsize as i32 } else { 0 }, "mode={mode}");
        assert_eq!(stack.path_mtu(IpAddr::V6(remote), Some(iface), false),
                   Ok(if accepted { PATH_MTU } else { 1_500 }), "mode={mode}");

        error.set_recverr6(true);
        stack.deliver_rx_ipv6(iface, &packet).unwrap();
        assert_eq!(error.take(), if accepted { Errno::Emsgsize as i32 } else { 0 }, "mode={mode}");
        assert_eq!(error.take_extended().map(|entry| entry.errno),
                   accepted.then_some(Errno::Emsgsize as i32), "mode={mode}");
    }
}

#[test]
fn packet_too_big_clamps_ipv6_tcp_mss_without_socket_error() {
    let _domain = crate::hosted_fixture::init_net_domain();
    const PATH_MTU: u32 = 1_280;
    const IPV6_TCP_OVERHEAD: u16 = 60;
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();
    let local = Ipv6Addr::LOOPBACK;
    let remote = Ipv6Addr::LOOPBACK;
    let local_port = 43_100;
    let remote_port = 443;
    let entry = stack.tcp_connect_ip(
        IpAddr::V6(local), local_port, IpAddr::V6(remote), remote_port,
    ).unwrap();
    entry.conn.lock().peer_mss = 1_460;
    let mut tcp_quote = [0u8; 4];
    tcp_quote[0..2].copy_from_slice(&local_port.to_be_bytes());
    tcp_quote[2..4].copy_from_slice(&remote_port.to_be_bytes());
    let invoking = ipv6_packet(local, remote, IpProto::Tcp, &tcp_quote);
    let mut message = alloc::vec![0u8; crate::icmpv6::ICMPV6_HDR_LEN + invoking.len()];
    message[0] = crate::icmpv6::ICMPV6_TYPE_PACKET_TOO_BIG;
    message[4..8].copy_from_slice(&PATH_MTU.to_be_bytes());
    message[crate::icmpv6::ICMPV6_HDR_LEN..].copy_from_slice(&invoking);
    set_icmpv6_checksum(&mut message, remote, local);
    let packet = ipv6_packet(remote, local, IpProto::Icmpv6, &message);

    stack.deliver_rx_ipv6(iface, &packet).unwrap();

    assert_eq!(entry.conn.lock().peer_mss, PATH_MTU as u16 - IPV6_TCP_OVERHEAD);
    assert!(!entry.error.has());
}

#[test]
fn packet_too_big_publishes_emsgsize_to_exact_udp6_endpoint() {
    let _domain = crate::hosted_fixture::init_net_domain();
    const PATH_MTU: u32 = 1_280;
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();
    let local = Ipv6Addr::LOOPBACK;
    let remote = Ipv6Addr::from_segments([0x2001, 0xdb8, 3, 0, 0, 0, 0, 1]);
    let error = Arc::new(SocketError::new());
    bind_connected(&stack, iface, local, remote, error.clone());
    let invoking = quoted_udp(local, remote);
    let packet = packet_too_big(remote, local, PATH_MTU, &invoking);

    stack.deliver_rx_ipv6(iface, &packet).unwrap();

    assert_eq!(error.take(), syscall::errno::Errno::Emsgsize as i32);
    assert_eq!(stack.path_mtu(IpAddr::V6(remote), Some(iface), false), Ok(PATH_MTU));
    let oversized = alloc::vec![0u8; 1_233];
    assert_eq!(stack.send_udp6_pmtu_to_bound_opts(
        local, LOCAL_PORT, remote, REMOTE_PORT, &oversized, Some(iface),
        crate::ipv6::IPV6_DEFAULT_HOP_LIMIT, 0, crate::uapi::IPV6_PMTUDISC_DO,
    ), Err(crate::NetError::Emsgsize));
}

#[test]
fn udp6_pmtudisc_modes_select_cache_interface_and_fragmentation() {
    let stack = NetStack::new();
    let remote = Ipv6Addr::from_segments([0x2001, 0xdb8, 5, 0, 0, 0, 0, 1]);
    let dev = Arc::new(Pmtu6Dev {
        tx: AtomicUsize::new(0), fragments: AtomicUsize::new(0),
    });
    let iface = stack.ifaces.register(dev.clone());
    stack.update_pmtu_v6(iface, remote, 1_280);
    let cached_large = alloc::vec![0u8; 1_280];
    let interface_large = alloc::vec![0u8; 1_500];
    let send = |mode, payload: &[u8]| stack.send_udp6_pmtu_to_bound_opts(
        Ipv6Addr::LOOPBACK, LOCAL_PORT, remote, REMOTE_PORT, payload, Some(iface),
        crate::ipv6::IPV6_DEFAULT_HOP_LIMIT, 0, mode,
    );

    assert_eq!(send(crate::uapi::IPV6_PMTUDISC_DONT, &cached_large), Ok(()));
    assert_eq!((dev.tx.load(Ordering::Relaxed), dev.fragments.load(Ordering::Relaxed)), (2, 2));
    assert_eq!(send(crate::uapi::IPV6_PMTUDISC_WANT, &cached_large), Ok(()));
    assert_eq!((dev.tx.load(Ordering::Relaxed), dev.fragments.load(Ordering::Relaxed)), (4, 4));
    assert_eq!(send(crate::uapi::IPV6_PMTUDISC_DO, &cached_large), Err(crate::NetError::Emsgsize));
    assert_eq!(send(crate::uapi::IPV6_PMTUDISC_PROBE, &cached_large), Ok(()));
    assert_eq!(send(crate::uapi::IPV6_PMTUDISC_INTERFACE, &cached_large), Ok(()));
    assert_eq!(send(crate::uapi::IPV6_PMTUDISC_OMIT, &interface_large), Ok(()));
    assert_eq!((dev.tx.load(Ordering::Relaxed), dev.fragments.load(Ordering::Relaxed)), (8, 6));
    assert_eq!(send(crate::uapi::IPV6_PMTUDISC_PROBE, &interface_large), Err(crate::NetError::Emsgsize));
    assert_eq!(send(crate::uapi::IPV6_PMTUDISC_INTERFACE, &interface_large), Err(crate::NetError::Emsgsize));
}
