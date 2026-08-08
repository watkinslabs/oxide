// Module manifest
//   pmtu — `IP_PMTUDISC_*` modes and the FRAG_NEEDED route-cache update.
// The ICMP error-report tests and the shared UDP/ICMP fixture stay here.
mod pmtu;

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

fn rfc4884_quote() -> alloc::vec::Vec<u8> {
    let mut out = quote();
    out.resize(8 + 128 + 4, 0);
    out[5] = 32;
    out[8 + 128] = 0x20;
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
fn recverr_rfc4884_controls_the_queued_extension_offset() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();
    let error = Arc::new(SocketError::new());
    error.set_recverr4(true);
    bind(&stack, error.clone(), false, crate::uapi::IP_PMTUDISC_WANT);

    crate::stack_icmp::handle_error(&stack, iface, REMOTE,
        crate::icmp::ICMP_TYPE_DEST_UNREACH, 3, &rfc4884_quote());
    assert_eq!(error.take_extended().unwrap().data, 0);

    error.set_recverr_rfc4884_4(true);
    crate::stack_icmp::handle_error(&stack, iface, REMOTE,
        crate::icmp::ICMP_TYPE_DEST_UNREACH, 3, &rfc4884_quote());
    assert_eq!(error.take_extended().unwrap().data,
        u32::from_ne_bytes([100, 0, 0, 0]));
}

#[test]
fn recverr_rfc4884_marks_a_malformed_extension_invalid() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, _) = stack.register_loopback();
    let error = Arc::new(SocketError::new());
    error.set_recverr4(true);
    error.set_recverr_rfc4884_4(true);
    bind(&stack, error.clone(), false, crate::uapi::IP_PMTUDISC_WANT);
    let mut quoted = rfc4884_quote();
    quoted.resize(8 + 128 + 8, 0);
    quoted[8 + 132..8 + 134].copy_from_slice(&3u16.to_be_bytes());

    crate::stack_icmp::handle_error(&stack, iface, REMOTE,
        crate::icmp::ICMP_TYPE_DEST_UNREACH, 3, &quoted);
    assert_eq!(error.take_extended().unwrap().data,
        u32::from_ne_bytes([100, 0, 1, 0]));
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
