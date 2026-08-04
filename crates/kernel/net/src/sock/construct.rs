use alloc::sync::Arc;

use network_namespace::NetworkNamespaceRef;
use sync::Spinlock;

use super::{InetSocket, PacketRings, PacketRxQueue, PacketTxGate, SockKind, SockOpts,
            AF_INET, AF_INET6, AF_PACKET, AF_UNIX};
use crate::Ipv4Addr;

impl InetSocket {
    /// Derive the short-lived namespace table key. # C: O(1)
    pub fn net_ns(&self) -> u64 { self.owner.net_ns() }

    /// # C: O(1)
    pub fn new_udp() -> Self { Self::new_udp_in(crate::net_ns::current_namespace()) }

    /// Build an IPv4 datagram socket retaining an explicit owner. # C: O(1)
    pub fn new_udp_in(net_namespace: NetworkNamespaceRef) -> Self {
        Self::new_in(net_namespace, Arc::new(crate::bpf_filter::SocketFilter::new()),
            Arc::new(crate::SocketError::new()), SockKind::Udp)
    }

    fn new_in(net_namespace: NetworkNamespaceRef,
              bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
              error: Arc<crate::SocketError>, kind: SockKind) -> Self {
        Self::new_owned(crate::SocketOwner::current(net_namespace), bpf_filter, error, kind)
    }

    fn new_owned(owner: Arc<crate::SocketOwner>,
                 bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
                 error: Arc<crate::SocketError>, kind: SockKind) -> Self {
        // Linux seeds every socket from `wmem_default`/`rmem_default` and lets
        // the protocol replace them when it initialises, which is why a fresh
        // TCP socket reports a much smaller send buffer than a fresh datagram
        // or AF_UNIX one.
        let personality = match kind {
            SockKind::TcpInit | SockKind::TcpListener(_) | SockKind::TcpConn(_) =>
                crate::sysctl::BufPersonality::Tcp,
            _ => crate::sysctl::BufPersonality::Generic,
        };
        let (sndbuf, rcvbuf) = crate::sysctl::initial_bufs(&owner.net_namespace, personality);
        let sock = Self {
            family: core::sync::atomic::AtomicU16::new(AF_INET), local_port: Spinlock::new(None),
            local_ip: Spinlock::new(Ipv4Addr::ANY), peer: Arc::new(Spinlock::new(None)),
            udp4: Spinlock::new(None), udp6: Spinlock::new(None), tcp_bind: Spinlock::new(None),
            bpf_filter, reuseport_group: crate::reuseport::new_slot(),
            mcast: Arc::new(crate::mcast_filter::SocketMcast::new()), kind: Spinlock::new(kind),
            anycast: Arc::new(crate::sock_anycast::SocketAnycast::new()),
            packet_memberships: crate::sock::PacketMemberships::new(),
            packet_fanout: Spinlock::new(None),
            packet_rings: Spinlock::new(PacketRings::default()),
            packet_tx: PacketTxGate::new(),
            opts: SockOpts::default(), error,
            read_shut: core::sync::atomic::AtomicBool::new(false),
            write_shut: core::sync::atomic::AtomicBool::new(false),
            released: core::sync::atomic::AtomicBool::new(false),
            mcast_ops: crate::mcast_filter::SocketMcastGate::new(),
            #[cfg(target_os = "oxide-kernel")]
            recv_waiters: sched::live::WaitList::new(),
            #[cfg(target_os = "oxide-kernel")]
            connect_waiters: sched::live::WaitList::new(),
            poll_subs: Arc::new(vfs::PollSubscribers::new()),
            local_ip6: Spinlock::new(crate::Ipv6Addr([0; 16])), peer6: Arc::new(Spinlock::new(None)),
            peer6_scope: core::sync::atomic::AtomicU32::new(0),
            fastopen_deferred: Spinlock::new(None),
            owner,
            receive_timestamp_ns: core::sync::atomic::AtomicU64::new(crate::sock::SOCKET_TIMESTAMP_UNSET),
            receive_timestamp_enabled: core::sync::atomic::AtomicBool::new(false),
            unix_bound: Spinlock::new(None),
        };
        sock.opts.sndbuf.store(sndbuf, core::sync::atomic::Ordering::Release);
        sock.opts.rcvbuf.store(rcvbuf, core::sync::atomic::Ordering::Release);
        sock
    }

    /// # C: O(1)
    pub fn new_tcp() -> Self { Self::new_tcp_in(crate::net_ns::current_namespace()) }

    /// Build an IPv4 stream socket retaining an explicit owner. # C: O(1)
    pub fn new_tcp_in(net_namespace: NetworkNamespaceRef) -> Self {
        Self::new_tcp_with_state_in(Arc::new(crate::SocketError::new()),
            Arc::new(crate::bpf_filter::SocketFilter::new()), net_namespace)
    }

    /// Build a TCP socket around transport state allocated before accept. # C: O(1)
    pub fn new_tcp_with_error(error: Arc<crate::SocketError>) -> Self {
        Self::new_tcp_with_state_in(error, Arc::new(crate::bpf_filter::SocketFilter::new()),
            crate::net_ns::current_namespace())
    }

    /// Build a TCP socket sharing pre-existing transport state. # C: O(1)
    pub fn new_tcp_with_filter(error: Arc<crate::SocketError>,
                               bpf_filter: Arc<crate::bpf_filter::SocketFilter>) -> Self {
        Self::new_tcp_with_state_in(error, bpf_filter, crate::net_ns::current_namespace())
    }

    /// Build a TCP socket retaining an explicit namespace owner. # C: O(1)
    pub(super) fn new_tcp_with_state_in(error: Arc<crate::SocketError>,
                                        bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
                                        net_namespace: NetworkNamespaceRef) -> Self {
        Self::new_in(net_namespace, bpf_filter, error, SockKind::TcpInit)
    }

    /// Build a TCP socket sharing all transport-owned state after accept. # C: O(1)
    #[cfg(test)]
    pub(super) fn new_tcp_with_transport_state_in(error: Arc<crate::SocketError>,
                                        bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
                                        ip_mtu_discover: Arc<core::sync::atomic::AtomicI32>,
                                        ipv6_mtu_discover: Arc<core::sync::atomic::AtomicI32>,
                                        net_namespace: NetworkNamespaceRef) -> Self {
        let mut sock = Self::new_in(net_namespace, bpf_filter, error, SockKind::TcpInit);
        sock.opts.ip_mtu_discover = ip_mtu_discover;
        sock.opts.ipv6_mtu_discover = ipv6_mtu_discover;
        sock
    }

    fn new_tcp_with_transport_state_owned(error: Arc<crate::SocketError>,
                                        bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
                                        ip_mtu_discover: Arc<core::sync::atomic::AtomicI32>,
                                        ipv6_mtu_discover: Arc<core::sync::atomic::AtomicI32>,
                                        owner: Arc<crate::SocketOwner>) -> Self {
        let mut sock = Self::new_owned(owner, bpf_filter, error, SockKind::TcpInit);
        sock.opts.ip_mtu_discover = ip_mtu_discover;
        sock.opts.ipv6_mtu_discover = ipv6_mtu_discover;
        sock
    }

    /// `socket(AF_INET6, SOCK_DGRAM, ...)`. # C: O(1)
    pub fn new_udp6() -> Self { Self::new_udp6_in(crate::net_ns::current_namespace()) }
    /// Build an IPv6 datagram socket retaining an explicit owner. # C: O(1)
    pub fn new_udp6_in(net_namespace: NetworkNamespaceRef) -> Self {
        let s = Self::new_udp_in(net_namespace); s.family.store(AF_INET6, core::sync::atomic::Ordering::Release); s
    }
    /// `socket(AF_INET6, SOCK_STREAM, ...)`. # C: O(1)
    pub fn new_tcp6() -> Self { Self::new_tcp6_in(crate::net_ns::current_namespace()) }
    /// Build an IPv6 stream socket retaining an explicit owner. # C: O(1)
    pub fn new_tcp6_in(net_namespace: NetworkNamespaceRef) -> Self {
        let s = Self::new_tcp_in(net_namespace); s.family.store(AF_INET6, core::sync::atomic::Ordering::Release); s
    }
    /// `socket(AF_UNIX, SOCK_STREAM, ...)`. # C: O(1)
    pub fn new_unix() -> Self { Self::new_unix_in(crate::net_ns::current_namespace()) }
    /// Build a UNIX stream socket retaining an explicit owner. # C: O(1)
    pub fn new_unix_in(net_namespace: NetworkNamespaceRef) -> Self {
        let error = Arc::new(crate::SocketError::new());
        let filter = Arc::new(crate::bpf_filter::SocketFilter::new());
        let pair = crate::UnixPair::new();
        let end = crate::UnixEnd::B;
        let s = Self::new_in(net_namespace, filter, error.clone(), SockKind::UnixUnbound(pair.clone(), end));
        s.family.store(AF_UNIX, core::sync::atomic::Ordering::Release);
        pair.register_end_subs(end, &s.poll_subs);
        pair.attach_end_error(end, &error);
        s
    }

    fn new_unix_pair_end_with_filter_owned(owner: Arc<crate::SocketOwner>,
                                        pair: Arc<crate::UnixPair>, end: crate::UnixEnd,
                                        filter: Arc<crate::bpf_filter::SocketFilter>) -> Self {
        let error = pair.end_error(end);
        let s = Self::new_owned(owner, filter, error.clone(), SockKind::Unix(pair.clone(), end));
        s.family.store(AF_UNIX, core::sync::atomic::Ordering::Release);
        pair.register_end_subs(end, &s.poll_subs);
        pair.attach_end_error(end, &error);
        s
    }

    /// Build one already-connected AF_UNIX stream endpoint. # C: O(1)
    pub fn new_unix_pair_end_in(net_namespace: NetworkNamespaceRef,
                                pair: Arc<crate::UnixPair>, end: crate::UnixEnd) -> Self {
        Self::new_unix_pair_end_with_filter_owned(crate::SocketOwner::current(net_namespace), pair, end,
            Arc::new(crate::bpf_filter::SocketFilter::new()))
    }

    /// Build the server socket for one accepted TCP transport child. # C: O(1)
    pub(super) fn from_accepted_tcp(listener: &Self,
                                    entry: Arc<crate::stack::TcpEntry>) -> Arc<Self> {
        let sock = Arc::new(Self::new_tcp_with_transport_state_owned(
            entry.error.clone(), entry.bpf_filter.clone(), entry.ip_mtu_discover.clone(),
            entry.ipv6_mtu_discover.clone(), listener.owner.clone()));
        let family = listener.family.load(core::sync::atomic::Ordering::Acquire);
        sock.family.store(family, core::sync::atomic::Ordering::Release);
        entry.register_poll_subs(&sock.poll_subs);
        let bound_ifindex = entry.bound_iface().map(crate::NetIfaceId::raw).unwrap_or_default();
        {
            let conn = entry.conn.lock();
            *sock.local_port.lock() = Some(conn.local.port);
            match conn.local.ip {
                crate::IpAddr::V4(ip) => *sock.local_ip.lock() = ip,
                crate::IpAddr::V6(ip) => *sock.local_ip6.lock() = ip,
            }
            match conn.remote.ip {
                crate::IpAddr::V4(ip) => *sock.peer.lock() = Some((ip, conn.remote.port)),
                crate::IpAddr::V6(ip) => {
                    *sock.peer6.lock() = Some((ip, conn.remote.port));
                    sock.peer6_scope.store(bound_ifindex, core::sync::atomic::Ordering::Release);
                }
            }
        }
        sock.opts.bound_ifindex.store(bound_ifindex, core::sync::atomic::Ordering::Release);
        // Linux `sk_clone_lock` copies the listening `struct sock` wholesale,
        // so an accepted child starts with the listener's buffer sizing and
        // its `sk_userlocks` — which is why `setsockopt(SO_RCVBUF)` on a
        // listener is the documented way to size every future connection's
        // receive window (the window is negotiated during the handshake, so
        // setting it on the accepted fd is already too late).
        super::tcp_rcvbuf::inherit_buffer_opts(listener, &sock);
        super::tcp_rcvbuf::apply_tcp_rcvbuf_opt(&sock, &entry);
        *sock.kind.lock() = SockKind::TcpConn(entry);
        sock
    }

    /// Build the server socket for one accepted UNIX stream child. # C: O(1)
    pub(super) fn from_accepted_unix(listener: &Self,
                                     pair: Arc<crate::UnixPair>) -> Arc<Self> {
        Arc::new(Self::new_unix_pair_end_with_filter_owned(listener.owner.clone(), pair,
            crate::UnixEnd::A,
            Arc::new(crate::bpf_filter::SocketFilter::inherited(&listener.bpf_filter))))
    }

    /// `socket(AF_UNIX, SOCK_DGRAM, ...)`. # C: O(1)
    pub fn new_unix_dgram() -> Self {
        Self::new_unix_dgram_in(crate::net_ns::current_namespace())
    }
    /// Build a UNIX datagram socket retaining an explicit owner. # C: O(1)
    pub fn new_unix_dgram_in(net_namespace: NetworkNamespaceRef) -> Self {
        let error = Arc::new(crate::SocketError::new());
        let filter = Arc::new(crate::bpf_filter::SocketFilter::new());
        let q = crate::UnixDgramQueue::new_with_filter(filter.clone());
        let s = Self::new_in(net_namespace, filter, error, SockKind::UnixDgram(q.clone()));
        s.family.store(AF_UNIX, core::sync::atomic::Ordering::Release);
        q.register_subs(&s.poll_subs);
        s
    }

    /// `socket(AF_PACKET, type, protocol)`. # C: O(1)
    pub fn new_packet(proto: u16, sock_type: u8) -> Self {
        Self::new_packet_in(proto, sock_type, crate::net_ns::current_namespace())
    }
    /// Build a packet socket retaining an explicit owner. # C: O(1)
    pub fn new_packet_in(proto: u16, sock_type: u8, net_namespace: NetworkNamespaceRef) -> Self {
        let s = Self::new_tcp_in(net_namespace); s.family.store(AF_PACKET, core::sync::atomic::Ordering::Release);
        // A packet socket is not TCP: it keeps the generic buffer defaults.
        let (sndbuf, rcvbuf) = crate::sysctl::initial_bufs(&s.owner.net_namespace,
            crate::sysctl::BufPersonality::Generic);
        s.opts.sndbuf.store(sndbuf, core::sync::atomic::Ordering::Release);
        s.opts.rcvbuf.store(rcvbuf, core::sync::atomic::Ordering::Release);
        *s.kind.lock() = SockKind::Packet {
            ifindex: core::sync::atomic::AtomicU32::new(0),
            protocol: core::sync::atomic::AtomicU16::new(proto),
            sock_type: core::sync::atomic::AtomicU8::new(sock_type),
            options: super::packet_options::PacketOptions::default(),
            rx: Spinlock::new(PacketRxQueue::default()),
        };
        s
    }
}

impl Default for InetSocket { fn default() -> Self { Self::new_udp() } }

#[cfg(test)]
mod tests {
    use super::*;
    use ::core::sync::atomic::{AtomicI32, Ordering};

    #[test]
    fn accepted_tcp_socket_shares_both_transport_pmtu_modes() {
        let ip_pmtu = Arc::new(AtomicI32::new(crate::uapi::IP_PMTUDISC_WANT));
        let ipv6_pmtu = Arc::new(AtomicI32::new(crate::uapi::IPV6_PMTUDISC_WANT));
        let sock = InetSocket::new_tcp_with_transport_state_in(
            Arc::new(crate::SocketError::new()),
            Arc::new(crate::bpf_filter::SocketFilter::new()), ip_pmtu.clone(),
            ipv6_pmtu.clone(),
            crate::net_ns::current_namespace());
        assert!(Arc::ptr_eq(&sock.opts.ip_mtu_discover, &ip_pmtu));
        assert!(Arc::ptr_eq(&sock.opts.ipv6_mtu_discover, &ipv6_pmtu));
        ip_pmtu.store(crate::uapi::IP_PMTUDISC_PROBE, Ordering::Release);
        ipv6_pmtu.store(crate::uapi::IPV6_PMTUDISC_OMIT, Ordering::Release);
        assert_eq!(sock.opts.ip_mtu_discover.load(Ordering::Acquire),
            crate::uapi::IP_PMTUDISC_PROBE);
        assert_eq!(sock.opts.ipv6_mtu_discover.load(Ordering::Acquire),
            crate::uapi::IPV6_PMTUDISC_OMIT);
    }

    #[test]
    fn accepted_tcp_socket_inherits_listener_owner() {
        let listener = InetSocket::new_tcp();
        let local = crate::Endpoint {
            ip: crate::IpAddr::V4(crate::Ipv4Addr::LOOPBACK), port: 41000,
        };
        let remote = crate::Endpoint {
            ip: crate::IpAddr::V4(crate::Ipv4Addr::new(192, 0, 2, 1)), port: 443,
        };
        let bind = Arc::new(crate::stack::TcpBindReservation::new_owned(
            listener.owner.clone(), local, None, false, false, false));
        let entry = Arc::new(crate::stack::TcpEntry::new_bound_with_error(
            crate::TcpConn::new_client(local, remote, 1), listener.error.clone(), Some(bind)));
        let child = InetSocket::from_accepted_tcp(&listener, entry);
        assert!(Arc::ptr_eq(&child.owner, &listener.owner));
    }

    /// One accepted child, with the header fields the passive open recorded.
    fn accepted_with_header(iif: u32, ttl: u8, tos: u8) -> Arc<InetSocket> {
        let listener = InetSocket::new_tcp();
        let local = crate::Endpoint {
            ip: crate::IpAddr::V4(crate::Ipv4Addr::LOOPBACK), port: 41001,
        };
        let remote = crate::Endpoint {
            ip: crate::IpAddr::V4(crate::Ipv4Addr::new(192, 0, 2, 1)), port: 443,
        };
        let mut conn = crate::TcpConn::new_client(local, remote, 1);
        conn.rcv_iif = iif;
        conn.rcv_ttl = ttl;
        conn.rcv_tos = tos;
        let entry = Arc::new(crate::stack::TcpEntry::new_bound_with_error(
            conn, listener.error.clone(), None));
        let child = InetSocket::from_accepted_tcp(&listener, entry.clone());
        crate::sock_opts::record_accepted_header(&child, &entry);
        child
    }

    #[test]
    fn an_accepted_socket_records_what_the_opening_header_carried() {
        let child = accepted_with_header(9, 57, 0x2c);
        assert_eq!(child.opts.ip_mcast_ifindex.load(Ordering::Acquire), 9);
        assert_eq!(child.opts.ip_mcast_ttl.load(Ordering::Acquire), 57);
        assert_eq!(child.opts.ip_rcv_tos.load(Ordering::Acquire), 0x2c);
    }

    #[test]
    fn a_child_opened_by_no_ipv4_header_keeps_the_multicast_defaults() {
        // An IPv6 passive open records no interface, and must not overwrite
        // the multicast hop limit a socket starts life with.
        let child = accepted_with_header(0, 0, 0);
        assert_eq!(child.opts.ip_mcast_ttl.load(Ordering::Acquire), 1);
        assert_eq!(child.opts.ip_rcv_tos.load(Ordering::Acquire), 0);
    }
}
