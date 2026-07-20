use super::*;
use crate::UdpRxQueue;

/// Per-AF_INET-socket variant.
pub enum SockKind {
    Raw4(Arc<crate::raw4::Raw4Endpoint>),
    Raw6(Arc<crate::raw6::Raw6Endpoint>),
    /// SOCK_DGRAM — bound port managed via NetStack's UDP map.
    Udp,
    /// SOCK_STREAM after `socket()` but before `listen()`/`connect()`/
    /// `accept()`. Discriminates a fresh TCP socket from a fresh UDP
    /// one so `connect()` routes through `tcp_connect` instead of the
    /// UDP "store peer + Ok" short-circuit at line ~572.
    TcpInit,
    /// SOCK_STREAM, after `listen()`. Holds the listener handle.
    TcpListener(Arc<TcpListenEntry>),
    /// SOCK_STREAM, after `connect()` or `accept()`.
    TcpConn(Arc<TcpEntry>),
    /// AF_UNIX SOCK_STREAM — both ends share an `UnixPair`; the
    /// `UnixEnd` tags this fd as the A or B side.
    Unix(Arc<crate::UnixPair>, crate::UnixEnd),
    /// AF_UNIX path-bound listener. `accept` pops a queued pair.
    UnixListener(Arc<crate::UnixListener>),
    /// AF_UNIX SOCK_DGRAM (F120 / `24§R01`). Per-socket message
    /// queue; sendto/recvfrom push/pop here. Real per-message SCM
    /// metadata (sender creds, fd array) rides F121.
    UnixDgram(Arc<crate::UnixDgramQueue>),
    /// AF_UNIX SOCK_SEQPACKET / SOCK_DGRAM on a socketpair —
    /// bidirectional msg-boundary-preserving pair. F125.
    UnixMsgPair(Arc<crate::UnixMsgPair>, crate::UnixEnd),
    /// F131: AF_PACKET / PF_PACKET SOCK_RAW. dhcpcd uses this to
    /// send the DHCPDISCOVER L2 frame before it has an IPv4 address.
    /// `ifindex == 0` means unbound. Receive accepts every interface
    /// in the captured namespace; send requires a destination interface.
    Packet {
        ifindex:  core::sync::atomic::AtomicU32,
        protocol: core::sync::atomic::AtomicU16,
        /// F146: sock_type — SOCK_RAW (3) caller sends full L2 frame
        /// (xmit_raw); SOCK_DGRAM (2) caller sends L3 payload and the
        /// kernel prepends the ethernet header using sll_addr from
        /// sendto's destination sockaddr_ll. A SOCK_DGRAM DHCP client
        /// uses this path; dhcpcd 10.3.2 opens SOCK_RAW.
        sock_type: core::sync::atomic::AtomicU8,
        options: PacketOptions,
        /// Pending RX frames.
        rx: sync::Spinlock<PacketRxQueue, SockLockClass>,
    },
}

/// Process-global AF_UNIX path registry.
pub static UNIX_REGISTRY: crate::UnixRegistry = crate::UnixRegistry::new();

/// AF_INET/AF_INET6 socket VFS state.
pub struct InetSocket {
    pub family:     core::sync::atomic::AtomicU16,
    pub local_port: Spinlock<Option<u16>, SockLockClass>,
    pub local_ip:   Spinlock<Ipv4Addr, SockLockClass>,
    pub peer:       Arc<Spinlock<Option<(Ipv4Addr, u16)>, SockLockClass>>,
    /// Exact socket-owned UDP endpoints; registry lookup never identifies ownership.
    pub udp4:       Spinlock<Option<Arc<UdpRxQueue>>, SockLockClass>,
    pub udp6:       Spinlock<Option<Arc<crate::stack_ipv6::Udp6RxQueue>>, SockLockClass>,
    /// Exact socket-owned TCP local reservation, retained across state transitions.
    pub tcp_bind:   Spinlock<Option<Arc<crate::stack::TcpBindReservation>>, SockLockClass>,
    /// Socket-owned filter exists before bind and is shared with its endpoint.
    pub bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
    pub mcast: Arc<crate::mcast_filter::SocketMcast>,
    pub(crate) packet_memberships: crate::sock::PacketMemberships,
    pub(crate) packet_fanout: Spinlock<Option<Arc<PacketFanoutMember>>, SockLockClass>,
    pub(crate) packet_rings: Spinlock<PacketRings, SockLockClass>,
    pub(crate) packet_tx: PacketTxGate,
    pub kind:       Spinlock<SockKind, SockLockClass>,
    pub opts: SockOpts,
    /// Canonical Linux `sk_err`, shared with the active transport owner.
    pub error: Arc<crate::SocketError>,
    /// F166: SHUT_RD/RDWR latch — subsequent read returns Ok(0).
    pub read_shut: core::sync::atomic::AtomicBool,
    /// Generic send-half shutdown for connected datagram/TCP sockets.
    pub write_shut: core::sync::atomic::AtomicBool,
    /// Final open-file-description release has run.
    pub released: core::sync::atomic::AtomicBool,
    /// Multicast mutation admission: high bit closes, low bits count active calls.
    pub(crate) mcast_ops: crate::mcast_filter::SocketMcastGate,
    /// F180a: AF_INET6 address slots; IPv4 uses local_ip / peer.
    pub local_ip6: Spinlock<crate::Ipv6Addr, SockLockClass>,
    pub peer6:     Arc<Spinlock<Option<(crate::Ipv6Addr, u16)>, SockLockClass>>,
    pub peer6_scope: core::sync::atomic::AtomicU32,
    #[cfg(target_os = "oxide-kernel")]
    pub recv_waiters: sched::live::WaitList,
    /// Calls waiting to connect this socket, independent of target listener.
    #[cfg(target_os = "oxide-kernel")]
    pub connect_waiters: sched::live::WaitList,
    /// F181: per-fd epoll subscribers.
    pub poll_subs: Arc<vfs::PollSubscribers>,
    /// Concrete network namespace owner snapshotted at socket creation.
    /// Numeric IDs are derived only while accessing namespace-keyed tables.
    pub net_namespace: network_namespace::NetworkNamespaceRef,
    /// Effective UID captured when Linux creates the socket.
    pub owner_uid: u32,
    /// Linux `sk_stamp`: timestamp of the most recently delivered receive
    /// record. `SOCKET_TIMESTAMP_UNSET` is the in-kernel representation of Linux's unset
    /// `SK_DEFAULT_STAMP` and is never exposed to userspace.
    pub receive_timestamp_ns: core::sync::atomic::AtomicU64,
    /// Linux `SOCK_TIMESTAMP`: set by `SIOCGSTAMP*` so subsequent receive
    /// handoffs retain their actual timestamp.
    pub receive_timestamp_enabled: core::sync::atomic::AtomicBool,
    /// AF_UNIX stream address reserved by `bind(2)`, independent of whether
    /// this socket later listens or actively connects.
    pub unix_bound: Spinlock<Option<Arc<crate::UnixListener>>, SockLockClass>,
}

impl InetSocket {
    /// Record the realtime timestamp attached to one delivered receive record.
    /// # C: O(1)
    pub fn note_receive_timestamp(&self, timestamp_ns: u64) {
        use core::sync::atomic::Ordering;
        if self.receive_timestamp_enabled.load(Ordering::Acquire) {
            self.receive_timestamp_ns.store(timestamp_ns, Ordering::Release);
        } else {
            let _ = self.receive_timestamp_ns.compare_exchange(SOCKET_TIMESTAMP_UNSET, 0,
                Ordering::AcqRel, Ordering::Acquire);
        }
    }

    /// Record a receive handoff using the kernel's canonical realtime clock.
    /// # C: O(1)
    pub fn note_receive_now(&self) {
        self.note_receive_timestamp(vfs::inode_times::realtime_now_ns());
    }

    /// Return Linux `sk_stamp`, if this socket has delivered a receive record.
    /// # C: O(1)
    pub fn receive_timestamp(&self) -> Option<u64> {
        let timestamp_ns = self.receive_timestamp_ns.load(core::sync::atomic::Ordering::Acquire);
        (timestamp_ns != SOCKET_TIMESTAMP_UNSET).then_some(timestamp_ns)
    }

    /// Enable Linux `SOCK_TIMESTAMP` and read the resulting receive stamp.
    /// A pre-enable receive has Linux's zero marker, which is promoted to the
    /// query-time realtime value by `sock_gettstamp`. # C: O(1)
    pub fn enable_receive_timestamp(&self) -> Option<u64> {
        use core::sync::atomic::Ordering;
        self.receive_timestamp_enabled.store(true, Ordering::Release);
        let stamp = self.receive_timestamp_ns.load(Ordering::Acquire);
        if stamp == 0 {
            let now = vfs::inode_times::realtime_now_ns();
            let _ = self.receive_timestamp_ns.compare_exchange(0, now, Ordering::AcqRel,
                Ordering::Acquire);
        }
        self.receive_timestamp()
    }
}

/// SOL_SOCKET options — Linux `int`-shaped cells. SO_LINGER pair.
pub struct SockOpts {
    pub reuseaddr: Arc<core::sync::atomic::AtomicI32>,
    pub reuseport: Arc<core::sync::atomic::AtomicI32>,
    pub keepalive: core::sync::atomic::AtomicI32,
    pub broadcast: core::sync::atomic::AtomicI32,
    pub oobinline: core::sync::atomic::AtomicI32,
    /// F164: SO_SNDBUF (bytes); enforced by tcp_send → backpressure.
    pub sndbuf:    core::sync::atomic::AtomicI32,
    pub rcvbuf:    core::sync::atomic::AtomicI32,
    pub sndtimeo_ns: core::sync::atomic::AtomicI64,
    pub rcvtimeo_ns: core::sync::atomic::AtomicI64,
    pub linger_on: core::sync::atomic::AtomicI32,
    pub linger_s:  core::sync::atomic::AtomicI32,
    pub priority:  core::sync::atomic::AtomicI32,
    pub mark:      core::sync::atomic::AtomicI32,
    pub ip_ttl:    core::sync::atomic::AtomicI32,
    pub ip_tos:    core::sync::atomic::AtomicI32,
    pub ip_pktinfo: core::sync::atomic::AtomicI32, pub ip_mcast_ttl: core::sync::atomic::AtomicI32, pub ip_mcast_loop: core::sync::atomic::AtomicI32, pub ip_mcast_ifaddr: core::sync::atomic::AtomicU32, pub ip_mcast_ifindex: core::sync::atomic::AtomicU32,
    /// IP_RECVTTL: deliver the received IPv4 header TTL as an IP_TTL cmsg on
    /// recvmsg (systemd-resolved LLMNR/mDNS hop check). IP_MTU_DISCOVER is
    /// shared with the bound UDP endpoint because ICMP owns PMTU error input.
    pub ip_recvttl: core::sync::atomic::AtomicI32,
    pub ip_mtu_discover: Arc<core::sync::atomic::AtomicI32>,
    pub ipv6_v6only: Arc<core::sync::atomic::AtomicI32>,
    /// Canonical `IPV6_MTU_DISCOVER` mode used by IPv6 transmit policy.
    pub ipv6_mtu_discover: Arc<core::sync::atomic::AtomicI32>,
    /// IPV6_UNICAST_HOPS / IPV6_MULTICAST_HOPS: outbound hop limit for
    /// unicast / multicast IPv6 datagrams. Linux sentinel `-1` = derive the
    /// per-route/interface default (64 unicast, 1 multicast); an explicit
    /// `0..=255` overrides. avahi sets both to 255 (mDNS RFC 6762 §11).
    pub ipv6_ucast_hops: core::sync::atomic::AtomicI32,
    pub ipv6_mcast_hops: core::sync::atomic::AtomicI32,
    /// IPV6_MULTICAST_LOOP: loop multicast TX back to local members (default 1).
    pub ipv6_mcast_loop: core::sync::atomic::AtomicI32,
    /// IPV6_MULTICAST_IF: outbound multicast interface index (0 = unset).
    pub ipv6_mcast_ifindex: core::sync::atomic::AtomicU32,
    /// IPV6_RECVPKTINFO: deliver IPV6_PKTINFO ancillary (dst addr + ifindex)
    /// on recvmsg. IPV6_RECVHOPLIMIT: deliver IPV6_HOPLIMIT ancillary (the
    /// received hop limit; avahi enforces == 255 for on-link mDNS).
    pub ipv6_recvpktinfo: core::sync::atomic::AtomicI32,
    pub ipv6_recvhoplimit: core::sync::atomic::AtomicI32,
    /// SO_BINDTODEVICE: 0 means no bound egress/ingress interface.
    pub bound_ifindex: core::sync::atomic::AtomicU32,
    pub tcp_nodelay: core::sync::atomic::AtomicI32,
    pub tcp_cork: core::sync::atomic::AtomicI32,
    pub tcp_keepidle_s: core::sync::atomic::AtomicI32,
    pub tcp_keepintvl_s: core::sync::atomic::AtomicI32,
    pub tcp_keepcnt: core::sync::atomic::AtomicI32,
    pub passcred: core::sync::atomic::AtomicI32,
    pub timestamping: core::sync::atomic::AtomicI32,
    /// SO_TYPE override (Linux `sock->type`) for AF_UNIX sockets whose
    /// `SockKind` doesn't itself encode the requested shape — chiefly a
    /// `SOCK_SEQPACKET` listener, which is byte-ring-backed internally but
    /// MUST report SOCK_SEQPACKET so `sd_is_socket()` socket-activation
    /// checks (systemd-udevd control socket) pass. `0` = derive from kind.
    pub so_type: core::sync::atomic::AtomicU8,
}

pub const TCP_SNDBUF_DEFAULT: i32 = 16384; pub const TCP_RCVBUF_DEFAULT: i32 = 16384;
#[cfg(target_os = "oxide-kernel")]
pub use crate::sock_io::compute_deadline_ns;

impl Default for SockOpts {
    fn default() -> Self {
        use core::sync::atomic::*;
        Self {
            reuseaddr:   Arc::new(AtomicI32::new(0)),
            reuseport:   Arc::new(AtomicI32::new(0)),
            keepalive:   AtomicI32::new(0),
            broadcast:   AtomicI32::new(0),
            oobinline:   AtomicI32::new(0),
            sndbuf:      AtomicI32::new(TCP_SNDBUF_DEFAULT),
            rcvbuf:      AtomicI32::new(TCP_RCVBUF_DEFAULT),
            sndtimeo_ns: AtomicI64::new(0),
            rcvtimeo_ns: AtomicI64::new(0),
            linger_on:   AtomicI32::new(0),
            linger_s:    AtomicI32::new(0),
            priority:    AtomicI32::new(0),
            mark:        AtomicI32::new(0),
            ip_ttl:      AtomicI32::new(crate::ipv4::IPV4_DEFAULT_TTL as i32),
            ip_tos:      AtomicI32::new(0),
            ip_pktinfo:  AtomicI32::new(0), ip_mcast_ttl: AtomicI32::new(1), ip_mcast_loop: AtomicI32::new(1), ip_mcast_ifaddr: AtomicU32::new(0), ip_mcast_ifindex: AtomicU32::new(0),
            ip_recvttl: AtomicI32::new(0),
            ip_mtu_discover: Arc::new(AtomicI32::new(crate::uapi::IP_PMTUDISC_WANT)),
            ipv6_v6only: Arc::new(AtomicI32::new(0)),
            ipv6_mtu_discover: Arc::new(AtomicI32::new(crate::uapi::IPV6_PMTUDISC_WANT)),
            ipv6_ucast_hops: AtomicI32::new(-1),
            ipv6_mcast_hops: AtomicI32::new(-1),
            ipv6_mcast_loop: AtomicI32::new(1),
            ipv6_mcast_ifindex: AtomicU32::new(0),
            ipv6_recvpktinfo: AtomicI32::new(0),
            ipv6_recvhoplimit: AtomicI32::new(0),
            bound_ifindex: AtomicU32::new(0),
            tcp_nodelay: AtomicI32::new(0),
            tcp_cork:    AtomicI32::new(0),
            tcp_keepidle_s: AtomicI32::new(crate::sock_opts::TCP_KEEPIDLE_DEFAULT_S),
            tcp_keepintvl_s: AtomicI32::new(crate::sock_opts::TCP_KEEPINTVL_DEFAULT_S),
            tcp_keepcnt:    AtomicI32::new(crate::sock_opts::TCP_KEEPCNT_DEFAULT),
            passcred: AtomicI32::new(0),
            timestamping: AtomicI32::new(0),
            so_type: AtomicU8::new(0),
        }
    }
}

pub use crate::socket_args::{AF_INET6_SOCK_WIRE as AF_INET6, AF_INET_SOCK_WIRE as AF_INET,
    AF_PACKET_SOCK_WIRE as AF_PACKET, AF_UNIX_SOCK_WIRE as AF_UNIX};
pub const AF_VSOCK: u16 = crate::socket_args::AF_VSOCK as u16;
/// Internal representation of Linux's unset `SK_DEFAULT_STAMP`.
pub const SOCKET_TIMESTAMP_UNSET: u64 = u64::MAX;
