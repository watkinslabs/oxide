use super::*;
use crate::UdpRxQueue;

/// Per-AF_INET-socket variant.
pub enum SockKind {
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
        /// Pending RX frames.
        rx: sync::Spinlock<alloc::collections::VecDeque<PacketFrame>, SockLockClass>,
    },
}

#[derive(Clone)]
pub struct PacketFrame {
    pub payload: alloc::vec::Vec<u8>,
    pub addr: crate::sock_io::PacketAddr,
}

/// Process-global AF_UNIX path registry.
pub static UNIX_REGISTRY: crate::UnixRegistry = crate::UnixRegistry::new();

/// F137: AF_PACKET registry — Weak<InetSocket>; GC on next pass.
pub static PACKET_REGISTRY: Spinlock<Vec<alloc::sync::Weak<InetSocket>>, SockLockClass>
    = Spinlock::new(Vec::new());

/// Add to AF_PACKET registry. Idempotent. # C: O(N).
pub fn register_packet(sock: &Arc<InetSocket>) {
    let mut g = PACKET_REGISTRY.lock();
    g.retain(|w| w.upgrade().is_some());
    if g.iter().filter_map(alloc::sync::Weak::upgrade).any(|s| Arc::ptr_eq(&s, sock)) {
        return;
    }
    g.push(Arc::downgrade(sock));
}

/// Deliver L2 frame to AF_PACKET socks on `iface` (0=any). Filters by
/// proto (ETH_P_ALL or ethertype). 64 frames/sock cap. # C: O(N socks).
pub fn deliver_packet_rx(iface: NetIfaceId, frame: &[u8]) {
    use core::sync::atomic::Ordering;
    if frame.len() < 14 { return; }
    let et = ((frame[12] as u16) << 8) | (frame[13] as u16);
    let Some(net_ns) = crate::sock::stack().ifaces.namespace(iface) else { return };
    let hatype = crate::sock::stack().ifaces.lookup_in_ns(iface, net_ns)
        .map_or(0, |dev| if dev.name() == "lo" { 772 } else { 1 });
    // F172: collect socks; wake outside PACKET_REGISTRY lock to
    // avoid nesting wake_all's runqueue inner lock under it.
    let mut woken: Vec<Arc<InetSocket>> = Vec::new();
    let sockets = {
        let mut registry = PACKET_REGISTRY.lock();
        registry.retain(|weak| weak.upgrade().is_some());
        registry.iter().filter_map(alloc::sync::Weak::upgrade).collect::<Vec<_>>()
    };
    for sock in sockets {
        if sock.net_ns.load(Ordering::Acquire) != net_ns { continue; }
        let k = sock.kind.lock();
        if let SockKind::Packet { ifindex, protocol, sock_type, rx } = &*k {
            let want_if = ifindex.load(Ordering::Acquire);
            if want_if != 0 && want_if != iface.raw() { continue; }
            let p = protocol.load(Ordering::Acquire);
            if p != 0x0003 && p != et { continue; }
            const SOCK_DGRAM: u8 = 2;
            let stype = sock_type.load(Ordering::Acquire);
            let packet = if stype == SOCK_DGRAM { &frame[14..] } else { frame };
            let verdict = sock.bpf_filter.verdict_with_context(crate::bpf_filter::FilterContext {
                packet, protocol: et, ifindex: Some(iface.raw()),
                pay_offset: packet_payload_offset(packet, stype != SOCK_DGRAM),
                hatype,
            });
            if verdict == 0 { continue; }
            let keep = packet.len().min(verdict as usize);
            let mut addr = [0u8; 8];
            addr[..6].copy_from_slice(&frame[6..12]);
            let pkttype = if frame[..6] == [0xff; 6] {
                1
            } else if frame[0] & 1 != 0 {
                2
            } else {
                0
            };
            let queued = PacketFrame {
                payload: packet[..keep].to_vec(),
                addr: crate::sock_io::PacketAddr {
                    ifindex: iface.raw(), protocol: et, hatype, pkttype, halen: 6, addr,
                },
            };
            let mut q = rx.lock();
            if q.len() < 64 {
                q.push_back(queued);
                drop(q);
                drop(k);
                woken.push(sock);
            }
        }
    }
    if !woken.is_empty() {
        for s in &woken {
            s.recv_waiters.wake_all();
            // F181: targeted epoll wake — only the epolls that
            // `epoll_ctl(ADD)`d this AF_PACKET fd, not every epoll
            // on the box. Falls back to no-op (returns immediately)
            // when this socket has no subscribers.
            s.poll_subs.notify();
        }
    }
}

fn packet_payload_offset(packet: &[u8], has_ethernet: bool) -> u32 {
    let network = if has_ethernet { 14 } else { 0 };
    let Some(version) = packet.get(network).map(|b| b >> 4) else { return network as u32 };
    match version {
        4 => {
            let ihl = packet.get(network).map_or(20, |b| ((b & 0x0f) as usize * 4).max(20));
            let proto = packet.get(network + 9).copied().unwrap_or(0);
            let transport = network + ihl;
            match proto {
                6 => transport + packet.get(transport + 12)
                    .map_or(20, |b| ((b >> 4) as usize * 4).max(20)),
                17 => transport + 8,
                _ => transport,
            }
        }
        6 => {
            let transport = network + 40;
            match packet.get(network + 6).copied().unwrap_or(0) {
                6 => transport + packet.get(transport + 12)
                    .map_or(20, |b| ((b >> 4) as usize * 4).max(20)),
                17 => transport + 8,
                _ => transport,
            }
        }
        _ => network,
    }.min(packet.len()) as u32
}

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
    /// B518: net_ns id this socket bound its AF_UNIX path in (0 = the
    /// global registry). Captured at bind so Drop unbinds from the SAME
    /// per-ns registry regardless of the closing task's ns. Untouched
    /// (0) for every non-AF_UNIX-bound socket → global semantics.
    pub unix_ns: core::sync::atomic::AtomicU64,
    /// Network namespace that owned this socket at creation. Unlike
    /// `unix_ns`, pathname AF_UNIX rendezvous never rewrites this value.
    pub net_ns: core::sync::atomic::AtomicU64,
    /// Effective UID captured when Linux creates the socket.
    pub owner_uid: u32,
    /// AF_UNIX stream address reserved by `bind(2)`, independent of whether
    /// this socket later listens or actively connects.
    pub unix_bound: Spinlock<Option<Arc<crate::UnixListener>>, SockLockClass>,
}

/// SOL_SOCKET options — Linux `int`-shaped cells. SO_LINGER pair.
pub struct SockOpts {
    pub reuseaddr: Arc<core::sync::atomic::AtomicI32>,
    pub reuseport: Arc<core::sync::atomic::AtomicI32>,
    pub keepalive: core::sync::atomic::AtomicI32,
    pub broadcast: core::sync::atomic::AtomicI32,
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
pub use crate::sock_io::compute_deadline_ns;

impl Default for SockOpts {
    fn default() -> Self {
        use core::sync::atomic::*;
        Self {
            reuseaddr:   Arc::new(AtomicI32::new(0)),
            reuseport:   Arc::new(AtomicI32::new(0)),
            keepalive:   AtomicI32::new(0),
            broadcast:   AtomicI32::new(0),
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

pub const AF_INET:  u16 = 2;
pub const AF_INET6: u16 = 10;
pub const AF_UNIX:  u16 = 1;
pub const AF_PACKET: u16 = 17;

#[cfg(target_os = "oxide-kernel")]
fn current_socket_uid() -> u32 {
    sched::live::current().map(|task| {
        task.creds.euid.load(core::sync::atomic::Ordering::Acquire)
    }).unwrap_or(0)
}

#[cfg(not(target_os = "oxide-kernel"))]
fn current_socket_uid() -> u32 { 0 }

impl InetSocket {
    /// # C: O(1)
    pub fn new_udp() -> Self {
        let _s = Self {
            family:     core::sync::atomic::AtomicU16::new(AF_INET),
            local_port: Spinlock::new(None),
            local_ip:   Spinlock::new(Ipv4Addr::ANY),
            peer:       Arc::new(Spinlock::new(None)),
            udp4:       Spinlock::new(None),
            udp6:       Spinlock::new(None),
            tcp_bind:   Spinlock::new(None),
            bpf_filter: Arc::new(crate::bpf_filter::SocketFilter::new()),
            mcast: Arc::new(crate::mcast_filter::SocketMcast::new()),
            kind:       Spinlock::new(SockKind::Udp),
            opts:       SockOpts::default(),
            error: Arc::new(crate::SocketError::new()),
            read_shut:  core::sync::atomic::AtomicBool::new(false),
            write_shut: core::sync::atomic::AtomicBool::new(false),
            released:   core::sync::atomic::AtomicBool::new(false),
            #[cfg(target_os = "oxide-kernel")]
            recv_waiters: sched::live::WaitList::new(),
            #[cfg(target_os = "oxide-kernel")]
            connect_waiters: sched::live::WaitList::new(),
            poll_subs:    Arc::new(vfs::PollSubscribers::new()),
            local_ip6: Spinlock::new(crate::Ipv6Addr([0; 16])),
            peer6:     Arc::new(Spinlock::new(None)),
            peer6_scope: core::sync::atomic::AtomicU32::new(0),
            unix_ns:   core::sync::atomic::AtomicU64::new(0),
            net_ns:    core::sync::atomic::AtomicU64::new(crate::netdev::current_net_ns()),
            owner_uid: current_socket_uid(),
            unix_bound: Spinlock::new(None),
        };
        _s
    }
    /// # C: O(1)
    pub fn new_tcp() -> Self { Self::new_tcp_with_error(Arc::new(crate::SocketError::new())) }

    /// Build a TCP socket around transport state allocated before accept. # C: O(1)
    pub fn new_tcp_with_error(error: Arc<crate::SocketError>) -> Self {
        Self::new_tcp_with_filter(error, Arc::new(crate::bpf_filter::SocketFilter::new()))
    }

    /// Build a TCP socket sharing a pre-existing transport filter. # C: O(1)
    pub fn new_tcp_with_filter(error: Arc<crate::SocketError>,
                               bpf_filter: Arc<crate::bpf_filter::SocketFilter>) -> Self {
        let _s = Self {
            family:     core::sync::atomic::AtomicU16::new(AF_INET),
            local_port: Spinlock::new(None),
            local_ip:   Spinlock::new(Ipv4Addr::ANY),
            peer:       Arc::new(Spinlock::new(None)),
            udp4:       Spinlock::new(None),
            udp6:       Spinlock::new(None),
            tcp_bind:   Spinlock::new(None),
            bpf_filter,
            mcast: Arc::new(crate::mcast_filter::SocketMcast::new()),
            // TcpInit makes connect() route SOCK_STREAM through the 3WHS path.
            // the UDP store-peer-and-return-Ok short-circuit.
            // listen()/connect()/accept() transition to TcpListener
            // or TcpConn.
            kind:       Spinlock::new(SockKind::TcpInit),
            opts:       SockOpts::default(),
            error,
            read_shut:  core::sync::atomic::AtomicBool::new(false),
            write_shut: core::sync::atomic::AtomicBool::new(false),
            released:   core::sync::atomic::AtomicBool::new(false),
            #[cfg(target_os = "oxide-kernel")]
            recv_waiters: sched::live::WaitList::new(),
            #[cfg(target_os = "oxide-kernel")]
            connect_waiters: sched::live::WaitList::new(),
            poll_subs:    Arc::new(vfs::PollSubscribers::new()),
            local_ip6: Spinlock::new(crate::Ipv6Addr([0; 16])),
            peer6:     Arc::new(Spinlock::new(None)),
            peer6_scope: core::sync::atomic::AtomicU32::new(0),
            unix_ns:   core::sync::atomic::AtomicU64::new(0),
            net_ns:    core::sync::atomic::AtomicU64::new(crate::netdev::current_net_ns()),
            owner_uid: current_socket_uid(),
            unix_bound: Spinlock::new(None),
        };
        _s
    }
    /// `socket(AF_INET6, SOCK_DGRAM, …)`. V4 transport substrate;
    /// `family = AF_INET6` flips the ABI to the 28-byte sockaddr_in6.
    /// # C: O(1)
    pub fn new_udp6() -> Self {
        let s = Self::new_udp();
        s.family.store(AF_INET6, core::sync::atomic::Ordering::Release);
        s
    }
    /// `socket(AF_INET6, SOCK_STREAM, …)`. # C: O(1)
    pub fn new_tcp6() -> Self {
        let s = Self::new_tcp();
        s.family.store(AF_INET6, core::sync::atomic::Ordering::Release);
        s
    }

    /// `socket(AF_UNIX, SOCK_STREAM, …)`. F114: InetSocket shell
    /// tagged AF_UNIX, kind set by bind/connect/accept transition
    /// to `SockKind::Unix(pair, end)`.
    /// # C: O(1)
    pub fn new_unix() -> Self {
        let s = Self::new_tcp();
        s.family.store(AF_UNIX, core::sync::atomic::Ordering::Release);
        s
    }

    /// `socket(AF_UNIX, SOCK_DGRAM, …)` per F120 / `24§R01`. Allocates
    /// a fresh `UnixDgramQueue` so sendto from a peer can push
    /// payloads. v1 sends are EOPNOTSUPP until the path-keyed dgram
    /// registry lands in F121; the queue alone lets feature-probing
    /// programs succeed at socket() + close().
    /// # C: O(1)
    pub fn new_unix_dgram() -> Self {
        let s = Self::new_tcp();
        s.family.store(AF_UNIX, core::sync::atomic::Ordering::Release);
        let q = crate::UnixDgramQueue::new();
        // F181a: queue wakes the owning socket's subscribers.
        q.register_subs(&s.poll_subs);
        *s.kind.lock() = SockKind::UnixDgram(q);
        s
    }

    /// F131: `socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))` —
    /// raw L2 packet socket dhcpcd uses for DHCPDISCOVER before
    /// it owns an IPv4. `proto` is the wire byte-order protocol
    /// the caller passed; we store host-order.
    /// # C: O(1)
    pub fn new_packet(proto: u16, sock_type: u8) -> Self {
        let s = Self::new_tcp();
        s.family.store(AF_PACKET, core::sync::atomic::Ordering::Release);
        *s.kind.lock() = SockKind::Packet {
            ifindex:   core::sync::atomic::AtomicU32::new(0),
            protocol:  core::sync::atomic::AtomicU16::new(proto),
            sock_type: core::sync::atomic::AtomicU8::new(sock_type),
            rx:        Spinlock::new(alloc::collections::VecDeque::new()),
        };
        s
    }

}

impl Default for InetSocket { fn default() -> Self { Self::new_udp() } }
