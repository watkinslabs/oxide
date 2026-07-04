use super::*;

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
    /// `ifindex == 0` means unbound (sendto / recvfrom return EINVAL
    /// until bind sets a specific iface).
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
        rx: sync::Spinlock<alloc::collections::VecDeque<alloc::vec::Vec<u8>>, SockLockClass>,
    },
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
    g.push(Arc::downgrade(sock));
}

/// Deliver L2 frame to AF_PACKET socks on `iface` (0=any). Filters by
/// proto (ETH_P_ALL or ethertype). 64 frames/sock cap. # C: O(N socks).
pub fn deliver_packet_rx(iface: NetIfaceId, frame: &[u8]) {
    use core::sync::atomic::Ordering;
    if frame.len() < 14 { return; }
    let et = ((frame[12] as u16) << 8) | (frame[13] as u16);
    // F172: collect socks; wake outside PACKET_REGISTRY lock to
    // avoid nesting wake_all's runqueue inner lock under it.
    let mut woken: Vec<Arc<InetSocket>> = Vec::new();
    let mut g = PACKET_REGISTRY.lock();
    g.retain(|w| w.upgrade().is_some());
    for w in g.iter() {
        let sock = match w.upgrade() { Some(s) => s, None => continue };
        let k = sock.kind.lock();
        if let SockKind::Packet { ifindex, protocol, sock_type, rx } = &*k {
            let want_if = ifindex.load(Ordering::Acquire);
            if want_if != 0 && want_if != iface.raw() { continue; }
            let p = protocol.load(Ordering::Acquire);
            if p != 0x0003 && p != et { continue; }
            const SOCK_DGRAM: u8 = 2;
            let stype = sock_type.load(Ordering::Acquire);
            let payload: alloc::vec::Vec<u8> = if stype == SOCK_DGRAM {
                frame[14..].to_vec()
            } else {
                frame.to_vec()
            };
            let mut q = rx.lock();
            if q.len() < 64 {
                q.push_back(payload);
                drop(q);
                drop(k);
                woken.push(sock);
            }
        }
    }
    drop(g);
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

/// AF_INET/AF_INET6 socket VFS state — one Inode per fd. v1: V4
/// slots only; AF_INET6 stores V4-mapped. Real V6 in F180.
pub struct InetSocket {
    pub family:     core::sync::atomic::AtomicU16,
    pub local_port: Spinlock<Option<u16>, SockLockClass>,
    pub local_ip:   Spinlock<Ipv4Addr, SockLockClass>,
    pub peer:       Spinlock<Option<(Ipv4Addr, u16)>, SockLockClass>,
    pub kind:       Spinlock<SockKind, SockLockClass>,
    pub opts: SockOpts,
    /// F166: SHUT_RD/RDWR latch — subsequent read returns Ok(0).
    pub read_shut: core::sync::atomic::AtomicBool,
    /// F180a: AF_INET6 address slots; IPv4 uses local_ip / peer.
    pub local_ip6: Spinlock<crate::Ipv6Addr, SockLockClass>,
    pub peer6:     Spinlock<Option<(crate::Ipv6Addr, u16)>, SockLockClass>,
    #[cfg(target_os = "oxide-kernel")]
    pub recv_waiters: sched::live::WaitList,
    /// F181: per-fd epoll subscribers.
    pub poll_subs: Arc<vfs::PollSubscribers>,
}

/// SOL_SOCKET options — Linux `int`-shaped cells. SO_LINGER pair.
pub struct SockOpts {
    pub reuseaddr: core::sync::atomic::AtomicI32,
    pub reuseport: core::sync::atomic::AtomicI32,
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
    pub ipv6_v6only: core::sync::atomic::AtomicI32,
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
            reuseaddr:   AtomicI32::new(0),
            reuseport:   AtomicI32::new(0),
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
            ipv6_v6only: AtomicI32::new(0),
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

impl InetSocket {
    /// # C: O(1)
    pub fn new_udp() -> Self {
        let _s = Self {
            family:     core::sync::atomic::AtomicU16::new(AF_INET),
            local_port: Spinlock::new(None),
            local_ip:   Spinlock::new(Ipv4Addr::ANY),
            peer:       Spinlock::new(None),
            kind:       Spinlock::new(SockKind::Udp),
            opts:       SockOpts::default(),
            read_shut:  core::sync::atomic::AtomicBool::new(false),
            #[cfg(target_os = "oxide-kernel")]
            recv_waiters: sched::live::WaitList::new(),
            poll_subs:    Arc::new(vfs::PollSubscribers::new()),
            local_ip6: Spinlock::new(crate::Ipv6Addr([0; 16])),
            peer6:     Spinlock::new(None),
        };
        _s
    }
    /// # C: O(1)
    pub fn new_tcp() -> Self {
        let _s = Self {
            family:     core::sync::atomic::AtomicU16::new(AF_INET),
            local_port: Spinlock::new(None),
            local_ip:   Spinlock::new(Ipv4Addr::ANY),
            peer:       Spinlock::new(None),
            // TcpInit makes connect() route SOCK_STREAM through the 3WHS path.
            // the UDP store-peer-and-return-Ok short-circuit.
            // listen()/connect()/accept() transition to TcpListener
            // or TcpConn.
            kind:       Spinlock::new(SockKind::TcpInit),
            opts:       SockOpts::default(),
            read_shut:  core::sync::atomic::AtomicBool::new(false),
            #[cfg(target_os = "oxide-kernel")]
            recv_waiters: sched::live::WaitList::new(),
            poll_subs:    Arc::new(vfs::PollSubscribers::new()),
            local_ip6: Spinlock::new(crate::Ipv6Addr([0; 16])),
            peer6:     Spinlock::new(None),
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

    /// Ensure a local port is bound (auto-bind to an ephemeral
    /// port when sendto is called before bind).
    /// # C: O(1) if already bound, else O(N) ephemeral scan
    pub fn ensure_bound(&self) -> Result<u16, NetError> {
        let mut g = self.local_port.lock();
        if let Some(p) = *g { return Ok(p); }
        let p = alloc_ephemeral_port()?;
        let iface = stack().bound_iface(
            self.opts.bound_ifindex.load(core::sync::atomic::Ordering::Acquire),
        )?;
        stack().set_udp_bound_iface(p, iface);
        *g = Some(p);
        Ok(p)
    }
}

impl Default for InetSocket { fn default() -> Self { Self::new_udp() } }

// F161 InetSocket::Drop moved to sock_drop.rs (1000-line cap).
