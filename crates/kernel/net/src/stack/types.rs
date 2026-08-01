use super::*;

mod tcp_entry_wait;

/// One queued IPv4 UDP datagram plus every header field the ancillary
/// messages publish: `dst` + `iface` back IP_PKTINFO, `dport` completes the
/// IP_ORIGDSTADDR socket address, `ttl` backs IP_TTL, `tos` backs IP_TOS,
/// `options` backs IP_RECVOPTS and IP_RETOPTS, and `frag_max` backs
/// IP_RECVFRAGSIZE.
#[derive(Clone, Debug)]
pub struct UdpDatagram {
    pub src: Ipv4Addr,
    pub sport: u16,
    pub dst: Ipv4Addr,
    pub dport: u16,
    pub iface: NetIfaceId,
    pub ttl: u8,
    pub tos: u8,
    /// Received header option area, empty when the header carried none.
    pub options: Vec<u8>,
    /// Largest fragment this datagram was reassembled from, zero when it
    /// arrived whole.
    pub frag_max: u32,
    pub payload: Vec<u8>,
}

impl UdpDatagram {
    /// A datagram carrying nothing beyond the addresses, hop limit and body —
    /// the shape a loopback delivery produces. # C: O(1)
    pub fn plain(src: Ipv4Addr, sport: u16, dst: Ipv4Addr, iface: NetIfaceId, ttl: u8,
                 payload: Vec<u8>) -> Self
    {
        Self { src, sport, dst, dport: 0, iface, ttl, tos: 0, options: Vec::new(),
               frag_max: 0, payload }
    }
}

/// One queued IPv4 UDP receive plus the coalescing run it belongs to.
#[derive(Clone)]
pub(super) struct QueuedUdp {
    pub(super) datagram: UdpDatagram,
    pub(super) gro: crate::udp_gro::GroRun,
}

pub(super) struct UdpRxState {
    pub(super) accepting: bool,
    pub(super) datagrams: VecDeque<QueuedUdp>,
}

/// One bridge next-hop's unresolved packets and its last wire solicitation.
pub(crate) struct BridgePending {
    pub(crate) packets: VecDeque<(u64, Pkt)>,
    pub(crate) last_solicit_ns: u64,
    pub(crate) solicit_attempts: u8,
    pub(crate) next_id: u64,
}

pub struct UdpRxQueue {
    pub owner: Arc<crate::SocketOwner>,
    pub bound_ip:   Ipv4Addr,
    pub bound_port: u16,
    /// Datagrams waiting for a reader, each carrying the header fields the
    /// ancillary messages publish.
    pub(super) state: Spinlock<UdpRxState, StackLockClass>,
    /// F162: blocking sys_recvfrom waiters (kernel only).
    #[cfg(target_os = "oxide-kernel")]
    pub waiters: sched::live::WaitList,
    /// Canonical owning socket error state.
    pub error: Arc<crate::SocketError>,
    /// Connected peer filter. `None` accepts datagrams from any peer.
    pub peer: Arc<Spinlock<Option<(Ipv4Addr, u16)>, StackLockClass>>,
    pub reuseaddr: Arc<::core::sync::atomic::AtomicI32>,
    pub reuseport: Arc<::core::sync::atomic::AtomicI32>,
    pub ip_mtu_discover: Arc<::core::sync::atomic::AtomicI32>,
    /// `UDP_GRO`, shared with the owning socket: while set, arriving
    /// datagrams of one flow coalesce into a single receive.
    pub gro: Arc<::core::sync::atomic::AtomicI32>,
    pub bound_ifindex: ::core::sync::atomic::AtomicU32,
    /// F181a: per-fd epoll subscribers.
    pub poll_subs: Spinlock<Option<alloc::sync::Weak<vfs::PollSubscribers>>, StackLockClass>,
    pub bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
    /// Socket multicast state shared before and after bind.
    pub mcast: Arc<crate::mcast_filter::SocketMcast>,
    /// SO_REUSEPORT group reached from the bind table on the delivery path.
    /// Published by bind-time join; the owning socket's cell holds membership.
    pub reuseport_group: crate::reuseport::ReuseportSlot,
}

impl UdpRxQueue {
    /// SO_REUSEPORT membership captured when this endpoint was bound. # C: O(1)
    pub(crate) fn reuseport_member(&self) -> bool {
        self.reuseport.load(::core::sync::atomic::Ordering::Acquire) != 0
    }
}

impl ::core::ops::Deref for UdpRxQueue {
    type Target = crate::SocketOwner;

    fn deref(&self) -> &Self::Target { &self.owner }
}


/// Connection 4-tuple key for TCP demultiplexing.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct TcpKey {
    pub local_ip:    IpAddr,
    pub local_port:  u16,
    pub remote_ip:   IpAddr,
    pub remote_port: u16,
}

/// Listening socket key (only local side). F180b: `IpAddr` so a single
/// table covers v4 + v6 listeners; UNSPECIFIED matches both families.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct TcpListenKey { pub local_ip: IpAddr, pub local_port: u16 }

pub const TCP_BIND_BOUND: u8 = 0;
pub const TCP_BIND_LISTEN: u8 = 1;
pub const TCP_BIND_CONNECT: u8 = 2;

/// Result of atomically rechecking and arming a blocking TCP connect.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TcpConnectWait {
    /// The handshake completed before the wait was armed.
    Established,
    /// The transport reached its terminal state before the wait was armed.
    Closed,
    /// The current task was registered while the connection lock was held.
    Parked,
}

/// One socket's canonical TCP local-name reservation.
pub struct TcpBindReservation {
    pub owner: Arc<crate::SocketOwner>,
    pub local: Endpoint,
    pub(crate) bound_ifindex: ::core::sync::atomic::AtomicU32,
    pub(crate) reuseaddr: bool,
    pub(crate) reuseport: bool,
    pub(crate) v6only: bool,
    pub(crate) role: ::core::sync::atomic::AtomicU8,
}

impl TcpBindReservation {
    /// Build a reservation before registry publication. # C: O(1)
    #[cfg(test)]
    pub(crate) fn new(namespace: network_namespace::NetworkNamespaceRef, local: Endpoint,
                      iface: Option<NetIfaceId>, reuseaddr: bool,
                      reuseport: bool, owner_uid: u32, v6only: bool) -> Self {
        Self::new_owned(crate::SocketOwner::root(namespace, owner_uid), local, iface,
            reuseaddr, reuseport, v6only)
    }

    /// Build a reservation retaining the socket's canonical owner. # C: O(1)
    pub(crate) fn new_owned(owner: Arc<crate::SocketOwner>, local: Endpoint,
                      iface: Option<NetIfaceId>, reuseaddr: bool,
                      reuseport: bool, v6only: bool) -> Self {
        Self {
            owner,
            local,
            bound_ifindex: ::core::sync::atomic::AtomicU32::new(
                iface.map(|id| id.raw()).unwrap_or(0),
            ),
            reuseaddr, reuseport, v6only,
            role: ::core::sync::atomic::AtomicU8::new(TCP_BIND_BOUND),
        }
    }

    /// Derive the short-lived namespace table key. # C: O(1)
    pub fn net_ns(&self) -> u64 { self.owner.net_ns() }

    /// Current SO_BINDTODEVICE scope. # C: O(1)
    pub fn bound_iface(&self) -> Option<NetIfaceId> {
        match self.bound_ifindex.load(::core::sync::atomic::Ordering::Acquire) {
            0 => None,
            raw => Some(NetIfaceId::from_raw(raw)),
        }
    }
}

impl ::core::ops::Deref for TcpBindReservation {
    type Target = crate::SocketOwner;

    fn deref(&self) -> &Self::Target { &self.owner }
}

/// Stack-owned per-connection record. Wraps the TcpConn TCB in
/// its own Spinlock so demux + app calls don't contend with the
/// listener table lock. Cheap to clone the Arc.
pub struct TcpEntry {
    /// Socket identity retained across asynchronous transport processing.
    pub owner: Arc<crate::SocketOwner>,
    pub conn: Spinlock<TcpConn, StackLockClass>,
    /// Canonical Linux `sk_err`, shared with the owning socket.
    pub error: Arc<crate::SocketError>,
    /// Canonical Linux `inet_sk(sk)->pmtudisc`, shared with the owning socket.
    pub ip_mtu_discover: Arc<::core::sync::atomic::AtomicI32>,
    /// Canonical Linux `inet6_sk(sk)->pmtudisc`, shared with the owning socket.
    pub ipv6_mtu_discover: Arc<::core::sync::atomic::AtomicI32>,
    /// Shared local bind owner. Passive children share their listener's bind.
    pub bind: Option<Arc<TcpBindReservation>>,
    /// Filter snapshot/shared socket owner used before TCP state processing.
    pub bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
    /// Listener retained weakly until a passive child completes its handshake.
    pub passive_listener: Option<alloc::sync::Weak<TcpListenEntry>>,
    pub syn_backlog_reserved: ::core::sync::atomic::AtomicBool,
    pub accept_backlog_reserved: ::core::sync::atomic::AtomicBool,
    /// Passive child has crossed accept and is no longer listener-owned.
    pub accepted: ::core::sync::atomic::AtomicBool,
    /// F158: blocking-read waiters (kernel only).
    #[cfg(target_os = "oxide-kernel")]
    pub rx_waiters: sched::live::WaitList,
    /// F181a: per-fd epoll subscribers (deliver_tcp wakes).
    pub poll_subs: Spinlock<Option<alloc::sync::Weak<vfs::PollSubscribers>>, StackLockClass>,
}

impl TcpEntry {
    /// # C: O(1)
    pub fn new(conn: TcpConn) -> Self {
        Self::new_with_error(conn, Arc::new(crate::SocketError::new()))
    }

    /// Whether Linux `getpeername` may expose this TCP peer. # C: O(1)
    pub fn peer_name_connected(&self) -> bool {
        !matches!(self.conn.lock().state,
            crate::tcp_state::TcpState::Closed | crate::tcp_state::TcpState::SynSent)
    }

    /// Build an entry sharing the socket's canonical error cell. # C: O(1)
    pub fn new_with_error(conn: TcpConn, error: Arc<crate::SocketError>) -> Self {
        Self::new_bound_with_error(conn, error, None)
    }

    /// Build an entry using the socket's canonical local bind. # C: O(1)
    pub fn new_bound_with_error(conn: TcpConn, error: Arc<crate::SocketError>,
                                bind: Option<Arc<TcpBindReservation>>) -> Self {
        Self::new_bound_with_filter(conn, error, bind,
            Arc::new(crate::bpf_filter::SocketFilter::new()))
    }

    /// Build an entry sharing the owning socket's filter. # C: O(1)
    pub fn new_bound_with_filter(conn: TcpConn, error: Arc<crate::SocketError>,
                                 bind: Option<Arc<TcpBindReservation>>,
                                 bpf_filter: Arc<crate::bpf_filter::SocketFilter>) -> Self {
        Self::new_bound_with_filter_pmtu(conn, error, bind, bpf_filter,
            Arc::new(::core::sync::atomic::AtomicI32::new(crate::uapi::IP_PMTUDISC_WANT)))
    }

    /// Build an entry sharing the owning socket's IPv4 PMTU mode. # C: O(1)
    pub fn new_bound_with_filter_pmtu(conn: TcpConn, error: Arc<crate::SocketError>,
                                 bind: Option<Arc<TcpBindReservation>>,
                                 bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
                                 ip_mtu_discover: Arc<::core::sync::atomic::AtomicI32>) -> Self {
        Self::new_bound_with_filter_pmtu_modes(conn, error, bind, bpf_filter, ip_mtu_discover,
            Arc::new(::core::sync::atomic::AtomicI32::new(crate::uapi::IPV6_PMTUDISC_WANT)))
    }

    /// Build an entry sharing both owning-socket PMTU modes. # C: O(1)
    pub fn new_bound_with_filter_pmtu_modes(conn: TcpConn, error: Arc<crate::SocketError>,
                                 bind: Option<Arc<TcpBindReservation>>,
                                 bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
                                 ip_mtu_discover: Arc<::core::sync::atomic::AtomicI32>,
                                 ipv6_mtu_discover: Arc<::core::sync::atomic::AtomicI32>) -> Self {
        Self::new_bound_with_filter_listener(conn, error, bind, bpf_filter, ip_mtu_discover,
            ipv6_mtu_discover, None)
    }

    /// Build a transport entry with its passive-handshake owner. # C: O(1)
    pub fn new_bound_with_filter_listener(conn: TcpConn, error: Arc<crate::SocketError>,
                                 bind: Option<Arc<TcpBindReservation>>,
                                 bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
                                 ip_mtu_discover: Arc<::core::sync::atomic::AtomicI32>,
                                 ipv6_mtu_discover: Arc<::core::sync::atomic::AtomicI32>,
                                 passive_listener: Option<alloc::sync::Weak<TcpListenEntry>>) -> Self {
        let syn_backlog_reserved = passive_listener.is_some();
        let owner = bind.as_ref().map(|bind| bind.owner.clone())
            .unwrap_or_else(|| crate::SocketOwner::root(network_namespace::initial(), 0));
        Self {
            owner,
            conn: Spinlock::new(conn),
            error,
            ip_mtu_discover,
            ipv6_mtu_discover,
            bind,
            bpf_filter,
            passive_listener,
            syn_backlog_reserved: ::core::sync::atomic::AtomicBool::new(syn_backlog_reserved),
            accept_backlog_reserved: ::core::sync::atomic::AtomicBool::new(false),
            accepted: ::core::sync::atomic::AtomicBool::new(false),
            #[cfg(target_os = "oxide-kernel")]
            rx_waiters: sched::live::WaitList::new(),
            poll_subs: Spinlock::new(None),
        }
    }

    /// Move a completed passive child from SYN backlog to accept backlog. # C: O(1)
    pub fn promote_to_accept_backlog(&self) -> bool {
        let Some(listener) = self.passive_listener.as_ref().and_then(alloc::sync::Weak::upgrade) else { return true; };
        if !listener.reserve_accept_backlog() { return false; }
        self.accept_backlog_reserved.store(true, ::core::sync::atomic::Ordering::Release);
        self.release_syn_backlog();
        true
    }

    /// Release this passive child's SYN-RECV reservation once. # C: O(1)
    pub fn release_syn_backlog(&self) {
        if self.syn_backlog_reserved.swap(false, ::core::sync::atomic::Ordering::AcqRel) {
            if let Some(listener) = self.passive_listener.as_ref().and_then(alloc::sync::Weak::upgrade) {
                listener.syn_backlog_used.fetch_sub(1, ::core::sync::atomic::Ordering::AcqRel);
            }
        }
    }

    /// Release this passive child's completed accept reservation once. # C: O(1)
    pub fn release_accept_backlog(&self) {
        if self.accept_backlog_reserved.swap(false, ::core::sync::atomic::Ordering::AcqRel) {
            if let Some(listener) = self.passive_listener.as_ref().and_then(alloc::sync::Weak::upgrade) {
                listener.accept_backlog_used.fetch_sub(1, ::core::sync::atomic::Ordering::AcqRel);
            }
        }
    }

    /// Release either passive backlog reservation still owned by this child. # C: O(1)
    pub fn release_backlog(&self) {
        self.release_syn_backlog();
        self.release_accept_backlog();
    }

    /// # C: O(1)
    pub fn bound_iface(&self) -> Option<NetIfaceId> {
        self.bind.as_ref().and_then(|bind| bind.bound_iface())
    }

    /// Network namespace captured by the owning TCP bind. # C: O(1)
    pub fn net_ns(&self) -> u64 { self.bind.as_ref().map(|bind| bind.net_ns()).unwrap_or(0) }
}

fn tcp_transmit_ready(conn: &TcpConn, sndbuf_cap: usize) -> bool {
    let in_flight: usize = conn.retx_q.iter().map(|segment| segment.payload.len()).sum();
    conn.send_buf.len().saturating_add(in_flight) < sndbuf_cap
}

/// Report whether TCP state forbids additional stream payload. # C: O(1)
pub(crate) fn tcp_send_closed(state: crate::tcp_state::TcpState) -> bool {
    matches!(state, crate::tcp_state::TcpState::Closed
        | crate::tcp_state::TcpState::LastAck
        | crate::tcp_state::TcpState::Closing | crate::tcp_state::TcpState::TimeWait
        | crate::tcp_state::TcpState::FinWait1 | crate::tcp_state::TcpState::FinWait2)
}

/// F159: monotonic time source visible to net crate. On
/// `oxide-kernel` builds uses the per-arch HAL timer; hosted tests
/// return 0 so retx_tick is a no-op without a real clock.
/// # C: O(1)
pub(crate) fn monotonic_ns_safe() -> u64 {
    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
    {
        use hal::TimerOps;
        return hal_x86_64::X86TimerOps::monotonic_ns().0;
    }
    #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
    {
        use hal::TimerOps;
        return hal_aarch64::ArmTimerOps::monotonic_ns().0;
    }
    #[allow(unreachable_code)]
    0
}

/// F159: stamp the last `n` entries of `entry`'s retx_q with the
/// current monotonic ns. Called immediately after the corresponding
/// segments are handed to the iface for xmit so retx_tick has a
/// real baseline to compare RTO against. No-op on n == 0 / empty
/// queue.
/// # C: O(n)
/// F190: TOS byte for an outbound TCP segment — ECT(0)=0x02 when
/// the conn negotiated ECN, else 0. # C: O(1)
pub(crate) fn ecn_tos(c: &TcpConn) -> u8 {
    if c.ecn_enabled { 0x02 } else { 0 }
}

/// Bridge to tcp_conn::ka_now_ns from stack code. # C: O(1)
pub(crate) fn net_now_ns() -> u64 { crate::tcp_conn::ka_now_ns() }

/// # C: O(n)
pub(crate) fn stamp_last_sent(entry: &TcpEntry, n: usize) {
    if n == 0 { return; }
    let now = monotonic_ns_safe();
    if now == 0 { return; } // hosted tests / pre-timer boot
    let mut c = entry.conn.lock();
    let len = c.retx_q.len();
    let start = len.saturating_sub(n);
    for i in start..len {
        c.retx_q[i].last_sent_ns = now;
    }
}

/// # C: O(n)
pub(crate) fn stamp_last_sent_public(entry: &TcpEntry, n: usize) {
    stamp_last_sent(entry, n);
}

pub struct TcpListenEntry {
    /// Listening socket identity inherited by passive children.
    pub owner: Arc<crate::SocketOwner>,
    pub accept_q: Spinlock<VecDeque<Arc<TcpEntry>>, StackLockClass>,
    pub bind: Arc<TcpBindReservation>,
    /// Live listening-socket filter; passive children snapshot this state.
    pub bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
    /// Live listening-socket IPv4 PMTU mode; each passive child snapshots it.
    pub ip_mtu_discover: Arc<::core::sync::atomic::AtomicI32>,
    /// Live listening-socket IPv6 PMTU mode; each passive child snapshots it.
    pub ipv6_mtu_discover: Arc<::core::sync::atomic::AtomicI32>,
    /// F192: backlog cap (listen(2), clamped by live `somaxconn`).
    pub backlog: ::core::sync::atomic::AtomicUsize,
    /// Half-open plus completed children not yet removed by accept.
    pub syn_backlog_used: ::core::sync::atomic::AtomicUsize,
    pub accept_backlog_used: ::core::sync::atomic::AtomicUsize,
    /// `TCP_DEFER_ACCEPT` as the seconds window the owning socket's stored
    /// retransmit count covers. The option block is the source of truth; this
    /// is the applied copy the delivery path reads without reaching back into
    /// the socket, already in the unit the hand-over rule waits in.
    pub defer_window_secs: ::core::sync::atomic::AtomicI32,
    /// Listener close linearizes child admission and accept publication here.
    pub closed: ::core::sync::atomic::AtomicBool,
    pub local: Endpoint,
    /// F160: blocking-accept waiters.
    #[cfg(target_os = "oxide-kernel")]
    pub accept_waiters: sched::live::WaitList,
    /// F181a: per-fd epoll subscribers (POLL_IN on accept_q growth).
    pub poll_subs: Spinlock<Option<alloc::sync::Weak<vfs::PollSubscribers>>, StackLockClass>,
    /// SO_REUSEPORT group reached from the listen table on the delivery path.
    /// Published by listen-time join; the owning socket's cell holds membership.
    pub reuseport_group: crate::reuseport::ReuseportSlot,
}

pub(crate) struct ArpNeighbor {
    pub(crate) mac: MacAddr,
    pub(crate) learned_ns: u64,
    pub(crate) permanent: bool,
}

pub struct NetStack {
    pub(crate) rtnl: crate::rtnl::Rtnl,
    pub ifaces: IfaceRegistry,
    pub routes: RouteTable,
    pub routes6: Route6Table,
    /// Canonical IPv4 proxy-neighbour keys, scoped to namespace and interface generation.
    pub(crate) arp_proxy: crate::arp::proxy::ProxyTable,
    /// Canonical bridge-port and forwarding database owner, serialized by RTNL.
    pub(crate) bridges: super::bridge::BridgeTable,
    /// Canonical IPv4 neighbour bindings, scoped by live egress interface.
    pub(crate) arp: Spinlock<BTreeMap<(NetIfaceId, Ipv4Addr), ArpNeighbor>, StackLockClass>,
    /// Packets accepted by a bridge while its next-hop neighbour is unresolved.
    pub(crate) bridge_pending: Spinlock<BTreeMap<(NetIfaceId, IpAddr), BridgePending>, StackLockClass>,
    /// Sole AF_INET/AF_INET6 transport owner, indexed by network namespace.
    pub(crate) inet: Spinlock<BTreeMap<u64, Arc<super::inet_tables::InetTables>>, StackLockClass>,
    /// Monotonic id for IP packets we emit.
    pub(crate) next_ip_id: Spinlock<u16, StackLockClass>,
    /// Monotonic ISN base for TCP active opens.
    /// F180c: IPv6 neighbor cache keyed by ingress/egress interface.
    pub(crate) ndp: Spinlock<BTreeMap<(NetIfaceId, Ipv6Addr), MacAddr>, StackLockClass>,
    /// F195: IPv4 reassembly table.
    pub ipv4_reasm: crate::ipv4_reasm::ReasmTable,
    /// IPv6 Fragment extension reassembly table.
    pub ipv6_reasm: crate::ipv6_reasm::ReasmTable,
    /// F180c: per-iface IPv6 address registry (NS responder).
    pub(crate) v6_addrs: Spinlock<BTreeMap<NetIfaceId, Vec<crate::stack_ipv6::Ipv6IfaceAddr>>, StackLockClass>, pub(crate) v6_mcast: Spinlock<BTreeMap<NetIfaceId, Vec<crate::mcast_state::V6IfaceGroup>>, StackLockClass>, pub(crate) v4_mcast: Spinlock<BTreeMap<NetIfaceId, Vec<crate::mcast_state::V4IfaceGroup>>, StackLockClass>,
    pub(crate) v6_ra_pending: Spinlock<Vec<crate::stack_ipv6::PendingRa>, StackLockClass>,
    #[cfg(not(target_os = "oxide-kernel"))]
    pub(crate) ra_now_ns: ::core::sync::atomic::AtomicU64,
}

impl Default for NetStack { fn default() -> Self { Self::new() } }

#[cfg(test)]
#[path = "types_tests.rs"]
mod tests;
