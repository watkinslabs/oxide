use super::*;

pub struct UdpRxQueue {
    pub bound_ip:   Ipv4Addr,
    pub bound_port: u16,
    /// Datagrams waiting for a reader: (src, sport, dst, iface, payload).
    pub q: Spinlock<VecDeque<(Ipv4Addr, u16, Ipv4Addr, NetIfaceId, Vec<u8>)>, StackLockClass>,
    /// F162: blocking sys_recvfrom waiters (kernel only).
    #[cfg(target_os = "oxide-kernel")]
    pub waiters: sched::live::WaitList,
    /// F174: per-port pending async error (Linux errno).
    pub error_eno: ::core::sync::atomic::AtomicI32,
    pub bound_ifindex: ::core::sync::atomic::AtomicU32,
    /// F181a: per-fd epoll subscribers.
    pub poll_subs: Spinlock<Option<alloc::sync::Weak<vfs::PollSubscribers>>, StackLockClass>,
    /// SO_ATTACH_BPF socket-filter program bytes (run per datagram; r0==0 drops).
    pub bpf_filter: Spinlock<Option<Vec<u8>>, StackLockClass>,
}

pub use crate::bpf_filter::{install_bpf_filter_runner, BpfFilterFn}; // bridge in bpf_filter.rs
use crate::bpf_filter::bpf_accept;
// F180a Udp6RxQueue + IPv6 methods in stack_ipv6.rs.
impl UdpRxQueue {
    /// F174: read+clear pending per-port errno. # C: O(1)
    pub fn take_error(&self) -> i32 { self.error_eno.swap(0, ::core::sync::atomic::Ordering::AcqRel) }
    /// # C: O(1)
    pub fn new(bound_ip: Ipv4Addr, bound_port: u16) -> Self {
        Self {
            bound_ip, bound_port,
            q: Spinlock::new(VecDeque::new()),
            #[cfg(target_os = "oxide-kernel")]
            waiters: sched::live::WaitList::new(),
            error_eno: ::core::sync::atomic::AtomicI32::new(0),
            bound_ifindex: ::core::sync::atomic::AtomicU32::new(0),
            poll_subs: Spinlock::new(None),
            bpf_filter: Spinlock::new(None),
        }
    }

    /// F181a: register bound socket's subscribers. # C: O(1)
    pub fn register_poll_subs(&self, subs: &alloc::sync::Arc<vfs::PollSubscribers>) {
        *self.poll_subs.lock() = Some(alloc::sync::Arc::downgrade(subs));
    }
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

/// Stack-owned per-connection record. Wraps the TcpConn TCB in
/// its own Spinlock so demux + app calls don't contend with the
/// listener table lock. Cheap to clone the Arc.
pub struct TcpEntry {
    pub conn: Spinlock<TcpConn, StackLockClass>,
    pub bound_ifindex: ::core::sync::atomic::AtomicU32,
    /// F158: blocking-read waiters (kernel only).
    #[cfg(target_os = "oxide-kernel")]
    pub rx_waiters: sched::live::WaitList,
    /// F181a: per-fd epoll subscribers (deliver_tcp wakes).
    pub poll_subs: Spinlock<Option<alloc::sync::Weak<vfs::PollSubscribers>>, StackLockClass>,
}

impl TcpEntry {
    /// # C: O(1)
    pub fn new(conn: TcpConn) -> Self {
        Self {
            conn: Spinlock::new(conn),
            bound_ifindex: ::core::sync::atomic::AtomicU32::new(0),
            #[cfg(target_os = "oxide-kernel")]
            rx_waiters: sched::live::WaitList::new(),
            poll_subs: Spinlock::new(None),
        }
    }

    /// F181a: register owning InetSocket's epoll subscribers. Call
    /// when binding `entry → TcpConn(entry)` on the InetSocket.
    /// # C: O(1)
    pub fn register_poll_subs(&self, subs: &alloc::sync::Arc<vfs::PollSubscribers>) {
        *self.poll_subs.lock() = Some(alloc::sync::Arc::downgrade(subs));
    }

    /// # C: O(1)
    pub fn set_bound_iface(&self, iface: Option<NetIfaceId>) {
        self.bound_ifindex.store(
            iface.map(|i| i.raw()).unwrap_or(0),
            ::core::sync::atomic::Ordering::Release,
        );
    }

    /// # C: O(1)
    pub fn bound_iface(&self) -> Option<NetIfaceId> {
        match self.bound_ifindex.load(::core::sync::atomic::Ordering::Acquire) {
            0 => None,
            raw => Some(NetIfaceId::from_raw(raw)),
        }
    }
}

/// F159: monotonic time source visible to net crate. On
/// `oxide-kernel` builds uses the per-arch HAL timer; hosted tests
/// return 0 so retx_tick is a no-op without a real clock.
/// # C: O(1)
fn monotonic_ns_safe() -> u64 {
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
    pub accept_q: Spinlock<VecDeque<Arc<TcpEntry>>, StackLockClass>,
    pub bound_ifindex: ::core::sync::atomic::AtomicU32,
    /// F192: backlog cap (listen(2), clamped somaxconn=4096).
    pub backlog: ::core::sync::atomic::AtomicUsize,
    pub local: Endpoint,
    /// F160: blocking-accept waiters.
    #[cfg(target_os = "oxide-kernel")]
    pub accept_waiters: sched::live::WaitList,
    /// F181a: per-fd epoll subscribers (POLL_IN on accept_q growth).
    pub poll_subs: Spinlock<Option<alloc::sync::Weak<vfs::PollSubscribers>>, StackLockClass>,
}

impl TcpListenEntry {
    /// # C: O(1)
    pub fn new(local: Endpoint) -> Self {
        Self {
            accept_q: Spinlock::new(VecDeque::new()),
            bound_ifindex: ::core::sync::atomic::AtomicU32::new(0),
            backlog: ::core::sync::atomic::AtomicUsize::new(128),
            local,
            #[cfg(target_os = "oxide-kernel")]
            accept_waiters: sched::live::WaitList::new(),
            poll_subs: Spinlock::new(None),
        }
    }
    /// F192: set listen(2) backlog (clamped 1..=somaxconn). # C: O(1)
    pub fn set_backlog(&self, b: i32) {
        let n = if b <= 0 { 128 } else { ::core::cmp::min(b as usize, 4096) };
        self.backlog.store(n, ::core::sync::atomic::Ordering::Release);
    }

    /// F181a: register listener-fd subscribers.
    /// # C: O(1)
    pub fn register_poll_subs(&self, subs: &alloc::sync::Arc<vfs::PollSubscribers>) {
        *self.poll_subs.lock() = Some(alloc::sync::Arc::downgrade(subs));
    }

    /// # C: O(1)
    pub fn set_bound_iface(&self, iface: Option<NetIfaceId>) {
        self.bound_ifindex.store(
            iface.map(|i| i.raw()).unwrap_or(0),
            ::core::sync::atomic::Ordering::Release,
        );
    }

    /// # C: O(1)
    pub fn bound_iface(&self) -> Option<NetIfaceId> {
        match self.bound_ifindex.load(::core::sync::atomic::Ordering::Acquire) {
            0 => None,
            raw => Some(NetIfaceId::from_raw(raw)),
        }
    }
}

pub struct NetStack {
    pub ifaces: IfaceRegistry,
    pub routes: RouteTable,
    pub routes6: Route6Table,
    pub(crate) udp: Spinlock<BTreeMap<u16, Arc<UdpRxQueue>>, StackLockClass>,
    /// F180a: IPv6 UDP socket map. Accessor `udp6_map()` exposed to
    /// `stack_ipv6` impls without making the field pub.
    pub(crate) udp6: Spinlock<BTreeMap<u16, Arc<crate::stack_ipv6::Udp6RxQueue>>, StackLockClass>,
    pub(crate) tcp_conns: Spinlock<BTreeMap<TcpKey, Arc<TcpEntry>>, StackLockClass>,
    pub(crate) tcp_listens: Spinlock<BTreeMap<TcpListenKey, Vec<Arc<TcpListenEntry>>>, StackLockClass>,
    /// Monotonic id for IP packets we emit.
    pub(crate) next_ip_id: Spinlock<u16, StackLockClass>,
    /// Monotonic ISN base for TCP active opens.
    pub(crate) next_isn: Spinlock<u32, StackLockClass>,
    /// F180c: IPv6 neighbor cache keyed by ingress/egress interface.
    pub(crate) ndp: Spinlock<BTreeMap<(NetIfaceId, Ipv6Addr), MacAddr>, StackLockClass>,
    /// F195: IPv4 reassembly table.
    pub ipv4_reasm: crate::ipv4_reasm::ReasmTable,
    /// IPv6 Fragment extension reassembly table.
    pub ipv6_reasm: crate::ipv6_reasm::ReasmTable,
    /// F180c: per-iface IPv6 address registry (NS responder).
    pub(crate) v6_addrs: Spinlock<BTreeMap<NetIfaceId, Vec<crate::stack_ipv6::Ipv6IfaceAddr>>, StackLockClass>, pub(crate) v6_mcast: Spinlock<BTreeMap<NetIfaceId, Vec<crate::addr::Ipv6Addr>>, StackLockClass>, pub(crate) v4_mcast: Spinlock<BTreeMap<NetIfaceId, Vec<(Ipv4Addr, Ipv4Addr)>>, StackLockClass>,
}

impl Default for NetStack { fn default() -> Self { Self::new() } }
