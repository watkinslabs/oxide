// NetStack: ifaces + routing + UDP/TCP demux. v6 helpers in
// stack_ipv6.rs. Hosted-testable via LoopbackDev.

extern crate alloc;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use alloc::vec::Vec;

use sync::{Spinlock, Socket as StackLockClass};

use crate::addr::{IpAddr, IpProto, Ipv4Addr, Ipv6Addr, NetIfaceId};
use crate::icmp::{self, ICMP_TYPE_ECHO_REQUEST};
use crate::ipv4::{Ipv4Hdr, IPV4_HDR_LEN, push_ipv4_header};
use crate::loopback::LoopbackDev;
use crate::netdev::{IfaceRegistry, NetDev, NetError, NetResult};
use crate::pkt::Pkt;
use crate::route::RouteTable;
use crate::route6::Route6Table;
use crate::udp::UdpHdr;
use crate::tcp_hdr::{flags as tcp_flags, TCP_HDR_MIN_LEN};
use crate::tcp_conn::{TcpConn, Endpoint};

// Netfilter hook bridge lives in `netfilter_hook` (08§7 split). Re-export
// the public API so `net::stack::install_nf_hook` / `NF_INET_*` paths stay
// stable; pull the crate-internal helpers into scope for the packet path.
pub use crate::netfilter_hook::{NfHookFn, install_nf_hook, NFPROTO_IPV4,
    NF_INET_PRE_ROUTING, NF_INET_LOCAL_IN, NF_INET_LOCAL_OUT, NF_INET_POST_ROUTING};
use crate::netfilter_hook::{nf_hook_eval, nf_output};

/// Per-port UDP rx queue (bind-syscall reads from here). F162: q + waiters
/// have their own locks so deliver_rx / sys_recvfrom don't hold the udp-map
/// lock across parks.
pub struct UdpRxQueue {
    pub bound_ip:   Ipv4Addr,
    pub bound_port: u16,
    /// Datagrams waiting for a reader: (src, sport, dst, iface, payload).
    pub q: Spinlock<VecDeque<(Ipv4Addr, u16, Ipv4Addr, NetIfaceId, Vec<u8>)>, StackLockClass>,
    /// F162: blocking sys_recvfrom waiters (kernel only).
    #[cfg(target_os = "oxide-kernel")]
    pub waiters: sched::live::WaitList,
    /// F174: per-port pending async error (Linux errno).
    pub error_eno: core::sync::atomic::AtomicI32,
    pub bound_ifindex: core::sync::atomic::AtomicU32,
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
    pub fn take_error(&self) -> i32 { self.error_eno.swap(0, core::sync::atomic::Ordering::AcqRel) }
    /// # C: O(1)
    pub fn new(bound_ip: Ipv4Addr, bound_port: u16) -> Self {
        Self {
            bound_ip, bound_port,
            q: Spinlock::new(VecDeque::new()),
            #[cfg(target_os = "oxide-kernel")]
            waiters: sched::live::WaitList::new(),
            error_eno: core::sync::atomic::AtomicI32::new(0),
            bound_ifindex: core::sync::atomic::AtomicU32::new(0),
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
    pub bound_ifindex: core::sync::atomic::AtomicU32,
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
            bound_ifindex: core::sync::atomic::AtomicU32::new(0),
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
            core::sync::atomic::Ordering::Release,
        );
    }

    /// # C: O(1)
    pub fn bound_iface(&self) -> Option<NetIfaceId> {
        match self.bound_ifindex.load(core::sync::atomic::Ordering::Acquire) {
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
fn ecn_tos(c: &TcpConn) -> u8 {
    if c.ecn_enabled { 0x02 } else { 0 }
}

/// Bridge to tcp_conn::ka_now_ns from stack code. # C: O(1)
pub(crate) fn net_now_ns() -> u64 { crate::tcp_conn::ka_now_ns() }

fn stamp_last_sent(entry: &TcpEntry, n: usize) {
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
    pub bound_ifindex: core::sync::atomic::AtomicU32,
    /// F192: backlog cap (listen(2), clamped somaxconn=4096).
    pub backlog: core::sync::atomic::AtomicUsize,
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
            bound_ifindex: core::sync::atomic::AtomicU32::new(0),
            backlog: core::sync::atomic::AtomicUsize::new(128),
            local,
            #[cfg(target_os = "oxide-kernel")]
            accept_waiters: sched::live::WaitList::new(),
            poll_subs: Spinlock::new(None),
        }
    }
    /// F192: set listen(2) backlog (clamped 1..=somaxconn). # C: O(1)
    pub fn set_backlog(&self, b: i32) {
        let n = if b <= 0 { 128 } else { core::cmp::min(b as usize, 4096) };
        self.backlog.store(n, core::sync::atomic::Ordering::Release);
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
            core::sync::atomic::Ordering::Release,
        );
    }

    /// # C: O(1)
    pub fn bound_iface(&self) -> Option<NetIfaceId> {
        match self.bound_ifindex.load(core::sync::atomic::Ordering::Acquire) {
            0 => None,
            raw => Some(NetIfaceId::from_raw(raw)),
        }
    }
}

pub struct NetStack {
    pub ifaces: IfaceRegistry,
    pub routes: RouteTable,
    pub routes6: Route6Table,
    udp:        Spinlock<BTreeMap<u16, Arc<UdpRxQueue>>, StackLockClass>,
    /// F180a: IPv6 UDP socket map. Accessor `udp6_map()` exposed to
    /// `stack_ipv6` impls without making the field pub.
    udp6:       Spinlock<BTreeMap<u16, Arc<crate::stack_ipv6::Udp6RxQueue>>, StackLockClass>,
    pub(crate) tcp_conns: Spinlock<BTreeMap<TcpKey, Arc<TcpEntry>>, StackLockClass>,
    tcp_listens:  Spinlock<BTreeMap<TcpListenKey, Vec<Arc<TcpListenEntry>>>, StackLockClass>,
    /// Monotonic id for IP packets we emit.
    pub(crate) next_ip_id: Spinlock<u16, StackLockClass>,
    /// Monotonic ISN base for TCP active opens.
    pub(crate) next_isn: Spinlock<u32, StackLockClass>,
    /// F180c: global NDP cache (ip → MAC).
    pub ndp: crate::ndp::NdpCache,
    /// F195: IPv4 reassembly table.
    pub ipv4_reasm: crate::ipv4_reasm::ReasmTable,
    /// IPv6 Fragment extension reassembly table.
    pub ipv6_reasm: crate::ipv6_reasm::ReasmTable,
    /// F180c: per-iface IPv6 address registry (NS responder).
    v6_addrs: Spinlock<BTreeMap<NetIfaceId, Vec<crate::addr::Ipv6Addr>>, StackLockClass>, pub(crate) v6_mcast: Spinlock<BTreeMap<NetIfaceId, Vec<crate::addr::Ipv6Addr>>, StackLockClass>,
}

impl NetStack {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self {
            ifaces: IfaceRegistry::new(),
            routes: RouteTable::new(),
            routes6: Route6Table::new(),
            udp:    Spinlock::new(BTreeMap::new()),
            udp6:   Spinlock::new(BTreeMap::new()),
            tcp_conns:   Spinlock::new(BTreeMap::new()),
            tcp_listens: Spinlock::new(BTreeMap::new()),
            next_ip_id: Spinlock::new(1),
            next_isn:   Spinlock::new(0x1000_0000),
            ndp:        crate::ndp::NdpCache::new(),
            ipv4_reasm: crate::ipv4_reasm::ReasmTable::new(),
            ipv6_reasm: crate::ipv6_reasm::ReasmTable::new(),
            v6_addrs:   Spinlock::new(BTreeMap::new()),
            v6_mcast:   Spinlock::new(BTreeMap::new()),
        }
    }

    /// F184: MSS for `dst` = egress iface MTU − (v4:40, v6:60). 0 if
    /// no iface — caller falls back to OWN_MSS_DEFAULT. # C: O(log N).
    pub fn mss_for_dst(&self, dst: IpAddr) -> u16 {
        let mtu = match dst {
            IpAddr::V4(d) => self.routes.lookup(d)
                .and_then(|r| self.ifaces.lookup(r.iface))
                .map(|i| i.mtu()),
            IpAddr::V6(d) => self.route6_iface(d).map(|(_, i)| i.mtu()),
        };
        let overhead = if matches!(dst, IpAddr::V6(_)) { 60 } else { 40 };
        mtu.map(|m| (m.saturating_sub(overhead)).min(0xFFFF) as u16).unwrap_or(0)
    }

    /// Resolve the IPv6 egress interface using longest-prefix match.
    /// # C: O(N routes)
    pub(crate) fn route6_iface(&self, dst: Ipv6Addr) -> Option<(NetIfaceId, Arc<dyn NetDev>)> {
        let route = self.routes6.lookup(dst)?;
        let iface = self.ifaces.lookup(route.iface)?;
        Some((route.iface, iface))
    }

    /// F180c: register a v6 addr on `iface`; NS replies. # C: O(log N)
    pub fn add_v6_addr(&self, iface: NetIfaceId, ip: crate::addr::Ipv6Addr) {
        let mut g = self.v6_addrs.lock();
        let addrs = g.entry(iface).or_default();
        if !addrs.iter().any(|a| *a == ip) { addrs.push(ip); }
    }
    /// F180c: is `ip` bound on `iface`? # C: O(N addrs)
    pub fn v6_addr_owned_by(&self, iface: NetIfaceId, ip: crate::addr::Ipv6Addr) -> bool { self.v6_addrs.lock().get(&iface).map(|v| v.iter().any(|a| *a == ip)).unwrap_or(false) }
    /// Pick an IPv6 source address bound to `iface`, if one exists. # C: O(N addrs)
    pub(crate) fn v6_src_on_iface(&self, iface: NetIfaceId) -> Option<crate::addr::Ipv6Addr> { self.v6_addrs.lock().get(&iface).and_then(|v| v.first().copied()) }

    /// Boot-time wiring: create + register a loopback netdev,
    /// add canonical loopback routes through it. Returns
    /// the assigned iface id.
    /// # C: O(1)
    pub fn register_loopback(&self) -> (NetIfaceId, Arc<LoopbackDev>) {
        let lo = Arc::new(LoopbackDev::new());
        let id = self.ifaces.register(lo.clone() as Arc<dyn NetDev>);
        self.routes.add(crate::route::RouteEntry {
            dst:        Ipv4Addr::new(127, 0, 0, 0),
            prefix_len: 8,
            iface:      id,
            gateway:    None,
            src_hint:   Some(Ipv4Addr::LOOPBACK),
        });
        self.routes6.add(crate::route6::Route6Entry {
            dst:        Ipv6Addr::LOOPBACK,
            prefix_len: 128,
            iface:      id,
            gateway:    None,
            src_hint:   Some(Ipv6Addr::LOOPBACK),
        });
        (id, lo)
    }

    /// SO_ATTACH_BPF / SO_DETACH_BPF: set/clear the UDP port's socket filter
    /// (false if nothing is bound there). # C: O(log N)
    pub fn set_udp_bpf_filter(&self, port: u16, insns: Option<Vec<u8>>) -> bool {
        let q = { self.udp.lock().get(&port).cloned() };
        match q { Some(q) => { *q.bpf_filter.lock() = insns; true } None => false }
    }

    /// UDP bind. Eaddrinuse if taken. # C: O(log N)
    pub fn bind_udp(&self, bind_ip: Ipv4Addr, port: u16) -> NetResult<()> {
        self.bind_udp_with_iface(bind_ip, port, None)
    }

    /// UDP bind with an optional SO_BINDTODEVICE filter. # C: O(log N)
    pub fn bind_udp_with_iface(&self, bind_ip: Ipv4Addr, port: u16,
                               iface: Option<NetIfaceId>) -> NetResult<()> {
        let mut g = self.udp.lock();
        if g.contains_key(&port) { return Err(NetError::Eaddrinuse); }
        let q = Arc::new(UdpRxQueue::new(bind_ip, port));
        q.bound_ifindex.store(iface.map(|i| i.raw()).unwrap_or(0), core::sync::atomic::Ordering::Release);
        g.insert(port, q);
        Ok(())
    }

    /// Update the bound iface for an already-bound UDP port. # C: O(log N)
    pub fn set_udp_bound_iface(&self, port: u16, iface: Option<NetIfaceId>) -> bool {
        if let Some(q) = self.udp.lock().get(&port) {
            q.bound_ifindex.store(iface.map(|i| i.raw()).unwrap_or(0), core::sync::atomic::Ordering::Release);
            true
        } else { false }
    }

    /// Pop one queued datagram or None. # C: O(log N)
    pub fn recv_udp(&self, port: u16) -> Option<(Ipv4Addr, u16, Vec<u8>)> {
        self.recv_udp_opts(port, false)
    }

    /// Pop or peek one queued datagram or None. Peeking clones the
    /// front payload and leaves queue state unchanged.
    /// # C: O(log N + payload bytes when peeking)
    pub fn recv_udp_opts(&self, port: u16, peek: bool) -> Option<(Ipv4Addr, u16, Vec<u8>)> {
        let (src, sport, _, _, payload) = self.recv_udp_meta_opts(port, peek)?;
        Some((src, sport, payload))
    }

    /// Pop or peek one queued datagram with destination/interface metadata.
    /// # C: O(log N + payload bytes when peeking)
    pub fn recv_udp_meta_opts(&self, port: u16, peek: bool)
        -> Option<(Ipv4Addr, u16, Ipv4Addr, NetIfaceId, Vec<u8>)>
    {
        let q = { self.udp.lock().get(&port)?.clone() };
        let mut g = q.q.lock();
        if peek { g.front().cloned() } else { g.pop_front() }
    }

    /// F162: clone the per-port UdpRxQueue Arc out of the udp map so
    /// callers (sys_recvfrom) can park on its waitlist without holding
    /// the map lock. None when nothing's bound.
    /// # C: O(log N)
    pub fn udp_queue_arc(&self, port: u16) -> Option<Arc<UdpRxQueue>> {
        self.udp.lock().get(&port).cloned()
    }

    /// F161: release UDP port (from Drop). # C: O(log N)
    pub fn unbind_udp(&self, port: u16) {
        self.udp.lock().remove(&port);
    }

    /// F180a: v6 UDP map accessor. # C: O(1)
    pub fn udp6_map(&self) -> &Spinlock<BTreeMap<u16, Arc<crate::stack_ipv6::Udp6RxQueue>>, StackLockClass> {
        &self.udp6
    }
    /// F174: expose udp v4 map for stack_icmp. # C: O(1)
    pub fn udp_map(&self) -> &Spinlock<BTreeMap<u16, Arc<UdpRxQueue>>, StackLockClass> { &self.udp }
    /// F174: expose tcp conn map for stack_icmp. # C: O(1)
    pub fn tcp_conns_map(&self) -> &Spinlock<BTreeMap<TcpKey, Arc<TcpEntry>>, StackLockClass> { &self.tcp_conns }
    /// # C: O(1) — caller locks before iterating
    pub fn tcp_listens_map(&self) -> &Spinlock<BTreeMap<TcpListenKey, Vec<Arc<TcpListenEntry>>>, StackLockClass> { &self.tcp_listens }

    /// F161: pub send_l4_over_ipv4 wrapper. # C: O(payload + route)
    pub fn send_l4_over_ipv4_pub(&self, src: Ipv4Addr, dst: Ipv4Addr, l4: &[u8])
        -> NetResult<()>
    {
        self.send_l4_over_ipv4(src, dst, IpProto::Tcp, l4)
    }

    /// Build + xmit UDP datagram. # C: O(payload + route lookup)
    pub fn send_udp_to(&self, src_ip: Ipv4Addr, src_port: u16,
                        dst_ip: Ipv4Addr, dst_port: u16, payload: &[u8])
        -> NetResult<()>
    {
        // F122: 255.255.255.255 has no specific route entry (DHCP
        // DISCOVER fires before any route is installed). Fall back
        // to the first non-loopback iface so the broadcast lands.
        // Once route tables track scope (LOCAL_BROADCAST etc.), the
        // fallback retires.
        let (iface_id, iface) = match self.routes.lookup(dst_ip) {
            Some(r) => (r.iface, self.ifaces.lookup(r.iface)
                            .ok_or(NetError::Enetunreach)?),
            None if dst_ip.is_broadcast() => {
                let devs = self.ifaces.snapshot_devs();
                let pick = devs.iter()
                    .find(|(_, d)| d.name() != "lo")
                    .ok_or(NetError::Enetunreach)?;
                (pick.0, pick.1.clone())
            }
            None => return Err(NetError::Enetunreach),
        };
        let total = crate::udp::UDP_HDR_LEN + payload.len();
        let mut p = Pkt::with_capacity(IPV4_HDR_LEN, total + IPV4_HDR_LEN);
        let udp_total = crate::udp::UDP_HDR_LEN + payload.len();
        let slot = p.put(udp_total).map_err(|_| NetError::Enobufs)?;
        UdpHdr::build_into(src_port, dst_port, src_ip, dst_ip, payload, slot);
        let id = {
            let mut s = self.next_ip_id.lock();
            *s = s.wrapping_add(1);
            *s
        };
        self.xmit_ipv4_l4_on_iface(iface_id, iface, src_ip, dst_ip, IpProto::Udp, p.data(), 0, id)
    }

    /// Open v4 listener at (ip,port). Eaddrinuse if taken or TIME_WAIT
    /// conflict (unless SO_REUSEADDR). # C: O(log N + N_conns).
    pub fn tcp_listen(&self, local_ip: Ipv4Addr, local_port: u16, reuseaddr: bool)
        -> NetResult<Arc<TcpListenEntry>>
    {
        self.tcp_listen_ip(IpAddr::V4(local_ip), local_port, reuseaddr)
    }

    /// F180b: address-family-aware listen (v4 + v6). # C: O(log N).
    pub fn tcp_listen_ip(&self, local_ip: IpAddr, local_port: u16, reuseaddr: bool)
        -> NetResult<Arc<TcpListenEntry>>
    {
        self.tcp_listen_ip_with(local_ip, local_port, reuseaddr, false)
    }

    /// F192: SO_REUSEPORT-aware listen. When `reuseport=true`, a
    /// duplicate (ip,port) registration appends to the per-key Vec
    /// instead of failing; deliver_tcp hash-distributes SYNs across
    /// the bucket by 4-tuple. # C: O(log N).
    pub fn tcp_listen_ip_with(&self, local_ip: IpAddr, local_port: u16,
                                reuseaddr: bool, reuseport: bool)
        -> NetResult<Arc<TcpListenEntry>>
    {
        let key = TcpListenKey { local_ip, local_port };
        let mut g = self.tcp_listens.lock();
        if g.contains_key(&key) && !reuseport { return Err(NetError::Eaddrinuse); }
        if !reuseaddr {
            let conns = self.tcp_conns.lock();
            let any_v4 = IpAddr::V4(Ipv4Addr::ANY);
            let any_v6 = IpAddr::V6(crate::addr::Ipv6Addr::ANY);
            let conflict = conns.iter().any(|(k, e)| {
                k.local_port == local_port
                    && (k.local_ip == local_ip
                        || local_ip == any_v4 || local_ip == any_v6)
                    && e.conn.lock().state == crate::tcp_state::TcpState::TimeWait
            });
            if conflict { return Err(NetError::Eaddrinuse); }
        }
        let entry = Arc::new(TcpListenEntry::new(
            Endpoint { ip: local_ip, port: local_port },
        ));
        g.entry(key).or_default().push(entry.clone());
        Ok(entry)
    }

    /// Open an active TCP connection from `local` to `remote`.
    /// Emits the SYN, parks the half-open conn in the demux table.
    /// Caller (`sock::connect`) parks on `entry.rx_waiters` for the
    /// SYN-ACK; `tcp_retx_tick` handles SYN retransmission on RTO.
    /// # C: O(log N) demux insert + 1 segment xmit
    pub fn tcp_connect(&self, local_ip: Ipv4Addr, local_port: u16,
                        remote_ip: Ipv4Addr, remote_port: u16)
        -> NetResult<Arc<TcpEntry>>
    {
        self.tcp_connect_ip(
            IpAddr::V4(local_ip), local_port,
            IpAddr::V4(remote_ip), remote_port,
        )
    }

    /// F180b: address-family-aware active open (v4+v6). # C: O(log N).
    pub fn tcp_connect_ip(&self, local_ip: IpAddr, local_port: u16,
                           remote_ip: IpAddr, remote_port: u16)
        -> NetResult<Arc<TcpEntry>>
    {
        self.tcp_connect_ip_bound(local_ip, local_port, remote_ip, remote_port, None)
    }

    /// Pop one accepted connection from listener's backlog. # C: O(1)
    pub fn tcp_accept(&self, listener: &TcpListenEntry) -> Option<Arc<TcpEntry>> {
        listener.accept_q.lock().pop_front()
    }

    /// F164: send `data`; bounded by `sndbuf_cap`. Returns Eagain
    /// when full. # C: O(data + N segments)
    pub fn tcp_send(&self, entry: &TcpEntry, data: &[u8], sndbuf_cap: usize, nodelay: bool, cork: bool)
        -> NetResult<usize>
    {
        let (segs, accepted, src, dst, tos) = {
            let mut c = entry.conn.lock();
            // Quotas: send_buf bytes + retx_q bytes both count
            // against SO_SNDBUF (unACKed data total — RFC 1122
            // §4.2.2.1 / Linux sk_wmem_queued).
            let in_flight: usize = c.retx_q.iter().map(|s| s.payload.len()).sum();
            let used = c.send_buf.len() + in_flight;
            let avail = sndbuf_cap.saturating_sub(used);
            if avail == 0 && !data.is_empty() { return Err(NetError::Eagain); }
            let accept = core::cmp::min(avail, data.len());
            c.send(&data[..accept]);
            let segs = c.output(1500, nodelay, cork);
            (segs, accept, c.local.ip, c.remote.ip, ecn_tos(&c))
        };
        let n = segs.len();
        for s in &segs {
            self.send_l4_over_ip_tos_bound(src, dst, IpProto::Tcp, s, tos, entry.bound_iface())?;
        }
        // F159: stamp the last N retx_q entries (one per emitted segment)
        // with the actual xmit time.
        stamp_last_sent(entry, n);
        Ok(accepted)
    }

    /// Application drains up to `max` bytes from the recv buffer.
    /// # C: O(min(max, recv_buf.len()))
    pub fn tcp_recv(&self, entry: &TcpEntry, max: usize) -> Vec<u8> {
        entry.conn.lock().recv(max)
    }

    /// Graceful close: emit FIN; demux drives the rest. # C: O(1)
    pub fn tcp_close(&self, entry: &TcpEntry) -> NetResult<()> {
        let (seg, src, dst, tos) = {
            let mut c = entry.conn.lock();
            let s = c.local_close().map_err(|_| NetError::Eio)?;
            (s, c.local.ip, c.remote.ip, ecn_tos(&c))
        };
        self.send_l4_over_ip_tos_bound(src, dst, IpProto::Tcp, &seg, tos, entry.bound_iface())
    }

    /// F174: ICMP Destination Unreachable → SO_ERROR on origin sock.
    /// Implementation moved to stack_icmp.rs (1000-line cap).
    fn handle_dest_unreach(&self, code: u8, payload: &[u8]) {
        crate::stack_icmp::handle_dest_unreach(self, code, payload)
    }

    /// F159: RTO scanner. Re-emits expired segs; drops conns past
    /// retry ceilings (SYN=6, data=15). # C: O(N_conns·retx_q).
    pub fn tcp_retx_tick(&self, now_ns: u64) {
        // Snapshot the conn list to keep the tcp_conns lock short.
        let entries: Vec<(TcpKey, Arc<TcpEntry>)> = {
            let g = self.tcp_conns.lock();
            g.iter().map(|(k, v)| (*k, v.clone())).collect()
        };
        let mut to_drop: Vec<TcpKey> = Vec::new();
        // F161: 2*MSL linger before reclaiming a TIME_WAIT 4-tuple
        // (Linux tcp_fin_timeout default 60 s). Closed conns are
        // dropped immediately — no 4-tuple reservation needed once
        // both sides agree the connection is gone.
        const TW_TIMEOUT_NS: u64 = 60_000_000_000;
        for (key, entry) in entries.iter() {
            // Per-entry: decide retx + drop under the conn lock,
            // collect segments to emit after dropping it.
            let (segs, abort, src, dst) = {
                let mut c = entry.conn.lock();
                // F161: TIME_WAIT timer + Closed-cleanup. Reap any
                // conn that has reached Closed, or has lingered in
                // TimeWait past 2*MSL. Stamp tw_start_ns on first
                // observation if zero.
                if c.state == crate::tcp_state::TcpState::Closed {
                    (Vec::new(), true, c.local.ip, c.remote.ip)
                } else if c.state == crate::tcp_state::TcpState::TimeWait {
                    if c.tw_start_ns == 0 { c.tw_start_ns = now_ns; }
                    if now_ns.saturating_sub(c.tw_start_ns) >= TW_TIMEOUT_NS {
                        c.state = crate::tcp_state::TcpState::Closed;
                        (Vec::new(), true, c.local.ip, c.remote.ip)
                    } else {
                        (Vec::new(), false, c.local.ip, c.remote.ip)
                    }
                } else if c.retx_q.is_empty() {
                    (Vec::new(), false, c.local.ip, c.remote.ip)
                } else {
                    let front_is_syn = (c.retx_q.front().unwrap().flags
                        & crate::tcp_hdr::flags::SYN) != 0;
                    let max = if front_is_syn { 6 } else { 15 };
                    let max_retries = c.retx_q.iter().map(|s| s.retries).max().unwrap_or(0);
                    if max_retries >= max {
                        // Give up on this connection. F163: surface as
                        // SO_ERROR = ETIMEDOUT so a getsockopt after
                        // async-connect's EPOLLOUT can report the cause.
                        if c.error_eno == 0 {
                            c.error_eno = syscall::errno::Errno::Etimedout as i32;
                        }
                        c.state = crate::tcp_state::TcpState::Closed;
                        c.retx_q.clear();
                        (Vec::new(), true, c.local.ip, c.remote.ip)
                    } else {
                        let segs = c.retransmit_due(now_ns);
                        (segs, false, c.local.ip, c.remote.ip)
                    }
                }
            };
            for s in &segs {
                let _ = self.send_l4_over_ip_bound(src, dst, IpProto::Tcp, s, entry.bound_iface());
            }
            // F193: keepalive probe scheduling. Idle for ka_idle_ns →
            // fire probes at ka_intvl_ns cadence; abort after ka_cnt_max.
            let (ka_seg, ka_abort, ka_src, ka_dst) = {
                let mut c = entry.conn.lock();
                let probe = c.keepalive_due(now_ns);
                let abort_ka = c.ka_count > c.ka_cnt_max;
                if abort_ka && c.error_eno == 0 {
                    c.error_eno = syscall::errno::Errno::Etimedout as i32;
                    c.state = crate::tcp_state::TcpState::Closed;
                }
                (probe, abort_ka, c.local.ip, c.remote.ip)
            };
            if let Some(s) = &ka_seg {
                let _ = self.send_l4_over_ip_bound(ka_src, ka_dst, IpProto::Tcp, s, entry.bound_iface());
            }
            if ka_abort {
                to_drop.push(*key);
                #[cfg(target_os = "oxide-kernel")]
                entry.rx_waiters.wake_all();
                continue;
            }
            if abort {
                to_drop.push(*key);
                #[cfg(target_os = "oxide-kernel")]
                entry.rx_waiters.wake_all();
            } else if !segs.is_empty() {
                // Wake too — connect waiters might have been parked
                // forever otherwise on a successful retx that revives
                // the handshake.
                #[cfg(target_os = "oxide-kernel")]
                entry.rx_waiters.wake_all();
            }
        }
        if !to_drop.is_empty() {
            let mut g = self.tcp_conns.lock();
            for k in to_drop { g.remove(&k); }
        }
    }

    /// Wrap an L4 segment in IPv4 + xmit it via the routing table.
    /// # C: O(payload)
    fn send_l4_over_ipv4(&self, src: Ipv4Addr, dst: Ipv4Addr,
                          proto: IpProto, l4: &[u8]) -> NetResult<()>
    {
        self.send_l4_over_ipv4_tos(src, dst, proto, l4, 0)
    }

    /// F190: ECN TOS variant. # C: O(payload)
    pub(crate) fn send_l4_over_ipv4_tos(&self, src: Ipv4Addr, dst: Ipv4Addr,
                          proto: IpProto, l4: &[u8], tos: u8) -> NetResult<()>
    {
        let route = self.routes.lookup(dst).ok_or(NetError::Enetunreach)?;
        let iface = self.ifaces.lookup(route.iface).ok_or(NetError::Enetunreach)?;
        let id = { let mut s = self.next_ip_id.lock(); *s = s.wrapping_add(1); *s };
        self.xmit_ipv4_l4_on_iface(route.iface, iface, src, dst, proto, l4, tos, id)
    }

    /// Emit one IPv4 L4 payload on a selected iface, fragmenting when
    /// `IP header + payload` exceeds the iface MTU. # C: O(payload)
    pub(crate) fn xmit_ipv4_l4_on_iface(&self, iface_id: NetIfaceId,
        iface: Arc<dyn NetDev>, src: Ipv4Addr, dst: Ipv4Addr, proto: IpProto,
        l4: &[u8], tos: u8, id: u16) -> NetResult<()>
    {
        self.xmit_ipv4_l4_on_iface_opts(
            iface_id, iface, src, dst, proto, l4, tos, crate::ipv4::IPV4_DEFAULT_TTL, id,
        )
    }

    /// Emit one IPv4 L4 payload with explicit TOS and TTL on a selected iface,
    /// fragmenting when `IP header + payload` exceeds the iface MTU. # C: O(payload)
    pub(crate) fn xmit_ipv4_l4_on_iface_opts(&self, iface_id: NetIfaceId,
        iface: Arc<dyn NetDev>, src: Ipv4Addr, dst: Ipv4Addr, proto: IpProto,
        l4: &[u8], tos: u8, ttl: u8, id: u16) -> NetResult<()>
    {
        let mtu = iface.mtu() as usize;
        if l4.len() + IPV4_HDR_LEN <= mtu {
            let total = IPV4_HDR_LEN + l4.len();
            let mut p = Pkt::with_capacity(IPV4_HDR_LEN, total + IPV4_HDR_LEN);
            p.put(l4.len()).map_err(|_| NetError::Enobufs)?.copy_from_slice(l4);
            crate::ipv4::push_ipv4_header_tos_ttl(&mut p, src, dst, proto, id, tos, ttl)
                .map_err(|_| NetError::Enobufs)?;
            p.proto = crate::addr::eth_p::IPV4;
            p.iface = Some(iface_id);
            if !nf_output(&p, NFPROTO_IPV4) { return Ok(()); }
            return iface.xmit(p);
        }

        let max_payload = mtu.saturating_sub(IPV4_HDR_LEN) & !7usize;
        if max_payload == 0 { return Err(NetError::Enobufs); }
        let mut off = 0usize;
        while off < l4.len() {
            let take = core::cmp::min(max_payload, l4.len() - off);
            let more = off + take < l4.len();
            let frag_off_units = (off / 8) as u16;
            let flags_frag = if more { 0x2000 } else { 0 } | frag_off_units;
            let total = IPV4_HDR_LEN + take;
            let mut p = Pkt::with_capacity(IPV4_HDR_LEN, total + IPV4_HDR_LEN);
            p.put(take).map_err(|_| NetError::Enobufs)?.copy_from_slice(&l4[off..off + take]);
            crate::ipv4::push_ipv4_header_tos_ttl_frag(&mut p, src, dst, proto, id, tos, ttl, flags_frag)
                .map_err(|_| NetError::Enobufs)?;
            p.proto = crate::addr::eth_p::IPV4;
            p.iface = Some(iface_id);
            if nf_output(&p, NFPROTO_IPV4) {
                iface.xmit(p)?;
            }
            off += take;
        }
        Ok(())
    }

    // F180b: send_l4 in stack_ipv6.rs.

    /// Demux IPv4 → ICMP/UDP/TCP. # C: O(payload)
    pub fn deliver_rx(&self, iface: NetIfaceId, l3: &[u8]) -> NetResult<()> {
        // PRE_ROUTING fires on every received packet before the routing
        // decision; this is a host stack so all accepted packets are then
        // delivered locally → LOCAL_IN (no FORWARD path).
        if nf_hook_eval(NF_INET_PRE_ROUTING, l3, NFPROTO_IPV4) == 0 { return Ok(()); }
        if nf_hook_eval(NF_INET_LOCAL_IN, l3, NFPROTO_IPV4) == 0 { return Ok(()); }
        let hdr = Ipv4Hdr::parse(l3).map_err(|_| NetError::Einval)?;
        let total = hdr.total_len as usize;
        if total > l3.len() { return Err(NetError::Einval); }
        let frag_payload = &l3[hdr.ihl_bytes() .. total];
        let assembled;
        let mf = (hdr.flags_frag & 0x2000) != 0;
        let off8 = (hdr.flags_frag & 0x1FFF) as usize;
        let payload: &[u8] = if mf || off8 != 0 {
            let k = crate::ipv4_reasm::ReasmKey { src: hdr.src, dst: hdr.dst, proto: hdr.proto, id: hdr.id };
            match self.ipv4_reasm.push(k, net_now_ns(), off8 * 8, frag_payload, mf) {
                Some(b) => { assembled = b; &assembled[..] }
                None    => return Ok(()),
            }
        } else { frag_payload };
        match hdr.proto {
            p if p == IpProto::Icmp as u8 => {
                let echo = match icmp::IcmpEcho::parse(payload) {
                    Ok(h) => h, Err(_) => return Ok(()),
                };
                if echo.typ == ICMP_TYPE_ECHO_REQUEST {
                    let reply = match icmp::build_echo_reply(payload) {
                        Ok(r) => r, Err(_) => return Ok(()),
                    };
                    let total = IPV4_HDR_LEN + reply.len();
                    let mut p = Pkt::with_capacity(IPV4_HDR_LEN, total + IPV4_HDR_LEN);
                    p.put(reply.len()).map_err(|_| NetError::Enobufs)?
                        .copy_from_slice(&reply);
                    let id = { let mut s = self.next_ip_id.lock(); *s = s.wrapping_add(1); *s };
                    push_ipv4_header(&mut p, hdr.dst, hdr.src, IpProto::Icmp, id)
                        .map_err(|_| NetError::Enobufs)?;
                    p.proto = crate::addr::eth_p::IPV4;
                    p.iface = Some(iface);
                    let dev = self.ifaces.lookup(iface).ok_or(NetError::Enetunreach)?;
                    // ICMP echo reply is kernel-generated → LOCAL_OUT + POST_ROUTING.
                    if nf_output(&p, NFPROTO_IPV4) { dev.xmit(p)?; }
                } else if echo.typ == icmp::ICMP_TYPE_DEST_UNREACH {
                    self.handle_dest_unreach(echo.code, payload);
                }
            }
            p if p == IpProto::Udp as u8 => {
                let udp = UdpHdr::parse(payload, hdr.src, hdr.dst)
                    .map_err(|_| NetError::Einval)?;
                // Clone the queue Arc out of the map then drop the
                // map lock before touching the queue itself. wake_all
                // takes the waitlist lock + runqueue inner; we must
                // not hold the udp-map lock across either.
                let q_arc = { self.udp.lock().get(&udp.dst_port).cloned() };
                if let Some(q) = q_arc {
                    let bound = q.bound_ifindex.load(core::sync::atomic::Ordering::Acquire);
                    if bound != 0 && bound != iface.raw() { return Ok(()); }
                    let body = &payload[crate::udp::UDP_HDR_LEN .. udp.length as usize];
                    // SO_ATTACH_BPF: a 0 verdict drops the datagram.
                    let drop = { q.bpf_filter.lock().as_ref()
                        .map(|insns| !bpf_accept(insns, body)).unwrap_or(false) };
                    if drop { return Ok(()); }
                    q.q.lock().push_back((hdr.src, udp.src_port, hdr.dst, iface, body.to_vec()));
                    #[cfg(target_os = "oxide-kernel")]
                    {
                        q.waiters.wake_all();
                        // F181a: targeted epoll wake on bound socket.
                        let slot = q.poll_subs.lock().clone();
                        if let Some(weak) = slot {
                            if let Some(s) = weak.upgrade() { s.notify(); }
                        }
                    }
                }
            }
            p if p == IpProto::Tcp as u8 =>
                self.deliver_tcp(iface, IpAddr::V4(hdr.src), IpAddr::V4(hdr.dst), payload)?,
            _ => {}
        }
        Ok(())
    }

    /// TCP demux. Look up an established connection by 4-tuple
    /// first; on miss, look for a matching listener and (on SYN)
    /// instantiate a new connection from it. Drives the matched
    /// TcpConn's `input`; xmit any returned response segment.
    /// # C: O(log N) lookup + O(payload) handler
    pub(crate) fn deliver_tcp(&self, iface: NetIfaceId,
                    src_ip: IpAddr, dst_ip: IpAddr, seg: &[u8])
        -> NetResult<()>
    {
        if seg.len() < TCP_HDR_MIN_LEN { return Err(NetError::Einval); }
        let hdr = match crate::tcp_hdr::parse_ip(seg, src_ip, dst_ip) {
            Ok(h) => h, Err(_) => return Ok(()),
        };
        let key = TcpKey {
            local_ip: dst_ip, local_port: hdr.dst_port,
            remote_ip: src_ip, remote_port: hdr.src_port,
        };
        // Established-conn lookup first.
        let entry = {
            let g = self.tcp_conns.lock();
            g.get(&key).cloned()
        };
        if let Some(entry) = entry {
            if entry.bound_iface().is_some_and(|id| id != iface) { return Ok(()); }
            // F158: wake on either recv_buf growth or terminal state
            let (pre_len, _pre_state) = {
                let c = entry.conn.lock();
                (c.recv_buf.len(), c.state)
            };
            let resp = entry.conn.lock().input(src_ip, dst_ip, seg)
                .map_err(|_| NetError::Einval)?;
            let (post_len, post_state) = {
                let c = entry.conn.lock();
                (c.recv_buf.len(), c.state)
            };
            if let Some(r) = resp {
                self.send_l4_over_ip_bound(dst_ip, src_ip, IpProto::Tcp, &r, entry.bound_iface())?;
            }
            // F175: post-input output drain. ACK that clears retx_q
            // unblocks Nagle-held sends; pump them out now. Use
            // nodelay=true because the Nagle condition is already
            // expressed by retx_q.is_empty(); calling with true just
            // skips the redundant guard.
            let drain_segs = {
                let mut c = entry.conn.lock();
                let (src, dst, tos) = (c.local.ip, c.remote.ip, ecn_tos(&c));
                let segs = c.output(1500, true, false);
                (segs, src, dst, tos)
            };
            let (segs, src, dst, tos) = drain_segs;
            for s in &segs {
                self.send_l4_over_ip_tos_bound(src, dst, IpProto::Tcp, s, tos, entry.bound_iface())?;
            }
            stamp_last_sent(&entry, segs.len());
            // F159+F181a: wake conn rx + targeted epoll.
            #[cfg(target_os = "oxide-kernel")]
            {
                let _ = (pre_len, post_len, post_state);
                entry.rx_waiters.wake_all();
                let slot = entry.poll_subs.lock().clone();
                if let Some(weak) = slot {
                    if let Some(s) = weak.upgrade() { s.notify(); }
                }
            }
            return Ok(());
        }
        // Listener path: only SYNs spawn new conns.
        if (hdr.flags & tcp_flags::SYN) == 0 { return Ok(()); }
        let lkey = TcpListenKey { local_ip: dst_ip, local_port: hdr.dst_port };
        let any_for_family = match dst_ip {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::ANY),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::ANY),
        };
        let bucket = {
            let g = self.tcp_listens.lock();
            g.get(&lkey).cloned()
                .or_else(|| g.get(&TcpListenKey { local_ip: any_for_family, local_port: hdr.dst_port }).cloned())
        };
        let bucket = match bucket { Some(b) if !b.is_empty() => b, _ => return Ok(()) };
        // F192: SO_REUSEPORT hash distribute by 4-tuple. Single-entry
        // bucket → idx 0.
        let idx = if bucket.len() == 1 { 0 } else {
            let mut h: u32 = 0;
            let v4_oct;
            let v6_arr;
            let bytes: &[u8] = match src_ip {
                IpAddr::V4(a) => { v4_oct = a.octets(); &v4_oct[..] }
                IpAddr::V6(a) => { v6_arr = a.0;         &v6_arr[..] }
            };
            for b in bytes { h = h.wrapping_mul(31).wrapping_add(*b as u32); }
            h = h.wrapping_add(hdr.src_port as u32).wrapping_add(hdr.dst_port as u32);
            (h as usize) % bucket.len()
        };
        let mut listener = None;
        for off in 0..bucket.len() {
            let cand = bucket[(idx + off) % bucket.len()].clone();
            if cand.bound_iface().is_none_or(|id| id == iface) {
                listener = Some(cand);
                break;
            }
        }
        let Some(listener) = listener else { return Ok(()); };
        // F180b: synthesise a per-conn local endpoint that pins the
        // wildcard listener to the actual delivery dst — so outbound
        // segments carry a real src, not 0.0.0.0/::.
        let mut local_ep = listener.local;
        if local_ep.ip == IpAddr::V4(Ipv4Addr::ANY) || local_ep.ip == IpAddr::V6(Ipv6Addr::ANY) {
            local_ep.ip = dst_ip;
        }
        // F192: enforce listen backlog. Drop the SYN on the floor
        // when accept_q is already at cap — peer retries naturally
        // via SYN retx.
        {
            let q = listener.accept_q.lock();
            let cap = listener.backlog.load(core::sync::atomic::Ordering::Acquire);
            if q.len() >= cap { return Ok(()); }
        }
        let mut new_conn = TcpConn::new_listener(local_ep);
        // F184: SYN-ACK we're about to build advertises our MSS too.
        let bound = listener.bound_iface();
        new_conn.own_mss = self.mss_for_dst_on_iface(src_ip, bound);
        let resp = new_conn.input(src_ip, dst_ip, seg)
            .map_err(|_| NetError::Einval)?;
        let new_entry = Arc::new(TcpEntry::new(new_conn));
        new_entry.set_bound_iface(bound);
        self.tcp_conns.lock().insert(key, new_entry.clone());
        listener.accept_q.lock().push_back(new_entry);
        if let Some(r) = resp {
            self.send_l4_over_ip_bound(dst_ip, src_ip, IpProto::Tcp, &r, bound)?;
        }
        // F160: wake any blocking accept() parked on this listener.
        #[cfg(target_os = "oxide-kernel")]
        {
            listener.accept_waiters.wake_all();
            // F181a: targeted epoll wake for the listener fd.
            let slot = listener.poll_subs.lock().clone();
            if let Some(weak) = slot {
                if let Some(s) = weak.upgrade() { s.notify(); }
            }
        }
        Ok(())
    }

    /// Drain lo xmit → deliver_rx; v6 frames route to deliver_rx_ipv6.
    /// # C: O(N pending)
    pub fn drain_loopback(&self, iface: NetIfaceId, lo: &LoopbackDev) {
        while let Some(p) = lo.rx_pop() {
            // F180b: dispatch by ethertype so v6 lo round-trips work.
            if p.proto == crate::addr::eth_p::IPV6 {
                let _ = self.deliver_rx_ipv6(iface, p.data());
            } else {
                let _ = self.deliver_rx(iface, p.data());
            }
        }
    }
}

impl Default for NetStack { fn default() -> Self { Self::new() } }
