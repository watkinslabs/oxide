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
use crate::ipv6::{Ipv6Hdr, IPV6_HDR_LEN, push_ipv6_header};
use crate::loopback::LoopbackDev;
use crate::netdev::{IfaceRegistry, NetDev, NetError, NetResult};
use crate::pkt::Pkt;
use crate::route::RouteTable;
use crate::udp::UdpHdr;
use crate::tcp_hdr::{TcpHdr, flags as tcp_flags, TCP_HDR_MIN_LEN};
use crate::tcp_conn::{TcpConn, Endpoint};

/// Netfilter verdict callback. Verdict u32: NF_DROP=0, NF_ACCEPT=1.
pub type NfHookFn = fn(hook_id: u32, pkt: &[u8]) -> u32;

static NF_HOOK: core::sync::atomic::AtomicPtr<()> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// Install netfilter bridge. Idempotent. # C: O(1)
pub fn install_nf_hook(f: NfHookFn) {
    NF_HOOK.store(f as *mut (), core::sync::atomic::Ordering::Release);
}

/// Invoke the registered netfilter hook. Returns NF_ACCEPT (1)
/// when no hook is installed so the default-accept path still
/// works without netfilter wired.
/// # C: O(1) when no hook; otherwise O(eval)
fn nf_hook_eval(hook_id: u32, pkt: &[u8]) -> u32 {
    let raw = NF_HOOK.load(core::sync::atomic::Ordering::Acquire);
    if raw.is_null() { return 1; /* NF_ACCEPT */ }
    // SAFETY: raw was installed via `install_nf_hook` with the documented `fn(u32, &[u8]) -> u32` signature.
    let f: NfHookFn = unsafe { core::mem::transmute(raw) };
    f(hook_id, pkt)
}

pub const NF_INET_LOCAL_IN: u32 = 1;

/// Per-port UDP rx queue. The bind-syscall reads from here.
/// F162: q + waiters live behind their own locks so `deliver_rx`
/// and `sys_recvfrom` can serialize against each other without
/// holding the outer udp-map lock across long operations / parks.
pub struct UdpRxQueue {
    pub bound_ip:   Ipv4Addr,
    pub bound_port: u16,
    /// Datagrams waiting for a reader. Each entry is
    /// (src_ip, src_port, payload bytes).
    pub q: Spinlock<VecDeque<(Ipv4Addr, u16, Vec<u8>)>, StackLockClass>,
    /// F162: tasks parked in blocking sys_recvfrom on this port.
    /// deliver_rx wakes after pushing.
    #[cfg(target_os = "oxide-kernel")]
    pub waiters: sched::live::WaitList,
    /// F174: per-port pending async error (ICMP destination
    /// unreachable, etc.). Linux errno value; cleared by SO_ERROR
    /// read or consumed by the next recvfrom call.
    pub error_eno: core::sync::atomic::AtomicI32,
    /// F181a: epoll subscribers of the bound socket — set via
    /// `register_poll_subs` after bind. deliver_rx UDP arm wakes
    /// targeted instead of broadcasting.
    pub poll_subs: Spinlock<Option<alloc::sync::Weak<vfs::PollSubscribers>>, StackLockClass>,
}

// F180a Udp6RxQueue + IPv6 NetStack methods moved to stack_ipv6.rs.

impl UdpRxQueue {
    /// F174: read + clear the pending per-port error (ICMP unreach).
    /// Returns 0 if no error pending. Linux semantic: SO_ERROR /
    /// next recv consumes the error.
    /// # C: O(1)
    pub fn take_error(&self) -> i32 {
        self.error_eno.swap(0, core::sync::atomic::Ordering::AcqRel)
    }
    /// # C: O(1)
    pub fn new(bound_ip: Ipv4Addr, bound_port: u16) -> Self {
        Self {
            bound_ip, bound_port,
            q: Spinlock::new(VecDeque::new()),
            #[cfg(target_os = "oxide-kernel")]
            waiters: sched::live::WaitList::new(),
            error_eno: core::sync::atomic::AtomicI32::new(0),
            poll_subs: Spinlock::new(None),
        }
    }

    /// F181a: register bound socket's subscribers.
    /// # C: O(1)
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
    /// F158: tasks parked in a blocking sys_read on this connection.
    /// `deliver_tcp` wakes the list after appending to recv_buf or
    /// after a state change that ends data-transfer (FIN / RST).
    /// Kernel-only: hosted tests don't run the scheduler.
    #[cfg(target_os = "oxide-kernel")]
    pub rx_waiters: sched::live::WaitList,
    /// F181a: per-fd epoll subscribers of the owning InetSocket.
    /// Registered via `register_poll_subs` when the entry is bound
    /// (connect → TcpConn assignment; accept → new socket). Wakes
    /// from deliver_tcp use this instead of the global broadcast.
    pub poll_subs: Spinlock<Option<alloc::sync::Weak<vfs::PollSubscribers>>, StackLockClass>,
}

impl TcpEntry {
    /// # C: O(1)
    pub fn new(conn: TcpConn) -> Self {
        Self {
            conn: Spinlock::new(conn),
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

pub struct TcpListenEntry {
    /// Backlog of accepted-but-not-yet-claimed Arc<TcpEntry>.
    pub accept_q: Spinlock<VecDeque<Arc<TcpEntry>>, StackLockClass>,
    pub local: Endpoint,
    /// F160: tasks parked in blocking sys_accept waiting for a SYN.
    /// `deliver_tcp` (listener branch) wakes the list after pushing
    /// a freshly-spawned TcpEntry to accept_q.
    #[cfg(target_os = "oxide-kernel")]
    pub accept_waiters: sched::live::WaitList,
    /// F181a: owning listener-fd epoll subscribers — wakes when
    /// accept_q grows (fd flips POLL_IN).
    pub poll_subs: Spinlock<Option<alloc::sync::Weak<vfs::PollSubscribers>>, StackLockClass>,
}

impl TcpListenEntry {
    /// # C: O(1)
    pub fn new(local: Endpoint) -> Self {
        Self {
            accept_q: Spinlock::new(VecDeque::new()),
            local,
            #[cfg(target_os = "oxide-kernel")]
            accept_waiters: sched::live::WaitList::new(),
            poll_subs: Spinlock::new(None),
        }
    }

    /// F181a: register listener-fd subscribers.
    /// # C: O(1)
    pub fn register_poll_subs(&self, subs: &alloc::sync::Arc<vfs::PollSubscribers>) {
        *self.poll_subs.lock() = Some(alloc::sync::Arc::downgrade(subs));
    }
}

pub struct NetStack {
    pub ifaces: IfaceRegistry,
    pub routes: RouteTable,
    udp:        Spinlock<BTreeMap<u16, Arc<UdpRxQueue>>, StackLockClass>,
    /// F180a: IPv6 UDP socket map. Accessor `udp6_map()` exposed to
    /// `stack_ipv6` impls without making the field pub.
    udp6:       Spinlock<BTreeMap<u16, Arc<crate::stack_ipv6::Udp6RxQueue>>, StackLockClass>,
    tcp_conns:    Spinlock<BTreeMap<TcpKey, Arc<TcpEntry>>, StackLockClass>,
    tcp_listens:  Spinlock<BTreeMap<TcpListenKey, Arc<TcpListenEntry>>, StackLockClass>,
    /// Monotonic id for IP packets we emit.
    next_ip_id: Spinlock<u16, StackLockClass>,
    /// Monotonic ISN base for TCP active opens.
    next_isn: Spinlock<u32, StackLockClass>,
    /// F180c: global NDP cache (ip → MAC).
    pub ndp: crate::ndp::NdpCache,
    /// F180c: per-iface IPv6 address registry (NS responder).
    v6_addrs: Spinlock<BTreeMap<NetIfaceId, Vec<crate::addr::Ipv6Addr>>, StackLockClass>,
}

impl NetStack {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self {
            ifaces: IfaceRegistry::new(),
            routes: RouteTable::new(),
            udp:    Spinlock::new(BTreeMap::new()),
            udp6:   Spinlock::new(BTreeMap::new()),
            tcp_conns:   Spinlock::new(BTreeMap::new()),
            tcp_listens: Spinlock::new(BTreeMap::new()),
            next_ip_id: Spinlock::new(1),
            next_isn:   Spinlock::new(0x1000_0000),
            ndp:        crate::ndp::NdpCache::new(),
            v6_addrs:   Spinlock::new(BTreeMap::new()),
        }
    }

    /// F184: MSS for `dst` = egress iface MTU − (v4:40, v6:60). 0 if
    /// no iface — caller falls back to OWN_MSS_DEFAULT. # C: O(log N).
    pub fn mss_for_dst(&self, dst: IpAddr) -> u16 {
        let mtu = match dst {
            IpAddr::V4(d) => self.routes.lookup(d)
                .and_then(|r| self.ifaces.lookup(r.iface))
                .map(|i| i.mtu()),
            IpAddr::V6(d) => {
                let devs = self.ifaces.snapshot_devs();
                let iface_id = if d == Ipv6Addr::LOOPBACK {
                    devs.iter().find(|(_, dev)| dev.name() == "lo").map(|(i, _)| *i)
                } else {
                    devs.iter().find(|(_, dev)| dev.name() != "lo").map(|(i, _)| *i)
                };
                iface_id.and_then(|i| self.ifaces.lookup(i)).map(|i| i.mtu())
            }
        };
        let overhead = if matches!(dst, IpAddr::V6(_)) { 60 } else { 40 };
        mtu.map(|m| (m.saturating_sub(overhead)).min(0xFFFF) as u16).unwrap_or(0)
    }

    /// F180c: register a v6 addr on `iface`; NS replies. # C: O(log N)
    pub fn add_v6_addr(&self, iface: NetIfaceId, ip: crate::addr::Ipv6Addr) {
        self.v6_addrs.lock().entry(iface).or_default().push(ip);
    }
    /// F180c: is `ip` bound on `iface`? # C: O(N addrs)
    pub fn v6_addr_owned_by(&self, iface: NetIfaceId, ip: crate::addr::Ipv6Addr) -> bool {
        self.v6_addrs.lock().get(&iface).map(|v| v.iter().any(|a| *a == ip)).unwrap_or(false)
    }

    /// Boot-time wiring: create + register a loopback netdev,
    /// add the canonical 127.0.0.0/8 route through it. Returns
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
        (id, lo)
    }

    /// Reserve `port` for incoming UDP datagrams to `bind_ip`.
    /// `Eaddrinuse` if already bound.
    /// # C: O(log N)
    pub fn bind_udp(&self, bind_ip: Ipv4Addr, port: u16) -> NetResult<()> {
        let mut g = self.udp.lock();
        if g.contains_key(&port) { return Err(NetError::Eaddrinuse); }
        g.insert(port, Arc::new(UdpRxQueue::new(bind_ip, port)));
        Ok(())
    }

    /// Pop one queued datagram for `port`, blocking-style: returns
    /// `None` immediately if nothing is queued.
    /// # C: O(log N)
    pub fn recv_udp(&self, port: u16) -> Option<(Ipv4Addr, u16, Vec<u8>)> {
        let q = { self.udp.lock().get(&port)?.clone() };
        let popped = q.q.lock().pop_front();
        popped
    }

    /// F162: clone the per-port UdpRxQueue Arc out of the udp map so
    /// callers (sys_recvfrom) can park on its waitlist without holding
    /// the map lock. None when nothing's bound.
    /// # C: O(log N)
    pub fn udp_queue_arc(&self, port: u16) -> Option<Arc<UdpRxQueue>> {
        self.udp.lock().get(&port).cloned()
    }

    /// F161: release a previously-bound UDP port. Called from
    /// `InetSocket::Drop` so close on a UDP socket frees its port
    /// for reuse without an explicit close() syscall hook.
    /// # C: O(log N)
    pub fn unbind_udp(&self, port: u16) {
        self.udp.lock().remove(&port);
    }

    /// F180a: expose the v6 UDP map to `stack_ipv6` impls without
    /// making the field pub-everywhere.
    /// # C: O(1)
    pub fn udp6_map(&self) -> &Spinlock<BTreeMap<u16, Arc<crate::stack_ipv6::Udp6RxQueue>>, StackLockClass> {
        &self.udp6
    }
    /// F174: expose udp v4 map for stack_icmp. # C: O(1)
    pub fn udp_map(&self) -> &Spinlock<BTreeMap<u16, Arc<UdpRxQueue>>, StackLockClass> { &self.udp }
    /// F174: expose tcp conn map for stack_icmp. # C: O(1)
    pub fn tcp_conns_map(&self) -> &Spinlock<BTreeMap<TcpKey, Arc<TcpEntry>>, StackLockClass> { &self.tcp_conns }

    /// F161: public wrapper for the private send_l4_over_ipv4 path
    /// — used by `InetSocket::Drop` to emit the FIN/RST from the
    /// kernel-side close. Restricted to IpProto::Tcp; UDP / ICMP
    /// already have dedicated public entry points.
    /// # C: O(payload + route lookup)
    pub fn send_l4_over_ipv4_pub(&self, src: Ipv4Addr, dst: Ipv4Addr, l4: &[u8])
        -> NetResult<()>
    {
        self.send_l4_over_ipv4(src, dst, IpProto::Tcp, l4)
    }

    /// Build + transmit a UDP datagram. Looks up the route to
    /// `dst_ip`; if the route's iface is loopback (no L2), hand
    /// the IP packet straight to xmit.
    /// # C: O(payload + route lookup)
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
        let total = IPV4_HDR_LEN + crate::udp::UDP_HDR_LEN + payload.len();
        let mut p = Pkt::with_capacity(IPV4_HDR_LEN, total + IPV4_HDR_LEN);
        let udp_total = crate::udp::UDP_HDR_LEN + payload.len();
        let slot = p.put(udp_total).map_err(|_| NetError::Enobufs)?;
        UdpHdr::build_into(src_port, dst_port, src_ip, dst_ip, payload, slot);
        let id = {
            let mut s = self.next_ip_id.lock();
            *s = s.wrapping_add(1);
            *s
        };
        push_ipv4_header(&mut p, src_ip, dst_ip, IpProto::Udp, id)
            .map_err(|_| NetError::Enobufs)?;
        p.proto = crate::addr::eth_p::IPV4;
        p.iface = Some(iface_id);
        iface.xmit(p)
    }

    /// Open a passive listener at (`local_ip`, `local_port`).
    /// Returns the listen-entry Arc so callers can poll `accept`.
    /// `Eaddrinuse` if the (ip, port) tuple is already a listener
    /// OR if a TIME_WAIT conn lingers at that (local_ip, local_port)
    /// AND `reuseaddr == false` (POSIX SO_REUSEADDR semantic per
    /// Linux's `tcp_v4_get_port`).
    /// # C: O(log N) listener lookup + O(N_conns) TIME_WAIT scan
    pub fn tcp_listen(&self, local_ip: Ipv4Addr, local_port: u16, reuseaddr: bool)
        -> NetResult<Arc<TcpListenEntry>>
    {
        self.tcp_listen_ip(IpAddr::V4(local_ip), local_port, reuseaddr)
    }

    /// F180b: address-family-aware listen (v4 + v6). # C: O(log N).
    pub fn tcp_listen_ip(&self, local_ip: IpAddr, local_port: u16, reuseaddr: bool)
        -> NetResult<Arc<TcpListenEntry>>
    {
        let key = TcpListenKey { local_ip, local_port };
        let mut g = self.tcp_listens.lock();
        if g.contains_key(&key) { return Err(NetError::Eaddrinuse); }
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
        g.insert(key, entry.clone());
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
        let isn = {
            let mut s = self.next_isn.lock();
            *s = s.wrapping_add(0x1000);
            *s
        };
        let mut conn = TcpConn::new_client(
            Endpoint { ip: local_ip, port: local_port },
            Endpoint { ip: remote_ip, port: remote_port },
            isn,
        );
        // F184: derive advertised MSS from the egress iface MTU minus
        // L3+L4 header (v4=40, v6=60). 0 = fall back to OWN_MSS_DEFAULT.
        conn.own_mss = self.mss_for_dst(remote_ip);
        let syn = conn.active_open().map_err(|_| NetError::Eio)?;
        let entry = Arc::new(TcpEntry::new(conn));
        let key = TcpKey { local_ip, local_port, remote_ip, remote_port };
        self.tcp_conns.lock().insert(key, entry.clone());
        self.send_l4_over_ip(local_ip, remote_ip, IpProto::Tcp, &syn)?;
        // F159: stamp the queued SYN with the actual xmit time so the
        // retx scanner doesn't treat it as instantly overdue (default
        // last_sent_ns=0 from active_open). On stamp failure (no timer
        // yet, hosted tests) leave at 0 — retx_tick is a no-op there.
        stamp_last_sent(&entry, 1);
        Ok(entry)
    }

    /// Pop one accepted connection from a listener's backlog.
    /// Returns `None` if no connection is ready.
    /// # C: O(1)
    pub fn tcp_accept(&self, listener: &TcpListenEntry) -> Option<Arc<TcpEntry>> {
        listener.accept_q.lock().pop_front()
    }

    /// Application sends `data` on an established connection.
    /// Returns the number of bytes drained into segments and
    /// transmitted; bytes still queued (waiting for ACK clocking)
    /// stay in the conn's send_buf for output() to drain later.
    /// # C: O(data + N segments)
    /// Append `data` to the connection's send queue and drain
    /// whatever output() can produce immediately. Returns the byte
    /// count actually accepted into send_buf (may be less than
    /// data.len() if SO_SNDBUF would be exceeded).
    ///
    /// F164: bounded by `sndbuf_cap` — caller passes the socket's
    /// effective SO_SNDBUF. Returns Eagain when the buffer is at
    /// cap and zero bytes can be queued.
    /// # C: O(data) + O(N segments)
    pub fn tcp_send(&self, entry: &TcpEntry, data: &[u8], sndbuf_cap: usize, nodelay: bool)
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
            if avail == 0 { return Err(NetError::Eagain); }
            let accept = core::cmp::min(avail, data.len());
            c.send(&data[..accept]);
            let segs = c.output(1500, nodelay);
            (segs, accept, c.local.ip, c.remote.ip, ecn_tos(&c))
        };
        let n = segs.len();
        for s in &segs {
            self.send_l4_over_ip_tos(src, dst, IpProto::Tcp, s, tos)?;
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
        self.send_l4_over_ip_tos(src, dst, IpProto::Tcp, &seg, tos)
    }

    /// F174: ICMP Destination Unreachable → SO_ERROR on origin sock.
    /// Implementation moved to stack_icmp.rs (1000-line cap).
    fn handle_dest_unreach(&self, code: u8, payload: &[u8]) {
        crate::stack_icmp::handle_dest_unreach(self, code, payload)
    }

    /// F159: walk active TCP conns and re-emit any segments whose
    /// RTO has expired. Drops conns whose front-of-retx_q segment
    /// has been retried past a state-dependent ceiling (6 for SYN,
    /// 15 for data — Linux defaults for tcp_syn_retries /
    /// tcp_retries2). Dropped conns transition to Closed and wake
    /// their rx_waiters so parked connect / read / accept calls
    /// observe the failure.
    ///
    /// Intended call site: `virtio_net_rx_kthread`'s loop, ~100 ms
    /// cadence. Not safe from IRQ context (acquires tcp_conns lock +
    /// per-conn lock + ifaces.lookup).
    /// # C: O(N_conns * retx_q.len())
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
                let _ = self.send_l4_over_ip(src, dst, IpProto::Tcp, s);
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

    /// F190: ECN-aware variant — `tos` populates the TOS byte.
    /// # C: O(payload)
    pub(crate) fn send_l4_over_ipv4_tos(&self, src: Ipv4Addr, dst: Ipv4Addr,
                          proto: IpProto, l4: &[u8], tos: u8) -> NetResult<()>
    {
        let route = self.routes.lookup(dst).ok_or(NetError::Enetunreach)?;
        let iface = self.ifaces.lookup(route.iface).ok_or(NetError::Enetunreach)?;
        let total = IPV4_HDR_LEN + l4.len();
        let mut p = Pkt::with_capacity(IPV4_HDR_LEN, total + IPV4_HDR_LEN);
        p.put(l4.len()).map_err(|_| NetError::Enobufs)?
            .copy_from_slice(l4);
        let id = { let mut s = self.next_ip_id.lock(); *s = s.wrapping_add(1); *s };
        crate::ipv4::push_ipv4_header_tos(&mut p, src, dst, proto, id, tos)
            .map_err(|_| NetError::Enobufs)?;
        p.proto = crate::addr::eth_p::IPV4;
        p.iface = Some(route.iface);
        iface.xmit(p)
    }

    // F180b: send_l4_over_ip / send_l4_over_ipv6 live in stack_ipv6.rs.

    /// Deliver an L3 frame (starting at the IPv4 header) up the
    /// stack: parse IP, demux to ICMP / UDP / TCP, dispatch.
    /// # C: O(payload)
    pub fn deliver_rx(&self, iface: NetIfaceId, l3: &[u8]) -> NetResult<()> {
        // Netfilter LOCAL_IN hook: drop the packet silently when
        // a chain bound to NF_INET_LOCAL_IN votes Drop.
        if nf_hook_eval(NF_INET_LOCAL_IN, l3) == 0 { return Ok(()); }
        let hdr = Ipv4Hdr::parse(l3).map_err(|_| NetError::Einval)?;
        let total = hdr.total_len as usize;
        if total > l3.len() { return Err(NetError::Einval); }
        let payload = &l3[hdr.ihl_bytes() .. total];
        match hdr.proto {
            p if p == IpProto::Icmp as u8 => {
                let echo = match icmp::IcmpEcho::parse(payload) {
                    Ok(h) => h, Err(_) => return Ok(()),
                };
                if echo.typ == ICMP_TYPE_ECHO_REQUEST {
                    // Build reply, ship back via the same iface.
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
                    dev.xmit(p)?;
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
                    let body = &payload[crate::udp::UDP_HDR_LEN..];
                    q.q.lock().push_back((hdr.src, udp.src_port, body.to_vec()));
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
    pub(crate) fn deliver_tcp(&self, _iface: NetIfaceId,
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
            // F158: snapshot recv_buf len + state pre/post input() so we
            // can decide whether to wake parked readers. Wake on either
            // (a) new bytes appended to recv_buf, or (b) terminal state
            // transition (Closed / CloseWait / LastAck) so a parked
            // reader can observe EOF.
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
                self.send_l4_over_ip(dst_ip, src_ip, IpProto::Tcp, &r)?;
            }
            // F175: post-input output drain. ACK that clears retx_q
            // unblocks Nagle-held sends; pump them out now. Use
            // nodelay=true because the Nagle condition is already
            // expressed by retx_q.is_empty(); calling with true just
            // skips the redundant guard.
            let drain_segs = {
                let mut c = entry.conn.lock();
                let (src, dst, tos) = (c.local.ip, c.remote.ip, ecn_tos(&c));
                let segs = c.output(1500, true);
                (segs, src, dst, tos)
            };
            let (segs, src, dst, tos) = drain_segs;
            for s in &segs {
                self.send_l4_over_ip_tos(src, dst, IpProto::Tcp, s, tos)?;
            }
            stamp_last_sent(&entry, segs.len());
            // F159: wake unconditionally — any input may have changed
            // state (SynSent→Established for connect waiters, * → Closed
            // for terminal observers) or appended data (recv waiters).
            #[cfg(target_os = "oxide-kernel")]
            {
                let _ = (pre_len, post_len, post_state);
                entry.rx_waiters.wake_all();
                // F181a: targeted epoll wake for the owning fd.
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
        let listener = {
            let g = self.tcp_listens.lock();
            g.get(&lkey).cloned()
                .or_else(|| g.get(&TcpListenKey { local_ip: any_for_family, local_port: hdr.dst_port }).cloned())
        };
        let listener = match listener { Some(l) => l, None => return Ok(()) };
        // F180b: synthesise a per-conn local endpoint that pins the
        // wildcard listener to the actual delivery dst — so outbound
        // segments carry a real src, not 0.0.0.0/::.
        let mut local_ep = listener.local;
        if local_ep.ip == IpAddr::V4(Ipv4Addr::ANY) || local_ep.ip == IpAddr::V6(Ipv6Addr::ANY) {
            local_ep.ip = dst_ip;
        }
        let mut new_conn = TcpConn::new_listener(local_ep);
        // F184: SYN-ACK we're about to build advertises our MSS too.
        new_conn.own_mss = self.mss_for_dst(src_ip);
        let resp = new_conn.input(src_ip, dst_ip, seg)
            .map_err(|_| NetError::Einval)?;
        let new_entry = Arc::new(TcpEntry::new(new_conn));
        self.tcp_conns.lock().insert(key, new_entry.clone());
        listener.accept_q.lock().push_back(new_entry);
        if let Some(r) = resp {
            self.send_l4_over_ip(dst_ip, src_ip, IpProto::Tcp, &r)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_udp_round_trip() {
        let stack = NetStack::new();
        let (id, lo) = stack.register_loopback();
        stack.bind_udp(Ipv4Addr::LOOPBACK, 4242).unwrap();
        stack.send_udp_to(
            Ipv4Addr::LOOPBACK, 5000,
            Ipv4Addr::LOOPBACK, 4242,
            b"hello-net",
        ).unwrap();
        stack.drain_loopback(id, &lo);
        let (src, src_port, payload) = stack.recv_udp(4242).unwrap();
        assert_eq!(src, Ipv4Addr::LOOPBACK);
        assert_eq!(src_port, 5000);
        assert_eq!(payload, b"hello-net");
    }

    #[test]
    fn icmp_echo_round_trip_via_loopback() {
        let stack = NetStack::new();
        let (id, lo) = stack.register_loopback();
        // Build an Echo Request and hand it to the stack as a
        // received frame on lo. Stack should respond with an
        // Echo Reply on lo's xmit, which we then drain.
        let payload = b"oxide-icmp";
        let mut req = alloc::vec![0u8; icmp::ICMP_HDR_LEN + payload.len()];
        let mut hdr = icmp::IcmpEcho {
            typ: icmp::ICMP_TYPE_ECHO_REQUEST, code: 0,
            checksum: 0, id: 0xBEEF, seq: 1,
        };
        hdr.build_into(payload, &mut req);
        let total = IPV4_HDR_LEN + req.len();
        let mut frame = alloc::vec![0u8; total];
        let ip = Ipv4Hdr::build(
            Ipv4Addr::LOOPBACK, Ipv4Addr::LOOPBACK,
            IpProto::Icmp, req.len() as u16, 1,
        );
        ip.write_to(&mut frame[..IPV4_HDR_LEN]);
        frame[IPV4_HDR_LEN..].copy_from_slice(&req);
        stack.deliver_rx(id, &frame).unwrap();
        // lo has the reply; drain + verify.
        let reply = lo.rx_pop().unwrap();
        let parsed_ip = Ipv4Hdr::parse(reply.data()).unwrap();
        assert_eq!(parsed_ip.proto, IpProto::Icmp as u8);
        let icmp_payload = &reply.data()[IPV4_HDR_LEN .. parsed_ip.total_len as usize];
        let echo = icmp::IcmpEcho::parse(icmp_payload).unwrap();
        assert_eq!(echo.typ, icmp::ICMP_TYPE_ECHO_REPLY);
        assert_eq!(echo.id, 0xBEEF);
    }

    #[test]
    fn unbound_port_drops_silently() {
        let stack = NetStack::new();
        let (id, lo) = stack.register_loopback();
        stack.send_udp_to(
            Ipv4Addr::LOOPBACK, 1, Ipv4Addr::LOOPBACK, 9999, b"x",
        ).unwrap();
        stack.drain_loopback(id, &lo);
        assert!(stack.recv_udp(9999).is_none());
    }

    #[test]
    fn double_bind_fails() {
        let stack = NetStack::new();
        let _ = stack.register_loopback();
        stack.bind_udp(Ipv4Addr::LOOPBACK, 100).unwrap();
        assert_eq!(stack.bind_udp(Ipv4Addr::LOOPBACK, 100).err().unwrap(),
                   NetError::Eaddrinuse);
    }

    #[test]
    fn tcp_handshake_via_loopback() {
        let stack = NetStack::new();
        let (id, lo) = stack.register_loopback();
        let listener = stack.tcp_listen(Ipv4Addr::LOOPBACK, 1234, true).unwrap();
        let client = stack.tcp_connect(
            Ipv4Addr::LOOPBACK, 50000,
            Ipv4Addr::LOOPBACK, 1234,
        ).unwrap();
        // Drain lo a couple of times: SYN → SYN+ACK → ACK.
        for _ in 0..3 { stack.drain_loopback(id, &lo); }
        let server = stack.tcp_accept(&listener).expect("accepted");
        assert_eq!(client.conn.lock().state, crate::tcp_state::TcpState::Established);
        assert_eq!(server.conn.lock().state, crate::tcp_state::TcpState::Established);
    }

    #[test]
    fn tcp_data_round_trip_via_loopback() {
        let stack = NetStack::new();
        let (id, lo) = stack.register_loopback();
        let listener = stack.tcp_listen(Ipv4Addr::LOOPBACK, 1234, true).unwrap();
        let client = stack.tcp_connect(
            Ipv4Addr::LOOPBACK, 50000,
            Ipv4Addr::LOOPBACK, 1234,
        ).unwrap();
        for _ in 0..3 { stack.drain_loopback(id, &lo); }
        let server = stack.tcp_accept(&listener).unwrap();
        stack.tcp_send(&client, b"oxide-tcp-payload", 65536, true).unwrap();
        for _ in 0..3 { stack.drain_loopback(id, &lo); }
        let got = stack.tcp_recv(&server, 1024);
        assert_eq!(&got[..], b"oxide-tcp-payload");
    }

    #[test]
    fn route_miss_is_enetunreach() {
        let stack = NetStack::new();
        let _ = stack.register_loopback();
        // 8.8.8.8 has no route — expect Enetunreach.
        assert_eq!(
            stack.send_udp_to(Ipv4Addr::LOOPBACK, 1, Ipv4Addr::new(8,8,8,8), 1, b"x")
                 .err().unwrap(),
            NetError::Enetunreach,
        );
    }
}
