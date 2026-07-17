use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;

use sync::{Spinlock, Socket as LockClass};

use crate::addr::{Ipv4Addr, NetIfaceId};
use crate::bpf_filter::SocketFilter;
use crate::mcast_filter::SocketMcast;
use crate::netdev::{NetError, NetResult};
use crate::socket_error::SocketError;

pub const DEFAULT_RAW4_RCVBUF: usize = 212_992;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Raw4Datagram {
    pub packet: Vec<u8>,
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub iface: NetIfaceId,
    pub ttl: u8,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Raw4StateSnapshot {
    pub local: Ipv4Addr,
    pub remote: Option<Ipv4Addr>,
    pub bound_iface: Option<NetIfaceId>,
    pub queued_bytes: usize,
    pub drops: u32,
    pub hdrincl: bool,
    pub accepting: bool,
}

struct EndpointState {
    local: Ipv4Addr,
    explicit_local: bool,
    remote: Option<Ipv4Addr>,
    bound_iface: Option<NetIfaceId>,
    hdrincl: bool,
    icmp_filter: u32,
    accepting: bool,
    datagrams: VecDeque<Raw4Datagram>,
    queued_bytes: usize,
    rcvbuf: usize,
    drops: u32,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Raw4TxOptions {
    pub source: Option<Ipv4Addr>,
    pub iface: Option<NetIfaceId>,
    pub tos: u8,
    pub ttl: u8,
    pub pmtudisc: i32,
    pub broadcast: bool,
}

impl Default for Raw4TxOptions {
    fn default() -> Self {
        Self {
            source: None,
            iface: None,
            tos: 0,
            ttl: crate::ipv4::IPV4_DEFAULT_TTL,
            pmtudisc: crate::uapi::IP_PMTUDISC_WANT,
            broadcast: false,
        }
    }
}

pub struct Raw4Endpoint {
    protocol: u8,
    net_namespace: network_namespace::NetworkNamespaceRef,
    state: Spinlock<EndpointState, LockClass>,
    pub bpf_filter: Arc<SocketFilter>,
    pub mcast: Arc<SocketMcast>,
    pub error: Arc<SocketError>,
    ip_mtu_discover: Arc<core::sync::atomic::AtomicI32>,
    #[cfg(target_os = "oxide-kernel")]
    pub waiters: sched::live::WaitList,
    pub(super) poll_subs: Spinlock<Option<alloc::sync::Weak<vfs::PollSubscribers>>, LockClass>,
}

impl Raw4Endpoint {
    /// Build one unpublished raw IPv4 endpoint. # C: O(1)
    pub fn new(protocol: u8, net_namespace: network_namespace::NetworkNamespaceRef, bpf: Arc<SocketFilter>,
               mcast: Arc<SocketMcast>, error: Arc<SocketError>) -> Arc<Self> {
        Self::new_with_pmtudisc(protocol, net_namespace, bpf, mcast, error,
            Arc::new(core::sync::atomic::AtomicI32::new(crate::uapi::IP_PMTUDISC_WANT)))
    }

    /// Build one endpoint sharing its owning socket's PMTU mode. # C: O(1)
    pub fn new_with_pmtudisc(protocol: u8, net_namespace: network_namespace::NetworkNamespaceRef,
               bpf: Arc<SocketFilter>, mcast: Arc<SocketMcast>, error: Arc<SocketError>,
               ip_mtu_discover: Arc<core::sync::atomic::AtomicI32>) -> Arc<Self> {
        Arc::new(Self {
            protocol,
            net_namespace,
            state: Spinlock::new(EndpointState {
                local: Ipv4Addr::ANY,
                explicit_local: false,
                remote: None,
                bound_iface: None,
                hdrincl: protocol == 255,
                icmp_filter: 0,
                accepting: true,
                datagrams: VecDeque::new(),
                queued_bytes: 0,
                rcvbuf: DEFAULT_RAW4_RCVBUF,
                drops: 0,
            }),
            bpf_filter: bpf,
            mcast,
            error,
            ip_mtu_discover,
            #[cfg(target_os = "oxide-kernel")]
            waiters: sched::live::WaitList::new(),
            poll_subs: Spinlock::new(None),
        })
    }

    /// Exact IPv4 protocol selected at socket creation. # C: O(1)
    pub fn protocol(&self) -> u8 { self.protocol }

    /// Whether the endpoint still accepts traffic from its network namespace. # C: O(1)
    pub fn is_accepting(&self) -> bool { self.state.lock().accepting }

    /// Snapshot Linux raw-socket readiness, including terminal close state. # C: O(1)
    pub fn poll_mask(&self) -> u32 {
        let mut mask = if self.is_accepting() { vfs::POLL_OUT } else { vfs::POLL_HUP };
        if self.queued_len() != 0 { mask |= vfs::POLL_IN; }
        mask
    }

    /// Network namespace owning this endpoint and its registry entry. # C: O(1)
    pub fn net_ns(&self) -> u64 { crate::net_ns::namespace_id(&self.net_namespace) }

    /// Clone the concrete namespace owner retained by this endpoint. # C: O(1)
    pub fn network_namespace(&self) -> network_namespace::NetworkNamespaceRef {
        self.net_namespace.clone()
    }

    /// Atomically publish local-address and optional device binding. # C: O(1)
    pub fn bind(&self, local: Ipv4Addr, iface: Option<NetIfaceId>) -> NetResult<()> {
        let mut state = self.state.lock();
        if !state.accepting { return Err(NetError::Enoent); }
        state.local = local;
        state.explicit_local = !local.is_unspecified();
        if iface.is_some() { state.bound_iface = iface; }
        Ok(())
    }

    /// Validate namespace/device ownership before publishing a local bind. # C: O(N)
    pub fn bind_checked(&self, local: Ipv4Addr, iface: Option<NetIfaceId>) -> NetResult<()> {
        if !local.is_unspecified() {
            let net_ns = self.net_ns();
            let owned = crate::iface_addr::snapshot_ns(net_ns).into_iter()
                .any(|row| row.addr == local && iface.is_none_or(|id| id == row.iface))
                || crate::global_stack().routes.lookup_in(net_ns, local).is_some_and(|route| {
                    route.table == crate::policy_rule::RT_TABLE_LOCAL && route.src_hint == Some(local)
                        && iface.is_none_or(|id| id == route.iface)
                });
            if !owned { return Err(NetError::Eaddrnotavail); }
        }
        self.bind(local, iface)
    }

    /// Connect receive/error matching to one peer without allocating a port. # C: O(1)
    pub fn connect(&self, remote: Ipv4Addr, iface: Option<NetIfaceId>) -> NetResult<()> {
        if remote.is_unspecified() { return Err(NetError::Eaddrnotavail); }
        let mut state = self.state.lock();
        if !state.accepting { return Err(NetError::Enoent); }
        state.remote = Some(remote);
        if iface.is_some() { state.bound_iface = iface; }
        Ok(())
    }

    /// Connect and install the route-selected local address when unbound. # C: O(N)
    pub fn connect_routed(&self, remote: Ipv4Addr, iface: Option<NetIfaceId>) -> NetResult<()> {
        if remote.is_unspecified() { return Err(NetError::Eaddrnotavail); }
        let stack = crate::global_stack();
        let net_ns = self.net_ns();
        let (route_iface, _, _) = stack.route_v4_iface_in(net_ns, remote, iface)?;
        let local = stack.routes.lookup_in(net_ns, remote)
            .filter(|route| route.iface == route_iface).and_then(|route| route.src_hint)
            .or_else(|| crate::iface_addr::primary(net_ns, route_iface).map(|row| row.0))
            .ok_or(NetError::Eaddrnotavail)?;
        let mut state = self.state.lock();
        if !state.accepting { return Err(NetError::Enoent); }
        state.remote = Some(remote);
        if !state.explicit_local { state.local = local; }
        if iface.is_some() { state.bound_iface = iface; }
        Ok(())
    }

    /// Remove peer matching and route-selected local state. # C: O(1)
    pub fn disconnect(&self) {
        let mut state = self.state.lock();
        state.remote = None;
        if !state.explicit_local { state.local = Ipv4Addr::ANY; }
    }

    /// Serialize SO_BINDTODEVICE state with bind/connect/close. # C: O(1)
    pub fn set_bound_iface(&self, iface: Option<NetIfaceId>) -> NetResult<()> {
        let mut state = self.state.lock();
        if !state.accepting { return Err(NetError::Enoent); }
        state.bound_iface = iface;
        Ok(())
    }

    /// Enable or disable caller-supplied IPv4 headers. # C: O(1)
    pub fn set_hdrincl(&self, enabled: bool) { self.state.lock().hdrincl = enabled; }

    /// Observe caller-supplied IPv4 header mode. # C: O(1)
    pub fn hdrincl(&self) -> bool { self.state.lock().hdrincl }

    /// Snapshot canonical Linux `IP_MTU_DISCOVER` mode. # C: O(1)
    pub fn pmtudisc(&self) -> i32 {
        self.ip_mtu_discover.load(core::sync::atomic::Ordering::Acquire)
    }

    /// Replace Linux `ICMP_FILTER`; set bits reject matching ICMP types. # C: O(1)
    pub fn set_icmp_filter(&self, filter: u32) { self.state.lock().icmp_filter = filter; }

    /// Snapshot Linux `ICMP_FILTER`. # C: O(1)
    pub fn icmp_filter(&self) -> u32 { self.state.lock().icmp_filter }

    pub(crate) fn accepts_icmp_type(&self, typ: u8) -> bool {
        typ >= 32 || self.state.lock().icmp_filter & (1u32 << typ) == 0
    }

    /// Snapshot lifecycle fields under their canonical lock. # C: O(1)
    pub fn snapshot(&self) -> Raw4StateSnapshot {
        let state = self.state.lock();
        Raw4StateSnapshot {
            local: state.local,
            remote: state.remote,
            bound_iface: state.bound_iface,
            queued_bytes: state.queued_bytes,
            drops: state.drops,
            hdrincl: state.hdrincl,
            accepting: state.accepting,
        }
    }

    /// Pop or peek one complete IPv4 datagram. # C: O(packet when peeking)
    pub fn recv(&self, peek: bool) -> Option<Raw4Datagram> {
        let mut state = self.state.lock();
        if peek { return state.datagrams.front().cloned(); }
        let datagram = state.datagrams.pop_front()?;
        state.queued_bytes -= datagram.packet.len();
        Some(datagram)
    }

    /// Publish one receive datagram unless close won publication. # C: O(packet)
    pub(crate) fn enqueue(&self, datagram: Raw4Datagram) -> bool {
        let mut state = self.state.lock();
        if !state.accepting { return false; }
        let bytes = datagram.packet.len();
        if state.queued_bytes.saturating_add(bytes) > state.rcvbuf {
            state.drops = state.drops.saturating_add(1);
            return false;
        }
        state.datagrams.push_back(datagram);
        state.queued_bytes += bytes;
        drop(state);
        #[cfg(target_os = "oxide-kernel")]
        self.waiters.wake_all();
        let poll = self.poll_subs.lock().clone();
        if let Some(subs) = poll.and_then(|weak| weak.upgrade()) { subs.notify(); }
        true
    }

    /// Number of complete datagrams available. # C: O(1)
    pub fn queued_len(&self) -> usize { self.state.lock().datagrams.len() }

    /// Bytes in the next datagram, matching FIONREAD semantics. # C: O(1)
    pub fn next_len(&self) -> usize {
        self.state.lock().datagrams.front().map_or(0, |d| d.packet.len())
    }

    /// Set the receive-byte admission limit used by raw4 queueing. # C: O(1)
    pub fn set_rcvbuf(&self, bytes: usize) { self.state.lock().rcvbuf = bytes; }

    /// Register epoll subscribers for receive/close notification. # C: O(1)
    pub fn register_poll_subs(&self, subs: &Arc<vfs::PollSubscribers>) {
        *self.poll_subs.lock() = Some(Arc::downgrade(subs));
    }

    /// Atomically publish read shutdown against receive wait registration. # C: O(1)
    pub fn shutdown_read(&self, read_shut: &core::sync::atomic::AtomicBool) {
        self.shutdown_read_with(read_shut, || {
            #[cfg(target_os = "oxide-kernel")]
            self.waiters.wake_all();
        });
    }

    fn shutdown_read_with(&self, read_shut: &core::sync::atomic::AtomicBool,
                          wake: impl FnOnce()) {
        let state = self.state.lock();
        read_shut.store(true, core::sync::atomic::Ordering::Release);
        drop(state);
        wake();
    }

    /// Linearize close against receive admission and wake observers. # C: O(1)
    pub fn close(&self) {
        let mut state = self.state.lock();
        if !state.accepting { return; }
        state.accepting = false;
        drop(state);
        #[cfg(target_os = "oxide-kernel")]
        self.waiters.wake_all();
        let poll = self.poll_subs.lock().clone();
        if let Some(subs) = poll.and_then(|weak| weak.upgrade()) {
            subs.notify_mask(vfs::POLL_HUP);
        }
    }

    /// Park a kernel reader only while the queue is empty and live. # C: O(1)
    #[cfg(target_os = "oxide-kernel")]
    pub fn arm_recv_wait(&self, read_shut: &core::sync::atomic::AtomicBool,
                         deadline_ns: u64) -> bool {
        self.arm_recv_wait_with(read_shut, || {
            // SAFETY: endpoint lock closes receive/shutdown publication before registration.
            unsafe { self.waiters.park_interruptible_with_deadline(deadline_ns); }
        })
    }

    fn arm_recv_wait_with(&self, read_shut: &core::sync::atomic::AtomicBool,
                          arm: impl FnOnce()) -> bool {
        let state = self.state.lock();
        if !state.accepting || !state.datagrams.is_empty() || self.error.has()
            || read_shut.load(core::sync::atomic::Ordering::Acquire) { return false; }
        arm();
        drop(state);
        true
    }
}

#[cfg(test)]
#[path = "shutdown_tests.rs"]
mod shutdown_tests;
