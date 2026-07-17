use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use sync::{Spinlock, Socket as LockClass};

use crate::addr::{Ipv6Addr, NetIfaceId};
use crate::bpf_filter::SocketFilter;
use crate::mcast_filter::SocketMcast;
use crate::socket_error::SocketError;

use super::{Icmp6Filter, Raw6Checksum};

pub const DEFAULT_RAW6_RCVBUF: usize = 212_992;

/// Address plus IPv6 zone; raw receive source ports are always zero.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Raw6Address {
    pub addr: Ipv6Addr,
    pub scope_id: u32,
}

impl Raw6Address {
    pub const UNSPECIFIED: Self = Self { addr: Ipv6Addr::ANY, scope_id: 0 };

    /// Construct an IPv6 address and preserve its zone identifier. # C: O(1)
    pub const fn new(addr: Ipv6Addr, scope_id: u32) -> Self { Self { addr, scope_id } }
}

/// Ancillary and source-address state retained with one raw datagram.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Raw6RxMeta {
    pub source: Raw6Address,
    pub source_port: u16,
    pub destination: Ipv6Addr,
    pub iface: NetIfaceId,
    pub hop_limit: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
}

/// One queued upper-layer raw IPv6 datagram.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Raw6Datagram {
    pub payload: Vec<u8>,
    pub meta: Raw6RxMeta,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Raw6StateSnapshot {
    pub local: Raw6Address,
    pub peer: Option<Raw6Address>,
    pub bound_iface: Option<NetIfaceId>,
    pub queued_bytes: usize,
    pub accepting: bool,
}

pub(super) struct Raw6State {
    pub accepting: bool,
    pub local: Raw6Address,
    pub explicit_local: bool,
    pub peer: Option<Raw6Address>,
    pub bound_iface: Option<NetIfaceId>,
    pub datagrams: VecDeque<Raw6Datagram>,
    pub queued_bytes: usize,
    pub rcvbuf: usize,
    pub icmp_filter: Icmp6Filter,
    pub checksum: Raw6Checksum,
    pub header_included: bool,
}

/// Protocol-owned raw IPv6 endpoint; canonical tables retain weak references.
pub struct Raw6Endpoint {
    net_namespace: network_namespace::NetworkNamespaceRef,
    protocol: u8,
    pub bpf_filter: Arc<SocketFilter>,
    pub mcast: Arc<SocketMcast>,
    pub error: Arc<SocketError>,
    pub(super) state: Spinlock<Raw6State, LockClass>,
    #[cfg(target_os = "oxide-kernel")]
    pub waiters: sched::live::WaitList,
    pub(super) poll_subs: Spinlock<Option<alloc::sync::Weak<vfs::PollSubscribers>>, LockClass>,
}

impl Raw6Endpoint {
    /// Build an endpoint sharing its owning socket's common state. # C: O(1)
    pub fn new(net_namespace: network_namespace::NetworkNamespaceRef, protocol: u8, bpf_filter: Arc<SocketFilter>,
               mcast: Arc<SocketMcast>, error: Arc<SocketError>) -> Self {
        Self {
            net_namespace, protocol, bpf_filter, mcast, error,
            state: Spinlock::new(Raw6State {
                accepting: true, local: Raw6Address::UNSPECIFIED, explicit_local: false, peer: None,
                bound_iface: None, datagrams: VecDeque::new(), queued_bytes: 0,
                rcvbuf: DEFAULT_RAW6_RCVBUF, icmp_filter: Icmp6Filter::PASS_ALL,
                checksum: Raw6Checksum::for_protocol(protocol),
                header_included: protocol == crate::addr::IpProto::Raw as u8,
            }),
            #[cfg(target_os = "oxide-kernel")]
            waiters: sched::live::WaitList::new(),
            poll_subs: Spinlock::new(None),
        }
    }

    /// Exact IPv6 Next Header selected at socket creation. # C: O(1)
    pub const fn protocol(&self) -> u8 { self.protocol }

    /// Network namespace owning this endpoint and its table entry. # C: O(1)
    pub fn net_ns(&self) -> u64 { crate::net_ns::namespace_id(&self.net_namespace) }

    /// Clone the concrete namespace owner retained by this endpoint. # C: O(1)
    pub fn network_namespace(&self) -> network_namespace::NetworkNamespaceRef {
        self.net_namespace.clone()
    }

    /// Build a self-contained endpoint for hosted stack users. # C: O(1)
    pub fn standalone(net_namespace: network_namespace::NetworkNamespaceRef, protocol: u8) -> Self {
        Self::new(net_namespace, protocol, Arc::new(SocketFilter::new()),
            Arc::new(SocketMcast::new()), Arc::new(SocketError::new()))
    }

    /// Atomically replace local address and device binding. # C: O(1)
    pub fn bind(&self, local: Raw6Address, iface: Option<NetIfaceId>) {
        let mut state = self.state.lock();
        state.local = local;
        state.explicit_local = !local.addr.is_unspecified();
        state.bound_iface = iface;
    }

    /// Validate native IPv6 namespace/device ownership before binding. # C: O(N)
    pub fn bind_checked(&self, local: Raw6Address, iface: Option<NetIfaceId>) -> crate::netdev::NetResult<()> {
        if local.addr.to_v4_mapped().is_some() { return Err(crate::netdev::NetError::Eaddrnotavail); }
        let net_ns = self.net_ns();
        if !local.addr.is_unspecified() && !crate::global_stack().v6_addr_snapshot_in(net_ns)
            .into_iter().any(|(id, row)| row.addr == local.addr && iface.is_none_or(|want| want == id))
        {
            return Err(crate::netdev::NetError::Eaddrnotavail);
        }
        self.bind(local, iface);
        Ok(())
    }

    /// Atomically update SO_BINDTODEVICE state against receive admission. # C: O(1)
    pub fn set_bound_iface(&self, iface: Option<NetIfaceId>) {
        self.state.lock().bound_iface = iface;
    }

    /// Connect receive/error matching to one peer and its zone. # C: O(1)
    pub fn connect(&self, peer: Raw6Address) { self.state.lock().peer = Some(peer); }

    /// Connect and install the route-selected local address when unbound. # C: O(N)
    pub fn connect_routed(&self, peer: Raw6Address, iface: Option<NetIfaceId>)
        -> crate::netdev::NetResult<()>
    {
        if peer.addr.is_unspecified() { return Err(crate::netdev::NetError::Eaddrnotavail); }
        let stack = crate::global_stack();
        let net_ns = self.net_ns();
        let (route_iface, _, _) = stack.route_v6_iface_in(net_ns, peer.addr, iface)?;
        let hint = stack.routes6.lookup_in(net_ns, peer.addr)
            .filter(|route| route.iface == route_iface).and_then(|route| route.src_hint);
        let local = stack.v6_select_source(route_iface, peer.addr, hint)
            .ok_or(crate::netdev::NetError::Eaddrnotavail)?;
        let scope = if local.is_link_local() { route_iface.raw() } else { 0 };
        let mut state = self.state.lock();
        if !state.accepting { return Err(crate::netdev::NetError::Enoent); }
        state.peer = Some(peer);
        if !state.explicit_local { state.local = Raw6Address::new(local, scope); }
        if iface.is_some() { state.bound_iface = iface; }
        Ok(())
    }

    /// Apply Linux AF_UNSPEC disconnect without changing explicit bind state. # C: O(1)
    pub fn disconnect(&self) {
        let mut state = self.state.lock();
        state.peer = None;
        if !state.explicit_local { state.local = Raw6Address::UNSPECIFIED; }
    }

    /// Snapshot the local raw address. # C: O(1)
    pub fn local(&self) -> Raw6Address { self.state.lock().local }

    /// Snapshot the connected peer. # C: O(1)
    pub fn peer(&self) -> Option<Raw6Address> { self.state.lock().peer }

    /// Snapshot diagnostic tuple, device, queue, and lifecycle state. # C: O(1)
    pub fn snapshot(&self) -> Raw6StateSnapshot {
        let state = self.state.lock();
        Raw6StateSnapshot {
            local: state.local, peer: state.peer, bound_iface: state.bound_iface,
            queued_bytes: state.queued_bytes, accepting: state.accepting,
        }
    }

    /// Stop future queue admission atomically against in-flight receive. # C: O(1)
    pub fn deactivate(&self) { self.close(); }

    /// Observe whether table delivery may still enter this endpoint. # C: O(1)
    pub fn is_accepting(&self) -> bool { self.state.lock().accepting }

    /// Snapshot Linux raw-socket readiness, including terminal close state. # C: O(1)
    pub fn poll_mask(&self) -> u32 {
        let mut mask = if self.is_accepting() { vfs::POLL_OUT } else { vfs::POLL_HUP };
        if self.queue_usage().0 != 0 { mask |= vfs::POLL_IN; }
        mask
    }

    /// Pop or peek one upper-layer datagram. # C: O(payload when peeking)
    pub fn recv(&self, peek: bool) -> Option<Raw6Datagram> {
        let mut state = self.state.lock();
        if peek { return state.datagrams.front().cloned(); }
        let datagram = state.datagrams.pop_front()?;
        state.queued_bytes -= datagram.payload.len();
        Some(datagram)
    }

    /// Return first datagram size for FIONREAD. # C: O(1)
    pub fn first_len(&self) -> usize {
        self.state.lock().datagrams.front().map_or(0, |d| d.payload.len())
    }

    /// Return queued datagram and byte counts. # C: O(1)
    pub fn queue_usage(&self) -> (usize, usize) {
        let state = self.state.lock();
        (state.datagrams.len(), state.queued_bytes)
    }

    /// Set the endpoint receive-byte admission limit. # C: O(1)
    pub fn set_rcvbuf(&self, bytes: usize) { self.state.lock().rcvbuf = bytes; }

    /// Register epoll subscribers for receive and close notification. # C: O(1)
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

    /// Linearize close against admission and wake endpoint observers. # C: O(1)
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

    /// Replace ICMP6_FILTER state. # C: O(1)
    pub fn set_icmp_filter(&self, filter: Icmp6Filter) { self.state.lock().icmp_filter = filter; }

    /// Snapshot ICMP6_FILTER state. # C: O(1)
    pub fn icmp_filter(&self) -> Icmp6Filter { self.state.lock().icmp_filter }

    /// Validate and replace IPV6_CHECKSUM state. # C: O(1)
    pub fn set_checksum(&self, value: i32) -> crate::netdev::NetResult<()> {
        self.state.lock().checksum = Raw6Checksum::from_linux(value)?;
        Ok(())
    }

    /// Snapshot IPV6_CHECKSUM state. # C: O(1)
    pub fn checksum(&self) -> Raw6Checksum { self.state.lock().checksum }

    /// Select kernel-header or caller-header transmission. # C: O(1)
    pub fn set_header_included(&self, enabled: bool) { self.state.lock().header_included = enabled; }

    /// Observe IPV6_HDRINCL state. # C: O(1)
    pub fn header_included(&self) -> bool { self.state.lock().header_included }

    pub(super) fn notify_receive(&self) {
        #[cfg(target_os = "oxide-kernel")]
        self.waiters.wake_all();
        let poll = self.poll_subs.lock().clone();
        if let Some(subs) = poll.and_then(|weak| weak.upgrade()) { subs.notify(); }
    }
}

#[cfg(test)]
#[path = "shutdown_tests.rs"]
mod shutdown_tests;
