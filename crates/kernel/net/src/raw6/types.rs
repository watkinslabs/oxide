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
    net_ns: u64,
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
    pub fn new(net_ns: u64, protocol: u8, bpf_filter: Arc<SocketFilter>,
               mcast: Arc<SocketMcast>, error: Arc<SocketError>) -> Self {
        Self {
            net_ns, protocol, bpf_filter, mcast, error,
            state: Spinlock::new(Raw6State {
                accepting: true, local: Raw6Address::UNSPECIFIED, peer: None,
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
    pub const fn net_ns(&self) -> u64 { self.net_ns }

    /// Build a self-contained endpoint for hosted stack users. # C: O(1)
    pub fn standalone(net_ns: u64, protocol: u8) -> Self {
        Self::new(net_ns, protocol, Arc::new(SocketFilter::new()),
            Arc::new(SocketMcast::new()), Arc::new(SocketError::new()))
    }

    /// Atomically replace local address and device binding. # C: O(1)
    pub fn bind(&self, local: Raw6Address, iface: Option<NetIfaceId>) {
        let mut state = self.state.lock();
        state.local = local;
        state.bound_iface = iface;
    }

    /// Atomically update SO_BINDTODEVICE state against receive admission. # C: O(1)
    pub fn set_bound_iface(&self, iface: Option<NetIfaceId>) {
        self.state.lock().bound_iface = iface;
    }

    /// Connect receive/error matching to one peer and its zone. # C: O(1)
    pub fn connect(&self, peer: Raw6Address) { self.state.lock().peer = Some(peer); }

    /// Apply Linux AF_UNSPEC disconnect without changing explicit bind state. # C: O(1)
    pub fn disconnect(&self) { self.state.lock().peer = None; }

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
    pub fn arm_recv_wait(&self, deadline_ns: u64) -> bool {
        let state = self.state.lock();
        if !state.accepting || !state.datagrams.is_empty() { return false; }
        // SAFETY: endpoint lock closes receive/close publication before sleep registration.
        unsafe { self.waiters.park_interruptible_with_deadline(deadline_ns); }
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
