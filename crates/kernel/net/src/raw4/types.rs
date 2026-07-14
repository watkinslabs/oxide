use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;

use sync::{Spinlock, Socket as LockClass};

use crate::addr::{Ipv4Addr, NetIfaceId};
use crate::bpf_filter::SocketFilter;
use crate::mcast_filter::SocketMcast;
use crate::netdev::{NetError, NetResult};

const RAW4_RX_MAX_DATAGRAMS: usize = 1_024;

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
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Raw4TxOptions {
    pub source: Option<Ipv4Addr>,
    pub iface: Option<NetIfaceId>,
    pub tos: u8,
    pub ttl: u8,
    pub pmtudisc: i32,
}

impl Default for Raw4TxOptions {
    fn default() -> Self {
        Self {
            source: None,
            iface: None,
            tos: 0,
            ttl: crate::ipv4::IPV4_DEFAULT_TTL,
            pmtudisc: crate::uapi::IP_PMTUDISC_WANT,
        }
    }
}

pub struct Raw4Endpoint {
    protocol: u8,
    net_ns: u64,
    state: Spinlock<EndpointState, LockClass>,
    pub bpf_filter: Arc<SocketFilter>,
    pub mcast: Arc<SocketMcast>,
    #[cfg(target_os = "oxide-kernel")]
    pub waiters: sched::live::WaitList,
    poll_subs: Spinlock<Option<alloc::sync::Weak<vfs::PollSubscribers>>, LockClass>,
}

impl Raw4Endpoint {
    /// Build one unpublished raw IPv4 endpoint. # C: O(1)
    pub fn new(protocol: u8, net_ns: u64, bpf: Arc<SocketFilter>,
               mcast: Arc<SocketMcast>) -> Arc<Self> {
        Arc::new(Self {
            protocol,
            net_ns,
            state: Spinlock::new(EndpointState {
                local: Ipv4Addr::ANY,
                explicit_local: false,
                remote: None,
                bound_iface: None,
                hdrincl: protocol == 255,
                icmp_filter: 0,
                accepting: true,
                datagrams: VecDeque::new(),
            }),
            bpf_filter: bpf,
            mcast,
            #[cfg(target_os = "oxide-kernel")]
            waiters: sched::live::WaitList::new(),
            poll_subs: Spinlock::new(None),
        })
    }

    /// Exact IPv4 protocol selected at socket creation. # C: O(1)
    pub fn protocol(&self) -> u8 { self.protocol }

    /// Network namespace owning this endpoint and its registry entry. # C: O(1)
    pub fn net_ns(&self) -> u64 { self.net_ns }

    /// Atomically publish local-address and optional device binding. # C: O(1)
    pub fn bind(&self, local: Ipv4Addr, iface: Option<NetIfaceId>) -> NetResult<()> {
        let mut state = self.state.lock();
        if !state.accepting { return Err(NetError::Enoent); }
        state.local = local;
        state.explicit_local = !local.is_unspecified();
        if iface.is_some() { state.bound_iface = iface; }
        Ok(())
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
            hdrincl: state.hdrincl,
            accepting: state.accepting,
        }
    }

    /// Pop or peek one complete IPv4 datagram. # C: O(packet when peeking)
    pub fn recv(&self, peek: bool) -> Option<Raw4Datagram> {
        let mut state = self.state.lock();
        if peek { state.datagrams.front().cloned() } else { state.datagrams.pop_front() }
    }

    /// Publish one receive datagram unless close won publication. # C: O(packet)
    pub(crate) fn enqueue(&self, datagram: Raw4Datagram) -> bool {
        let mut state = self.state.lock();
        if !state.accepting || state.datagrams.len() >= RAW4_RX_MAX_DATAGRAMS { return false; }
        state.datagrams.push_back(datagram);
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

    /// Register epoll subscribers for receive/close notification. # C: O(1)
    pub fn register_poll_subs(&self, subs: &Arc<vfs::PollSubscribers>) {
        *self.poll_subs.lock() = Some(Arc::downgrade(subs));
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
    pub fn arm_recv_wait(&self, deadline_ns: u64) -> bool {
        let state = self.state.lock();
        if !state.accepting || !state.datagrams.is_empty() { return false; }
        // SAFETY: endpoint lock closes enqueue/close publication before sleep registration.
        unsafe { self.waiters.park_interruptible_with_deadline(deadline_ns); }
        drop(state);
        true
    }
}
