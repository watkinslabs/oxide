use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use sync::{Spinlock, Socket as StackLockClass};

use crate::addr::{Ipv6Addr, NetIfaceId};

/// One queued IPv6 UDP datagram plus every header field the ancillary
/// messages publish. `dst` + `iface` back IPV6_PKTINFO; `hop_limit` backs
/// IPV6_HOPLIMIT (avahi enforces == 255 for on-link mDNS, RFC 6762 §11);
/// `traffic_class` backs IPV6_TCLASS; `flowinfo` backs IPV6_FLOWINFO;
/// `dport` completes the IPV6_ORIGDSTADDR socket address; `ext_headers`
/// carries the received extension headers in wire order for IPV6_HOPOPTS,
/// IPV6_DSTOPTS and IPV6_RTHDR; `frag_max` backs IPV6_RECVFRAGSIZE.
#[derive(Clone, Debug)]
pub struct Udp6Datagram {
    pub src: Ipv6Addr,
    pub sport: u16,
    pub dst: Ipv6Addr,
    pub dport: u16,
    pub iface: NetIfaceId,
    pub hop_limit: u8,
    pub traffic_class: u8,
    pub flowinfo: u32,
    /// `(next-header kind, whole header bytes)`, in the order they arrived.
    pub ext_headers: Vec<(u8, Vec<u8>)>,
    pub frag_max: u32,
    pub payload: Vec<u8>,
}

impl Udp6Datagram {
    /// A datagram carrying nothing beyond the addresses, hop limit, traffic
    /// class and body. # C: O(1)
    pub fn plain(src: Ipv6Addr, sport: u16, dst: Ipv6Addr, iface: NetIfaceId, hop_limit: u8,
                 traffic_class: u8, payload: Vec<u8>) -> Self
    {
        Self { src, sport, dst, dport: 0, iface, hop_limit, traffic_class, flowinfo: 0,
               ext_headers: Vec::new(), frag_max: 0, payload }
    }
}

/// One queued IPv6 UDP receive plus the coalescing run it belongs to.
#[derive(Clone)]
struct QueuedUdp6 {
    datagram: Udp6Datagram,
    gro: crate::udp_gro::GroRun,
}

struct Udp6RxState {
    accepting: bool,
    datagrams: VecDeque<QueuedUdp6>,
}

pub struct Udp6RxQueue {
    pub owner: Arc<crate::SocketOwner>,
    pub bound_ip: Ipv6Addr,
    pub bound_port: u16,
    state: Spinlock<Udp6RxState, StackLockClass>,
    #[cfg(target_os = "oxide-kernel")]
    pub waiters: sched::live::WaitList,
    pub error: Arc<crate::SocketError>,
    /// Connected peer filter. `None` accepts datagrams from any peer.
    pub peer: Arc<Spinlock<Option<(Ipv6Addr, u16)>, StackLockClass>>,
    pub reuseaddr: Arc<core::sync::atomic::AtomicI32>,
    pub reuseport: Arc<core::sync::atomic::AtomicI32>,
    pub v6only: Arc<core::sync::atomic::AtomicI32>,
    /// Canonical Linux `inet_sk(sk)->pmtudisc`, shared with the owning socket.
    pub ip_mtu_discover: Arc<core::sync::atomic::AtomicI32>,
    /// Canonical Linux `inet6_sk(sk)->pmtudisc`, shared with the owning socket.
    pub ipv6_mtu_discover: Arc<core::sync::atomic::AtomicI32>,
    /// `UDP_NO_CHECK6_RX`, shared with the owning socket: a zero-checksum
    /// datagram reaches this endpoint only while the cell is set.
    pub no_check6_rx: Arc<core::sync::atomic::AtomicI32>,
    /// `UDP_GRO`, shared with the owning socket: while set, arriving
    /// datagrams of one flow coalesce into a single receive.
    pub gro: Arc<core::sync::atomic::AtomicI32>,
    pub bound_ifindex: core::sync::atomic::AtomicU32,
    pub poll_subs: Spinlock<Option<alloc::sync::Weak<vfs::PollSubscribers>>, StackLockClass>,
    pub bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
    /// Socket multicast state shared before and after bind.
    pub mcast: Arc<crate::mcast_filter::SocketMcast>,
    /// SO_REUSEPORT group reached from the bind table on the delivery path.
    /// Published by bind-time join; the owning socket's cell holds membership.
    pub reuseport_group: crate::reuseport::ReuseportSlot,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Ipv6AddrOrigin {
    Static,
    Slaac { prefix: Ipv6Addr, preferred_until_ns: u64, valid_until_ns: u64 },
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Ipv6AddrState {
    Tentative { dad_until_ns: Option<u64>, retry_at_ns: u64, retrans_timer_ns: u64 },
    Assigned,
    DadFailed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv6IfaceAddr {
    pub addr: Ipv6Addr,
    pub prefixlen: u8,
    pub preferred: u32,
    pub valid: u32,
    pub origin: Ipv6AddrOrigin,
    pub state: Ipv6AddrState,
    pub deprecated: bool,
    pub(crate) notify_pending: bool,
}

pub(crate) struct PendingRa {
    pub namespace: network_namespace::NetworkNamespaceRef,
    pub iface: NetIfaceId,
    pub generation: u64,
    pub router: Ipv6Addr,
    pub advertisement: crate::ndp::RouterAdvertisement,
}

impl Ipv6IfaceAddr {
    pub const PERMANENT: (u32, u32) = (u32::MAX, u32::MAX);

    pub(crate) fn valid_at(&self, now_ns: u64) -> bool {
        match self.origin {
            Ipv6AddrOrigin::Static => true,
            Ipv6AddrOrigin::Slaac { valid_until_ns, .. } => valid_until_ns > now_ns,
        }
    }

    pub(crate) fn preferred_at(&self, now_ns: u64) -> bool {
        match self.origin {
            Ipv6AddrOrigin::Static => self.preferred != 0,
            Ipv6AddrOrigin::Slaac { preferred_until_ns, .. } => preferred_until_ns > now_ns,
        }
    }

    pub(crate) fn usable_at(&self, now_ns: u64) -> bool {
        self.valid_at(now_ns) && self.state == Ipv6AddrState::Assigned
    }

    pub fn flags(&self) -> u32 {
        let mut flags = if matches!(self.origin, Ipv6AddrOrigin::Static) {
            crate::iface_addr::IFA_F_PERMANENT
        } else { 0 };
        if self.deprecated { flags |= crate::iface_addr::IFA_F_DEPRECATED; }
        flags |= match self.state {
            Ipv6AddrState::Tentative { .. } => crate::iface_addr::IFA_F_TENTATIVE,
            Ipv6AddrState::DadFailed => crate::iface_addr::IFA_F_DADFAILED,
            Ipv6AddrState::Assigned => 0,
        };
        flags
    }
}

impl Udp6RxQueue {
    /// SO_REUSEPORT membership captured when this endpoint was bound. # C: O(1)
    pub(crate) fn reuseport_member(&self) -> bool {
        self.reuseport.load(core::sync::atomic::Ordering::Acquire) != 0
    }

    /// IPV6_V6ONLY mode captured when this endpoint was bound. # C: O(1)
    pub(crate) fn v6only_at_bind(&self) -> bool {
        self.v6only.load(core::sync::atomic::Ordering::Acquire) != 0
    }

    /// Build a standalone IPv6 UDP queue for hosted stack users. # C: O(1)
    pub fn new(bound_ip: Ipv6Addr, bound_port: u16) -> Self {
        Self::new_with_error(bound_ip, bound_port, Arc::new(crate::SocketError::new()))
    }

    /// Build a queue sharing one socket's canonical error state. # C: O(1)
    pub fn new_with_error(bound_ip: Ipv6Addr, bound_port: u16, error: Arc<crate::SocketError>) -> Self {
        Self::new_socket(0, bound_ip, bound_port, error,
            Arc::new(core::sync::atomic::AtomicI32::new(0)),
            Arc::new(core::sync::atomic::AtomicI32::new(0)),
            crate::SocketOwner::root(network_namespace::initial(), 0),
            Arc::new(core::sync::atomic::AtomicI32::new(0)), Arc::new(Spinlock::new(None)),
            Arc::new(core::sync::atomic::AtomicI32::new(crate::uapi::IP_PMTUDISC_WANT)),
            Arc::new(core::sync::atomic::AtomicI32::new(crate::uapi::IPV6_PMTUDISC_WANT)),
            Arc::new(core::sync::atomic::AtomicI32::new(0)),
            Arc::new(core::sync::atomic::AtomicI32::new(0)),
            Arc::new(crate::bpf_filter::SocketFilter::new()), Arc::new(crate::mcast_filter::SocketMcast::new()))
    }

    /// Build one socket-owned endpoint for a grouped UDP port binding. # C: O(1)
    pub fn new_socket(_net_ns: u64, bound_ip: Ipv6Addr, bound_port: u16, error: Arc<crate::SocketError>,
                      reuseaddr: Arc<core::sync::atomic::AtomicI32>,
                      reuseport: Arc<core::sync::atomic::AtomicI32>,
                      owner: Arc<crate::SocketOwner>,
                      v6only: Arc<core::sync::atomic::AtomicI32>,
                      peer: Arc<Spinlock<Option<(Ipv6Addr, u16)>, StackLockClass>>,
                      ip_mtu_discover: Arc<core::sync::atomic::AtomicI32>,
                      ipv6_mtu_discover: Arc<core::sync::atomic::AtomicI32>,
                      no_check6_rx: Arc<core::sync::atomic::AtomicI32>,
                      gro: Arc<core::sync::atomic::AtomicI32>,
                      bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
                      mcast: Arc<crate::mcast_filter::SocketMcast>) -> Self {
        Self {
            owner,
            bound_ip,
            bound_port,
            state: Spinlock::new(Udp6RxState { accepting: true, datagrams: VecDeque::new() }),
            #[cfg(target_os = "oxide-kernel")]
            waiters: sched::live::WaitList::new(),
            error,
            peer,
            reuseaddr,
            reuseport,
            v6only,
            ip_mtu_discover,
            ipv6_mtu_discover,
            no_check6_rx,
            gro,
            bound_ifindex: core::sync::atomic::AtomicU32::new(0),
            poll_subs: Spinlock::new(None),
            bpf_filter,
            mcast,
            reuseport_group: crate::reuseport::new_slot(),
        }
    }

    /// Publish one ICMPv6 error using this endpoint's connected/RECVERR policy. # C: O(1)
    pub fn publish_error(&self, entry: crate::SocketErrorEntry, hard: bool) -> bool {
        let connected = self.peer.lock().is_some();
        let state = self.state.lock();
        if !state.accepting { return false; }
        if !self.error.publish(entry, connected, hard) { return false; }
        drop(state);
        #[cfg(target_os = "oxide-kernel")]
        self.waiters.wake_all();
        let slot = self.poll_subs.lock().clone();
        if let Some(weak) = slot {
            if let Some(s) = weak.upgrade() { s.notify_mask(vfs::POLL_ERR); }
        }
        true
    }

    /// Publish an asynchronous socket error and wake all endpoint observers. # C: O(1)
    pub fn set_error(&self, errno: i32) -> bool {
        let state = self.state.lock();
        if !state.accepting { return false; }
        if !self.error.set(errno) { return false; }
        drop(state);
        #[cfg(target_os = "oxide-kernel")]
        self.waiters.wake_all();
        let slot = self.poll_subs.lock().clone();
        if let Some(weak) = slot {
            if let Some(s) = weak.upgrade() { s.notify_mask(vfs::POLL_ERR); }
        }
        true
    }

    /// Register the owning socket's poll subscribers. # C: O(1)
    pub fn register_poll_subs(&self, subs: &Arc<vfs::PollSubscribers>) {
        *self.poll_subs.lock() = Some(Arc::downgrade(subs));
    }


    /// Pop or peek one endpoint-local datagram. # C: O(payload when peeking)
    pub fn recv(&self, peek: bool) -> Option<Udp6Datagram> {
        self.recv_gro(peek).map(|(datagram, _)| datagram)
    }

    /// Pop or peek one receive together with the segment size it reports when
    /// several datagrams were coalesced into it. # C: O(payload when peeking)
    pub fn recv_gro(&self, peek: bool) -> Option<(Udp6Datagram, Option<usize>)> {
        let mut state = self.state.lock();
        let queued = if peek { state.datagrams.front().cloned() }
            else { state.datagrams.pop_front() };
        queued.map(|q| { let seg = q.gro.cmsg_seg_size(); (q.datagram, seg) })
    }

    /// `UDP_GRO` is engaged on the owning socket. # C: O(1)
    pub fn gro_enabled(&self) -> bool {
        self.gro.load(core::sync::atomic::Ordering::Acquire) != 0
    }

    /// Queue one datagram if this endpoint still accepts delivery. # C: O(payload)
    pub fn enqueue(&self, datagram: Udp6Datagram) -> bool {
        self.enqueue_gro(datagram, false, false)
    }

    /// Deliver one datagram, coalescing it into the queued run when the
    /// canonical rule admits it and the ingress interface offers coalescing.
    /// # C: O(payload)
    pub fn enqueue_gro(&self, datagram: Udp6Datagram, checksum_zero: bool, offered: bool) -> bool {
        use crate::udp_gro::{GroAdmit, GroRun, admit};
        let mut state = self.state.lock();
        if !state.accepting { return false; }
        let len = datagram.payload.len();
        let same_flow = state.datagrams.back()
            .is_some_and(|q| udp6_same_flow(&q.datagram, &datagram));
        let batch = crate::udp_gro::current_batch();
        let decision = admit(state.datagrams.back().map(|q| &q.gro), same_flow, len,
            checksum_zero,
            crate::udp_gro::coalescable_receive(offered, datagram.frag_max)
                && self.gro_enabled(), batch);
        match decision {
            GroAdmit::Merge => {
                let tail = state.datagrams.back_mut().expect("a merge names a tail");
                tail.datagram.payload.extend_from_slice(&datagram.payload);
                tail.gro.extend(len);
            }
            GroAdmit::Separate { open } => {
                let gro = if open { GroRun::open(len, batch) } else { GroRun::single(len, batch) };
                state.datagrams.push_back(QueuedUdp6 { datagram, gro });
            }
        }
        drop(state);
        #[cfg(target_os = "oxide-kernel")]
        self.waiters.wake_all();
        if let Some(weak) = self.poll_subs.lock().clone() {
            if let Some(subs) = weak.upgrade() { subs.notify_mask(vfs::POLL_IN); }
        }
        true
    }

    /// Stop future delivery; accepted datagrams remain endpoint-observable. # C: O(1)
    pub fn deactivate(&self) {
        let mut state = self.state.lock();
        if !state.accepting { return; }
        state.accepting = false;
        drop(state);
        #[cfg(target_os = "oxide-kernel")]
        self.waiters.wake_all();
        if let Some(weak) = self.poll_subs.lock().clone() {
            if let Some(subs) = weak.upgrade() { subs.notify_mask(vfs::POLL_IN | vfs::POLL_HUP); }
        }
    }

    /// Number of queued datagrams. # C: O(1)
    pub fn queued_len(&self) -> usize { self.state.lock().datagrams.len() }

    /// Whether the endpoint still accepts network delivery. # C: O(1)
    pub fn is_accepting(&self) -> bool { self.state.lock().accepting }

    /// Total queued payload bytes. # C: O(N)
    pub fn queued_bytes(&self) -> usize {
        self.state.lock().datagrams.iter().map(|q| q.datagram.payload.len()).sum()
    }

    /// Atomically publish read shutdown against receive delivery. # C: O(1)
    pub fn shutdown_read(&self, read_shut: &core::sync::atomic::AtomicBool) {
        let _state = self.state.lock();
        read_shut.store(true, core::sync::atomic::Ordering::Release);
    }

    /// Register the current task as a waiter only while the endpoint is idle. # C: O(1)
    #[cfg(target_os = "oxide-kernel")]
    pub fn park_if_idle(&self, read_shut: &core::sync::atomic::AtomicBool, deadline_ns: u64) -> bool {
        let state = self.state.lock();
        if !state.datagrams.is_empty() || self.error.has()
            || read_shut.load(core::sync::atomic::Ordering::Acquire) { return false; }
        // SAFETY: process context; endpoint state closes the delivery/wait race.
        unsafe { self.waiters.park_interruptible_with_deadline(deadline_ns); }
        drop(state);
        true
    }
}

impl core::ops::Deref for Udp6RxQueue {
    type Target = crate::SocketOwner;

    fn deref(&self) -> &Self::Target { &self.owner }
}

/// Two IPv6 receives belong to one coalescing flow when they share the source
/// and destination endpoints, the ingress interface, the hop limit, the
/// traffic class, the flow label and the extension-header chain, which is
/// compared byte for byte.
///
/// A difference in any of them terminates the run rather than joining it, so
/// the single set of header values a coalesced receive publishes describes
/// every datagram merged into it. # C: O(headers)
fn udp6_same_flow(a: &Udp6Datagram, b: &Udp6Datagram) -> bool {
    a.src == b.src && a.sport == b.sport && a.dst == b.dst && a.dport == b.dport
        && a.iface == b.iface && a.hop_limit == b.hop_limit
        && a.traffic_class == b.traffic_class && a.flowinfo == b.flowinfo
        && a.ext_headers == b.ext_headers
}
