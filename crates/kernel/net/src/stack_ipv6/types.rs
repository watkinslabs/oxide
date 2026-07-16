use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use sync::{Spinlock, Socket as StackLockClass};

use crate::addr::{Ipv6Addr, NetIfaceId};

/// A queued IPv6 UDP datagram plus the ancillary metadata Linux exposes
/// via recvmsg: `(src, src_port, dst, recv_iface, hop_limit, payload)`.
/// `dst` + `iface` back IPV6_PKTINFO; `hop_limit` backs IPV6_HOPLIMIT
/// (avahi enforces == 255 for on-link mDNS, RFC 6762 §11).
pub type Udp6Datagram = (Ipv6Addr, u16, Ipv6Addr, NetIfaceId, u8, Vec<u8>);

struct Udp6RxState {
    accepting: bool,
    datagrams: VecDeque<Udp6Datagram>,
}

pub struct Udp6RxQueue {
    pub net_ns: u64,
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
    pub owner_uid: u32,
    pub v6only: Arc<core::sync::atomic::AtomicI32>,
    /// Canonical Linux `inet_sk(sk)->pmtudisc`, shared with the owning socket.
    pub ip_mtu_discover: Arc<core::sync::atomic::AtomicI32>,
    /// Canonical Linux `inet6_sk(sk)->pmtudisc`, shared with the owning socket.
    pub ipv6_mtu_discover: Arc<core::sync::atomic::AtomicI32>,
    pub bound_ifindex: core::sync::atomic::AtomicU32,
    pub poll_subs: Spinlock<Option<alloc::sync::Weak<vfs::PollSubscribers>>, StackLockClass>,
    pub bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
    /// Socket multicast state shared before and after bind.
    pub mcast: Arc<crate::mcast_filter::SocketMcast>,
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
            Arc::new(core::sync::atomic::AtomicI32::new(0)), 0,
            Arc::new(core::sync::atomic::AtomicI32::new(0)), Arc::new(Spinlock::new(None)),
            Arc::new(core::sync::atomic::AtomicI32::new(crate::uapi::IP_PMTUDISC_WANT)),
            Arc::new(core::sync::atomic::AtomicI32::new(crate::uapi::IPV6_PMTUDISC_WANT)),
            Arc::new(crate::bpf_filter::SocketFilter::new()), Arc::new(crate::mcast_filter::SocketMcast::new()))
    }

    /// Build one socket-owned endpoint for a grouped UDP port binding. # C: O(1)
    pub fn new_socket(net_ns: u64, bound_ip: Ipv6Addr, bound_port: u16, error: Arc<crate::SocketError>,
                      reuseaddr: Arc<core::sync::atomic::AtomicI32>,
                      reuseport: Arc<core::sync::atomic::AtomicI32>,
                      owner_uid: u32,
                      v6only: Arc<core::sync::atomic::AtomicI32>,
                      peer: Arc<Spinlock<Option<(Ipv6Addr, u16)>, StackLockClass>>,
                      ip_mtu_discover: Arc<core::sync::atomic::AtomicI32>,
                      ipv6_mtu_discover: Arc<core::sync::atomic::AtomicI32>,
                      bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
                      mcast: Arc<crate::mcast_filter::SocketMcast>) -> Self {
        Self {
            net_ns,
            bound_ip,
            bound_port,
            state: Spinlock::new(Udp6RxState { accepting: true, datagrams: VecDeque::new() }),
            #[cfg(target_os = "oxide-kernel")]
            waiters: sched::live::WaitList::new(),
            error,
            peer,
            reuseaddr,
            reuseport,
            owner_uid,
            v6only,
            ip_mtu_discover,
            ipv6_mtu_discover,
            bound_ifindex: core::sync::atomic::AtomicU32::new(0),
            poll_subs: Spinlock::new(None),
            bpf_filter,
            mcast,
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
        let mut state = self.state.lock();
        if peek { state.datagrams.front().cloned() } else { state.datagrams.pop_front() }
    }

    /// Queue one datagram if this endpoint still accepts delivery. # C: O(payload)
    pub fn enqueue(&self, datagram: Udp6Datagram) -> bool {
        let mut state = self.state.lock();
        if !state.accepting { return false; }
        state.datagrams.push_back(datagram);
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

    /// Total queued payload bytes. # C: O(N)
    pub fn queued_bytes(&self) -> usize {
        self.state.lock().datagrams.iter().map(|(.., payload)| payload.len()).sum()
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
