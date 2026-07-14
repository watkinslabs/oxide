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

pub struct Udp6RxQueue {
    pub bound_ip: Ipv6Addr,
    pub bound_port: u16,
    pub q: Spinlock<VecDeque<Udp6Datagram>, StackLockClass>,
    #[cfg(target_os = "oxide-kernel")]
    pub waiters: sched::live::WaitList,
    pub error: Arc<crate::SocketError>,
    pub bound_ifindex: core::sync::atomic::AtomicU32,
    pub poll_subs: Spinlock<Option<alloc::sync::Weak<vfs::PollSubscribers>>, StackLockClass>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Ipv6IfaceAddr {
    pub addr: Ipv6Addr,
    pub prefixlen: u8,
    pub preferred: u32,
    pub valid: u32,
}

impl Ipv6IfaceAddr {
    pub const PERMANENT: (u32, u32) = (u32::MAX, u32::MAX);
}

impl Udp6RxQueue {
    /// Build a standalone IPv6 UDP queue for hosted stack users. # C: O(1)
    pub fn new(bound_ip: Ipv6Addr, bound_port: u16) -> Self {
        Self::new_with_error(bound_ip, bound_port, Arc::new(crate::SocketError::new()))
    }

    /// Build a queue sharing one socket's canonical error state. # C: O(1)
    pub fn new_with_error(bound_ip: Ipv6Addr, bound_port: u16, error: Arc<crate::SocketError>) -> Self {
        Self {
            bound_ip,
            bound_port,
            q: Spinlock::new(VecDeque::new()),
            #[cfg(target_os = "oxide-kernel")]
            waiters: sched::live::WaitList::new(),
            error,
            bound_ifindex: core::sync::atomic::AtomicU32::new(0),
            poll_subs: Spinlock::new(None),
        }
    }

    /// Publish an asynchronous socket error and wake all endpoint observers. # C: O(1)
    pub fn set_error(&self, errno: i32) -> bool {
        let _queue = self.q.lock();
        if !self.error.set(errno) { return false; }
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
}
