// The UDP receive-queue types: one queued datagram, the coalescing run it
// belongs to, and the endpoint that holds them. Split out of `stack::types` at
// the per-file size cutoff.

use super::super::*;

/// One queued IPv4 UDP datagram plus every header field the ancillary
/// messages publish: `dst` + `iface` back IP_PKTINFO, `dport` completes the
/// IP_ORIGDSTADDR socket address, `ttl` backs IP_TTL, `tos` backs IP_TOS,
/// `options` backs IP_RECVOPTS and IP_RETOPTS, and `frag_max` backs
/// IP_RECVFRAGSIZE.
#[derive(Clone, Debug)]
pub struct UdpDatagram {
    pub src: Ipv4Addr,
    pub sport: u16,
    pub dst: Ipv4Addr,
    pub dport: u16,
    pub iface: NetIfaceId,
    pub ttl: u8,
    pub tos: u8,
    /// Compiled receive-side option area, empty when the header carried
    /// none. Compiled rather than raw because the reply area IP_RETOPTS
    /// echoes needs the pointers the receive pass advanced.
    pub options: crate::ipv4_options::Compiled,
    /// Largest fragment this datagram was reassembled from, zero when it
    /// arrived whole.
    pub frag_max: u32,
    /// The header's don't-fragment bit, which no ancillary message publishes
    /// but which two receives must share to coalesce.
    pub dont_fragment: bool,
    pub payload: Vec<u8>,
}

impl UdpDatagram {
    /// A datagram carrying nothing beyond the addresses, hop limit and body —
    /// the shape a loopback delivery produces. # C: O(1)
    pub fn plain(src: Ipv4Addr, sport: u16, dst: Ipv4Addr, iface: NetIfaceId, ttl: u8,
                 payload: Vec<u8>) -> Self
    {
        Self { src, sport, dst, dport: 0, iface, ttl, tos: 0, options: Default::default(),
               frag_max: 0, dont_fragment: false, payload }
    }
}

/// One queued IPv4 UDP receive plus the coalescing run it belongs to.
#[derive(Clone)]
pub(crate) struct QueuedUdp {
    pub(crate) datagram: UdpDatagram,
    pub(crate) gro: crate::udp_gro::GroRun,
}

pub(crate) struct UdpRxState {
    pub(crate) accepting: bool,
    pub(crate) datagrams: VecDeque<QueuedUdp>,
}


pub struct UdpRxQueue {
    pub owner: Arc<crate::SocketOwner>,
    pub bound_ip:   Ipv4Addr,
    pub bound_port: u16,
    /// Datagrams waiting for a reader, each carrying the header fields the
    /// ancillary messages publish.
    pub(crate) state: Spinlock<UdpRxState, StackLockClass>,
    /// F162: blocking sys_recvfrom waiters (kernel only).
    #[cfg(target_os = "oxide-kernel")]
    pub waiters: sched::live::WaitList,
    /// Canonical owning socket error state.
    pub error: Arc<crate::SocketError>,
    /// Connected peer filter. `None` accepts datagrams from any peer.
    pub peer: Arc<Spinlock<Option<(Ipv4Addr, u16)>, StackLockClass>>,
    pub reuseaddr: Arc<::core::sync::atomic::AtomicI32>,
    pub reuseport: Arc<::core::sync::atomic::AtomicI32>,
    pub ip_mtu_discover: Arc<::core::sync::atomic::AtomicI32>,
    /// `UDP_GRO`, shared with the owning socket: while set, arriving
    /// datagrams of one flow coalesce into a single receive.
    pub gro: Arc<::core::sync::atomic::AtomicI32>,
    pub bound_ifindex: ::core::sync::atomic::AtomicU32,
    /// F181a: per-fd epoll subscribers.
    pub poll_subs: Spinlock<Option<alloc::sync::Weak<vfs::PollSubscribers>>, StackLockClass>,
    pub bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
    /// Socket multicast state shared before and after bind.
    pub mcast: Arc<crate::mcast_filter::SocketMcast>,
    /// SO_REUSEPORT group reached from the bind table on the delivery path.
    /// Published by bind-time join; the owning socket's cell holds membership.
    pub reuseport_group: crate::reuseport::ReuseportSlot,
}

impl UdpRxQueue {
    /// SO_REUSEPORT membership captured when this endpoint was bound. # C: O(1)
    pub(crate) fn reuseport_member(&self) -> bool {
        self.reuseport.load(::core::sync::atomic::Ordering::Acquire) != 0
    }
}

impl ::core::ops::Deref for UdpRxQueue {
    type Target = crate::SocketOwner;

    fn deref(&self) -> &Self::Target { &self.owner }
}
