// Per-socket level-17 cells. State only; the decisions that read it live in
// `table`, `cork`, and `segment`.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, Ordering};

use sync::{Socket as SockLockClass, Spinlock};

use crate::addr::{Ipv4Addr, Ipv6Addr};

/// The destination a corked datagram was pinned to by its first append. Linux
/// records the route at cork time and ignores the address of every later send
/// until the cork is pushed, so a corked socket has exactly one destination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CorkDest {
    V4 { ip: Ipv4Addr, port: u16 },
    V6 { ip: Ipv6Addr, port: u16, scope_id: u32 },
}

impl CorkDest {
    /// Address family this pinned destination belongs to. A send that would
    /// append across families to an already-corked socket is `EINVAL`.
    /// # C: O(1)
    pub fn family(&self) -> u16 {
        match self { Self::V4 { .. } => crate::sock::AF_INET, Self::V6 { .. } => crate::sock::AF_INET6 }
    }
}

/// One socket's accumulated cork.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorkPending { pub dest: CorkDest, pub payload: Vec<u8> }

/// Per-socket `IPPROTO_UDP` option state.
pub struct UdpOpts {
    /// `UDP_CORK`: hold partial datagrams until the cork clears.
    pub cork: AtomicI32,
    /// `UDP_ENCAP`: the encapsulation identity this socket announces.
    pub encap_type: AtomicI32,
    /// `UDP_NO_CHECK6_TX`: emit IPv6 datagrams with a zero checksum.
    pub no_check6_tx: AtomicI32,
    /// `UDP_NO_CHECK6_RX`: accept IPv6 datagrams that carry a zero checksum.
    /// Shared with the bound IPv6 endpoint so receive and option read can
    /// never disagree.
    pub no_check6_rx: Arc<AtomicI32>,
    /// `UDP_SEGMENT`: segmentation size, `0` when segmentation is off.
    pub gso_size: AtomicI32,
    /// `UDP_GRO`: this socket accepts coalesced receive segments.
    pub gro: AtomicI32,
    /// Bytes held by an active cork, plus the destination they are pinned to.
    pub pending: Spinlock<Option<CorkPending>, SockLockClass>,
}

impl Default for UdpOpts {
    fn default() -> Self {
        Self {
            cork: AtomicI32::new(0),
            encap_type: AtomicI32::new(super::uapi::UDP_ENCAP_NONE),
            no_check6_tx: AtomicI32::new(0),
            no_check6_rx: Arc::new(AtomicI32::new(0)),
            gso_size: AtomicI32::new(0),
            gro: AtomicI32::new(0),
            pending: Spinlock::new(None),
        }
    }
}

impl core::fmt::Debug for UdpOpts {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UdpOpts")
            .field("cork", &self.cork.load(Ordering::Acquire))
            .field("encap_type", &self.encap_type.load(Ordering::Acquire))
            .field("gso_size", &self.gso_size.load(Ordering::Acquire))
            .finish()
    }
}

impl UdpOpts {
    /// `UDP_CORK` is engaged. # C: O(1)
    pub fn corked(&self) -> bool { self.cork.load(Ordering::Acquire) != 0 }

    /// `UDP_SEGMENT` size, `0` when the socket does not segment. # C: O(1)
    pub fn gso_size(&self) -> usize { self.gso_size.load(Ordering::Acquire).max(0) as usize }

    /// `UDP_NO_CHECK6_TX`. # C: O(1)
    pub fn no_check6_tx(&self) -> bool { self.no_check6_tx.load(Ordering::Acquire) != 0 }

    /// `UDP_NO_CHECK6_RX`. # C: O(1)
    pub fn no_check6_rx(&self) -> bool { self.no_check6_rx.load(Ordering::Acquire) != 0 }
}
