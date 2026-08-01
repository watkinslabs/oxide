// Per-socket `IPPROTO_IPV6` state. Storage only: every admission rule lives in
// `set`, every value/shape rule in `get`.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};
use sync::{Socket as LockClass, Spinlock};

/// `ipv6_pinfo` boolean fields this level owns. Option numbers are ABI; the bit
/// positions are private. # C: O(1)
pub mod flag {
    /// The RFC 3542 receive personality.
    pub const RXHOPOPTS: u64 = 1 << 0;
    pub const RXDSTOPTS: u64 = 1 << 1;
    pub const RXSRCRT: u64 = 1 << 2;
    pub const RXORIGDSTADDR: u64 = 1 << 3;
    pub const RXPATHMTU: u64 = 1 << 4;
    pub const RXFLOW: u64 = 1 << 5;
    pub const RECVFRAGSIZE: u64 = 1 << 6;
    /// The RFC 2292 receive personality, which carries its own cmsg numbers.
    pub const RXOINFO: u64 = 1 << 7;
    pub const RXOHLIM: u64 = 1 << 8;
    pub const RXOHOPOPTS: u64 = 1 << 9;
    pub const RXODSTOPTS: u64 = 1 << 10;
    pub const RXOSRCRT: u64 = 1 << 11;

    pub const DONTFRAG: u64 = 1 << 12;
    pub const AUTOFLOWLABEL: u64 = 1 << 13;
    /// The caller named an autoflowlabel policy, overriding the namespace one.
    pub const AUTOFLOWLABEL_SET: u64 = 1 << 14;
    pub const SNDFLOW: u64 = 1 << 15;
    pub const TRANSPARENT: u64 = 1 << 16;
    pub const FREEBIND: u64 = 1 << 17;
    pub const RTALERT: u64 = 1 << 18;
    pub const RTALERT_ISOLATE: u64 = 1 << 19;
    pub const RECVERR_RFC4884: u64 = 1 << 20;
    pub const REPFLOW: u64 = 1 << 21;
    pub const USE_MIN_MTU_SET: u64 = 1 << 22;
    /// `IPV6_MULTICAST_ALL` starts ENABLED, so the stored bit records the
    /// caller having turned it OFF.
    pub const MC_ALL_OFF: u64 = 1 << 23;
}

/// Sticky extension-header slot. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Sticky { HopOpts = 0, RthdrDstOpts = 1, Rthdr = 2, DstOpts = 3 }

impl Sticky { pub const COUNT: usize = 4; }

/// Per-socket `IPPROTO_IPV6` option state. # C: O(1)
pub struct Ipv6Opts {
    flags: AtomicU64,
    min_hopcount: AtomicI32,
    /// `IPV6_MTU`: caller-named fragmentation size, zero to follow the path.
    frag_size: AtomicI32,
    /// `IPV6_USE_MIN_MTU`: -1 unset, 0 path MTU, 1 the IPv6 minimum.
    use_min_mtu: AtomicI32,
    unicast_if: AtomicU32,
    /// `IPV6_ADDR_PREFERENCES` source-selection bits.
    srcprefs: AtomicI32,
    /// The flow label carried on transmit, already in the low 20 bits.
    flow_label: AtomicU32,
    /// `IPV6_FLOWINFO` as received, published by the label manager's remote
    /// query.
    rcv_flowinfo: AtomicU32,
    /// `IPV6_PKTINFO`: sticky source address and interface.
    sticky_pktinfo: Spinlock<([u8; 16], u32), LockClass>,
    /// `IPV6_NEXTHOP`: sticky first hop.
    nexthop: Spinlock<Option<[u8; 16]>, LockClass>,
    headers: Spinlock<[Option<Vec<u8>>; Sticky::COUNT], LockClass>,
    /// Flow labels this socket holds a reference on.
    labels: Spinlock<Vec<u32>, LockClass>,
}

impl Default for Ipv6Opts {
    fn default() -> Self {
        Self {
            flags: AtomicU64::new(0),
            min_hopcount: AtomicI32::new(0),
            frag_size: AtomicI32::new(0),
            use_min_mtu: AtomicI32::new(-1),
            unicast_if: AtomicU32::new(0),
            srcprefs: AtomicI32::new(0),
            flow_label: AtomicU32::new(0),
            rcv_flowinfo: AtomicU32::new(0),
            sticky_pktinfo: Spinlock::new(([0u8; 16], 0)),
            nexthop: Spinlock::new(None),
            headers: Spinlock::new([const { None }; Sticky::COUNT]),
            labels: Spinlock::new(Vec::new()),
        }
    }
}

impl core::fmt::Debug for Ipv6Opts {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ipv6Opts").field("flags", &self.flags).finish_non_exhaustive()
    }
}

impl Ipv6Opts {
    /// # C: O(1)
    pub fn flag(&self, bit: u64) -> bool { self.flags.load(Ordering::Acquire) & bit != 0 }
    /// # C: O(1)
    pub fn flags(&self) -> u64 { self.flags.load(Ordering::Acquire) }

    /// # C: O(1)
    pub fn set_flag(&self, bit: u64, on: bool) {
        if on { self.flags.fetch_or(bit, Ordering::AcqRel); }
        else { self.flags.fetch_and(!bit, Ordering::AcqRel); }
    }

    /// `IPV6_MULTICAST_ALL`. # C: O(1)
    pub fn multicast_all(&self) -> bool { !self.flag(flag::MC_ALL_OFF) }

    /// # C: O(1)
    pub fn min_hopcount(&self) -> i32 { self.min_hopcount.load(Ordering::Acquire) }
    /// # C: O(1)
    pub fn set_min_hopcount(&self, v: i32) { self.min_hopcount.store(v, Ordering::Release); }

    /// # C: O(1)
    pub fn frag_size(&self) -> i32 { self.frag_size.load(Ordering::Acquire) }
    /// # C: O(1)
    pub fn set_frag_size(&self, v: i32) { self.frag_size.store(v, Ordering::Release); }

    /// # C: O(1)
    pub fn use_min_mtu(&self) -> i32 { self.use_min_mtu.load(Ordering::Acquire) }
    /// # C: O(1)
    pub fn set_use_min_mtu(&self, v: i32) { self.use_min_mtu.store(v, Ordering::Release); }

    /// # C: O(1)
    pub fn unicast_if(&self) -> u32 { self.unicast_if.load(Ordering::Acquire) }
    /// # C: O(1)
    pub fn set_unicast_if(&self, v: u32) { self.unicast_if.store(v, Ordering::Release); }

    /// # C: O(1)
    pub fn srcprefs(&self) -> i32 { self.srcprefs.load(Ordering::Acquire) }
    /// # C: O(1)
    pub fn set_srcprefs(&self, v: i32) { self.srcprefs.store(v, Ordering::Release); }

    /// # C: O(1)
    pub fn flow_label(&self) -> u32 { self.flow_label.load(Ordering::Acquire) }
    /// # C: O(1)
    pub fn set_flow_label(&self, v: u32) { self.flow_label.store(v, Ordering::Release); }

    /// # C: O(1)
    pub fn rcv_flowinfo(&self) -> u32 { self.rcv_flowinfo.load(Ordering::Acquire) }
    /// # C: O(1)
    pub fn set_rcv_flowinfo(&self, v: u32) { self.rcv_flowinfo.store(v, Ordering::Release); }

    /// # C: O(1)
    pub fn sticky_pktinfo(&self) -> ([u8; 16], u32) { *self.sticky_pktinfo.lock() }
    /// # C: O(1)
    pub fn set_sticky_pktinfo(&self, addr: [u8; 16], ifindex: u32) {
        *self.sticky_pktinfo.lock() = (addr, ifindex);
    }

    /// # C: O(1)
    pub fn nexthop(&self) -> Option<[u8; 16]> { *self.nexthop.lock() }
    /// # C: O(1)
    pub fn set_nexthop(&self, addr: Option<[u8; 16]>) { *self.nexthop.lock() = addr; }

    /// The sticky extension header in one slot. # C: O(len)
    pub fn header(&self, slot: Sticky) -> Option<Vec<u8>> {
        self.headers.lock()[slot as usize].clone()
    }

    /// Install or, with an empty area, remove one sticky extension header.
    /// # C: O(len)
    pub fn set_header(&self, slot: Sticky, bytes: Option<Vec<u8>>) {
        self.headers.lock()[slot as usize] = bytes.filter(|b| !b.is_empty());
    }

    /// The extension-header bytes an outgoing datagram carries, in the order
    /// IPv6 requires them on the wire. # C: O(total len)
    pub fn header_chain(&self) -> Vec<(Sticky, Vec<u8>)> {
        let held = self.headers.lock();
        let order = [Sticky::HopOpts, Sticky::RthdrDstOpts, Sticky::Rthdr, Sticky::DstOpts];
        order.iter().filter_map(|slot| {
            held[*slot as usize].clone().map(|bytes| (*slot, bytes))
        }).collect()
    }

    /// # C: O(labels)
    pub fn holds_label(&self, label: u32) -> bool { self.labels.lock().contains(&label) }
    /// # C: O(1)
    pub fn hold_label(&self, label: u32) {
        let mut held = self.labels.lock();
        if !held.contains(&label) { held.push(label); }
    }
    /// # C: O(labels)
    pub fn release_label(&self, label: u32) -> bool {
        let mut held = self.labels.lock();
        match held.iter().position(|l| *l == label) {
            Some(at) => { held.remove(at); true }
            None => false,
        }
    }
    /// Every label this socket still holds, for teardown. # C: O(labels)
    pub fn take_labels(&self) -> Vec<u32> { core::mem::take(&mut *self.labels.lock()) }
}
