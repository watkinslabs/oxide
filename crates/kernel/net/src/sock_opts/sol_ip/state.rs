// Per-socket `IPPROTO_IP` state. Storage only: every admission rule lives in
// `set`, every value/shape rule in `get`.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use sync::{Socket as LockClass, Spinlock};

use crate::ipv4_options::Compiled;

/// `inet_sock` boolean fields this level owns. The option numbers are ABI; the
/// bit positions are private. # C: O(1)
pub mod flag {
    pub const RECVTOS: u64 = 1 << 0;
    pub const RECVOPTS: u64 = 1 << 1;
    pub const RETOPTS: u64 = 1 << 2;
    pub const PASSSEC: u64 = 1 << 3;
    pub const ORIGDSTADDR: u64 = 1 << 4;
    pub const RECVFRAGSIZE: u64 = 1 << 5;
    pub const RECVERR_RFC4884: u64 = 1 << 6;
    pub const FREEBIND: u64 = 1 << 7;
    pub const TRANSPARENT: u64 = 1 << 8;
    pub const NODEFRAG: u64 = 1 << 9;
    pub const BIND_ADDRESS_NO_PORT: u64 = 1 << 10;
    pub const CHECKSUM: u64 = 1 << 11;
    pub const RTALERT: u64 = 1 << 12;
    /// `IP_MULTICAST_ALL` starts ENABLED, so the stored bit records the caller
    /// having turned it OFF.
    pub const MC_ALL_OFF: u64 = 1 << 13;
}

/// Per-socket `IPPROTO_IP` option state. # C: O(1)
pub struct IpOpts {
    flags: AtomicU64,
    /// `IP_UNICAST_IF` — outbound interface index for unicast, zero unset.
    unicast_if: AtomicU32,
    /// `IP_LOCAL_PORT_RANGE` — low half is the first port, high half the last.
    local_port_range: AtomicU32,
    options: Spinlock<Option<Compiled>, LockClass>,
}

impl Default for IpOpts {
    fn default() -> Self {
        Self {
            flags: AtomicU64::new(0),
            unicast_if: AtomicU32::new(0),
            local_port_range: AtomicU32::new(0),
            options: Spinlock::new(None),
        }
    }
}

impl core::fmt::Debug for IpOpts {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IpOpts").field("flags", &self.flags).finish_non_exhaustive()
    }
}

impl IpOpts {
    /// # C: O(1)
    pub fn flag(&self, bit: u64) -> bool { self.flags.load(Ordering::Acquire) & bit != 0 }

    /// The whole flag word, for the read table. # C: O(1)
    pub fn flag_word(&self) -> u64 { self.flags.load(Ordering::Acquire) }

    /// # C: O(1)
    pub fn set_flag(&self, bit: u64, on: bool) {
        if on { self.flags.fetch_or(bit, Ordering::AcqRel); }
        else { self.flags.fetch_and(!bit, Ordering::AcqRel); }
    }

    /// `IP_MULTICAST_ALL`: deliver every multicast datagram arriving on a
    /// joined group's port, not only those passing the source filter. # C: O(1)
    pub fn multicast_all(&self) -> bool { !self.flag(flag::MC_ALL_OFF) }

    /// # C: O(1)
    pub fn unicast_if(&self) -> u32 { self.unicast_if.load(Ordering::Acquire) }
    /// # C: O(1)
    pub fn set_unicast_if(&self, ifindex: u32) {
        self.unicast_if.store(ifindex, Ordering::Release);
    }

    /// The packed `IP_LOCAL_PORT_RANGE` word, zero when the socket follows the
    /// namespace range. # C: O(1)
    pub fn local_port_range(&self) -> u32 { self.local_port_range.load(Ordering::Acquire) }
    /// # C: O(1)
    pub fn set_local_port_range(&self, packed: u32) {
        self.local_port_range.store(packed, Ordering::Release);
    }

    /// The compiled option area an outgoing datagram carries. # C: O(optlen)
    pub fn options(&self) -> Option<Compiled> { self.options.lock().clone() }

    /// The option-area length an outgoing header must reserve. # C: O(1)
    pub fn options_len(&self) -> usize {
        self.options.lock().as_ref().map_or(0, Compiled::len)
    }

    /// The bytes `getsockopt(IP_OPTIONS)` publishes — the caller's own area,
    /// not the compiled form. # C: O(optlen)
    pub fn options_undone(&self) -> Vec<u8> {
        match self.options.lock().as_ref() {
            Some(c) => crate::ipv4_options::undo(c),
            None => Vec::new(),
        }
    }

    /// Install a compiled option area, or clear it when empty. # C: O(optlen)
    pub fn set_options(&self, compiled: Compiled) {
        *self.options.lock() = if compiled.is_empty() { None } else { Some(compiled) };
    }
}

/// The effective local port window: the socket's own when it named one, the
/// namespace's otherwise. A half-open request keeps the namespace bound on the
/// side it left zero. # C: O(1)
pub fn effective_port_range(packed: u32, ns: (u16, u16)) -> (u16, u16) {
    crate::local_port::effective_bounds(packed, ns)
}
