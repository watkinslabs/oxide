// IPv4 routing table per `25§10`. Longest-prefix-match over a
// small Vec — sufficient for the v1 single-iface use cases
// (loopback only) and easy to swap for an LPM trie later.

extern crate alloc;
use alloc::vec::Vec;

use sync::{Spinlock, Socket as RouteLockClass};

use crate::addr::{Ipv4Addr, NetIfaceId};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RouteEntry {
    pub dst:        Ipv4Addr,    // network address (already masked)
    pub prefix_len: u8,          // 0..=32
    pub iface:      NetIfaceId,
    pub gateway:    Option<Ipv4Addr>,
    pub src_hint:   Option<Ipv4Addr>,
}

impl RouteEntry {
    /// True iff `addr` falls under this route's prefix.
    /// # C: O(1)
    pub fn matches(&self, addr: Ipv4Addr) -> bool {
        let mask = if self.prefix_len == 0 { 0u32 } else { !0u32 << (32 - self.prefix_len) };
        (addr.as_u32() & mask) == (self.dst.as_u32() & mask)
    }
}

pub struct RouteTable {
    pub(crate) inner: Spinlock<Vec<RouteEntry>, RouteLockClass>,
}

impl RouteTable {
    pub const fn new() -> Self {
        Self { inner: Spinlock::new(Vec::new()) }
    }

    /// Insert a route. v1 doesn't dedup; caller controls.
    /// # C: O(1)
    pub fn add(&self, e: RouteEntry) {
        self.inner.lock().push(e);
    }

    /// Longest-prefix lookup. Returns `None` if no route matches.
    /// # C: O(N entries)
    pub fn lookup(&self, addr: Ipv4Addr) -> Option<RouteEntry> {
        let g = self.inner.lock();
        let mut best: Option<RouteEntry> = None;
        for e in g.iter() {
            if !e.matches(addr) { continue; }
            match best {
                Some(b) if b.prefix_len >= e.prefix_len => {}
                _ => best = Some(*e),
            }
        }
        best
    }

    /// All entries snapshot.
    /// # C: O(N)
    pub fn snapshot(&self) -> Vec<RouteEntry> { self.inner.lock().clone() }

    /// Remove entries matching `f`.
    /// # C: O(N)
    pub fn retain<F: FnMut(&RouteEntry) -> bool>(&self, mut f: F) {
        self.inner.lock().retain(|e| f(e));
    }
}

impl Default for RouteTable { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_default_matches_anything() {
        let t = RouteTable::new();
        t.add(RouteEntry {
            dst: Ipv4Addr::ANY, prefix_len: 0,
            iface: NetIfaceId::from_raw(1), gateway: None, src_hint: None,
        });
        let r = t.lookup(Ipv4Addr::new(8, 8, 8, 8)).unwrap();
        assert_eq!(r.iface, NetIfaceId::from_raw(1));
    }

    #[test]
    fn longest_prefix_wins() {
        let t = RouteTable::new();
        t.add(RouteEntry { dst: Ipv4Addr::ANY, prefix_len: 0, iface: NetIfaceId::from_raw(1), gateway: None, src_hint: None });
        t.add(RouteEntry { dst: Ipv4Addr::new(127, 0, 0, 0), prefix_len: 8, iface: NetIfaceId::from_raw(2), gateway: None, src_hint: None });
        let r = t.lookup(Ipv4Addr::LOOPBACK).unwrap();
        assert_eq!(r.iface, NetIfaceId::from_raw(2));
    }

    #[test]
    fn no_match_returns_none() {
        let t = RouteTable::new();
        t.add(RouteEntry { dst: Ipv4Addr::new(10, 0, 0, 0), prefix_len: 8, iface: NetIfaceId::from_raw(1), gateway: None, src_hint: None });
        assert!(t.lookup(Ipv4Addr::new(8, 8, 8, 8)).is_none());
    }
}
