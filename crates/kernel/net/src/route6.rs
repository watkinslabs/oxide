// IPv6 routing table. Longest-prefix-match over a small Vec, matching the
// IPv4 route table shape while keeping v6 prefix logic explicit.

extern crate alloc;
use alloc::{collections::BTreeMap, vec::Vec};

use sync::{Spinlock, Socket as RouteLockClass};

use crate::addr::{Ipv6Addr, NetIfaceId};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Route6Entry {
    pub dst:        Ipv6Addr,
    pub prefix_len: u8,
    pub iface:      NetIfaceId,
    pub gateway:    Option<Ipv6Addr>,
    pub src_hint:   Option<Ipv6Addr>,
}

impl Route6Entry {
    /// True iff `addr` falls under this route's prefix.
    /// # C: O(1)
    pub fn matches(&self, addr: Ipv6Addr) -> bool {
        let prefix_len = self.prefix_len.min(128);
        if prefix_len == 0 { return true; }
        let full = (prefix_len / 8) as usize;
        let rem = prefix_len % 8;
        let dst = self.dst.0;
        let addr = addr.0;
        let mut i = 0;
        while i < full {
            if dst[i] != addr[i] { return false; }
            i += 1;
        }
        if rem == 0 { return true; }
        let mask = !0u8 << (8 - rem);
        (dst[full] & mask) == (addr[full] & mask)
    }
}

pub struct Route6Table {
    pub(crate) inner: Spinlock<BTreeMap<u64, Vec<Route6Entry>>, RouteLockClass>,
}

impl Route6Table {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self { inner: Spinlock::new(BTreeMap::new()) }
    }

    /// Insert a route. v1 doesn't dedup; caller controls.
    /// # C: O(1)
    pub fn add(&self, e: Route6Entry) {
        self.add_in(0, e);
    }

    /// Insert a route in one network namespace. # C: O(log N_ns)
    pub fn add_in(&self, net_ns: u64, e: Route6Entry) {
        self.inner.lock().entry(net_ns).or_default().push(e);
    }

    /// Longest-prefix lookup. Returns `None` if no route matches.
    /// # C: O(N entries)
    pub fn lookup(&self, addr: Ipv6Addr) -> Option<Route6Entry> {
        self.lookup_in(0, addr)
    }

    /// Longest-prefix lookup in one network namespace. # C: O(N entries)
    pub fn lookup_in(&self, net_ns: u64, addr: Ipv6Addr) -> Option<Route6Entry> {
        let all = self.inner.lock();
        let g = all.get(&net_ns).map(Vec::as_slice).unwrap_or(&[]);
        let mut best: Option<Route6Entry> = None;
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
    pub fn snapshot(&self) -> Vec<Route6Entry> { self.snapshot_in(0) }

    /// Snapshot routes in one network namespace. # C: O(N)
    pub fn snapshot_in(&self, net_ns: u64) -> Vec<Route6Entry> {
        self.inner.lock().get(&net_ns).cloned().unwrap_or_default()
    }

    /// Remove entries matching `f`.
    /// # C: O(N)
    pub fn retain<F: FnMut(&Route6Entry) -> bool>(&self, mut f: F) {
        self.retain_in(0, |e| f(e));
    }

    /// Remove namespace routes not retained by `f`. # C: O(N)
    pub fn retain_in<F: FnMut(&Route6Entry) -> bool>(&self, net_ns: u64, mut f: F) {
        let mut all = self.inner.lock();
        let Some(routes) = all.get_mut(&net_ns) else { return; };
        routes.retain(|e| f(e));
        if routes.is_empty() { all.remove(&net_ns); }
    }

    /// Drop all routes owned by a destroyed namespace. # C: O(log N_ns)
    pub fn remove_namespace(&self, net_ns: u64) -> bool {
        if net_ns == 0 { return false; }
        self.inner.lock().remove(&net_ns).is_some()
    }
}

impl Default for Route6Table { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;

    fn v6(s: [u16; 8]) -> Ipv6Addr { Ipv6Addr::from_segments(s) }

    #[test]
    fn lookup_default_matches_anything() {
        let t = Route6Table::new();
        t.add(Route6Entry {
            dst: Ipv6Addr::ANY, prefix_len: 0,
            iface: NetIfaceId::from_raw(1), gateway: None, src_hint: None,
        });
        let r = t.lookup(v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1])).unwrap();
        assert_eq!(r.iface, NetIfaceId::from_raw(1));
    }

    #[test]
    fn longest_prefix_wins() {
        let t = Route6Table::new();
        t.add(Route6Entry { dst: Ipv6Addr::ANY, prefix_len: 0, iface: NetIfaceId::from_raw(1), gateway: None, src_hint: None });
        t.add(Route6Entry { dst: v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0]), prefix_len: 32, iface: NetIfaceId::from_raw(2), gateway: None, src_hint: None });
        t.add(Route6Entry { dst: v6([0x2001, 0xdb8, 0x10, 0, 0, 0, 0, 0]), prefix_len: 48, iface: NetIfaceId::from_raw(3), gateway: None, src_hint: None });
        let r = t.lookup(v6([0x2001, 0xdb8, 0x10, 0, 0, 0, 0, 1])).unwrap();
        assert_eq!(r.iface, NetIfaceId::from_raw(3));
    }

    #[test]
    fn partial_byte_prefix_matches() {
        let t = Route6Table::new();
        t.add(Route6Entry { dst: v6([0xfe80, 0, 0, 0, 0, 0, 0, 0]), prefix_len: 10, iface: NetIfaceId::from_raw(1), gateway: None, src_hint: None });
        assert!(t.lookup(v6([0xfebf, 0, 0, 0, 0, 0, 0, 1])).is_some());
        assert!(t.lookup(v6([0xfec0, 0, 0, 0, 0, 0, 0, 1])).is_none());
    }

    #[test]
    fn namespace_lookup_retain_and_removal_are_isolated() {
        let t = Route6Table::new();
        let dst = v6([0x2001, 0xdb8, 1, 0, 0, 0, 0, 1]);
        let a = NetIfaceId::from_raw(11);
        let b = NetIfaceId::from_raw(12);
        let init = NetIfaceId::from_raw(13);
        t.add(Route6Entry { dst: Ipv6Addr::ANY, prefix_len: 0, iface: init, gateway: None, src_hint: None });
        t.add_in(41, Route6Entry { dst: Ipv6Addr::ANY, prefix_len: 0, iface: a, gateway: None, src_hint: None });
        t.add_in(42, Route6Entry { dst: Ipv6Addr::ANY, prefix_len: 0, iface: b, gateway: None, src_hint: None });
        assert_eq!(t.lookup_in(41, dst).map(|r| r.iface), Some(a));
        assert_eq!(t.lookup_in(42, dst).map(|r| r.iface), Some(b));
        assert_eq!(t.lookup(dst).map(|r| r.iface), Some(init));
        t.retain_in(41, |_| false);
        assert!(t.lookup_in(41, dst).is_none());
        assert_eq!(t.lookup_in(42, dst).map(|r| r.iface), Some(b));
        assert!(t.remove_namespace(42));
        assert!(t.lookup_in(42, dst).is_none());
        assert_eq!(t.lookup(dst).map(|r| r.iface), Some(init));
        assert!(!t.remove_namespace(0));
    }
}
