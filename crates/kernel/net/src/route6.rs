// IPv6 routing table. Longest-prefix-match over a small Vec, matching the
// IPv4 route table shape while keeping v6 prefix logic explicit.

extern crate alloc;
use alloc::{collections::BTreeMap, vec::Vec};

use crate::addr::{Ipv6Addr, NetIfaceId};
use crate::fib_lock::FibLock;
use crate::policy_rule::{PolicyRuleTable, AF_INET6, RT_TABLE_MAIN};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Route6Origin {
    Static,
    RouterAdvertisementDefault { router: Ipv6Addr, valid_until_ns: u64 },
    RouterAdvertisementPrefix { valid_until_ns: u64 },
}

impl Route6Origin {
    pub(crate) fn ra_router(self) -> Option<Ipv6Addr> {
        match self {
            Self::Static => None,
            Self::RouterAdvertisementDefault { router, .. } => Some(router),
            Self::RouterAdvertisementPrefix { .. } => None,
        }
    }

    pub(crate) fn is_ra_prefix(self) -> bool {
        matches!(self, Self::RouterAdvertisementPrefix { .. })
    }

    fn live_at(self, now_ns: u64) -> bool {
        match self {
            Self::Static => true,
            Self::RouterAdvertisementDefault { valid_until_ns, .. }
            | Self::RouterAdvertisementPrefix { valid_until_ns } => valid_until_ns > now_ns,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Route6Entry {
    pub table:      u32,
    pub dst:        Ipv6Addr,
    pub prefix_len: u8,
    pub iface:      NetIfaceId,
    pub gateway:    Option<Ipv6Addr>,
    pub src_hint:   Option<Ipv6Addr>,
    pub origin:     Route6Origin,
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
    pub(crate) inner: FibLock<BTreeMap<u64, Vec<Route6Entry>>>,
    #[cfg(not(target_os = "oxide-kernel"))]
    now_ns: core::sync::atomic::AtomicU64,
}

impl Route6Table {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self {
            inner: FibLock::new(BTreeMap::new()),
            #[cfg(not(target_os = "oxide-kernel"))]
            now_ns: core::sync::atomic::AtomicU64::new(0),
        }
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
        self.lookup_in_table_in(net_ns, RT_TABLE_MAIN, addr)
    }

    /// Longest-prefix lookup in one namespace and table. # C: O(N entries)
    pub fn lookup_in_table_in(&self, net_ns: u64, table: u32,
                              addr: Ipv6Addr) -> Option<Route6Entry> {
        let now_ns = self.now_ns();
        let all = self.inner.lock();
        let g = all.get(&net_ns).map(Vec::as_slice).unwrap_or(&[]);
        let mut best: Option<Route6Entry> = None;
        for e in g.iter() {
            if e.table != table || !e.origin.live_at(now_ns) || !e.matches(addr) { continue; }
            match best {
                Some(b) if b.prefix_len >= e.prefix_len => {}
                _ => best = Some(*e),
            }
        }
        best
    }

    /// Policy-rule lookup in one network namespace. # C: O(N rules * N routes)
    pub fn lookup_policy_in(&self, net_ns: u64, addr: Ipv6Addr,
                            rules: &PolicyRuleTable) -> Option<Route6Entry> {
        self.lookup_policy_mark_in(net_ns, addr, rules, 0)
    }

    /// Policy-rule lookup for a packet carrying `mark`. A rule that selects on
    /// the mark is skipped by a packet whose mark it does not match, exactly as
    /// on the IPv4 side — the rule table is shared. # C: O(N rules * N routes)
    pub fn lookup_policy_mark_in(&self, net_ns: u64, addr: Ipv6Addr,
                                 rules: &PolicyRuleTable, mark: u32) -> Option<Route6Entry> {
        for rule in rules.snapshot_effective(net_ns, AF_INET6) {
            if rule.fwmask != 0 && mark & rule.fwmask != rule.fwmark { continue; }
            if let Some(route) = self.lookup_in_table_in(net_ns, rule.table, addr) {
                return Some(route);
            }
        }
        None
    }

    /// Policy-rule lookup constrained to one output interface. # C: O(N rules * N routes)
    pub fn lookup_policy_iface_in(&self, net_ns: u64, addr: Ipv6Addr,
                                  iface: NetIfaceId, rules: &PolicyRuleTable)
        -> Option<Route6Entry>
    {
        self.lookup_policy_iface_mark_in(net_ns, addr, iface, rules, 0)
    }

    /// [`lookup_policy_iface_in`] for a packet carrying `mark`. # C: O(N rules * N routes)
    pub fn lookup_policy_iface_mark_in(&self, net_ns: u64, addr: Ipv6Addr,
                                  iface: NetIfaceId, rules: &PolicyRuleTable, mark: u32)
        -> Option<Route6Entry>
    {
        let rules = rules.snapshot_effective(net_ns, AF_INET6);
        let now_ns = self.now_ns();
        let all = self.inner.lock();
        let routes = all.get(&net_ns).map(Vec::as_slice).unwrap_or(&[]);
        for rule in rules {
            if rule.fwmask != 0 && mark & rule.fwmask != rule.fwmark { continue; }
            let mut best = None;
            for route in routes {
                if route.table != rule.table || route.iface != iface
                    || !route.origin.live_at(now_ns) || !route.matches(addr) { continue; }
                if best.is_none_or(|old: Route6Entry| old.prefix_len < route.prefix_len) {
                    best = Some(*route);
                }
            }
            if best.is_some() { return best; }
        }
        None
    }

    /// All entries snapshot.
    /// # C: O(N)
    pub fn snapshot(&self) -> Vec<Route6Entry> { self.snapshot_in(0) }

    /// Snapshot routes in one network namespace. # C: O(N)
    pub fn snapshot_in(&self, net_ns: u64) -> Vec<Route6Entry> {
        let now_ns = self.now_ns();
        self.inner.lock().get(&net_ns).map(|routes| routes.iter().copied()
            .filter(|route| route.origin.live_at(now_ns)).collect()).unwrap_or_default()
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

    /// Atomically remove matching routes and publish replacements. # C: O(N + R)
    pub fn replace_in<F: FnMut(&Route6Entry) -> bool>(&self, net_ns: u64,
        mut remove: F, replacements: Vec<Route6Entry>)
    {
        let _ = self.replace_in_changes(net_ns, |route| remove(route), replacements);
    }

    /// Atomically replace routes and return removed canonical rows. # C: O(N + R)
    pub(crate) fn replace_in_changes<F: FnMut(&Route6Entry) -> bool>(&self, net_ns: u64,
        mut remove: F, replacements: Vec<Route6Entry>) -> Vec<Route6Entry>
    {
        let mut all = self.inner.lock();
        let routes = all.entry(net_ns).or_default();
        let mut removed = Vec::new();
        routes.retain(|e| {
            if !remove(e) { return true; }
            removed.push(*e);
            false
        });
        routes.extend(replacements);
        if routes.is_empty() { all.remove(&net_ns); }
        removed
    }

    /// Remove expired routes while matching stack RTNL is held. # C: O(N)
    pub(crate) fn take_expired_rtnl(&self, rtnl: &crate::RtnlGuard<'_>, now_ns: u64,
                                    ifaces: &[NetIfaceId])
        -> Vec<(u64, Route6Entry)>
    {
        if !core::ptr::eq(self, &rtnl.stack().routes6) { return Vec::new(); }
        let mut all = self.inner.lock();
        let mut removed = Vec::new();
        all.retain(|net_ns, routes| {
            routes.retain(|route| {
                if route.origin.live_at(now_ns) || !ifaces.contains(&route.iface) { return true; }
                removed.push((*net_ns, *route));
                false
            });
            !routes.is_empty()
        });
        removed
    }

    pub(crate) fn expired_ifaces(&self, now_ns: u64) -> Vec<NetIfaceId> {
        let mut out = Vec::new();
        for routes in self.inner.lock().values() {
            for route in routes {
                if !route.origin.live_at(now_ns) && !out.contains(&route.iface) {
                    out.push(route.iface);
                }
            }
        }
        out
    }

    pub(crate) fn take_iface_in_rtnl(&self, rtnl: &crate::RtnlGuard<'_>, net_ns: u64,
                                     iface: NetIfaceId) -> Vec<Route6Entry> {
        if !core::ptr::eq(self, &rtnl.stack().routes6) { return Vec::new(); }
        let mut all = self.inner.lock();
        let Some(routes) = all.get_mut(&net_ns) else { return Vec::new() };
        let mut removed = Vec::new();
        routes.retain(|route| {
            if route.iface != iface { return true; }
            removed.push(*route);
            false
        });
        if routes.is_empty() { all.remove(&net_ns); }
        removed
    }

    pub(crate) fn take_namespace_rtnl(&self, rtnl: &crate::RtnlGuard<'_>, net_ns: u64)
        -> Vec<Route6Entry>
    {
        if net_ns == 0 || !core::ptr::eq(self, &rtnl.stack().routes6) { return Vec::new(); }
        self.inner.lock().remove(&net_ns).unwrap_or_default()
    }

    pub(crate) fn clear_src_hint(&self, iface: NetIfaceId, addr: Ipv6Addr) {
        for routes in self.inner.lock().values_mut() {
            for route in routes.iter_mut() {
                if route.iface == iface && route.src_hint == Some(addr) { route.src_hint = None; }
            }
        }
    }

    /// Promote one DAD-complete SLAAC address into its on-link route. # C: O(N routes)
    pub(crate) fn activate_slaac_src_hint(&self, iface: NetIfaceId, prefix: Ipv6Addr,
                                          addr: Ipv6Addr) {
        for routes in self.inner.lock().values_mut() {
            for route in routes.iter_mut() {
                if route.iface == iface && route.dst == prefix && route.origin.is_ra_prefix() {
                    route.src_hint = Some(addr);
                }
            }
        }
    }

    #[cfg(not(target_os = "oxide-kernel"))]
    pub(crate) fn set_now_ns(&self, now_ns: u64) {
        self.now_ns.store(now_ns, core::sync::atomic::Ordering::Release);
    }

    fn now_ns(&self) -> u64 {
        #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
        { use hal::TimerOps; return hal_x86_64::X86TimerOps::monotonic_ns().0; }
        #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
        { use hal::TimerOps; return hal_aarch64::ArmTimerOps::monotonic_ns().0; }
        #[cfg(not(target_os = "oxide-kernel"))]
        { return self.now_ns.load(core::sync::atomic::Ordering::Acquire); }
        #[allow(unreachable_code)]
        0
    }

    /// Drop all routes owned by a destroyed namespace. # C: O(log N_ns)
    pub fn remove_namespace(&self, net_ns: u64) -> bool {
        if net_ns == 0 { return false; }
        self.inner.lock().remove(&net_ns).is_some()
    }

    /// Guarded namespace-route removal. # Lk: matching stack RTNL held. # C: O(log N_ns)
    pub fn remove_namespace_rtnl(&self, rtnl: &crate::RtnlGuard<'_>, net_ns: u64) -> bool {
        !self.take_namespace_rtnl(rtnl, net_ns).is_empty()
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
            table: RT_TABLE_MAIN,
            dst: Ipv6Addr::ANY, prefix_len: 0,
            iface: NetIfaceId::from_raw(1), gateway: None, src_hint: None,
            origin: Route6Origin::Static,
        });
        let r = t.lookup(v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1])).unwrap();
        assert_eq!(r.iface, NetIfaceId::from_raw(1));
    }

    #[test]
    fn longest_prefix_wins() {
        let t = Route6Table::new();
        t.add(Route6Entry { table: RT_TABLE_MAIN, dst: Ipv6Addr::ANY, prefix_len: 0, iface: NetIfaceId::from_raw(1), gateway: None, src_hint: None, origin: Route6Origin::Static });
        t.add(Route6Entry { table: RT_TABLE_MAIN, dst: v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0]), prefix_len: 32, iface: NetIfaceId::from_raw(2), gateway: None, src_hint: None, origin: Route6Origin::Static });
        t.add(Route6Entry { table: RT_TABLE_MAIN, dst: v6([0x2001, 0xdb8, 0x10, 0, 0, 0, 0, 0]), prefix_len: 48, iface: NetIfaceId::from_raw(3), gateway: None, src_hint: None, origin: Route6Origin::Static });
        let r = t.lookup(v6([0x2001, 0xdb8, 0x10, 0, 0, 0, 0, 1])).unwrap();
        assert_eq!(r.iface, NetIfaceId::from_raw(3));
    }

    #[test]
    fn partial_byte_prefix_matches() {
        let t = Route6Table::new();
        t.add(Route6Entry { table: RT_TABLE_MAIN, dst: v6([0xfe80, 0, 0, 0, 0, 0, 0, 0]), prefix_len: 10, iface: NetIfaceId::from_raw(1), gateway: None, src_hint: None, origin: Route6Origin::Static });
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
        t.add(Route6Entry { table: RT_TABLE_MAIN, dst: Ipv6Addr::ANY, prefix_len: 0, iface: init, gateway: None, src_hint: None, origin: Route6Origin::Static });
        t.add_in(41, Route6Entry { table: RT_TABLE_MAIN, dst: Ipv6Addr::ANY, prefix_len: 0, iface: a, gateway: None, src_hint: None, origin: Route6Origin::Static });
        t.add_in(42, Route6Entry { table: RT_TABLE_MAIN, dst: Ipv6Addr::ANY, prefix_len: 0, iface: b, gateway: None, src_hint: None, origin: Route6Origin::Static });
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

    #[test]
    fn replacement_blocks_lookup_until_new_route_is_published() {
        use alloc::sync::Arc;
        use core::time::Duration;
        use std::sync::mpsc;

        const NS: u64 = 43;
        let t = Arc::new(Route6Table::new());
        let dst = v6([0x2001, 0xdb8, 2, 0, 0, 0, 0, 1]);
        let old_iface = NetIfaceId::from_raw(21);
        let new_iface = NetIfaceId::from_raw(22);
        t.add_in(NS, Route6Entry { table: RT_TABLE_MAIN, dst: Ipv6Addr::ANY, prefix_len: 0,
            iface: old_iface, gateway: None, src_hint: None, origin: Route6Origin::Static });
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let replacing = Arc::clone(&t);
        let replace = std::thread::spawn(move || replacing.replace_in(NS, |route| {
            entered_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            route.prefix_len == 0
        }, alloc::vec![Route6Entry { table: RT_TABLE_MAIN, dst: Ipv6Addr::ANY, prefix_len: 0,
            iface: new_iface, gateway: None, src_hint: None, origin: Route6Origin::Static }]));
        entered_rx.recv().unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let (lookup_tx, lookup_rx) = mpsc::channel();
        let looking = Arc::clone(&t);
        let lookup = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            lookup_tx.send(looking.lookup_in(NS, dst)).unwrap();
        });
        started_rx.recv().unwrap();
        assert!(lookup_rx.recv_timeout(Duration::from_millis(20)).is_err());
        release_tx.send(()).unwrap();
        assert_eq!(lookup_rx.recv_timeout(Duration::from_secs(1)).unwrap().map(|r| r.iface),
            Some(new_iface));
        replace.join().unwrap();
        lookup.join().unwrap();
    }
}

/// The address a transmit to `dst` solicits. An all-zeroes gateway is not a
/// gateway — the reference reads a zero nexthop as directly-connected — and
/// answering with it makes every neighbour solicitation ask for `::`.
/// # C: O(1)
pub fn next_hop6_for(gateway: Option<crate::Ipv6Addr>, dst: crate::Ipv6Addr) -> crate::Ipv6Addr {
    match gateway {
        Some(gw) if !gw.is_unspecified() => gw,
        _ => dst,
    }
}
