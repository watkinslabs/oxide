// IPv4 routing table per `25§10`. Longest-prefix-match over a
// small Vec — sufficient for the v1 single-iface use cases
// (loopback only) and easy to swap for an LPM trie later.

extern crate alloc;
use alloc::{collections::BTreeMap, vec::Vec};

use sync::{Spinlock, Socket as RouteLockClass};

use crate::addr::{Ipv4Addr, NetIfaceId};
use crate::netdev::{NetError, NetResult};
use crate::policy_rule::{self, RT_TABLE_MAIN};

pub const RTN_UNICAST:     u8 = 1;
pub const RTN_LOCAL:       u8 = 2;
pub const RTN_BLACKHOLE:   u8 = 6;
pub const RTN_UNREACHABLE: u8 = 7;
pub const RTN_PROHIBIT:    u8 = 8;
pub const RTN_THROW:       u8 = 9;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RouteEntry {
    pub table:      u32,
    pub dst:        Ipv4Addr,    // network address (already masked)
    pub prefix_len: u8,          // 0..=32
    pub iface:      NetIfaceId,
    pub gateway:    Option<Ipv4Addr>,
    pub src_hint:   Option<Ipv4Addr>,
}

/// Linux route attributes retained beside the datapath key.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RouteRecord {
    pub route: RouteEntry,
    pub protocol: u8,
    pub scope: u8,
    pub kind: u8,
    pub metric: u32,
    pub mtu: Option<u32>,
    pub flags: u32,
    pub weight: u16,
    pub nh_flags: u8,
}

impl RouteRecord {
    /// Construct a normal unicast route with Linux kernel defaults. # C: O(1)
    pub const fn kernel(route: RouteEntry) -> Self {
        Self { route, protocol: 2, scope: 0, kind: 1, metric: 0, mtu: None, flags: 0,
            weight: 1, nh_flags: 0 }
    }
}

impl RouteEntry {
    /// True iff `addr` falls under this route's prefix.
    /// # C: O(1)
    pub fn matches(&self, addr: Ipv4Addr) -> bool {
        let mask = if self.prefix_len == 0 { 0u32 } else { !0u32 << (32 - self.prefix_len) };
        (addr.as_u32() & mask) == (self.dst.as_u32() & mask)
    }
}

impl RouteEntry {
    /// Main-table route constructor for tests and simple callers. # C: O(1)
    pub const fn main(
        dst: Ipv4Addr,
        prefix_len: u8,
        iface: NetIfaceId,
        gateway: Option<Ipv4Addr>,
        src_hint: Option<Ipv4Addr>,
    ) -> Self {
        Self { table: RT_TABLE_MAIN, dst, prefix_len, iface, gateway, src_hint }
    }
}

/// Stable per-destination ECMP bucket. # C: O(1)
fn ecmp_hash(addr: Ipv4Addr) -> u32 {
    let mut x = addr.as_u32();
    x ^= x >> 16;
    x = x.wrapping_mul(0x7feb_352d);
    x ^= x >> 15;
    x = x.wrapping_mul(0x846c_a68b);
    x ^ (x >> 16)
}

pub struct RouteTable {
    pub(crate) inner: Spinlock<BTreeMap<u64, Vec<RouteRecord>>, RouteLockClass>,
}

impl RouteTable {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self { inner: Spinlock::new(BTreeMap::new()) }
    }

    /// Insert a route. v1 doesn't dedup; caller controls.
    /// # C: O(1)
    pub fn add(&self, e: RouteEntry) {
        self.add_in(0, e);
    }

    /// Insert a route in one network namespace. # C: O(log N_ns)
    pub fn add_in(&self, net_ns: u64, e: RouteEntry) {
        self.add_record_in(net_ns, RouteRecord::kernel(e));
    }

    /// Insert a route and its Linux-visible metadata. # C: O(log N_ns)
    pub fn add_record_in(&self, net_ns: u64, record: RouteRecord) {
        self.inner.lock().entry(net_ns).or_default().push(record);
    }

    /// Replace the route keyed by table, prefix, and output interface. # C: O(N)
    pub fn replace_record_in(&self, net_ns: u64, record: RouteRecord) {
        let mut all = self.inner.lock();
        let routes = all.entry(net_ns).or_default();
        if let Some(old) = routes.iter_mut().find(|old| {
            old.route.table == record.route.table && old.route.dst == record.route.dst
                && old.route.prefix_len == record.route.prefix_len
                && old.route.iface == record.route.iface
                && old.route.gateway == record.route.gateway
        }) {
            *old = record;
        } else {
            routes.push(record);
        }
    }

    fn lookup_record_in_table_locked(g: &[RouteRecord], table: u32, addr: Ipv4Addr) -> Option<RouteRecord> {
        let mut best_prefix: Option<u8> = None;
        let mut best_metric: Option<u32> = None;
        let mut count = 0usize;
        for record in g.iter() {
            let e = record.route;
            if e.table != table || !e.matches(addr) { continue; }
            let rank = (e.prefix_len, core::cmp::Reverse(record.metric));
            let best = best_prefix.zip(best_metric)
                .map(|(prefix, metric)| (prefix, core::cmp::Reverse(metric)));
            match best {
                Some(current) if current > rank => {}
                Some(current) if current == rank => count += record.weight.max(1) as usize,
                _ => {
                    best_prefix = Some(e.prefix_len);
                    best_metric = Some(record.metric);
                    count = record.weight.max(1) as usize;
                }
            }
        }
        let prefix = best_prefix?;
        let metric = best_metric?;
        let mut nth = (ecmp_hash(addr) as usize) % count;
        for record in g.iter() {
            let e = record.route;
            if e.table == table && e.prefix_len == prefix && record.metric == metric && e.matches(addr) {
                let weight = record.weight.max(1) as usize;
                if nth < weight { return Some(*record); }
                nth -= weight;
            }
        }
        None
    }

    /// Longest-prefix lookup in one table. Returns `None` if no route matches.
    /// # C: O(N entries)
    pub fn lookup_in_table(&self, table: u32, addr: Ipv4Addr) -> Option<RouteEntry> {
        self.lookup_in_table_in(0, table, addr)
    }

    /// Longest-prefix lookup in one namespace and table. # C: O(N entries)
    pub fn lookup_in_table_in(&self, net_ns: u64, table: u32, addr: Ipv4Addr) -> Option<RouteEntry> {
        let all = self.inner.lock();
        Self::lookup_record_in_table_locked(all.get(&net_ns).map(Vec::as_slice).unwrap_or(&[]), table, addr)
            .map(|record| record.route)
    }

    /// Policy-rule lookup. Built-in local/main/default rules are always
    /// present; custom rules are selected by priority. # C: O(N rules * N routes)
    pub fn lookup(&self, addr: Ipv4Addr) -> Option<RouteEntry> {
        self.lookup_in(0, addr)
    }

    /// Policy-rule lookup in one network namespace. # C: O(N rules * N routes)
    pub fn lookup_in(&self, net_ns: u64, addr: Ipv4Addr) -> Option<RouteEntry> {
        self.lookup_record_in(net_ns, addr).map(|record| record.route)
    }

    /// Policy lookup with Linux terminal route-type errors. # C: O(N rules * N routes)
    pub fn lookup_result_in(&self, net_ns: u64, addr: Ipv4Addr) -> NetResult<RouteEntry> {
        let record = self.lookup_record_in(net_ns, addr).ok_or(NetError::Enetunreach)?;
        match record.kind {
            RTN_UNICAST | RTN_LOCAL => Ok(record.route),
            RTN_BLACKHOLE => Err(NetError::Einval),
            RTN_UNREACHABLE => Err(NetError::Ehostunreach),
            RTN_PROHIBIT => Err(NetError::Eacces),
            RTN_THROW => Err(NetError::Enetunreach),
            _ => Err(NetError::Eopnotsupp),
        }
    }

    /// Policy-rule lookup retaining metadata for the exact selected route. # C: O(N rules * N routes)
    pub fn lookup_record_in(&self, net_ns: u64, addr: Ipv4Addr) -> Option<RouteRecord> {
        let rules = policy_rule::snapshot_effective(net_ns, policy_rule::AF_INET);
        let all = self.inner.lock();
        let routes = all.get(&net_ns).map(Vec::as_slice).unwrap_or(&[]);
        for rule in rules {
            if let Some(r) = Self::lookup_record_in_table_locked(routes, rule.table, addr) {
                if r.kind == RTN_THROW { continue; }
                return Some(r);
            }
        }
        None
    }

    /// All entries snapshot.
    /// # C: O(N)
    pub fn snapshot(&self) -> Vec<RouteEntry> { self.snapshot_in(0) }

    /// Snapshot datapath routes in one network namespace. # C: O(N)
    pub fn snapshot_in(&self, net_ns: u64) -> Vec<RouteEntry> {
        self.snapshot_records_in(net_ns).into_iter().map(|record| record.route).collect()
    }

    /// Snapshot routes and Linux-visible metadata in one namespace. # C: O(N)
    pub fn snapshot_records_in(&self, net_ns: u64) -> Vec<RouteRecord> {
        self.inner.lock().get(&net_ns).cloned().unwrap_or_default()
    }

    /// Remove entries matching `f`.
    /// # C: O(N)
    pub fn retain<F: FnMut(&RouteEntry) -> bool>(&self, mut f: F) {
        self.retain_in(0, |e| f(e));
    }

    /// Remove namespace routes not retained by `f`. # C: O(N)
    pub fn retain_in<F: FnMut(&RouteEntry) -> bool>(&self, net_ns: u64, mut f: F) {
        let mut all = self.inner.lock();
        let Some(routes) = all.get_mut(&net_ns) else { return; };
        routes.retain(|record| f(&record.route));
        if routes.is_empty() { all.remove(&net_ns); }
    }

    /// Remove matching routes atomically and return the removed count. # C: O(N)
    pub fn remove_matching_in<F: FnMut(&RouteEntry) -> bool>(&self, net_ns: u64, mut matches: F) -> usize {
        let mut all = self.inner.lock();
        let Some(routes) = all.get_mut(&net_ns) else { return 0; };
        let before = routes.len();
        routes.retain(|record| !matches(&record.route));
        let removed = before - routes.len();
        if routes.is_empty() { all.remove(&net_ns); }
        removed
    }

    /// Remove canonical records matching `f` atomically. # C: O(N)
    pub fn remove_records_in<F: FnMut(&RouteRecord) -> bool>(&self, net_ns: u64, mut matches: F) -> usize {
        self.take_records_in(net_ns, |record| matches(record)).len()
    }

    /// Take canonical records matching `f` atomically. # C: O(N)
    pub fn take_records_in<F: FnMut(&RouteRecord) -> bool>(&self, net_ns: u64, mut matches: F) -> Vec<RouteRecord> {
        let mut all = self.inner.lock();
        let Some(routes) = all.get_mut(&net_ns) else { return Vec::new(); };
        let mut removed = Vec::new();
        let mut retained = Vec::with_capacity(routes.len());
        for record in core::mem::take(routes) {
            if matches(&record) { removed.push(record); } else { retained.push(record); }
        }
        *routes = retained;
        if routes.is_empty() { all.remove(&net_ns); }
        removed
    }

    /// Take the lowest-metric alias group among records selected by `matches`. # C: O(N)
    pub fn take_lowest_metric_group_in<F: FnMut(&RouteRecord) -> bool>(&self, net_ns: u64,
        mut matches: F) -> Vec<RouteRecord> {
        let mut all = self.inner.lock();
        let Some(routes) = all.get_mut(&net_ns) else { return Vec::new(); };
        let metric = routes.iter().filter(|record| matches(record)).map(|record| record.metric).min();
        let Some(metric) = metric else { return Vec::new(); };
        let mut removed = Vec::new();
        let mut retained = Vec::with_capacity(routes.len());
        for record in core::mem::take(routes) {
            if record.metric == metric && matches(&record) { removed.push(record); }
            else { retained.push(record); }
        }
        *routes = retained;
        if routes.is_empty() { all.remove(&net_ns); }
        removed
    }

    /// Atomically replace one FIB alias group selected by table/prefix/metric. # C: O(N + records)
    pub fn replace_group_in(&self, net_ns: u64, records: &[RouteRecord], create: bool,
        exclusive: bool, replace: bool, append: bool) -> Result<(), RouteChangeError> {
        let Some(first) = records.first().copied() else { return Err(RouteChangeError::Invalid); };
        if records.iter().any(|record| {
            record.route.table != first.route.table || record.route.dst != first.route.dst
                || record.route.prefix_len != first.route.prefix_len || record.metric != first.metric
        }) { return Err(RouteChangeError::Invalid); }
        for (i, record) in records.iter().enumerate() {
            if records[i + 1..].iter().any(|other| other == record) {
                return Err(RouteChangeError::Exists);
            }
        }
        let mut all = self.inner.lock();
        let routes = all.entry(net_ns).or_default();
        let same_group = |record: &RouteRecord| {
            record.route.table == first.route.table && record.route.dst == first.route.dst
                && record.route.prefix_len == first.route.prefix_len && record.metric == first.metric
        };
        let exists = routes.iter().any(same_group);
        if exclusive && exists { return Err(RouteChangeError::Exists); }
        if !exists && !create { return Err(RouteChangeError::NotFound); }
        if exists && !replace && !append { return Err(RouteChangeError::Exists); }
        if !replace && records.iter().any(|record| routes.iter().any(|old| old == record)) {
            return Err(RouteChangeError::Exists);
        }
        if replace { routes.retain(|record| !same_group(record)); }
        for record in records.iter().copied() {
            routes.push(record);
        }
        Ok(())
    }

    /// Drop all routes owned by a destroyed namespace. # C: O(log N_ns)
    pub fn remove_namespace(&self, net_ns: u64) -> bool {
        if net_ns == 0 { return false; }
        self.inner.lock().remove(&net_ns).is_some()
    }
}

impl Default for RouteTable { fn default() -> Self { Self::new() } }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RouteChangeError { Exists, NotFound, Invalid }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_default_matches_anything() {
        let t = RouteTable::new();
        t.add(RouteEntry::main(Ipv4Addr::ANY, 0, NetIfaceId::from_raw(1), None, None));
        let r = t.lookup(Ipv4Addr::new(8, 8, 8, 8)).unwrap();
        assert_eq!(r.iface, NetIfaceId::from_raw(1));
    }

    #[test]
    fn longest_prefix_wins() {
        let t = RouteTable::new();
        t.add(RouteEntry::main(Ipv4Addr::ANY, 0, NetIfaceId::from_raw(1), None, None));
        t.add(RouteEntry::main(Ipv4Addr::new(127, 0, 0, 0), 8, NetIfaceId::from_raw(2), None, None));
        let r = t.lookup(Ipv4Addr::LOOPBACK).unwrap();
        assert_eq!(r.iface, NetIfaceId::from_raw(2));
    }

    #[test]
    fn no_match_returns_none() {
        let t = RouteTable::new();
        t.add(RouteEntry::main(Ipv4Addr::new(10, 0, 0, 0), 8, NetIfaceId::from_raw(1), None, None));
        assert!(t.lookup(Ipv4Addr::new(8, 8, 8, 8)).is_none());
    }

    #[test]
    fn custom_policy_rule_selects_custom_table() {
        let t = RouteTable::new();
        t.add(RouteEntry::main(Ipv4Addr::ANY, 0, NetIfaceId::from_raw(1), None, None));
        t.add(RouteEntry {
            table: 100, dst: Ipv4Addr::ANY, prefix_len: 0,
            iface: NetIfaceId::from_raw(2), gateway: None, src_hint: None,
        });
        let rule = policy_rule::PolicyRule {
            ns: 0, family: policy_rule::AF_INET, priority: 1000, table: 100,
            action: policy_rule::FR_ACT_TO_TBL, dst_len: 0, src_len: 0, tos: 0, flags: 0,
        };
        policy_rule::insert(rule);
        let r = t.lookup(Ipv4Addr::new(8, 8, 8, 8)).unwrap();
        assert_eq!(r.iface, NetIfaceId::from_raw(2));
        assert_eq!(policy_rule::remove(0, policy_rule::AF_INET, Some(1000), Some(100)), 1);
    }

    #[test]
    fn ecmp_equal_prefix_uses_destination_hash() {
        let t = RouteTable::new();
        t.add(RouteEntry::main(Ipv4Addr::ANY, 0, NetIfaceId::from_raw(1), None, None));
        t.add(RouteEntry::main(Ipv4Addr::ANY, 0, NetIfaceId::from_raw(2), None, None));
        let first = t.lookup(Ipv4Addr::new(203, 0, 113, 1)).unwrap().iface;
        let mut saw_other = false;
        for last in 2..=254 {
            let r = t.lookup(Ipv4Addr::new(203, 0, 113, last)).unwrap();
            if r.iface != first {
                saw_other = true;
                break;
            }
        }
        assert!(saw_other);
        assert_eq!(t.lookup(Ipv4Addr::new(203, 0, 113, 1)).unwrap().iface, first);
    }

    #[test]
    fn lower_metric_wins_before_ecmp_selection() {
        let t = RouteTable::new();
        t.add_record_in(0, RouteRecord {
            route: RouteEntry::main(Ipv4Addr::ANY, 0, NetIfaceId::from_raw(1), None, None),
            metric: 200, ..RouteRecord::kernel(RouteEntry::main(
                Ipv4Addr::ANY, 0, NetIfaceId::from_raw(1), None, None))
        });
        t.add_record_in(0, RouteRecord {
            route: RouteEntry::main(Ipv4Addr::ANY, 0, NetIfaceId::from_raw(2), None, None),
            metric: 100, ..RouteRecord::kernel(RouteEntry::main(
                Ipv4Addr::ANY, 0, NetIfaceId::from_raw(2), None, None))
        });
        for last in 1..=32 {
            let record = t.lookup_record_in(0, Ipv4Addr::new(203, 0, 113, last)).unwrap();
            assert_eq!((record.route.iface, record.metric), (NetIfaceId::from_raw(2), 100));
        }
    }

    #[test]
    fn throw_route_continues_with_next_policy_rule() {
        const NS: u64 = 0x8250_2001;
        let t = RouteTable::new();
        let thrown = RouteEntry {
            table: 100, dst: Ipv4Addr::ANY, prefix_len: 0,
            iface: NetIfaceId::from_raw(0), gateway: None, src_hint: None,
        };
        t.add_record_in(NS, RouteRecord { kind: RTN_THROW, ..RouteRecord::kernel(thrown) });
        t.add_in(NS, RouteEntry::main(
            Ipv4Addr::ANY, 0, NetIfaceId::from_raw(9), None, None));
        policy_rule::insert(policy_rule::PolicyRule {
            ns: NS, family: policy_rule::AF_INET, priority: 100, table: 100,
            action: policy_rule::FR_ACT_TO_TBL, dst_len: 0, src_len: 0, tos: 0, flags: 0,
        });

        let route = t.lookup_result_in(NS, Ipv4Addr::new(203, 0, 113, 1)).unwrap();
        assert_eq!(route.iface, NetIfaceId::from_raw(9));
        assert_eq!(policy_rule::remove(NS, policy_rule::AF_INET, Some(100), Some(100)), 1);
    }

    #[test]
    fn namespace_routes_rules_and_teardown_are_isolated() {
        const NS_A: u64 = 0x8250_1001;
        const NS_B: u64 = 0x8250_1002;
        let t = RouteTable::new();
        let dst = Ipv4Addr::new(198, 51, 100, 7);
        t.add_in(NS_A, RouteEntry::main(Ipv4Addr::ANY, 0, NetIfaceId::from_raw(11), None, None));
        t.add_in(NS_B, RouteEntry::main(Ipv4Addr::ANY, 0, NetIfaceId::from_raw(22), None, None));
        t.add_in(0, RouteEntry::main(Ipv4Addr::ANY, 0, NetIfaceId::from_raw(33), None, None));
        t.add_record_in(NS_A, RouteRecord::kernel(RouteEntry {
            table: 100, dst: Ipv4Addr::ANY, prefix_len: 0,
            iface: NetIfaceId::from_raw(44), gateway: None, src_hint: None,
        }));
        policy_rule::insert(policy_rule::PolicyRule {
            ns: NS_A, family: policy_rule::AF_INET, priority: 100, table: 100,
            action: policy_rule::FR_ACT_TO_TBL, dst_len: 0, src_len: 0, tos: 0, flags: 0,
        });

        assert_eq!(t.lookup_in(NS_A, dst).unwrap().iface, NetIfaceId::from_raw(44));
        assert_eq!(t.lookup_in(NS_B, dst).unwrap().iface, NetIfaceId::from_raw(22));
        assert_eq!(t.lookup(dst).unwrap().iface, NetIfaceId::from_raw(33));
        assert_eq!(t.remove_matching_in(NS_B, |route| route.prefix_len == 0), 1);
        assert!(t.lookup_in(NS_B, dst).is_none());
        assert!(t.remove_namespace(NS_A));
        assert!(t.lookup_in(NS_A, dst).is_none());
        assert_eq!(t.lookup(dst).unwrap().iface, NetIfaceId::from_raw(33));
        assert_eq!(policy_rule::remove(NS_A, policy_rule::AF_INET, Some(100), Some(100)), 1);
    }
}
