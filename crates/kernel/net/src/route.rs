// IPv4 routing table per `25§10`. Longest-prefix-match over a
// small Vec — sufficient for the v1 single-iface use cases
// (loopback only) and easy to swap for an LPM trie later.

extern crate alloc;
use alloc::{collections::BTreeMap, vec::Vec};

use sync::{Spinlock, Socket as RouteLockClass};

use crate::addr::{Ipv4Addr, NetIfaceId};
use crate::netdev::{NetError, NetResult};
use crate::policy_rule::{self, PolicyRuleTable, RT_TABLE_MAIN};

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

    /// True when records are nexthops in one Linux-visible route alias group. # C: O(1)
    pub fn same_alias_group(&self, other: &Self) -> bool {
        self.route.table == other.route.table && self.route.dst == other.route.dst
            && self.route.prefix_len == other.route.prefix_len
            && self.route.src_hint == other.route.src_hint && self.protocol == other.protocol
            && self.scope == other.scope && self.kind == other.kind && self.metric == other.metric
            && self.mtu == other.mtu && self.flags == other.flags
    }

    /// Linux FIB selector used to locate the alias replaced by RTM_NEWROUTE. # C: O(1)
    pub fn same_replacement_target(&self, other: &Self) -> bool {
        self.route.table == other.route.table && self.route.dst == other.route.dst
            && self.route.prefix_len == other.route.prefix_len && self.metric == other.metric
            && self.kind == other.kind
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

fn usable_record(record: RouteRecord) -> NetResult<RouteEntry> {
    match record.kind {
        RTN_UNICAST | RTN_LOCAL => Ok(record.route),
        RTN_BLACKHOLE => Err(NetError::Einval),
        RTN_UNREACHABLE => Err(NetError::Ehostunreach),
        RTN_PROHIBIT => Err(NetError::Eacces),
        RTN_THROW => Err(NetError::Enetunreach),
        _ => Err(NetError::Eopnotsupp),
    }
}

pub struct RouteTable {
    pub(crate) inner: Spinlock<BTreeMap<u64, Vec<RouteRecord>>, RouteLockClass>,
    rules: PolicyRuleTable,
}

impl RouteTable {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self { inner: Spinlock::new(BTreeMap::new()), rules: PolicyRuleTable::new() }
    }

    /// Canonical policy-rule table paired with this route table. # C: O(1)
    pub fn policy_rules(&self) -> &PolicyRuleTable { &self.rules }

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

    /// Guarded replacement by canonical route key. # Lk: matching stack RTNL held. # C: O(N)
    pub fn replace_record_rtnl(&self, rtnl: &crate::RtnlGuard<'_>, net_ns: u64,
        record: RouteRecord) {
        if core::ptr::eq(self, &rtnl.stack().routes) { self.replace_record_in(net_ns, record); }
    }

    fn lookup_record_in_table_locked(g: &[RouteRecord], table: u32, addr: Ipv4Addr) -> Option<RouteRecord> {
        let mut best: Option<RouteRecord> = None;
        for record in g.iter() {
            let e = record.route;
            if e.table != table || !e.matches(addr) { continue; }
            let rank = (e.prefix_len, core::cmp::Reverse(record.metric));
            let current = best.map(|best| {
                (best.route.prefix_len, core::cmp::Reverse(best.metric))
            });
            if current.is_none_or(|current| rank > current) {
                best = Some(*record);
            }
        }
        let best = best?;
        let count = g.iter().filter(|record| record.same_alias_group(&best))
            .map(|record| record.weight.max(1) as usize).sum::<usize>();
        let mut nth = (ecmp_hash(addr) as usize) % count;
        for record in g.iter() {
            if record.same_alias_group(&best) {
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
        usable_record(record)
    }

    /// Policy-rule lookup retaining metadata from this table's canonical rules. # C: O(N rules * N routes)
    pub fn lookup_record_in(&self, net_ns: u64, addr: Ipv4Addr) -> Option<RouteRecord> {
        let rules = self.rules.snapshot_effective(net_ns, policy_rule::AF_INET);
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

    /// Snapshot one true alias group containing `member`. # C: O(N)
    pub fn snapshot_alias_group_in(&self, net_ns: u64, member: RouteRecord) -> Vec<RouteRecord> {
        self.inner.lock().get(&net_ns).map(|routes| routes.iter().copied()
            .filter(|record| record.same_alias_group(&member)).collect()).unwrap_or_default()
    }

    /// Partition records into true Linux-visible alias groups. # C: O(N^2)
    pub fn alias_groups(records: Vec<RouteRecord>) -> Vec<Vec<RouteRecord>> {
        let mut groups: Vec<Vec<RouteRecord>> = Vec::new();
        for record in records {
            if let Some(group) = groups.iter_mut().find(|group| group[0].same_alias_group(&record)) {
                group.push(record);
            } else {
                groups.push(alloc::vec![record]);
            }
        }
        groups
    }

    /// Select the lowest-metric true alias group matching `matches`. # C: O(N)
    pub fn lowest_metric_group<F: FnMut(&RouteRecord) -> bool>(records: &[RouteRecord],
        mut matches: F) -> Vec<RouteRecord> {
        let first = records.iter().filter(|record| matches(record))
            .min_by_key(|record| record.metric).copied();
        let Some(first) = first else { return Vec::new(); };
        records.iter().copied().filter(|record| record.same_alias_group(&first)
            && matches(record)).collect()
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

    /// Guarded matching-route removal. # Lk: matching stack RTNL held. # C: O(N)
    pub fn remove_matching_rtnl<F: FnMut(&RouteEntry) -> bool>(&self,
        rtnl: &crate::RtnlGuard<'_>, net_ns: u64, matches: F) -> usize {
        if !core::ptr::eq(self, &rtnl.stack().routes) { return 0; }
        self.remove_matching_in(net_ns, matches)
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
        let first = routes.iter().filter(|record| matches(record))
            .min_by_key(|record| record.metric).copied();
        let Some(first) = first else { return Vec::new(); };
        let mut removed = Vec::new();
        let mut retained = Vec::with_capacity(routes.len());
        for record in core::mem::take(routes) {
            if record.same_alias_group(&first) && matches(&record) { removed.push(record); }
            else { retained.push(record); }
        }
        *routes = retained;
        if routes.is_empty() { all.remove(&net_ns); }
        removed
    }

    /// Guarded lowest-metric alias-group removal. # Lk: matching stack RTNL held. # C: O(N)
    pub fn take_lowest_metric_group_rtnl<F: FnMut(&RouteRecord) -> bool>(&self,
        rtnl: &crate::RtnlGuard<'_>, net_ns: u64, matches: F) -> Vec<RouteRecord> {
        if !core::ptr::eq(self, &rtnl.stack().routes) { return Vec::new(); }
        self.take_lowest_metric_group_in(net_ns, matches)
    }

    /// Atomically replace one FIB alias group selected by table/prefix/metric. # C: O(N + records)
    pub fn replace_group_in(&self, net_ns: u64, records: &[RouteRecord], create: bool,
        exclusive: bool, replace: bool, append: bool) -> Result<(), RouteChangeError> {
        let Some(first) = records.first().copied() else { return Err(RouteChangeError::Invalid); };
        if records.iter().any(|record| !record.same_alias_group(&first)) {
            return Err(RouteChangeError::Invalid);
        }
        for (i, record) in records.iter().enumerate() {
            if records[i + 1..].iter().any(|other| other == record) {
                return Err(RouteChangeError::Exists);
            }
        }
        let mut all = self.inner.lock();
        let routes = all.entry(net_ns).or_default();
        let replacement_target = |record: &RouteRecord| record.same_replacement_target(&first);
        let exists = routes.iter().any(replacement_target);
        if exclusive && exists { return Err(RouteChangeError::Exists); }
        if !exists && !create { return Err(RouteChangeError::NotFound); }
        if exists && !replace && !append { return Err(RouteChangeError::Exists); }
        if !replace && records.iter().any(|record| routes.iter().any(|old| old == record)) {
            return Err(RouteChangeError::Exists);
        }
        if replace { routes.retain(|record| !replacement_target(record)); }
        for record in records.iter().copied() {
            routes.push(record);
        }
        Ok(())
    }

    /// Guarded atomic FIB alias-group mutation. # Lk: matching stack RTNL held. # C: O(N + records)
    pub fn replace_group_rtnl(&self, rtnl: &crate::RtnlGuard<'_>, net_ns: u64,
        records: &[RouteRecord], create: bool, exclusive: bool, replace: bool, append: bool)
        -> Result<(), RouteChangeError> {
        if !core::ptr::eq(self, &rtnl.stack().routes) { return Err(RouteChangeError::Invalid); }
        self.replace_group_in(net_ns, records, create, exclusive, replace, append)
    }

    /// Drop all routes owned by a destroyed namespace. # C: O(log N_ns)
    pub fn remove_namespace(&self, net_ns: u64) -> bool {
        if net_ns == 0 { return false; }
        self.inner.lock().remove(&net_ns).is_some()
    }
    /// Guarded namespace-route removal. # Lk: matching stack RTNL held. # C: O(log N_ns)
    pub fn remove_namespace_rtnl(&self, rtnl: &crate::RtnlGuard<'_>, net_ns: u64) -> bool {
        if !core::ptr::eq(self, &rtnl.stack().routes) { return false; }
        self.remove_namespace(net_ns)
    }
}

impl Default for RouteTable { fn default() -> Self { Self::new() } }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RouteChangeError { Exists, NotFound, Invalid }

#[cfg(test)]
#[path = "route_policy_tests.rs"]
mod policy_tests;

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
    fn equal_prefix_metric_different_aliases_do_not_form_ecmp() {
        let t = RouteTable::new();
        let first = RouteEntry::main(
            Ipv4Addr::ANY, 0, NetIfaceId::from_raw(1), None, None);
        let second = RouteEntry::main(
            Ipv4Addr::ANY, 0, NetIfaceId::from_raw(2), None, None);
        t.add_record_in(0, RouteRecord::kernel(first));
        t.add_record_in(0, RouteRecord { protocol: 99, ..RouteRecord::kernel(second) });
        for last in 1..=254 {
            assert_eq!(t.lookup(Ipv4Addr::new(203, 0, 113, last)).unwrap().iface,
                NetIfaceId::from_raw(1));
        }
    }

}
