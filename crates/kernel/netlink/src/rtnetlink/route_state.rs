extern crate alloc;

use alloc::vec::Vec;

use super::uapi::{
    RT_SCOPE_HOST, RT_SCOPE_LINK, RT_SCOPE_UNIVERSE, RT_TABLE_LOCAL, RT_TABLE_MAIN, RTN_LOCAL,
    RTN_UNICAST, RTPROT_BOOT, RTPROT_KERNEL,
};

/// One row in the kernel's route table. v1 IPv4 only.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RouteRow {
    pub ns: u64,
    pub table: u32,
    pub protocol: u8,
    pub scope: u8,
    pub kind: u8,
    pub dst: Option<([u8; 4], u8)>,
    pub gateway: Option<[u8; 4]>,
    pub oif_ifindex: u32,
    pub prefsrc: Option<[u8; 4]>,
    pub metric: u32,
    pub metrics: net::RouteMetrics,
    pub flags: u32,
    pub weight: u16,
    pub nh_flags: u8,
}

pub(crate) fn to_record(row: RouteRow) -> net::RouteRecord {
    let (dst, prefix_len) = super::route_ops::route_key(row.dst);
    net::RouteRecord {
        route: net::RouteEntry {
            table: row.table,
            dst,
            prefix_len,
            iface: net::NetIfaceId::from_raw(row.oif_ifindex),
            gateway: row.gateway.map(|g| net::Ipv4Addr::from_u32(u32::from_be_bytes(g))),
            src_hint: row.prefsrc.map(|s| net::Ipv4Addr::from_u32(u32::from_be_bytes(s))),
        },
        protocol: row.protocol,
        scope: row.scope,
        kind: row.kind,
        metric: row.metric,
        metrics: row.metrics,
        flags: row.flags,
        weight: row.weight,
        nh_flags: row.nh_flags,
    }
}

pub(crate) fn from_record(ns: u64, record: net::RouteRecord) -> RouteRow {
    let route = record.route;
    RouteRow {
        ns,
        table: route.table,
        protocol: record.protocol,
        scope: record.scope,
        kind: record.kind,
        dst: if route.prefix_len == 0 { None } else { Some((route.dst.as_u32().to_be_bytes(), route.prefix_len)) },
        gateway: route.gateway.map(|g| g.as_u32().to_be_bytes()),
        oif_ifindex: route.iface.raw(),
        prefsrc: route.src_hint.map(|s| s.as_u32().to_be_bytes()),
        metric: record.metric,
        metrics: record.metrics,
        flags: record.flags,
        weight: record.weight,
        nh_flags: record.nh_flags,
    }
}

/// Apply one atomic route-group mutation. # C: O(N + rows)
pub(crate) fn route_change(rtnl: &net::RtnlGuard<'_>, rows: &[RouteRow], create: bool, exclusive: bool,
    replace: bool, append: bool) -> Result<(), net::route::RouteChangeError> {
    let Some(first) = rows.first() else { return Err(net::route::RouteChangeError::Invalid); };
    if rows.iter().any(|row| row.ns != first.ns) {
        return Err(net::route::RouteChangeError::Invalid);
    }
    let records: Vec<net::RouteRecord> = rows.iter().copied().map(to_record).collect();
    net::global_stack().routes.replace_group_rtnl(rtnl, first.ns, &records,
        create, exclusive, replace, append)
}

/// Remove the lowest-metric matching alias group. # C: O(N)
pub(crate) fn route_take_lowest(rtnl: &net::RtnlGuard<'_>, ns: u64,
    matches: impl FnMut(&net::RouteRecord) -> bool) -> Vec<RouteRow> {
    net::global_stack().routes.take_lowest_metric_group_rtnl(rtnl, ns, matches).into_iter()
        .map(|record| from_record(ns, record)).collect()
}

/// Insert (or replace by key=`(ns, table, dst, oif)`).
/// # C: O(N)
pub fn route_insert(row: RouteRow) {
    let stack = net::global_stack();
    let rtnl = stack.rtnl_lock();
    stack.routes.replace_record_rtnl(&rtnl, row.ns, to_record(row));
}

/// Remove rows matching `(ns, table, dst, oif)`. Returns count removed.
/// # C: O(N)
pub fn route_remove(
    ns: u64, table: u32, dst: Option<([u8; 4], u8)>, oif: u32, gateway: Option<[u8; 4]>,
) -> usize {
    let (dst, prefix_len) = super::route_ops::route_key(dst);
    let gateway = gateway.map(|g| net::Ipv4Addr::from_u32(u32::from_be_bytes(g)));
    let stack = net::global_stack();
    let rtnl = stack.rtnl_lock();
    stack.routes.remove_matching_rtnl(&rtnl, ns, |route| {
        route.table == table && route.dst == dst && route.prefix_len == prefix_len
            && route.iface.raw() == oif
            && gateway.map(|expected| route.gateway == Some(expected)).unwrap_or(true)
    })
}

/// Snapshot the routes in network namespace `ns`.
/// # C: O(N)
pub fn route_snapshot_ns(ns: u64) -> Vec<RouteRow> {
    net::global_stack().routes.snapshot_records_in(ns).into_iter()
        .map(|record| from_record(ns, record)).collect()
}

/// Policy-aware canonical route lookup in one network namespace. # C: O(N rules * N routes)
pub fn route_lookup_ns(ns: u64, dst: [u8; 4]) -> Option<RouteRow> {
    let addr = net::Ipv4Addr::from_u32(u32::from_be_bytes(dst));
    net::global_stack().routes.lookup_record_in(ns, addr)
        .map(|record| from_record(ns, record))
}

/// Snapshot routes visible in the caller's network namespace. # C: O(N)
pub fn route_snapshot() -> Vec<RouteRow> {
    route_snapshot_ns(net::netdev::current_net_ns())
}

/// Seed the boot-time default route for the loopback iface.
/// # C: O(1)
pub fn seed_default_routes_lo(lo_ifindex: u32) {
    route_insert(RouteRow {
        ns: 0,
        table: RT_TABLE_LOCAL as u32,
        protocol: RTPROT_KERNEL,
        scope: RT_SCOPE_HOST,
        kind: RTN_LOCAL,
        dst: Some(([127, 0, 0, 0], 8)),
        gateway: None,
        oif_ifindex: lo_ifindex,
        prefsrc: Some([127, 0, 0, 1]), metric: 0, metrics: net::RouteMetrics::NONE,
        flags: 0, weight: 1, nh_flags: 0,
    });
}

/// Seed the boot-time default routes for the eth0 iface.
/// # C: O(1)
pub fn seed_default_routes(eth0_ifindex: u32) {
    route_insert(RouteRow {
        ns: 0,
        table: RT_TABLE_MAIN as u32,
        protocol: RTPROT_KERNEL,
        scope: RT_SCOPE_LINK,
        kind: RTN_UNICAST,
        dst: Some(([10, 0, 2, 0], 24)),
        gateway: None,
        oif_ifindex: eth0_ifindex,
        prefsrc: Some([10, 0, 2, 15]), metric: 0, metrics: net::RouteMetrics::NONE,
        flags: 0, weight: 1, nh_flags: 0,
    });
    route_insert(RouteRow {
        ns: 0,
        table: RT_TABLE_MAIN as u32,
        protocol: RTPROT_BOOT,
        scope: RT_SCOPE_UNIVERSE,
        kind: RTN_UNICAST,
        dst: None,
        gateway: Some([10, 0, 2, 2]),
        oif_ifindex: eth0_ifindex,
        prefsrc: Some([10, 0, 2, 15]), metric: 0, metrics: net::RouteMetrics::NONE,
        flags: 0, weight: 1, nh_flags: 0,
    });
}
