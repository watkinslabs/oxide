extern crate alloc;

use alloc::vec::Vec;

use sync::{Socket as SockLockClass, Spinlock};

use super::uapi::{
    RT_SCOPE_HOST, RT_SCOPE_LINK, RT_SCOPE_UNIVERSE, RT_TABLE_LOCAL, RT_TABLE_MAIN, RTN_LOCAL,
    RTN_UNICAST, RTPROT_BOOT, RTPROT_KERNEL,
};

/// One row in the kernel's route table. v1 IPv4 only.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RouteRow {
    pub ns: u64,
    pub table: u8,
    pub protocol: u8,
    pub scope: u8,
    pub kind: u8,
    pub dst: Option<([u8; 4], u8)>,
    pub gateway: Option<[u8; 4]>,
    pub oif_ifindex: u32,
    pub prefsrc: Option<[u8; 4]>,
}

static ROUTE_TABLE: Spinlock<Vec<RouteRow>, SockLockClass> =
    Spinlock::new(Vec::new());

/// Insert (or replace by key=`(ns, table, dst, oif)`).
/// # C: O(N)
pub fn route_insert(row: RouteRow) {
    let mut g = ROUTE_TABLE.lock();
    let dup = g.iter().position(|r|
        r.ns == row.ns && r.table == row.table && r.dst == row.dst && r.oif_ifindex == row.oif_ifindex);
    if let Some(i) = dup { g[i] = row; } else { g.push(row); }
}

/// Remove rows matching `(ns, table, dst, oif)`. Returns count removed.
/// # C: O(N)
pub fn route_remove(ns: u64, table: u8, dst: Option<([u8; 4], u8)>, oif: u32) -> usize {
    let mut g = ROUTE_TABLE.lock();
    let before = g.len();
    g.retain(|r| !(r.ns == ns && r.table == table && r.dst == dst && r.oif_ifindex == oif));
    before - g.len()
}

/// Snapshot the routes in network namespace `ns`.
/// # C: O(N)
pub fn route_snapshot_ns(ns: u64) -> Vec<RouteRow> {
    ROUTE_TABLE.lock().iter().filter(|r| r.ns == ns).cloned().collect()
}

/// Full snapshot for RTM_GETROUTE.
/// # C: O(N) clone
pub fn route_snapshot() -> Vec<RouteRow> {
    ROUTE_TABLE.lock().clone()
}

/// Seed the boot-time default route for the loopback iface.
/// # C: O(1)
pub fn seed_default_routes_lo(lo_ifindex: u32) {
    route_insert(RouteRow {
        ns: 0,
        table: RT_TABLE_LOCAL,
        protocol: RTPROT_KERNEL,
        scope: RT_SCOPE_HOST,
        kind: RTN_LOCAL,
        dst: Some(([127, 0, 0, 0], 8)),
        gateway: None,
        oif_ifindex: lo_ifindex,
        prefsrc: Some([127, 0, 0, 1]),
    });
}

/// Seed the boot-time default routes for the eth0 iface.
/// # C: O(1)
pub fn seed_default_routes(eth0_ifindex: u32) {
    route_insert(RouteRow {
        ns: 0,
        table: RT_TABLE_MAIN,
        protocol: RTPROT_KERNEL,
        scope: RT_SCOPE_LINK,
        kind: RTN_UNICAST,
        dst: Some(([10, 0, 2, 0], 24)),
        gateway: None,
        oif_ifindex: eth0_ifindex,
        prefsrc: Some([10, 0, 2, 15]),
    });
    route_insert(RouteRow {
        ns: 0,
        table: RT_TABLE_MAIN,
        protocol: RTPROT_BOOT,
        scope: RT_SCOPE_UNIVERSE,
        kind: RTN_UNICAST,
        dst: None,
        gateway: Some([10, 0, 2, 2]),
        oif_ifindex: eth0_ifindex,
        prefsrc: Some([10, 0, 2, 15]),
    });
}
