//! Linux bridge FDB snapshot ownership for legacy and rtnetlink ABI readers.

use super::{NetStack, NetResult};
use crate::{MacAddr, NetIfaceId, NetError};
use super::bridge::BridgeTable;
use alloc::vec::Vec;

const CLK_TCK_NS: u64 = 10_000_000;

/// One canonical bridge forwarding-database row exported to control ABI owners.
pub struct BridgeFdbEntry {
    pub mac: MacAddr,
    pub port_no: u16,
    pub local: bool,
    pub ageing_ticks: u32,
}

impl BridgeTable {
    /// Snapshot one bridge FDB after expiring dynamic entries. # C: O(N FDB)
    pub(crate) fn fdb_entries(&self, bridge: NetIfaceId, net_ns: u64, offset: usize, count: usize)
        -> NetResult<Vec<BridgeFdbEntry>>
    {
        let mut state = self.state.lock();
        let row = state.get_mut(&bridge).ok_or(NetError::Enodev)?;
        if row.net_ns != net_ns || row.deleting { return Err(NetError::Enodev); }
        let now = super::monotonic_ns_safe();
        if now != 0 { row.fdb.retain(|_, entry| entry.local || now.saturating_sub(entry.learned_ns) <= row.ageing_ns); }
        Ok(row.fdb.iter().skip(offset).take(count).map(|((_, mac), entry)| {
            let remaining_ns = if entry.local { 0 } else if now == 0 { row.ageing_ns }
                else { row.ageing_ns.saturating_sub(now.saturating_sub(entry.learned_ns)) };
            BridgeFdbEntry {
                mac: MacAddr(*mac), port_no: entry.port.and_then(|port| row.ports.get(&port))
                    .map_or(0, |port| port.number), local: entry.local,
                ageing_ticks: ::core::cmp::min(remaining_ns / CLK_TCK_NS, u32::MAX as u64) as u32,
            }
        }).collect())
    }
}

impl NetStack {
    /// Snapshot Linux bridge forwarding entries in stable FDB-key order. # C: O(N FDB)
    pub fn bridge_fdb_entries(&self, net_ns: u64, bridge: NetIfaceId, offset: usize, count: usize)
        -> NetResult<Vec<BridgeFdbEntry>>
    {
        self.bridges.fdb_entries(bridge, net_ns, offset, count)
    }
}
