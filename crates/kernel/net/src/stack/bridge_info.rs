//! Canonical Linux legacy bridge-info snapshot.

use super::{NetStack, NetResult};
use crate::NetIfaceId;
use super::bridge::{BridgeTable, BRIDGE_GC_INTERVAL_TICKS, CLK_TCK_NS};

/// One `struct __bridge_info` snapshot from the canonical bridge owner.
pub struct BridgeInfo {
    pub designated_root: [u8; 8],
    pub bridge_id: [u8; 8],
    pub root_path_cost: u32,
    pub max_age: u32,
    pub hello_time: u32,
    pub forward_delay: u32,
    pub bridge_max_age: u32,
    pub bridge_hello_time: u32,
    pub bridge_forward_delay: u32,
    pub topology_change: u8,
    pub topology_change_detected: u8,
    pub root_port: u8,
    pub stp_enabled: u8,
    pub ageing_time: u32,
    pub gc_interval: u32,
}

fn bridge_id(priority: u16, mac: crate::MacAddr) -> [u8; 8] {
    let mut id = [0; 8];
    id[..2].copy_from_slice(&priority.to_be_bytes());
    id[2..].copy_from_slice(&mac.0);
    id
}

impl BridgeTable {
    /// Snapshot legacy bridge configuration and canonical STP state. # C: O(1)
    pub(crate) fn info(&self, bridge: NetIfaceId, net_ns: u64) -> NetResult<BridgeInfo> {
        let state = self.state.lock();
        let row = state.get(&bridge).ok_or(crate::NetError::Enodev)?;
        if row.net_ns != net_ns || row.deleting { return Err(crate::NetError::Enodev); }
        let id = bridge_id(row.priority, row.mac);
        Ok(BridgeInfo {
            designated_root: row.stp.root_id, bridge_id: id, root_path_cost: row.stp.root_path_cost,
            max_age: clock_ticks(row.max_age), hello_time: clock_ticks(row.hello_time),
            forward_delay: clock_ticks(row.forward_delay), bridge_max_age: clock_ticks(row.bridge_max_age),
            bridge_hello_time: clock_ticks(row.bridge_hello_time), bridge_forward_delay: clock_ticks(row.bridge_forward_delay),
            topology_change: row.stp.topology_change as u8, topology_change_detected: row.stp.topology_change_detected as u8,
            root_port: row.stp.root_port.and_then(|port| row.ports.get(&port)).map_or(0, |port| port.number as u8),
            stp_enabled: row.stp.enabled as u8,
            ageing_time: ::core::cmp::min(row.ageing_ns / CLK_TCK_NS, u32::MAX as u64) as u32,
            gc_interval: BRIDGE_GC_INTERVAL_TICKS,
        })
    }
}

fn clock_ticks(ticks: u64) -> u32 { core::cmp::min(ticks, u32::MAX as u64) as u32 }

impl NetStack {
    /// Snapshot one bridge's legacy configuration and STP state. # C: O(1)
    pub fn bridge_info(&self, net_ns: u64, bridge: NetIfaceId) -> NetResult<BridgeInfo> {
        self.bridges.info(bridge, net_ns)
    }
}
