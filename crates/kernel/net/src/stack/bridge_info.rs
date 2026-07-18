//! Canonical Linux legacy bridge-info snapshot.

use super::{NetStack, NetResult};
use crate::NetIfaceId;
use super::bridge::{BridgeTable, BRIDGE_FORWARD_DELAY_TICKS,
    BRIDGE_GC_INTERVAL_TICKS, BRIDGE_HELLO_TIME_TICKS, BRIDGE_MAX_AGE_TICKS, CLK_TCK_NS};

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
    /// Snapshot legacy bridge configuration and inactive STP timer state. # C: O(1)
    pub(crate) fn info(&self, bridge: NetIfaceId, net_ns: u64) -> NetResult<BridgeInfo> {
        let state = self.state.lock();
        let row = state.get(&bridge).ok_or(crate::NetError::Enodev)?;
        if row.net_ns != net_ns || row.deleting { return Err(crate::NetError::Enodev); }
        let id = bridge_id(row.priority, row.mac);
        Ok(BridgeInfo {
            designated_root: id, bridge_id: id, root_path_cost: 0,
            max_age: BRIDGE_MAX_AGE_TICKS, hello_time: BRIDGE_HELLO_TIME_TICKS,
            forward_delay: BRIDGE_FORWARD_DELAY_TICKS, bridge_max_age: BRIDGE_MAX_AGE_TICKS,
            bridge_hello_time: BRIDGE_HELLO_TIME_TICKS, bridge_forward_delay: BRIDGE_FORWARD_DELAY_TICKS,
            topology_change: 0, topology_change_detected: 0, root_port: 0, stp_enabled: 0,
            ageing_time: ::core::cmp::min(row.ageing_ns / CLK_TCK_NS, u32::MAX as u64) as u32,
            gc_interval: BRIDGE_GC_INTERVAL_TICKS,
        })
    }
}

impl NetStack {
    /// Snapshot one bridge's legacy configuration and STP state. # C: O(1)
    pub fn bridge_info(&self, net_ns: u64, bridge: NetIfaceId) -> NetResult<BridgeInfo> {
        self.bridges.info(bridge, net_ns)
    }
}
