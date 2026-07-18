//! Canonical Linux legacy bridge-port information snapshots.

use super::{NetStack, NetResult};
use crate::NetIfaceId;
use super::bridge::{BridgeTable, BR_PORT_BITS, BR_STATE_FORWARDING};

/// One `struct __port_info` snapshot from the canonical bridge owner.
pub struct BridgePortInfo {
    pub designated_root: [u8; 8],
    pub designated_bridge: [u8; 8],
    pub port_id: u16,
    pub designated_port: u16,
    pub path_cost: u32,
    pub designated_cost: u32,
    pub state: u8,
}

fn bridge_id(priority: u16, mac: crate::MacAddr) -> [u8; 8] {
    let mut id = [0; 8];
    id[..2].copy_from_slice(&priority.to_be_bytes());
    id[2..].copy_from_slice(&mac.0);
    id
}

impl BridgeTable {
    /// Snapshot legacy STP port state, with inactive timers represented as zero. # C: O(N ports)
    pub(crate) fn port_info(&self, bridge: NetIfaceId, net_ns: u64, number: u64)
        -> NetResult<BridgePortInfo>
    {
        let state = self.state.lock();
        let row = state.get(&bridge).ok_or(crate::NetError::Enodev)?;
        if row.net_ns != net_ns || row.deleting { return Err(crate::NetError::Enodev); }
        let port = row.ports.values().find(|port| port.number as u64 == number).ok_or(crate::NetError::Einval)?;
        let id = bridge_id(row.priority, row.mac);
        let port_id = ((port.priority as u16) << BR_PORT_BITS) | port.number;
        Ok(BridgePortInfo { designated_root: id, designated_bridge: id, port_id,
            designated_port: port_id, path_cost: port.path_cost, designated_cost: 0,
            state: BR_STATE_FORWARDING })
    }
}

impl NetStack {
    /// Snapshot one bridge port selected by its legacy bridge port number. # C: O(N ports)
    pub fn bridge_port_info(&self, net_ns: u64, bridge: NetIfaceId, number: u64)
        -> NetResult<BridgePortInfo>
    {
        self.bridges.port_info(bridge, net_ns, number)
    }
}
