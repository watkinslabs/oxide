//! Rtnetlink snapshots of canonical multicast membership state.

use alloc::vec::Vec;

use crate::addr::{Ipv4Addr, Ipv6Addr, NetIfaceId};
use crate::stack::NetStack;

impl NetStack {
    /// Snapshot live IPv4 interface multicast memberships in one namespace. # C: O(N groups)
    pub fn v4_multicast_snapshot_in(&self, net_ns: u64) -> Vec<(NetIfaceId, Ipv4Addr)> {
        let all = self.v4_mcast.lock();
        let mut rows = Vec::new();
        for (iface, groups) in all.iter() {
            if self.ifaces.ifindex_in_ns(*iface, net_ns).is_none() { continue; }
            for state in groups {
                if !state.is_empty() { rows.push((*iface, state.group)); }
            }
        }
        rows
    }

    /// Snapshot live IPv6 interface multicast memberships in one namespace. # C: O(N groups)
    pub fn v6_multicast_snapshot_in(&self, net_ns: u64) -> Vec<(NetIfaceId, Ipv6Addr)> {
        let all = self.v6_mcast.lock();
        let mut rows = Vec::new();
        for (iface, groups) in all.iter() {
            if self.ifaces.ifindex_in_ns(*iface, net_ns).is_none() { continue; }
            for state in groups {
                if !state.is_empty() { rows.push((*iface, state.group)); }
            }
        }
        rows
    }
}
