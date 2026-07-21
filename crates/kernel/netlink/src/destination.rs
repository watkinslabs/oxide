//! AF_NETLINK connect destination ownership.

use core::sync::atomic::Ordering;

use crate::{NETLINK_UNCONNECTED_GROUPS, NETLINK_UNCONNECTED_PORT_ID, NetlinkSocket};

impl NetlinkSocket {
    /// Store one Linux AF_NETLINK connected destination. A connected Netlink
    /// socket accepts the first requested multicast group only. # C: O(1)
    pub fn connect_destination(&self, port_id: u32, groups: u32) -> Result<(), net::NetError> {
        self.dst_port_id.store(port_id, Ordering::Release);
        self.dst_groups.store(first_group(groups), Ordering::Release);
        self.connected.store(true, Ordering::Release);
        Ok(())
    }

    /// Clear one Linux AF_UNSPEC Netlink connection after connect admission.
    /// # C: O(1)
    pub fn disconnect_destination(&self) -> Result<(), net::NetError> {
        self.dst_port_id.store(NETLINK_UNCONNECTED_PORT_ID, Ordering::Release);
        self.dst_groups.store(NETLINK_UNCONNECTED_GROUPS, Ordering::Release);
        self.connected.store(false, Ordering::Release);
        Ok(())
    }

    /// Snapshot the only destination used by a destination-less sendmsg and
    /// reported by getpeername. # C: O(1)
    pub fn destination(&self) -> (u32, u32) {
        (self.dst_port_id.load(Ordering::Acquire), self.dst_groups.load(Ordering::Acquire))
    }

    /// Determine whether a local unicast sender is admitted by this connected
    /// destination socket. # C: O(1)
    pub(crate) fn accepts_unicast_from(&self, source_port_id: u32) -> bool {
        !self.connected.load(Ordering::Acquire)
            || self.dst_port_id.load(Ordering::Acquire) == source_port_id
    }
}

/// Linux `ffs(nl_groups)` retains only the least-significant group when a
/// sockaddr_nl connects an AF_NETLINK socket. # C: O(1)
fn first_group(groups: u32) -> u32 { groups & groups.wrapping_neg() }
