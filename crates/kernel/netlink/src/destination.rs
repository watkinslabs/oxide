//! AF_NETLINK connect destination ownership.

use core::sync::atomic::Ordering;

use crate::{NETLINK_UNCONNECTED_GROUPS, NETLINK_UNCONNECTED_PORT_ID, NetlinkSocket};

impl NetlinkSocket {
    /// Store one Linux AF_NETLINK connected destination. A connected Netlink
    /// socket accepts the first requested multicast group only. # C: O(1)
    pub fn connect_destination(&self, port_id: u32, groups: u32) -> Result<(), net::NetError> {
        net::security_admission::check(
            net::net_ns::namespace_id(&self.net_ns), net::socket_args::AF_NETLINK_WIRE,
            security::network::Operation::Connect,
        )?;
        self.dst_port_id.store(port_id, Ordering::Release);
        self.dst_groups.store(first_group(groups), Ordering::Release);
        Ok(())
    }

    /// Clear one Linux AF_UNSPEC Netlink connection after connect admission.
    /// # C: O(1)
    pub fn disconnect_destination(&self) -> Result<(), net::NetError> {
        net::security_admission::check(
            net::net_ns::namespace_id(&self.net_ns), net::socket_args::AF_NETLINK_WIRE,
            security::network::Operation::Connect,
        )?;
        self.dst_port_id.store(NETLINK_UNCONNECTED_PORT_ID, Ordering::Release);
        self.dst_groups.store(NETLINK_UNCONNECTED_GROUPS, Ordering::Release);
        Ok(())
    }

    /// Snapshot the only destination used by a destination-less sendmsg and
    /// reported by getpeername. # C: O(1)
    pub fn destination(&self) -> (u32, u32) {
        (self.dst_port_id.load(Ordering::Acquire), self.dst_groups.load(Ordering::Acquire))
    }
}

/// Linux `ffs(nl_groups)` retains only the least-significant group when a
/// sockaddr_nl connects an AF_NETLINK socket. # C: O(1)
fn first_group(groups: u32) -> u32 { groups & groups.wrapping_neg() }
