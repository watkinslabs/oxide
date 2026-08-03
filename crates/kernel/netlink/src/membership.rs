// Multicast-group membership and genetlink credentials of one netlink socket.
//
// Group subscription is protocol-shaped: how many groups exist depends on the
// protocol, `bind` writes only the low 32, and `NETLINK_ADD_MEMBERSHIP` reaches
// the rest. Kept beside the socket rather than inside it so the socket file
// stays the queue/dispatch owner.

extern crate alloc;

use alloc::vec::Vec;

use crate::netlink_socket::NetlinkSocket;
use crate::{genetlink, proto};

impl NetlinkSocket {
    /// `bind` nl_groups: subscribe to the given group bitmask.
    /// # C: O(1)
    pub fn set_group_mask(&self, mask: u32) {
        self.groups.set_low_mask(mask);
        #[cfg(feature = "debug-netlink")]
        trace_subscribe(self, mask, b"bindmask");
    }

    /// Multicast groups this socket's PROTOCOL offers. Netlink floors every
    /// protocol at a full word of groups; rtnetlink and genetlink each declare
    /// more, and genetlink's count grows as families register.
    /// # C: O(N genl families)
    pub fn ngroups(&self) -> u32 {
        match self.protocol {
            proto::NETLINK_ROUTE   => crate::groups::RTNLGRP_MAX,
            proto::NETLINK_GENERIC => genetlink::mcast_ngroups(),
            _                      => crate::groups::NETLINK_MIN_NGROUPS,
        }
    }

    /// A group number this socket may subscribe to. Group 0 and anything past
    /// the protocol's group count are `EINVAL`. # C: O(1)
    fn group_in_range(&self, group: u32) -> Result<(), net::NetError> {
        if group == 0 || group > self.ngroups() { return Err(net::NetError::Einval); }
        Ok(())
    }

    /// `NETLINK_ADD_MEMBERSHIP`: subscribe to one group NUMBER. # C: O(1)
    pub fn add_membership(&self, group: u32) -> Result<(), net::NetError> {
        self.group_in_range(group)?;
        self.groups.add(group);
        #[cfg(feature = "debug-netlink")]
        trace_subscribe(self, group, b"add");
        Ok(())
    }

    /// `NETLINK_DROP_MEMBERSHIP`: unsubscribe one group NUMBER. # C: O(1)
    pub fn drop_membership(&self, group: u32) -> Result<(), net::NetError> {
        self.group_in_range(group)?;
        self.groups.remove(group);
        Ok(())
    }

    /// `NETLINK_LIST_MEMBERSHIPS`: the subscription bitmap as `u32` words
    /// covering every group of the protocol. # C: O(words)
    pub fn membership_words(&self) -> Vec<u32> { self.groups.membership_words(self.ngroups()) }

    /// Capability answers a genetlink command's permission ladder consumes.
    /// `GENL_ADMIN_PERM` asks for `CAP_NET_ADMIN` in the INITIAL user
    /// namespace; `GENL_UNS_ADMIN_PERM` accepts it in the socket namespace's
    /// owner. # C: O(ns depth)
    pub(crate) fn genl_cred(&self) -> genetlink::GenlCred {
        #[cfg(target_os = "oxide-kernel")]
        {
            let Some(cur) = sched::current() else { return genetlink::GenlCred::default(); };
            genetlink::GenlCred {
                init_ns_net_admin: nscg::has_net_admin_for(&cur, &network_namespace::initial()),
                sock_ns_net_admin: nscg::has_net_admin_for(&cur, &self.net_ns),
            }
        }
        #[cfg(not(target_os = "oxide-kernel"))]
        { genetlink::GenlCred { init_ns_net_admin: true, sock_ns_net_admin: true } }
    }
}

/// Which task subscribed which netlink socket to which group, and how. A
/// notification that reaches nobody is explained either by no subscription
/// ever happening or by it happening after the event.
#[cfg(feature = "debug-netlink")]
fn trace_subscribe(sock: &NetlinkSocket, group: u32, via: &[u8]) {
    klog::write_raw(b"[NL-SUB ");
    #[cfg(target_os = "oxide-kernel")]
    if let Some(c) = sched::live::current() {
        klog::write_dec_u64(c.tid as u64);
        klog::write_raw(b"/");
        let comm = c.comm_bytes();
        klog::write_raw(sched::Task::comm_trim(&comm).as_bytes());
    }
    klog::write_raw(b" proto=");
    klog::write_dec_u64(sock.protocol as u64);
    klog::write_raw(b" ");
    klog::write_raw(via);
    klog::write_raw(b"=");
    klog::write_dec_u64(group as u64);
    klog::write_raw(b"]\n");
}
