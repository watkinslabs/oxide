// Netlink module manifest.
// - `wire`: AF_NETLINK numbers, nlmsghdr wire types, and alignment helpers.
// - `handler`: external protocol-handler registration for netfilter.
// - `listeners`: uevent + rtnetlink multicast/unicast listener registries.
// - `netlink_socket`: socket state, dispatch, RX queue, and poll behavior.
// - `shutdown`: AF_NETLINK's Linux `sock_no_shutdown` contract.
// - `receive`: canonical dequeue, pending-error ordering, and wait arming.
// - `inode`: VFS inode glue for netlink socket file descriptors.
// - `rtnetlink*` / `genetlink` / `sock_diag` / `mcast`: protocol-specific code.
//
// Netlink socket family (`AF_NETLINK` = 16) per Linux
// `include/uapi/linux/netlink.h`. v1 surface is the framing +
// dispatch substrate that `ip(8)`, DHCP clients, nftables, and
// any future "configure the iface" tool plug into.

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod handler;
mod inode;
mod listeners;
mod netlink_socket;
mod receive;
mod shutdown;
#[cfg(test)]
mod netlink_tests;
mod wire;

pub mod genetlink;
pub mod mcast;
pub mod rtnetlink;
mod rtnetlink_lookup;
pub mod rtnetlink_rule;
pub mod audit;
pub mod sock_diag;

pub use handler::{install_netfilter_handler, ProtoHandler};
pub use inode::{
    make_netlink_socket_inode, netlink_arc_from_inode, netlink_from_inode, NETLINK_INO_TAG,
};
pub use listeners::{
    emit_uevent, emit_uevent_with_env, rebroadcast_cooked_uevent, register_rtnl_listener,
    register_uevent_listener, rtnl_multicast, uevent_seqnum, unicast_uevent_to_port,
};
pub(crate) use handler::invoke_netfilter;
pub use netlink_socket::{NETLINK_SNDBUF_DEFAULT, NETLINK_SEND_OVERHEAD, NetlinkSocket, SendError};
pub use receive::{ReceiveState, ReceivedDatagram};
pub use wire::{alloc_port_id, flags, msg, nlmsg_align, proto, AF_NETLINK,
    NETLINK_UNCONNECTED_GROUPS, NETLINK_UNCONNECTED_PORT_ID, Nlmsghdr};
