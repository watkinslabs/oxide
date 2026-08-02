// Netlink module manifest.
// - `wire`: AF_NETLINK numbers, nlmsghdr wire types, and alignment helpers.
// - `handler`: external protocol-handler registration for netfilter.
// - `creds`: per-datagram sender credentials + the SO_PASSCRED report rule.
// - `groups`: the per-socket multicast-group subscription bitmap.
// - `membership`: socket-side group subscription + genetlink credentials.
// - `listeners`: uevent + rtnetlink multicast/unicast listener registries.
// - `netlink_socket`: socket state, dispatch, RX queue, and poll behavior.
// - `destination`: socket-owned connect destination and default-send state.
// - `ports`: live namespace/protocol/port-ID ownership and bind collision checks.
// - `rcv_skb`: netlink-core datagram framing walk and handler-admission rules.
// - `sockaddr`: the one `sockaddr_nl` destination decoder every send path uses.
// - `shutdown`: AF_NETLINK's Linux `sock_no_shutdown` contract.
// - `receive`: canonical dequeue, pending-error ordering, and wait arming.
// - `inode`: VFS inode glue for netlink socket file descriptors.
// - `rtnetlink*` / `genetlink` / `sock_diag` / `mcast`: protocol-specific code.
//
// Netlink socket family (`AF_NETLINK` = 16). Current surface is the framing +
// dispatch substrate that `ip(8)`, DHCP clients, nftables, and
// any future "configure the iface" tool plug into.

#![no_std]

// dead_code is meaningful for this crate ONLY on the kernel target. A large
// part of it sits behind `cfg(target_os = "oxide-kernel")`, so a host build
// (`cargo test`, `cargo check --workspace`) compiles a strict subset and calls
// hundreds of live items dead. The kernel builds keep dead_code fully enabled
// and are warning-clean, and every one of these crates links into `kmain`, so
// nothing is hidden: real dead code still surfaces on `xtask kernel`.
#![cfg_attr(not(target_os = "oxide-kernel"), allow(dead_code))]
extern crate alloc;
#[cfg(test)]
extern crate std;

#[cfg(test)]
pub(crate) mod test_serial;

mod creds;
mod groups;
mod handler;
mod membership;
mod inode;
mod listeners;
mod netlink_socket;
mod destination;
mod ports;
mod rcv_skb;
mod receive;
mod sockaddr;
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

pub use creds::{reported as reported_creds, NetlinkCreds};
pub use groups::{GroupBitmap, GROUP_BITS_PER_WORD, NETLINK_MIN_NGROUPS, RTNLGRP_MAX};
pub use handler::{install_netfilter_handler, ProtoHandler};
pub use inode::{
    make_netlink_socket_inode, netlink_arc_from_inode, netlink_from_inode,
};
pub use listeners::{
    emit_uevent, emit_uevent_with_env, emit_uevent_with_env_bytes, rebroadcast_cooked_uevent,
    register_rtnl_listener, register_uevent_listener, rtnl_multicast, rtnl_multicast_in,
    uevent_seqnum,
    unicast_uevent_to_port,
};
pub(crate) use handler::invoke_netfilter;
pub use ports::bind_port_id;
pub(crate) use ports::{register_port_id, unicast_port};
pub use netlink_socket::{NETLINK_RCVBUF_DEFAULT, NETLINK_SNDBUF_DEFAULT, NETLINK_SEND_OVERHEAD,
    NetlinkSocket, SendError};
pub use receive::{ReceiveState, ReceivedDatagram};
pub use sockaddr::{encode_dest, first_group, parse_dest, NlDest};
pub use wire::{alloc_port_id, flags, msg, nlmsg_align, proto, AF_NETLINK,
    KOBJECT_UEVENT_KERNEL_GROUP_MASK, KOBJECT_UEVENT_UDEV_GROUP_MASK,
    NETLINK_UNCONNECTED_GROUPS, NETLINK_UNCONNECTED_PORT_ID, SOCKADDR_NL_SIZE,
    SOCKADDR_NL_PORT_ID_OFFSET, SOCKADDR_NL_GROUPS_OFFSET, Nlmsghdr, sockopt};
