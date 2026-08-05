// NETLINK_GENERIC (genetlink) module manifest.
//
// - `uapi`:     family/command/attribute numbers and the `genlmsghdr`.
// - `attr`:     `nlattr` stream builder + walker (nesting, 64-bit padding).
// - `message`:  `nlmsghdr` + `genlmsghdr` framing and `NLMSG_ERROR` replies.
// - `family`:   the family registry and both id spaces (family, mcast group).
// - `ctrl`:     the `nlctrl` controller family and its registration events.
// - `dispatch`: request admission (ENOENT/EINVAL/EOPNOTSUPP/EPERM) + routing.
// - `mcast`:    multicast listener registry and the group fan-out.
// - `quota`:    the `VFS_DQUOT` family — quota warnings out to `quota_nld`.
// - `tcp_metrics`: TCP destination metrics projected from the canonical cache.
//
// A client cannot address a family until `nlctrl` has told it the family's id,
// so `init` registers the controller before anything else.

pub mod attr;
pub mod ctrl;
pub mod dispatch;
pub mod family;
pub mod mcast;
pub mod message;
pub mod quota;
pub mod tcp_metrics;
pub mod uapi;

#[cfg(test)]
mod tests;

pub use dispatch::{handle, GenlCred};
pub use family::{
    find_by_id, find_by_name, mcast_ngroups, register_family, snapshot_families,
    unregister_family, GenlFamily, GenlFamilySpec, GenlMcastGroup, GenlOp, GenlRegError,
    PolicyEntry,
};
pub use mcast::{
    genlmsg_multicast, genlmsg_multicast_allns, genlmsg_multicast_netns, register_genl_listener,
    GenlMcastError,
};
pub use uapi::{ctrl_attr, ctrl_cmd, Genlmsghdr, CTRL_FAMILY_NAME, GENL_ID_CTRL};

/// Bring generic netlink up: the controller first, then every in-kernel
/// family, then the hooks that feed them. # C: O(N families)
pub fn init() {
    let _ = ctrl::register();
    let _ = quota::init();
    let _ = tcp_metrics::init();
}
