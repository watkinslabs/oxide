// 802.1Q / 802.1ad VLAN interfaces.
//
// Module manifest:
//   uapi     — wire numbers and the `vlan` link-kind rtnetlink ABI
//   flags    — per-interface behaviour bits and flag-change arithmetic
//   limits   — priority-table sizes
//   tci      — tag control information encode/decode, tag insert and strip
//   prio     — code-point-to-priority and priority-to-code-point tables
//   caps     — lower-interface properties and the rules derived from them
//   xmit     — where the outgoing tag goes, and the frame that results
//   dev      — one VLAN interface, its transmit path and its receive path
//   registry — tag-to-interface table and the receive-side demultiplex
//   nla      — netlink attribute blob walking
//   netlink  — attribute parse, validation, creation and change requests
//   link_kind — the `vlan` entry in the rtnetlink link-kind table

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod uapi;
pub mod flags;
pub mod limits;
pub mod tci;
pub mod prio;
pub mod caps;
pub mod xmit;
pub mod dev;
pub mod registry;
pub mod nla;
pub mod netlink;
pub mod link_kind;

pub use caps::RealDevCaps;
pub use dev::{IngressResult, VlanDev};
pub use registry::{table, Demux, VlanKey, VlanTable};
pub use link_kind::{VlanLinkKind, VLAN_LINK_KIND_OPS};
pub use xmit::{EgressFrame, TagMode};

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
