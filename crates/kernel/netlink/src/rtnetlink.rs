// RTNETLINK module manifest.
// - `uapi`: rtnetlink message ids, structs, attribute ids, and route constants.
// - `attrs`: nlattr writers shared by dump builders and mutation paths.
// - `ack`: NLMSG_ERROR ack helper shared by mutating requests.
// - `dumps`: GETLINK/GETADDR builders and multi-part terminator.
// - `neigh`: RTM_*NEIGH bridge to the canonical ARP (v4) + NDP (v6) caches.
// - `addr_ops`: RTM_NEWADDR / RTM_DELADDR request parsing and updates.
// - `route_state`: persistent route table storage and boot seeding.
// - `route_ops`: route dump/mutation path and stack synchronization.
// - `iface`: live iface snapshot + RTM_SETLINK mutation path.
// - `rtnetlink_addr` / `rtnetlink_link` / `rtnetlink_route`: focused helpers.
//
// NETLINK_ROUTE per `25§7`. Implements the
// link/addr/route control plane `ip` + systemd-networkd drive.

mod ack;
mod addr_ops;
mod attrs;
mod dump_req;
mod dumps;
mod iface;
mod neigh;
mod nsid_req;
mod nsid;
mod route_ops;
pub(crate) mod route_state;
mod uapi;

#[path = "rtnetlink_addr.rs"]
mod rtnetlink_addr;
#[path = "rtnetlink_link.rs"]
mod rtnetlink_link;
#[path = "rtnetlink_route.rs"]
pub(crate) mod rtnetlink_route;

pub use ack::{nlmsg_ack_bad_attr, nlmsg_ack_pub};
pub use addr_ops::{handle_deladdr, handle_deladdr_in, handle_newaddr, handle_newaddr_in};
pub use attrs::{put_nlattr, put_nlattr_i32, put_nlattr_str, put_nlattr_u32, put_nlattr_u8};
pub(crate) use dumps::{build_newaddr6_reply, build_newaddr_reply, build_newlink_reply};
pub use dump_req::{is_dump, validate_addr_dump, validate_link_dump, AddrDump, LinkDump, NLM_F_DUMP_FILTERED};
pub use dumps::{done_multi, handle_getaddr, handle_getaddr6_one_in, handle_getaddr_in, handle_getlink, handle_getlink_in};
pub use neigh::{handle_delneigh_in, handle_getneigh_in, handle_getneigh_one_in, handle_newneigh_in};
pub use nsid_req::{dump as parse_dumpnsid, get as parse_getnsid, new as parse_newnsid,
    Dump as DumpNsid, Get as GetNsid, New as NewNsid, PeerRef,
    ParseError as ParseNsidError};
pub use nsid::{dump as handle_dumpnsid, get as handle_getnsid, new as handle_newnsid};
pub(crate) use rtnetlink_link::LinkStats64;
pub use iface::{handle_setlink, handle_setlink_in};
pub(crate) use route_ops::{build_newroute6_reply, build_newroute_group_reply,
    build_newroute_row_reply, route_oif_for_abi};
pub use route_ops::{
    handle_delroute, handle_delroute_in, handle_getroute, handle_getroute_in,
    handle_newroute, handle_newroute_in,
};
pub use route_state::{
    route_insert, route_lookup_ns, route_remove, route_snapshot, route_snapshot_ns, seed_default_routes,
    seed_default_routes_lo, RouteRow,
};
pub use rtnetlink_addr::{
    addr_insert, addr_remove, addr_snapshot, addr_snapshot_ns, cache_to_net, seed_defaults,
    IfaCacheInfo,
};
pub use uapi::*;

#[cfg(test)]
#[path = "rtnetlink_tests.rs"]
mod tests;
