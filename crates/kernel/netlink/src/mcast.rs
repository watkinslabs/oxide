// rtnetlink multicast notifications (`RTNLGRP_*`). Split out of
// rtnetlink.rs to keep that file under the 1000-line cap (08§7).
//
// When a userspace RTM_NEW*/DEL*/SETLINK request mutates kernel state,
// Linux broadcasts the matching RTM_* message to every NETLINK_ROUTE
// socket subscribed to the relevant group (`ip monitor`,
// systemd-networkd, NetworkManager). Mirrors `rtmsg_ifinfo` /
// `rtmsg_ifa` / `rtmsg_fib` → `nlmsg_multicast`. Broadcasts are
// kernel-originated (nlmsg_seq 0, nlmsg_pid 0) and are enqueued directly
// onto each subscribed socket, bypassing the per-socket pid stamping the
// request/reply path applies.

use crate::rtnetlink as rt;

/// `RTNLGRP_*` group numbers (uapi `rtnetlink.h`). A subscriber's
/// `groups` bitmask carries bit `g-1` for group `g` (legacy `RTMGRP_*`).
pub mod grp {
    pub const RTNLGRP_LINK:        u32 = 1;
    pub const RTNLGRP_IPV4_IFADDR: u32 = 5;
    pub const RTNLGRP_IPV4_ROUTE:  u32 = 7;
}

/// Overwrite the leading nlmsghdr's `nlmsg_type` (DEL* notifications reuse
/// the NEW* builder, then patch the type). # C: O(1)
fn patch_type(msg: &mut [u8], ty: u16) {
    if msg.len() >= 6 { msg[4..6].copy_from_slice(&ty.to_ne_bytes()); }
}

/// Iface name for `ifindex` (for IFA_LABEL), or "" if unknown.
fn iface_label(ifindex: i32) -> alloc::string::String {
    if ifindex <= 0 { return alloc::string::String::new(); }
    rt::ifaces_snapshot().into_iter()
        .find(|(id, ..)| *id == ifindex as u32)
        .map(|(_, name, ..)| name)
        .unwrap_or_default()
}

/// Broadcast RTM_NEWLINK for `ifindex`'s current registry state to
/// RTNLGRP_LINK (link up/down → `ip monitor link`). # C: O(N_listeners)
pub(crate) fn notify_link(ifindex: i32) {
    let row = rt::ifaces_snapshot().into_iter()
        .find(|(id, ..)| *id == ifindex as u32);
    let (id, name, mac, mtu, is_lo, flags) = match row { Some(r) => r, None => return };
    let msg = rt::build_newlink_reply(0, 0, id as i32, &name, mac, mtu, is_lo, flags, false);
    crate::rtnl_multicast(grp::RTNLGRP_LINK, &msg);
}

/// Broadcast RTM_NEWADDR / RTM_DELADDR to RTNLGRP_IPV4_IFADDR
/// (`ip addr add/del` → `ip monitor addr`). # C: O(N_listeners)
pub(crate) fn notify_addr(is_del: bool, ifindex: u32, addr: [u8; 4], prefixlen: u8, scope: u8) {
    let label = iface_label(ifindex as i32);
    let mut msg = rt::build_newaddr_reply(
        0, 0, ifindex as i32, &label, addr, prefixlen, scope,
        net::iface_addr::IFA_F_PERMANENT, rt::IfaCacheInfo::PERMANENT, false,
    );
    if is_del { patch_type(&mut msg, rt::RTM_DELADDR); }
    crate::rtnl_multicast(grp::RTNLGRP_IPV4_IFADDR, &msg);
}

/// Broadcast RTM_NEWROUTE / RTM_DELROUTE to RTNLGRP_IPV4_ROUTE
/// (`ip route add/del` → `ip monitor route`). # C: O(N_listeners)
#[allow(clippy::too_many_arguments)]
pub(crate) fn notify_route(
    is_del: bool, table: u8, protocol: u8, scope: u8, kind: u8,
    dst: Option<([u8; 4], u8)>, gateway: Option<[u8; 4]>, oif: u32, prefsrc: Option<[u8; 4]>,
) {
    let mut msg = rt::build_newroute_reply(
        0, 0, table, protocol, scope, kind, dst, gateway, oif, prefsrc, false);
    if is_del { patch_type(&mut msg, rt::RTM_DELROUTE); }
    crate::rtnl_multicast(grp::RTNLGRP_IPV4_ROUTE, &msg);
}
