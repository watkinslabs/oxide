extern crate alloc;

use crate::rtnetlink as rt;

#[cfg(test)]
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

#[cfg(test)]
static BLOCK_IFACE: AtomicU32 = AtomicU32::new(0);
#[cfg(test)]
static BLOCK_ENTERED: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static BLOCK_RELEASE: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
pub(crate) fn block_notification(ifindex: u32) {
    BLOCK_ENTERED.store(false, Ordering::Release);
    BLOCK_RELEASE.store(false, Ordering::Release);
    BLOCK_IFACE.store(ifindex, Ordering::Release);
}

#[cfg(test)]
pub(crate) fn wait_notification_blocked() {
    while !BLOCK_ENTERED.load(Ordering::Acquire) { std::thread::yield_now(); }
}

#[cfg(test)]
pub(crate) fn release_notification() {
    BLOCK_RELEASE.store(true, Ordering::Release);
    BLOCK_IFACE.store(0, Ordering::Release);
}

#[cfg(test)]
fn pause_notification(ifindex: u32) {
    if BLOCK_IFACE.load(Ordering::Acquire) != ifindex { return; }
    BLOCK_ENTERED.store(true, Ordering::Release);
    while !BLOCK_RELEASE.load(Ordering::Acquire) { std::thread::yield_now(); }
}

#[cfg(not(test))]
fn pause_notification(_ifindex: u32) {}

pub mod grp {
    pub const RTNLGRP_LINK:        u32 = 1;
    pub const RTNLGRP_IPV4_IFADDR: u32 = 5;
    pub const RTNLGRP_IPV4_ROUTE:  u32 = 7;
    pub const RTNLGRP_IPV4_RULE:   u32 = 8;
    pub const RTNLGRP_IPV6_IFADDR: u32 = 9;
    pub const RTNLGRP_IPV6_ROUTE:  u32 = 11;
    pub const RTNLGRP_IPV6_RULE:   u32 = 19;
}

fn patch_type(msg: &mut [u8], ty: u16) {
    if msg.len() >= 6 { msg[4..6].copy_from_slice(&ty.to_ne_bytes()); }
}

/// The interface index a NOTIFICATION must carry: the namespace-scoped Linux
/// ifindex, the same number the dumps report.
///
/// `NetIfaceId` is a process-global internal handle; `ifindex` is per-namespace
/// and is what userspace knows an interface by — each namespace's `lo` is 1.
/// Sending the internal id meant a notification could name a different
/// interface than the dump did, so a client that builds its table from a dump
/// cannot match the notification to anything. They coincide in the initial
/// namespace, which is exactly why this survived: it is wrong only where a
/// second namespace exists, and silently.
///
/// Falls back to the internal id if the interface has already gone, which is
/// the pre-existing behaviour for a device removed mid-notification.
/// # C: O(N_ifaces)
fn notify_ifindex(owner: &net::control_event::IfaceOwner, ns: u64) -> i32 {
    net::global_stack().ifaces.ifindex_in_ns(owner.iface, ns)
        .unwrap_or(owner.iface.raw()) as i32
}

fn emit_link(event: &net::control_event::LinkEvent) {
    pause_notification(event.owner.iface.raw());
    let stats = rt::LinkStats64 {
        rx_packets: event.stats.rx_packets, tx_packets: event.stats.tx_packets,
        rx_bytes: event.stats.rx_bytes, tx_bytes: event.stats.tx_bytes,
        rx_errors: event.stats.rx_errors, tx_errors: event.stats.tx_errors,
        rx_dropped: event.stats.rx_dropped, tx_dropped: event.stats.tx_dropped,
    };
    let mut msg = rt::build_newlink_reply(
        0, 0, event.ifindex as i32, &event.name, event.mac.0,
        &event.broadcast.bytes[..event.broadcast.len as usize], event.mtu,
        event.is_loopback, event.flags, stats, false);
    if event.kind == net::control_event::EventKind::Delete {
        patch_type(&mut msg, rt::RTM_DELLINK);
    }
    crate::listeners::rtnl_multicast_in(event.namespace.id(), grp::RTNLGRP_LINK, &msg);
}

fn emit_addr(event: &net::control_event::AddrEvent) {
    pause_notification(event.owner.iface.raw());
    let row = event.row;
    let mut msg = rt::build_newaddr_reply(
        0, 0, notify_ifindex(&event.owner, event.namespace.id()), &event.label, row.addr.octets(),
        row.peer.map(|peer| peer.octets()),
        row.prefixlen, row.scope, row.flags,
        rt::IfaCacheInfo {
            preferred: row.cacheinfo.preferred, valid: row.cacheinfo.valid,
            cstamp: row.cacheinfo.cstamp, tstamp: row.cacheinfo.tstamp,
        }, false,
    );
    if event.kind == net::control_event::EventKind::Delete {
        patch_type(&mut msg, rt::RTM_DELADDR);
    }
    crate::listeners::rtnl_multicast_in(event.namespace.id(), grp::RTNLGRP_IPV4_IFADDR, &msg);
}

fn emit_addr6(event: &net::control_event::Addr6Event) {
    pause_notification(event.owner.iface.raw());
    let row = &event.row;
    let scope = if row.addr.is_loopback() { rt::RT_SCOPE_HOST }
        else if row.addr.is_link_local() { rt::RT_SCOPE_LINK } else { rt::RT_SCOPE_UNIVERSE };
    let flags = row.flags();
    let mut msg = rt::build_newaddr6_reply(0, 0, notify_ifindex(&event.owner, event.namespace.id()),
        &event.label, row.addr.0, row.prefixlen, scope, flags,
        rt::IfaCacheInfo { preferred: row.preferred, valid: row.valid, cstamp: 0, tstamp: 0 },
        false);
    if event.kind == net::control_event::EventKind::Delete {
        patch_type(&mut msg, rt::RTM_DELADDR);
    }
    crate::listeners::rtnl_multicast_in(
        event.namespace.id(), grp::RTNLGRP_IPV6_IFADDR, &msg);
}

fn emit_route(event: &net::control_event::RouteEvent) {
    if let Some(owner) = event.owners.first() { pause_notification(owner.iface.raw()); }
    let rows: alloc::vec::Vec<_> = event.records.iter().copied()
        .map(|record| rt::route_state::from_record(event.namespace.id(), record)).collect();
    let mut msg = rt::build_newroute_group_reply(0, 0, &rows, false);
    if event.kind == net::control_event::EventKind::Delete {
        patch_type(&mut msg, rt::RTM_DELROUTE);
    }
    crate::listeners::rtnl_multicast_in(event.namespace.id(), grp::RTNLGRP_IPV4_ROUTE, &msg);
}

fn emit_route6(event: &net::control_event::Route6Event) {
    if let Some(owner) = event.owners.first() { pause_notification(owner.iface.raw()); }
    for row in event.rows.iter().copied() {
        let mut msg = rt::build_newroute6_reply(0, 0, row, false);
        if event.kind == net::control_event::EventKind::Delete {
            patch_type(&mut msg, rt::RTM_DELROUTE);
        }
        crate::listeners::rtnl_multicast_in(
            event.namespace.id(), grp::RTNLGRP_IPV6_ROUTE, &msg);
    }
}

fn emit_rule(event: &net::control_event::RuleEvent) {
    let group = match event.row.family {
        net::policy_rule::AF_INET => grp::RTNLGRP_IPV4_RULE,
        net::policy_rule::AF_INET6 => grp::RTNLGRP_IPV6_RULE,
        _ => return,
    };
    let mut msg = crate::rtnetlink_rule::build_newrule_reply(0, 0, event.row, false);
    if event.kind == net::control_event::EventKind::Delete {
        patch_type(&mut msg, rt::RTM_DELRULE);
    }
    if event.row.ns != event.namespace.id() { return; }
    crate::listeners::rtnl_multicast_in(event.namespace.id(), group, &msg);
}

/// Translate one canonical post-RTNL network event to Linux rtnetlink multicast. # C: O(N)
pub fn notify_control_event(event: &net::control_event::ControlEvent) {
    match event {
        net::control_event::ControlEvent::Link(event) => emit_link(event),
        net::control_event::ControlEvent::Addr(event) => emit_addr(event),
        net::control_event::ControlEvent::Addr6(event) => emit_addr6(event),
        net::control_event::ControlEvent::Route(event) => emit_route(event),
        net::control_event::ControlEvent::Route6(event) => emit_route6(event),
        net::control_event::ControlEvent::Rule(event) => emit_rule(event),
    }
}

#[cfg(test)]
mod notify_ifindex_tests {
    use super::*;

    /// A notification carries the namespace-scoped ifindex, not the internal
    /// handle — and this is only observable where the two differ.
    ///
    /// `NetIfaceId` is process-global; `ifindex` restarts per namespace, so a
    /// second namespace's first interface is ifindex 1 while its id keeps
    /// climbing. Sending the id meant a notification named a different
    /// interface than the dump did, and a client that builds its table from the
    /// dump could not match it. In the initial namespace the two coincide,
    /// which is why this was invisible.
    #[test]
    fn a_notification_carries_the_namespace_ifindex_not_the_internal_id() {
        let _domain = net::hosted_fixture::init_net_domain();
        let stack = net::global_stack();
        // Fill the initial namespace so the global id counter runs ahead.
        let _a = stack.ifaces.register_in_ns(alloc::sync::Arc::new(net::LoopbackDev::new()), 0);
        let _b = stack.ifaces.register_in_ns(alloc::sync::Arc::new(net::LoopbackDev::new()), 0);

        const OTHER_NS: u64 = 4242;
        let first = stack.ifaces.register_in_ns(
            alloc::sync::Arc::new(net::LoopbackDev::new()), OTHER_NS);

        let ifindex = stack.ifaces.ifindex_in_ns(first, OTHER_NS).expect("registered");
        assert_eq!(ifindex, 1, "each namespace numbers its own interfaces from 1");
        assert_ne!(ifindex, first.raw(),
            "the fixture must actually distinguish the two, or it proves nothing");

        let owner = net::control_event::IfaceOwner { iface: first, generation: 0 };
        assert_eq!(notify_ifindex(&owner, OTHER_NS), ifindex as i32,
            "notifications report what userspace knows the interface by");
    }
}
