extern crate alloc;

use alloc::vec::Vec;

use crate::Nlmsghdr;

use super::ack::build_ack;
use super::rtnetlink_link::LinkStats64;
use super::uapi::Ifinfomsg;

/// Iface snapshot used by RTM_GETLINK.
/// # C: O(N_ifaces)
pub(crate) fn ifaces_snapshot_in(ns: u64) -> Vec<(u32, alloc::string::String, [u8; 6], net::PacketLinkAddress, u32, bool, u32, LinkStats64)> {
    let stack = net::global_stack();
    stack.ifaces.snapshot_in_ns(ns)
        .into_iter()
        .map(|snap| {
            let id = snap.id;
            let dev = stack.ifaces.lookup_in_ns(id, ns).unwrap();
            let is_lo = snap.name == "lo";
            let flags = stack.ifaces.iface_flags(id).unwrap_or(0);
            let raw = dev.stats();
            let stats = LinkStats64 {
                rx_packets: raw.rx_packets, tx_packets: raw.tx_packets,
                rx_bytes: raw.rx_bytes, tx_bytes: raw.tx_bytes,
                rx_errors: raw.rx_errors, tx_errors: raw.tx_errors,
                rx_dropped: raw.rx_dropped, tx_dropped: raw.tx_dropped,
            };
            (id.0, snap.name,
             dev.mac().0, dev.hardware_broadcast(), dev.mtu(), is_lo, flags, stats)
        })
        .collect()
}

/// Handle RTM_NEWLINK / RTM_SETLINK.
/// # C: O(N)
pub fn handle_setlink(req: &Nlmsghdr, full_msg: &[u8]) -> Vec<u8> {
    handle_setlink_in(net::netdev::current_net_ns(), req, full_msg)
}

/// Handle RTM_NEWLINK / RTM_SETLINK in the socket's captured namespace.
/// # C: O(N)
pub fn handle_setlink_in(ns: u64, req: &Nlmsghdr, full_msg: &[u8]) -> Vec<u8> {
    let off = Nlmsghdr::SIZE;
    if full_msg.len() < off + Ifinfomsg::SIZE { return build_ack(req, -22); }
    let ifindex = i32::from_ne_bytes([
        full_msg[off + 4], full_msg[off + 5], full_msg[off + 6], full_msg[off + 7],
    ]);
    let ifi_flags = u32::from_ne_bytes([
        full_msg[off + 8], full_msg[off + 9], full_msg[off + 10], full_msg[off + 11],
    ]);
    let ifi_change = u32::from_ne_bytes([
        full_msg[off + 12], full_msg[off + 13], full_msg[off + 14], full_msg[off + 15],
    ]);
    if ifindex <= 0 { return build_ack(req, -19); }
    let id = net::addr::NetIfaceId::from_raw(ifindex as u32);
    let stack = net::global_stack();
    let Some(lease) = stack.ifaces.acquire_ingress(id) else {
        return build_ack(req, -19);
    };
    if lease.net_ns() != ns { return build_ack(req, -19); }
    let Some(dev) = stack.ifaces.lookup_in_ns(id, ns) else { return build_ack(req, -19) };
    let properties = net::control_event::LinkProperties::from_dev(dev.as_ref());
    let ticket = {
        let rtnl = stack.rtnl_lock();
        let Some(_) = stack.ifaces.control_ready_in_ns(&rtnl, id, ns) else {
            return build_ack(req, -19);
        };
        if stack.ifaces.control_generation_in_ns(&rtnl, id, ns) != Some(lease.generation()) {
            return build_ack(req, -19);
        }
        let Some(_) = stack.ifaces.set_iface_flags_in_ns(
            &rtnl, id, ns, ifi_flags, ifi_change) else { return build_ack(req, -19) };
        let Some(event) = stack.live_link_event(
            &rtnl, net::control_event::NamespaceOwner::Live(lease.namespace()), id,
            properties, net::control_event::EventKind::New) else {
            return build_ack(req, -19);
        };
        net::control_event::stage(&rtnl, net::control_event::ControlEvent::Link(event))
    };
    net::control_event::publish(ticket);
    build_ack(req, 0)
}
