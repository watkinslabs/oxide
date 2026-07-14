extern crate alloc;

use alloc::vec::Vec;

use crate::Nlmsghdr;

use super::ack::build_ack;
use super::rtnetlink_link::LinkStats64;
use super::uapi::Ifinfomsg;

/// Iface snapshot used by RTM_GETLINK.
/// # C: O(N_ifaces)
pub(crate) fn ifaces_snapshot_in(ns: u64) -> Vec<(u32, alloc::string::String, [u8; 6], u32, bool, u32, LinkStats64)> {
    let stack = net::global_stack();
    stack.ifaces.snapshot_devs_in_ns(ns)
        .into_iter()
        .map(|(id, dev)| {
            let is_lo = dev.name() == "lo";
            let flags = stack.ifaces.iface_flags(id).unwrap_or(0);
            let raw = dev.stats();
            let stats = LinkStats64 {
                rx_packets: raw.rx_packets, tx_packets: raw.tx_packets,
                rx_bytes: raw.rx_bytes, tx_bytes: raw.tx_bytes,
                rx_errors: raw.rx_errors, tx_errors: raw.tx_errors,
                rx_dropped: raw.rx_dropped, tx_dropped: raw.tx_dropped,
            };
            (id.0, alloc::string::String::from(dev.name()),
             dev.mac().0, dev.mtu(), is_lo, flags, stats)
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
    let ifaces = &net::global_stack().ifaces;
    if ifaces.lookup_in_ns(id, ns).is_none() { return build_ack(req, -19); }
    match ifaces.set_iface_flags(id, ifi_flags, ifi_change) {
        Some(_) => { crate::mcast::notify_link(ifindex); build_ack(req, 0) }
        None => build_ack(req, -19),
    }
}
