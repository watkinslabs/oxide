// The notifications the stack raises: what goes out on which multicast group
// when a scan finishes, a connection comes up or goes away, or a frame that
// userspace registered for arrives.
//
// Group choice is part of the contract. `wpa_supplicant` subscribes to `mlme`
// and `scan` and not to `config`, so a connection event sent on `config`
// reaches nobody that cares, and the supplicant waits forever for a result
// the kernel believes it delivered.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use netlink::genetlink::attr;
use netlink::genetlink::{family as genl_family, mcast};
use netlink::Nlmsghdr;

use crate::ieee80211::MacAddr;
use crate::sme::ConnectResult;
use crate::uapi::{attr as a, cmd, NL80211_FAMILY_VERSION};
use crate::wdev::Wdev;
use crate::wiphy::Wiphy;

use super::family::{self, GROUP_CONFIG, GROUP_MLME, GROUP_REGULATORY, GROUP_SCAN};

/// Start an event message. An event is not a reply, so it carries no
/// destination port and no request sequence number. # C: O(1)
pub fn start(cmd: u8) -> Vec<u8> {
    netlink::genetlink::message::start(0, 0, family::family_id(), NL80211_FAMILY_VERSION,
                                       0, cmd)
}

/// Finish an event message. # C: O(1)
pub fn end(out: &mut Vec<u8>) { netlink::genetlink::message::end(out, 0); }

/// Append the attributes that say which radio and interface an event is
/// about. Every event carries them; an event without them cannot be
/// attributed to a device by a listener watching several. # C: O(1)
pub fn put_ids(out: &mut Vec<u8>, wiphy: &Arc<Wiphy>, wdev: Option<&Arc<Wdev>>) {
    attr::put_u32(out, a::WIPHY, wiphy.index);
    if let Some(d) = wdev {
        if let Some(ifindex) = d.ifindex() { attr::put_u32(out, a::IFINDEX, ifindex); }
        super::msg::put_u64(out, a::WDEV, d.identifier);
    }
}

/// Send a finished event to one group in the radio's namespace. Reaching no
/// listener is not an error: nothing subscribed is the normal state for most
/// groups most of the time. # C: O(N listeners)
pub fn send(wiphy: &Arc<Wiphy>, group: usize, msg: &[u8]) {
    let Some(fam) = genl_family::find_by_id(family::family_id()) else { return; };
    let ns = wiphy.net_ns.load(core::sync::atomic::Ordering::Acquire);
    let _ = mcast::genlmsg_multicast_netns(&fam, ns, group, msg, 0);
}

/// Send a finished message to the one socket that asked for it. # C: O(N listeners)
pub fn send_to_port(wiphy: &Arc<Wiphy>, portid: u32, msg: &[u8]) {
    let ns = wiphy.net_ns.load(core::sync::atomic::Ordering::Acquire);
    let _ = mcast::genlmsg_unicast(ns, portid, msg);
}

/// A radio appeared.  # C: O(N listeners)
pub fn new_wiphy(wiphy: &Arc<Wiphy>) {
    let mut out = start(cmd::NEW_WIPHY);
    attr::put_u32(&mut out, a::WIPHY, wiphy.index);
    attr::put_str(&mut out, a::WIPHY_NAME, &wiphy.name);
    attr::put_u32(&mut out, a::GENERATION, wiphy.generation());
    end(&mut out);
    send(wiphy, GROUP_CONFIG, &out);
}

/// A radio went away. # C: O(N listeners)
pub fn del_wiphy(wiphy: &Arc<Wiphy>) {
    let mut out = start(cmd::DEL_WIPHY);
    attr::put_u32(&mut out, a::WIPHY, wiphy.index);
    attr::put_str(&mut out, a::WIPHY_NAME, &wiphy.name);
    end(&mut out);
    send(wiphy, GROUP_CONFIG, &out);
}

/// An interface appeared or changed. # C: O(N listeners)
pub fn new_interface(wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>) {
    let mut out = start(cmd::NEW_INTERFACE);
    put_ids(&mut out, wiphy, Some(wdev));
    let name = wdev.name();
    if !name.is_empty() { attr::put_str(&mut out, a::IFNAME, &name); }
    attr::put_u32(&mut out, a::IFTYPE, wdev.iftype().as_u32());
    super::msg::put_mac(&mut out, a::MAC, wdev.addr());
    attr::put_u32(&mut out, a::GENERATION, wiphy.generation());
    end(&mut out);
    send(wiphy, GROUP_CONFIG, &out);
}

/// An interface went away. # C: O(N listeners)
pub fn del_interface(wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>) {
    let mut out = start(cmd::DEL_INTERFACE);
    put_ids(&mut out, wiphy, Some(wdev));
    let name = wdev.name();
    if !name.is_empty() { attr::put_str(&mut out, a::IFNAME, &name); }
    end(&mut out);
    send(wiphy, GROUP_CONFIG, &out);
}

/// A scan started. # C: O(N listeners)
pub fn trigger_scan(wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>) {
    let mut out = start(cmd::TRIGGER_SCAN);
    put_ids(&mut out, wiphy, Some(wdev));
    end(&mut out);
    send(wiphy, GROUP_SCAN, &out);
}

/// A scan finished. `aborted` decides the command, because a supplicant
/// treats the two differently: results are worth reading after one and not
/// after the other. # C: O(N listeners)
pub fn scan_done(wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, aborted: bool) {
    let mut out = start(if aborted { cmd::SCAN_ABORTED } else { cmd::NEW_SCAN_RESULTS });
    put_ids(&mut out, wiphy, Some(wdev));
    end(&mut out);
    send(wiphy, GROUP_SCAN, &out);
}

/// A connect attempt reached its single terminal outcome. # C: O(N listeners)
pub fn connect_result(wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, result: &ConnectResult,
                      req_ie: &[u8], resp_ie: &[u8]) {
    let mut out = start(cmd::CONNECT);
    put_ids(&mut out, wiphy, Some(wdev));
    match result {
        ConnectResult::Success { bssid, .. } => {
            super::msg::put_mac(&mut out, a::MAC, *bssid);
            attr::put_u16(&mut out, a::STATUS_CODE,
                          crate::ieee80211::status::status::SUCCESS);
        }
        ConnectResult::Refused { bssid, status } => {
            if let Some(b) = bssid { super::msg::put_mac(&mut out, a::MAC, *b); }
            attr::put_u16(&mut out, a::STATUS_CODE, *status);
        }
        ConnectResult::TimedOut { reason } => {
            // A timed-out attempt carries the timeout flag and no status
            // code: there was no response to report a status from.
            super::msg::put_flag(&mut out, a::TIMED_OUT);
            attr::put_u32(&mut out, a::TIMEOUT_REASON, *reason);
        }
    }
    if !req_ie.is_empty() { attr::put(&mut out, a::REQ_IE, req_ie); }
    if !resp_ie.is_empty() { attr::put(&mut out, a::RESP_IE, resp_ie); }
    end(&mut out);
    send(wiphy, GROUP_MLME, &out);
}

/// A connection ended. `by_ap` says which side ended it, which is the
/// difference between a supplicant retrying and a supplicant not.
/// # C: O(N listeners)
pub fn disconnected(wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, reason: u16, by_ap: bool,
                    ie: &[u8]) {
    let mut out = start(cmd::DISCONNECT);
    put_ids(&mut out, wiphy, Some(wdev));
    attr::put_u16(&mut out, a::REASON_CODE, reason);
    if by_ap { super::msg::put_flag(&mut out, a::DISCONNECTED_BY_AP); }
    if !ie.is_empty() { attr::put(&mut out, a::IE, ie); }
    end(&mut out);
    send(wiphy, GROUP_MLME, &out);
}

/// The controlled port opened: the four-way handshake completed and data may
/// now flow. # C: O(N listeners)
pub fn port_authorized(wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, bssid: MacAddr) {
    let mut out = start(cmd::PORT_AUTHORIZED);
    put_ids(&mut out, wiphy, Some(wdev));
    super::msg::put_mac(&mut out, a::MAC, bssid);
    end(&mut out);
    send(wiphy, GROUP_MLME, &out);
}

/// One of the four management exchanges completed, reported as the raw frame
/// so userspace parses exactly what arrived. # C: O(len)
pub fn mlme_frame(wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, cmd: u8, frame: &[u8]) {
    let mut out = start(cmd);
    put_ids(&mut out, wiphy, Some(wdev));
    attr::put(&mut out, a::FRAME, frame);
    end(&mut out);
    send(wiphy, GROUP_MLME, &out);
}

/// A received management frame, delivered to the one socket that registered
/// for its subtype. A frame nobody registered for goes nowhere; broadcasting
/// it would hand every listener frames addressed to another. # C: O(N regs)
pub fn rx_mgmt(wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, freq: u32, signal_dbm: i32,
               frame: &[u8]) -> bool {
    let Some(hdr) = crate::ieee80211::MacHeader::parse(frame) else { return false; };
    let frame_type = crate::ieee80211::fctl::frame_type(hdr.frame_control);
    let body = &frame[hdr.len.min(frame.len())..];
    let ports = wdev.mgmt_targets(frame_type, body);
    if ports.is_empty() { return false; }
    for portid in ports {
        let mut out = netlink::genetlink::message::start(portid, 0, family::family_id(),
            NL80211_FAMILY_VERSION, 0, cmd::FRAME);
        put_ids(&mut out, wiphy, Some(wdev));
        attr::put_u32(&mut out, a::WIPHY_FREQ, freq);
        super::msg::put_i32(&mut out, a::RX_SIGNAL_DBM, signal_dbm);
        attr::put(&mut out, a::FRAME, frame);
        end(&mut out);
        send_to_port(wiphy, portid, &out);
    }
    true
}

/// The status of a management frame the stack transmitted. # C: O(len)
pub fn mgmt_tx_status(wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, cookie: u64, frame: &[u8],
                      acked: bool) {
    let mut out = start(cmd::FRAME_TX_STATUS);
    put_ids(&mut out, wiphy, Some(wdev));
    super::msg::put_u64(&mut out, a::COOKIE, cookie);
    attr::put(&mut out, a::FRAME, frame);
    if acked { super::msg::put_flag(&mut out, a::ACK); }
    end(&mut out);
    send(wiphy, GROUP_MLME, &out);
}

/// A station joined an access-point interface. # C: O(N listeners)
pub fn new_station(wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, mac: MacAddr, assoc_ie: &[u8]) {
    let mut out = start(cmd::NEW_STATION);
    put_ids(&mut out, wiphy, Some(wdev));
    super::msg::put_mac(&mut out, a::MAC, mac);
    attr::put_u32(&mut out, a::GENERATION, wiphy.generation());
    if !assoc_ie.is_empty() { attr::put(&mut out, a::IE, assoc_ie); }
    end(&mut out);
    send(wiphy, GROUP_MLME, &out);
}

/// A station left. # C: O(N listeners)
pub fn del_station(wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, mac: MacAddr) {
    let mut out = start(cmd::DEL_STATION);
    put_ids(&mut out, wiphy, Some(wdev));
    super::msg::put_mac(&mut out, a::MAC, mac);
    attr::put_u32(&mut out, a::GENERATION, wiphy.generation());
    end(&mut out);
    send(wiphy, GROUP_MLME, &out);
}

/// A frame failed its integrity check. This is a security event, not a
/// statistic: two within a minute require the link to be torn down, and only
/// userspace can decide that. # C: O(N listeners)
pub fn michael_mic_failure(wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, addr: MacAddr,
                           key_type: u32, key_id: Option<u8>, tsc: Option<&[u8]>) {
    let mut out = start(cmd::MICHAEL_MIC_FAILURE);
    put_ids(&mut out, wiphy, Some(wdev));
    super::msg::put_mac(&mut out, a::MAC, addr);
    attr::put_u32(&mut out, a::KEY_TYPE, key_type);
    if let Some(id) = key_id { super::msg::put_u8(&mut out, a::KEY_IDX, id); }
    if let Some(seq) = tsc { attr::put(&mut out, a::KEY_SEQ, seq); }
    end(&mut out);
    send(wiphy, GROUP_MLME, &out);
}

/// A connection-quality threshold was crossed. # C: O(N listeners)
pub fn cqm_notify(wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, event_attr: u16, value: u32) {
    let mut out = start(cmd::NOTIFY_CQM);
    put_ids(&mut out, wiphy, Some(wdev));
    let nest = attr::nest_start(&mut out, a::CQM);
    attr::put_u32(&mut out, event_attr, value);
    attr::nest_end(&mut out, nest);
    end(&mut out);
    send(wiphy, GROUP_MLME, &out);
}

/// The regulatory domain changed. # C: O(N listeners)
pub fn reg_change(wiphy: &Arc<Wiphy>, initiator: u32) {
    let regdom = wiphy.regdom();
    let mut out = start(cmd::REG_CHANGE);
    attr::put_u32(&mut out, a::WIPHY, wiphy.index);
    attr::put_u32(&mut out, a::REG_INITIATOR, initiator);
    attr::put_u32(&mut out, a::REG_TYPE, regdom.reg_type());
    attr::put(&mut out, a::REG_ALPHA2, &regdom.alpha2);
    if regdom.dfs_region != crate::uapi::enums::dfs_region::UNSET {
        super::msg::put_u8(&mut out, a::DFS_REGION, regdom.dfs_region);
    }
    end(&mut out);
    send(wiphy, GROUP_REGULATORY, &out);
}

/// A radio's channel changed. # C: O(N listeners)
pub fn ch_switch_notify(wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, def: &crate::chan::ChanDef) {
    let mut out = start(cmd::CH_SWITCH_NOTIFY);
    put_ids(&mut out, wiphy, Some(wdev));
    attr::put_u32(&mut out, a::WIPHY_FREQ, def.chan.center_freq);
    attr::put_u32(&mut out, a::CHANNEL_WIDTH, def.width.as_u32());
    attr::put_u32(&mut out, a::CENTER_FREQ1, def.center_freq1);
    if def.center_freq2 != 0 { attr::put_u32(&mut out, a::CENTER_FREQ2, def.center_freq2); }
    end(&mut out);
    send(wiphy, GROUP_MLME, &out);
}

/// Whether a built message is addressed to a request. Events are not, which
/// is what tells a reader an unsolicited message from a reply. # C: O(1)
pub fn is_unsolicited(msg: &[u8]) -> bool {
    Nlmsghdr::parse(msg).is_some_and(|h| h.nlmsg_seq == 0 && h.nlmsg_pid == 0)
}
