// Registration of interest in received management frames, and transmission
// of management frames userspace builds itself.
//
// This is how a supplicant that runs its own state machine gets and sends
// action frames. A registration that matched too widely would hand one
// socket the frames another asked for, so the match is exact on the subtype
// and a prefix of the body.

extern crate alloc;

use alloc::vec::Vec;

use netlink::genetlink::family::GenlCtx;
use netlink::Nlmsghdr;
use syscall::errno::Errno;

use crate::ieee80211::{fctl, MacHeader};
use crate::ops::MgmtTxRequest;
use crate::uapi::attr as a;
use crate::uapi::cmd;
use crate::uapi::enums::IfType;
use crate::wdev::MgmtRegistration;

use super::{chandef, msg, resolve};

/// Shortest management frame that carries anything at all: a header and one
/// byte of body.
const MIN_MGMT_FRAME_LEN: usize = crate::ieee80211::hdr::HDR_LEN_3ADDR + 1;
/// Shortest match a station may register for an authentication frame: the
/// algorithm number, so a registration cannot claim every authentication.
const AUTH_MATCH_MIN: usize = 2;
/// Shortest a caller may wait on a channel, in milliseconds.
const MIN_REMAIN_ON_CHANNEL_MS: u32 = 10;

/// Interface types that may register for and send management frames.
/// # C: O(1)
fn mgmt_capable(iftype: IfType) -> bool {
    matches!(iftype, IfType::Station | IfType::Adhoc | IfType::P2pClient | IfType::Ap
        | IfType::ApVlan | IfType::MeshPoint | IfType::P2pGo | IfType::P2pDevice)
}

/// Ask for received frames of one subtype. # C: O(N regs)
pub fn register_frame(hdr: &Nlmsghdr, attrs: &[u8], ctx: GenlCtx) -> Vec<u8> {
    match register_inner(attrs, ctx) {
        Ok(()) => msg::ack(hdr),
        Err(e) => msg::error(hdr, e),
    }
}

/// The decision `register_frame` makes. # C: O(N regs)
fn register_inner(attrs: &[u8], ctx: GenlCtx) -> Result<(), Errno> {
    let (wiphy, wdev) = resolve::wdev(attrs, ctx.net_ns)?;
    let match_prefix = msg::get_bytes(attrs, a::FRAME_MATCH).ok_or(Errno::Einval)?;
    let frame_type = msg::get_u16(attrs, a::FRAME_TYPE)
        .unwrap_or(fctl::FTYPE_MGMT | fctl::mgmt_stype::ACTION);
    let iftype = wdev.iftype();
    if !mgmt_capable(iftype) { return Err(Errno::Eopnotsupp); }
    if wiphy.caps.mgmt_stypes.is_empty() { return Err(Errno::Eopnotsupp); }
    // Only a management frame may be registered for, and the number must be
    // a type and a subtype and nothing else.
    if fctl::ftype(frame_type) != fctl::FTYPE_MGMT { return Err(Errno::Einval); }
    if frame_type & !(fctl::FCTL_FTYPE | fctl::FCTL_STYPE) != 0 { return Err(Errno::Einval); }
    let stype_bit = (fctl::stype(frame_type) >> 4) as u32;
    let rx = wiphy.caps.mgmt_stypes.iter()
        .find(|e| e.iftype == iftype.as_u32()).map_or(0, |e| e.rx);
    if rx & (1u16 << stype_bit) == 0 { return Err(Errno::Einval); }
    // A station registering for every authentication frame would swallow the
    // ones the stack's own exchange needs, so it must name an algorithm.
    if iftype == IfType::Station && fctl::stype(frame_type) == fctl::mgmt_stype::AUTH
        && match_prefix.len() < AUTH_MATCH_MIN {
        return Err(Errno::Einval);
    }
    // A match already configured for this subtype belongs to whoever
    // configured it; handing it to a second socket would split the frames
    // between two readers that each believe they see all of them.
    let clash = wdev.with(|w| w.mgmt_regs.iter().any(|r| {
        let n = r.match_prefix.len().min(match_prefix.len());
        r.frame_type == frame_type && r.match_prefix[..n] == match_prefix[..n]
    }));
    if clash { return Err(Errno::Ealready); }
    wdev.register_mgmt(MgmtRegistration {
        portid: ctx.portid, frame_type,
        match_prefix: match_prefix.to_vec(),
        multicast_rx: msg::get_flag(attrs, a::RECEIVE_MULTICAST),
    });
    Ok(())
}

/// Transmit a management frame. # C: O(len)
pub fn tx(hdr: &Nlmsghdr, attrs: &[u8], ctx: GenlCtx) -> Vec<u8> {
    match tx_inner(attrs, ctx) {
        Ok((cookie, wants_reply)) => {
            if !wants_reply { return msg::ack(hdr); }
            let mut out = msg::start(hdr, cmd::FRAME);
            msg::put_u64(&mut out, a::COOKIE, cookie);
            msg::end(&mut out);
            out
        }
        Err(e) => msg::error(hdr, e),
    }
}

/// The decision `tx` makes, and whether the caller waits for a cookie.
///
/// The transmitter address is checked against the interface's own: a frame
/// sent from an address the interface does not hold would be attributed to
/// whatever station really has it. # C: O(len)
fn tx_inner(attrs: &[u8], ctx: GenlCtx) -> Result<(u64, bool), Errno> {
    let (wiphy, wdev) = resolve::wdev(attrs, ctx.net_ns)?;
    let frame = msg::get_bytes(attrs, a::FRAME).ok_or(Errno::Einval)?;
    let iftype = wdev.iftype();
    if wiphy.caps.mgmt_stypes.is_empty() { return Err(Errno::Eopnotsupp); }
    if !mgmt_capable(iftype) { return Err(Errno::Eopnotsupp); }
    // A frame with no network device to send from needs a channel named.
    if iftype == IfType::P2pDevice && msg::get_u32(attrs, a::WIPHY_FREQ).is_none() {
        return Err(Errno::Einval);
    }
    let offchan = msg::get_flag(attrs, a::OFFCHANNEL_TX_OK);
    let wait_ms = match msg::get_u32(attrs, a::DURATION) {
        None => 0,
        Some(v) => {
            if !(MIN_REMAIN_ON_CHANNEL_MS..=wiphy.caps.max_remain_on_channel_duration)
                .contains(&v) { return Err(Errno::Einval); }
            v
        }
    };
    let def = match msg::get_u32(attrs, a::WIPHY_FREQ) {
        None => None,
        Some(_) => Some(chandef::parse(&wiphy, attrs)?),
    };
    // Leaving the operating channel needs somewhere to go.
    if def.is_none() && offchan { return Err(Errno::Einval); }

    if frame.len() < MIN_MGMT_FRAME_LEN { return Err(Errno::Einval); }
    let parsed = MacHeader::parse(frame).ok_or(Errno::Einval)?;
    let fc = parsed.frame_control;
    if !fctl::is_mgmt(fc) || fc & fctl::FCTL_ORDER != 0 { return Err(Errno::Einval); }
    let stype_bit = (fctl::stype(fc) >> 4) as u32;
    let tx_mask = wiphy.caps.mgmt_stypes.iter()
        .find(|e| e.iftype == iftype.as_u32()).map_or(0, |e| e.tx);
    if tx_mask & (1u16 << stype_bit) == 0 { return Err(Errno::Einval); }
    let source = parsed.source().ok_or(Errno::Einval)?;
    if source != wdev.addr() { return Err(Errno::Einval); }

    let req = MgmtTxRequest {
        chandef: def, offchan, wait_ms, frame: frame.to_vec(),
        no_cck: msg::get_flag(attrs, a::TX_NO_CCK_RATE),
        dont_wait_for_ack: msg::get_flag(attrs, a::DONT_WAIT_FOR_ACK),
    };
    let cookie = wiphy.ops.mgmt_tx(&wiphy, &wdev, &req)?;
    Ok((cookie, !req.dont_wait_for_ack))
}

/// Stop waiting on a channel for a transmission's answer. # C: O(1)
pub fn tx_cancel_wait(hdr: &Nlmsghdr, attrs: &[u8], ctx: GenlCtx) -> Vec<u8> {
    let cookie = msg::get_u64(attrs, a::COOKIE);
    let (_wiphy, wdev) = match resolve::wdev(attrs, ctx.net_ns) {
        Ok(v) => v,
        Err(e) => return msg::error(hdr, e),
    };
    if cookie.is_none() { return msg::error(hdr, Errno::Einval); }
    if !mgmt_capable(wdev.iftype()) { return msg::error(hdr, Errno::Eopnotsupp); }
    // No driver here holds a channel open past a transmission, so there is
    // no wait to cancel and nothing to tell the driver.
    msg::ack(hdr)
}

/// Drop every registration a netlink port made, for a socket that closed.
/// # C: O(N interfaces × N regs)
pub fn release_port(portid: u32, net_ns: u64) {
    crate::wiphy::registry::for_each(net_ns, |w| {
        for wdev in w.wdevs() { wdev.release_mgmt_port(portid); }
    });
}

/// The registrations one interface holds, for a caller checking coverage.
/// # C: O(N regs)
pub fn registrations(wdev: &alloc::sync::Arc<crate::wdev::Wdev>) -> Vec<MgmtRegistration> {
    wdev.with(|w| w.mgmt_regs.clone())
}

