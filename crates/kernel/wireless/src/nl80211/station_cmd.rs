// Station query and modification, and the per-channel occupancy survey.
//
// Module manifest:
// - `emit`: the station report and the survey report.

extern crate alloc;

use alloc::vec::Vec;

use netlink::genetlink::family::GenlCtx;
use netlink::Nlmsghdr;
use syscall::errno::Errno;

use crate::ieee80211::status::reason;
use crate::ieee80211::MacAddr;
use crate::sta::{StaFlags, StationParams};
use crate::uapi::attr as a;
use crate::uapi::cmd;
use crate::uapi::enums::IfType;
use crate::uapi::nested::sta_flag;

use super::{event, msg, resolve};

#[path = "station_cmd/emit.rs"]
pub mod emit;

/// Subtype of a disassociate and of a deauthenticate, as the removal request
/// names them: the subtype field shifted down four.
const STYPE_DISASSOC: u8 = (crate::ieee80211::fctl::mgmt_stype::DISASSOC >> 4) as u8;
const STYPE_DEAUTH: u8 = (crate::ieee80211::fctl::mgmt_stype::DEAUTH >> 4) as u8;

/// Interface types that hold stations of their own. # C: O(1)
fn holds_stations(iftype: IfType) -> bool {
    matches!(iftype, IfType::Ap | IfType::ApVlan | IfType::P2pGo | IfType::MeshPoint
        | IfType::Adhoc | IfType::Station | IfType::P2pClient)
}

/// One station's report. # C: O(N fields)
pub fn get(hdr: &Nlmsghdr, attrs: &[u8], ctx: GenlCtx) -> Vec<u8> {
    let (wiphy, wdev) = match resolve::wdev(attrs, ctx.net_ns) {
        Ok(v) => v,
        Err(e) => return msg::error(hdr, e),
    };
    let Some(peer) = msg::get_mac(attrs, a::MAC) else {
        return msg::error(hdr, Errno::Einval);
    };
    let info = match wiphy.ops.get_station(&wiphy, &wdev, peer) {
        Ok(i) => i,
        Err(e) => return msg::error(hdr, e),
    };
    let mut out = msg::start(hdr, cmd::NEW_STATION);
    emit::put(&mut out, &wiphy, &wdev, &info);
    msg::end(&mut out);
    out
}

/// Every station on an interface, one message each.
///
/// The walk ends when the driver reports there is no station at the next
/// index. A driver with no station reporting at all is a different answer
/// from a driver with no stations, so the first index decides which.
/// # C: O(N stations)
pub fn dump(hdr: &Nlmsghdr, attrs: &[u8], ctx: GenlCtx) -> Vec<u8> {
    let (wiphy, wdev) = match resolve::wdev(attrs, ctx.net_ns) {
        Ok(v) => v,
        Err(e) => return msg::error(hdr, e),
    };
    let mut reply: Vec<u8> = Vec::new();
    let mut idx = 0usize;
    loop {
        match wiphy.ops.dump_station(&wiphy, &wdev, idx) {
            Ok(info) => {
                let mut one = msg::start(hdr, cmd::NEW_STATION);
                emit::put(&mut one, &wiphy, &wdev, &info);
                msg::end(&mut one);
                msg::push(&mut reply, one);
                idx += 1;
            }
            Err(Errno::Enoent) => break,
            Err(e) => { if idx == 0 { return msg::error(hdr, e); } break; }
        }
    }
    msg::push_done(&mut reply, hdr);
    reply
}

/// Add a station. # C: O(N attrs)
pub fn new(hdr: &Nlmsghdr, attrs: &[u8], ctx: GenlCtx) -> Vec<u8> {
    modify(hdr, attrs, ctx, true)
}

/// Change a station. # C: O(N attrs)
pub fn set(hdr: &Nlmsghdr, attrs: &[u8], ctx: GenlCtx) -> Vec<u8> {
    modify(hdr, attrs, ctx, false)
}

/// The two modification commands, which differ only in the driver call and
/// in whether a notification goes out. # C: O(N attrs)
fn modify(hdr: &Nlmsghdr, attrs: &[u8], ctx: GenlCtx, add: bool) -> Vec<u8> {
    let (wiphy, wdev) = match resolve::wdev(attrs, ctx.net_ns) {
        Ok(v) => v,
        Err(e) => return msg::error(hdr, e),
    };
    let Some(peer) = msg::get_mac(attrs, a::MAC) else {
        return msg::error(hdr, Errno::Einval);
    };
    if !holds_stations(wdev.iftype()) { return msg::error(hdr, Errno::Einval); }
    let params = match parse_params(attrs) {
        Ok(p) => p,
        Err(e) => return msg::error(hdr, e),
    };
    let result = if add { wiphy.ops.add_station(&wiphy, &wdev, peer, &params) }
                 else { wiphy.ops.change_station(&wiphy, &wdev, peer, &params) };
    match result {
        Ok(()) => {
            if add {
                let ie = msg::get_bytes(attrs, a::IE).unwrap_or(&[]);
                event::new_station(&wiphy, &wdev, peer, ie);
            }
            msg::ack(hdr)
        }
        Err(e) => msg::error(hdr, e),
    }
}

/// The fields a station modification carries. # C: O(N attrs)
fn parse_params(attrs: &[u8]) -> Result<StationParams, Errno> {
    let mut params = StationParams {
        aid: msg::get_u16(attrs, a::STA_AID),
        listen_interval: msg::get_u16(attrs, a::STA_LISTEN_INTERVAL),
        supported_rates: msg::get_bytes(attrs, a::STA_SUPPORTED_RATES).map(<[u8]>::to_vec),
        ht_capa: msg::get_bytes(attrs, a::HT_CAPABILITY).map(<[u8]>::to_vec),
        vht_capa: msg::get_bytes(attrs, a::VHT_CAPABILITY).map(<[u8]>::to_vec),
        sta_flags: parse_flags(attrs)?,
        plink_action: msg::get_u8(attrs, a::STA_PLINK_ACTION),
        plink_state: msg::get_u8(attrs, a::STA_PLINK_STATE),
        vlan_id: msg::get_u16(attrs, a::VLAN_ID),
        airtime_weight: msg::get_u16(attrs, a::AIRTIME_WEIGHT),
        capability: msg::get_u16(attrs, a::STA_CAPABILITY),
        ext_capa: msg::get_bytes(attrs, a::STA_EXT_CAPABILITY).map(<[u8]>::to_vec),
        opmode_notif: msg::get_u8(attrs, a::OPMODE_NOTIF),
        use_4addr: None,
    };
    if let Some(state) = params.plink_state {
        if state > crate::sta::plink_state::MAX { return Err(Errno::Einval); }
    }
    if let Some(v) = msg::get_u8(attrs, a::_4ADDR) { params.use_4addr = Some(v != 0); }
    Ok(params)
}

/// The station flags a request sets, as the mask-and-value pair the wire
/// carries. The pair is what makes "not mentioned" different from "off".
/// # C: O(N attrs)
fn parse_flags(attrs: &[u8]) -> Result<Option<StaFlags>, Errno> {
    let Some(nest) = msg::get_bytes(attrs, a::STA_FLAGS2) else { return Ok(None); };
    // The two-word form is a mask followed by the values it selects.
    let mask = nest.get(..4).ok_or(Errno::Einval)?;
    let set = nest.get(4..8).ok_or(Errno::Einval)?;
    let flags = StaFlags {
        mask: u32::from_ne_bytes([mask[0], mask[1], mask[2], mask[3]]),
        set: u32::from_ne_bytes([set[0], set[1], set[2], set[3]]),
    };
    let known = ((1u32 << (sta_flag::MAX + 1)) - 1) & !1;
    if flags.mask & !known != 0 { return Err(Errno::Einval); }
    Ok(Some(flags))
}

/// Remove a station. # C: O(N attrs)
pub fn del(hdr: &Nlmsghdr, attrs: &[u8], ctx: GenlCtx) -> Vec<u8> {
    match del_inner(attrs, ctx) {
        Ok(()) => msg::ack(hdr),
        Err(e) => msg::error(hdr, e),
    }
}

/// The decision `del` makes. A removal with no address removes every station,
/// which is how an access point tears its network down. # C: O(N attrs)
fn del_inner(attrs: &[u8], ctx: GenlCtx) -> Result<(), Errno> {
    let (wiphy, wdev) = resolve::wdev(attrs, ctx.net_ns)?;
    let peer: Option<MacAddr> = msg::get_mac(attrs, a::MAC);
    let iftype = wdev.iftype();
    if !matches!(iftype, IfType::Ap | IfType::ApVlan | IfType::P2pGo | IfType::MeshPoint) {
        return Err(Errno::Einval);
    }
    if let Some(subtype) = msg::get_u8(attrs, a::MGMT_SUBTYPE) {
        if subtype != STYPE_DISASSOC && subtype != STYPE_DEAUTH {
            return Err(Errno::Einval);
        }
    }
    let code = match msg::get_u16(attrs, a::REASON_CODE) {
        None => reason::PREV_AUTH_NOT_VALID,
        Some(0) => return Err(Errno::Einval),
        Some(v) => v,
    };
    wiphy.ops.del_station(&wiphy, &wdev, peer, code)?;
    if let Some(p) = peer { event::del_station(&wiphy, &wdev, p); }
    Ok(())
}

/// Every channel's occupancy, one message each. # C: O(N channels)
pub fn dump_survey(hdr: &Nlmsghdr, attrs: &[u8], ctx: GenlCtx) -> Vec<u8> {
    let (wiphy, wdev) = match resolve::wdev(attrs, ctx.net_ns) {
        Ok(v) => v,
        Err(e) => return msg::error(hdr, e),
    };
    let mut reply: Vec<u8> = Vec::new();
    let mut idx = 0usize;
    loop {
        match wiphy.ops.dump_survey(&wiphy, &wdev, idx) {
            Ok(s) => {
                let mut one = msg::start(hdr, cmd::NEW_SURVEY_RESULTS);
                emit::put_survey(&mut one, &wdev, &s);
                msg::end(&mut one);
                msg::push(&mut reply, one);
                idx += 1;
            }
            Err(Errno::Enoent) => break,
            Err(e) => { if idx == 0 { return msg::error(hdr, e); } break; }
        }
    }
    msg::push_done(&mut reply, hdr);
    reply
}
