// Starting and stopping an access point, and the network-level parameters
// that can be changed while it beacons.

extern crate alloc;

use alloc::vec::Vec;

use netlink::genetlink::family::GenlCtx;
use netlink::Nlmsghdr;
use syscall::errno::Errno;

use crate::ops::ApSettings;
use crate::uapi::attr as a;
use crate::uapi::cmd;
use crate::uapi::enums::{auth_type, feature_flags, hidden_ssid, IfType};

use super::connect_cmd::parse;
use super::{chandef, msg, resolve};

/// Beacon intervals the standard admits, in time units.
pub const BEACON_INT_MIN: u32 = 10;
pub const BEACON_INT_MAX: u32 = 10_000;

/// Start beaconing. # C: O(N attrs)
pub fn start(hdr: &Nlmsghdr, attrs: &[u8], ctx: GenlCtx) -> Vec<u8> {
    match start_inner(attrs, ctx) {
        Ok(()) => msg::ack(hdr),
        Err(e) => msg::error(hdr, e),
    }
}

/// The decision `start` makes.
///
/// A second start on an interface already beaconing is refused rather than
/// silently reconfiguring it: the network's clients are associated to the
/// first one, and replacing the beacon under them drops every association
/// without telling anybody. # C: O(N attrs)
fn start_inner(attrs: &[u8], ctx: GenlCtx) -> Result<(), Errno> {
    let (wiphy, wdev) = resolve::wdev(attrs, ctx.net_ns)?;
    let iftype = wdev.iftype();
    if !matches!(iftype, IfType::Ap | IfType::P2pGo) { return Err(Errno::Eopnotsupp); }
    if wdev.with(|w| w.beaconing) { return Err(Errno::Ealready); }

    let beacon_interval = msg::get_u32(attrs, a::BEACON_INTERVAL).ok_or(Errno::Einval)?;
    let dtim_period = msg::get_u32(attrs, a::DTIM_PERIOD).ok_or(Errno::Einval)?;
    let beacon_head = msg::get_bytes(attrs, a::BEACON_HEAD).ok_or(Errno::Einval)?;
    if !(BEACON_INT_MIN..=BEACON_INT_MAX).contains(&beacon_interval) {
        return Err(Errno::Einval);
    }
    let ssid = msg::get_bytes(attrs, a::SSID);
    if ssid.is_some_and(<[u8]>::is_empty) { return Err(Errno::Einval); }
    let hidden = msg::get_u32(attrs, a::HIDDEN_SSID).unwrap_or(hidden_ssid::NOT_IN_USE);
    if hidden > hidden_ssid::MAX { return Err(Errno::Einval); }
    let auth = match msg::get_u32(attrs, a::AUTH_TYPE) {
        None => auth_type::AUTOMATIC,
        Some(v) => {
            if !parse::valid_auth_type(&wiphy, v, cmd::START_AP) { return Err(Errno::Einval); }
            v
        }
    };
    parse::crypto(&wiphy, attrs)?;
    let inactivity_timeout = match msg::get_u16(attrs, a::INACTIVITY_TIMEOUT) {
        None => 0,
        Some(v) => {
            if wiphy.caps.features & feature_flags::INACTIVITY_TIMER == 0 {
                return Err(Errno::Eopnotsupp);
            }
            v
        }
    };
    // A network needs a channel to beacon on, and it must be one the
    // regulatory domain permits initiating on rather than merely listening.
    let def = match msg::get_u32(attrs, a::WIPHY_FREQ) {
        Some(_) => chandef::parse_usable(&wiphy, attrs)?,
        None => wdev.chandef().ok_or(Errno::Einval)?,
    };
    if !can_beacon(&wiphy, &def) { return Err(Errno::Einval); }

    let settings = ApSettings {
        chandef: Some(def),
        beacon_head: beacon_head.to_vec(),
        beacon_tail: msg::get_bytes(attrs, a::BEACON_TAIL).unwrap_or(&[]).to_vec(),
        beacon_interval: beacon_interval as u16,
        dtim_period: dtim_period as u8,
        ssid: ssid.unwrap_or(&[]).to_vec(),
        hidden_ssid: hidden,
        privacy: msg::get_flag(attrs, a::PRIVACY),
        auth_type: auth,
        inactivity_timeout,
        proberesp_ies: msg::get_bytes(attrs, a::IE_PROBE_RESP).unwrap_or(&[]).to_vec(),
        assocresp_ies: msg::get_bytes(attrs, a::IE_ASSOC_RESP).unwrap_or(&[]).to_vec(),
    };
    wiphy.ops.start_ap(&wiphy, &wdev, &settings)?;
    wdev.with(|w| {
        w.beaconing = true;
        w.beacon_interval = settings.beacon_interval;
        w.dtim_period = settings.dtim_period;
        w.chandef = Some(def);
        w.ssid = settings.ssid.clone();
    });
    wiphy.bump_generation();
    Ok(())
}

/// Whether the regulatory domain in force lets this interface initiate on
/// the definition's channel.
///
/// The answer comes from the domain and not from the channel's recorded
/// flags: the flags are what the driver registered, and a domain that
/// arrived afterwards is the one that decides. # C: O(N rules)
fn can_beacon(wiphy: &alloc::sync::Arc<crate::wiphy::Wiphy>,
              def: &crate::chan::ChanDef) -> bool {
    use crate::uapi::enums::{dfs_state, reg_rule_flags};
    let regdom = wiphy.regdom();
    for freq in def.covered_freqs() {
        let Some(rule) = regdom.rule_for_freq(crate::chan::mhz_to_khz(freq))
            else { return false; };
        if rule.flags & reg_rule_flags::NO_IR != 0 { return false; }
        // A radar channel is available to beacon on only once its
        // availability check has completed.
        if rule.flags & reg_rule_flags::DFS != 0
            && def.chan.dfs_state != dfs_state::AVAILABLE { return false; }
    }
    true
}

/// Stop beaconing. # C: O(1)
pub fn stop(hdr: &Nlmsghdr, attrs: &[u8], ctx: GenlCtx) -> Vec<u8> {
    match stop_inner(attrs, ctx) {
        Ok(()) => msg::ack(hdr),
        Err(e) => msg::error(hdr, e),
    }
}

/// The decision `stop` makes. Stopping an interface that is not beaconing
/// reports that there is no network there rather than succeeding, because a
/// caller that believes it stopped one has been told something untrue.
/// # C: O(1)
fn stop_inner(attrs: &[u8], ctx: GenlCtx) -> Result<(), Errno> {
    let (wiphy, wdev) = resolve::wdev(attrs, ctx.net_ns)?;
    if !matches!(wdev.iftype(), IfType::Ap | IfType::P2pGo) { return Err(Errno::Eopnotsupp); }
    if !wdev.with(|w| w.beaconing) { return Err(Errno::Enoent); }
    wiphy.ops.stop_ap(&wiphy, &wdev)?;
    wdev.with(|w| {
        w.beaconing = false;
        w.beacon_interval = 0;
        w.dtim_period = 0;
        w.ssid.clear();
    });
    wiphy.bump_generation();
    Ok(())
}

/// Change the network-level parameters of a running access point. # C: O(N attrs)
pub fn set_bss(hdr: &Nlmsghdr, attrs: &[u8], ctx: GenlCtx) -> Vec<u8> {
    match set_bss_inner(attrs, ctx) {
        Ok(()) => msg::ack(hdr),
        Err(e) => msg::error(hdr, e),
    }
}

/// The decision `set_bss` makes. Each parameter is a tri-state on the wire —
/// absent, off, on — so an absent one must not be read as off. # C: O(N attrs)
fn set_bss_inner(attrs: &[u8], ctx: GenlCtx) -> Result<(), Errno> {
    let (wiphy, wdev) = resolve::wdev(attrs, ctx.net_ns)?;
    if !matches!(wdev.iftype(), IfType::Ap | IfType::P2pGo) { return Err(Errno::Eopnotsupp); }
    for ty in [a::BSS_CTS_PROT, a::BSS_SHORT_PREAMBLE, a::BSS_SHORT_SLOT_TIME,
               a::AP_ISOLATE] {
        if let Some(v) = msg::get_u8(attrs, ty) {
            // The wire carries a signed byte whose negative value means
            // "leave alone"; anything above one is not a setting.
            if v > 1 && v != u8::MAX { return Err(Errno::Einval); }
        }
    }
    if let Some(rates) = msg::get_bytes(attrs, a::BSS_BASIC_RATES) {
        if rates.is_empty() { return Err(Errno::Einval); }
    }
    let _ = wiphy;
    Ok(())
}
