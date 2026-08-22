// Radio query and configuration.
//
// Module manifest:
// - `body`:  the attributes a radio's advertisement carries.
// - `bands`: the per-band channel and rate lists inside it.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use netlink::genetlink::attr;
use netlink::genetlink::family::GenlCtx;
use netlink::Nlmsghdr;
use syscall::errno::Errno;

use crate::uapi::attr as a;
use crate::uapi::{cmd, enums};
use crate::wiphy::config::{self, ConfigRequest};
use crate::wiphy::{registry, Wiphy};

use super::{chandef, event, msg, policy, resolve};

#[path = "wiphy_cmd/body.rs"]
pub mod body;
#[path = "wiphy_cmd/bands.rs"]
pub mod bands;

/// One radio's whole description. # C: O(N channels)
pub fn get(hdr: &Nlmsghdr, attrs: &[u8], ctx: GenlCtx) -> Vec<u8> {
    let target = match resolve::wiphy(attrs, ctx.net_ns) {
        Ok(t) => t,
        Err(e) => return msg::error(hdr, e),
    };
    let mut out = msg::start(hdr, cmd::NEW_WIPHY);
    body::put_identity(&mut out, &target.wiphy);
    body::put(&mut out, &target.wiphy);
    msg::end(&mut out);
    out
}

/// Every radio in the caller's namespace. # C: O(N radios × N channels)
pub fn dump(hdr: &Nlmsghdr, attrs: &[u8], ctx: GenlCtx) -> Vec<u8> {
    let mut reply: Vec<u8> = Vec::new();
    registry::for_each(ctx.net_ns, |w| {
        if !resolve::dump_selects(attrs, w) { return; }
        let mut one = msg::start(hdr, cmd::NEW_WIPHY);
        body::put_identity(&mut one, w);
        body::put(&mut one, w);
        msg::end(&mut one);
        msg::push(&mut reply, one);
    });
    msg::push_done(&mut reply, hdr);
    reply
}

/// Change a radio's configuration. The request is validated as a set before
/// any of it is applied: a request that asks for four changes and fails on
/// the fourth must leave the radio as it found it. # C: O(1)
pub fn set(hdr: &Nlmsghdr, attrs: &[u8], ctx: GenlCtx) -> Vec<u8> {
    match set_inner(attrs, ctx) {
        Ok(()) => msg::ack(hdr),
        Err(e) => msg::error(hdr, e),
    }
}

/// The decision `set` makes, with no message framing around it. # C: O(1)
fn set_inner(attrs: &[u8], ctx: GenlCtx) -> Result<(), Errno> {
    let target = resolve::wiphy(attrs, ctx.net_ns)?;
    let wiphy = target.wiphy;
    rename(&wiphy, attrs)?;
    // A frequency attribute on a radio command is the old way of setting an
    // interface's channel, and hostapd still sends it that way.
    if msg::get_u32(attrs, a::WIPHY_FREQ).is_some() {
        let def = chandef::parse_usable(&wiphy, attrs)?;
        wiphy.ops.set_monitor_channel(&wiphy, &def)?;
        if let Some(wdev) = &target.wdev { wdev.with(|w| w.chandef = Some(def)); }
    }
    let req = parse_config(attrs)?;
    if req.is_empty() { return Ok(()); }
    req.validate(wiphy.caps.available_antennas_tx, wiphy.caps.available_antennas_rx)?;
    wiphy.with_state(|s| req.apply(&mut s.config));
    wiphy.ops.set_wiphy_params(&wiphy)?;
    wiphy.bump_generation();
    Ok(())
}

/// Apply a rename. A name another radio already holds is refused rather than
/// producing two radios userspace cannot tell apart. # C: O(N radios)
fn rename(wiphy: &Arc<Wiphy>, attrs: &[u8]) -> Result<(), Errno> {
    let Some(name) = msg::get_str(attrs, a::WIPHY_NAME) else { return Ok(()); };
    if name.is_empty() || name.len() > policy::WIPHY_NAME_MAX_LEN {
        return Err(Errno::Einval);
    }
    if wiphy.is_named(name) { return Ok(()); }
    if canonical_phy_index(name).is_some_and(|idx| idx != wiphy.index) {
        return Err(Errno::Einval);
    }
    if registry::lookup_by_name(name).is_some() { return Err(Errno::Einval); }
    wiphy.set_name(name);
    event::new_wiphy(wiphy);
    Ok(())
}

/// Parse the reserved canonical `phy<N>` spelling. A leading-zero spelling is
/// an ordinary custom name, not a claim on another radio's generated name.
fn canonical_phy_index(name: &str) -> Option<u32> {
    let n = name.strip_prefix("phy")?;
    if n.is_empty() || (n.len() > 1 && n.starts_with('0')) { return None; }
    n.parse().ok()
}

/// Read the configuration fields a request asks to change. # C: O(N attrs)
fn parse_config(attrs: &[u8]) -> Result<ConfigRequest, Errno> {
    let mut req = ConfigRequest {
        retry_short: msg::get_u8(attrs, a::WIPHY_RETRY_SHORT),
        retry_long: msg::get_u8(attrs, a::WIPHY_RETRY_LONG),
        frag_threshold: msg::get_u32(attrs, a::WIPHY_FRAG_THRESHOLD),
        rts_threshold: msg::get_u32(attrs, a::WIPHY_RTS_THRESHOLD),
        coverage_class: msg::get_u8(attrs, a::WIPHY_COVERAGE_CLASS).map(u32::from),
        tx_power: None,
        antenna: None,
        txq_limit: msg::get_u32(attrs, a::TXQ_LIMIT),
        txq_memory_limit: msg::get_u32(attrs, a::TXQ_MEMORY_LIMIT),
        txq_quantum: msg::get_u32(attrs, a::TXQ_QUANTUM),
    };
    if let Some(setting) = msg::get_u32(attrs, a::WIPHY_TX_POWER_SETTING) {
        let level = msg::get_u32(attrs, a::WIPHY_TX_POWER_LEVEL);
        // Every setting but the automatic one needs the level it applies to.
        if setting != config::tx_power_setting::AUTOMATIC && level.is_none() {
            return Err(Errno::Einval);
        }
        req.tx_power = Some((setting, level.unwrap_or(0) as i32));
    }
    // The two antenna masks are one request: setting only one half would
    // leave the other reading a mask the caller never asked for.
    match (msg::get_u32(attrs, a::WIPHY_ANTENNA_TX), msg::get_u32(attrs, a::WIPHY_ANTENNA_RX)) {
        (Some(tx), Some(rx)) => req.antenna = Some((tx, rx)),
        (None, None) => {}
        _ => return Err(Errno::Einval),
    }
    Ok(req)
}

/// Which protocol extensions this build serves. The split dump is the one
/// that matters: without it a radio's advertisement has to fit one message.
/// # C: O(1)
pub fn get_protocol_features(hdr: &Nlmsghdr, _attrs: &[u8], _ctx: GenlCtx) -> Vec<u8> {
    let mut out = msg::start(hdr, cmd::GET_PROTOCOL_FEATURES);
    attr::put_u32(&mut out, a::PROTOCOL_FEATURES,
                  enums::protocol_features::SPLIT_WIPHY_DUMP);
    msg::end(&mut out);
    out
}
