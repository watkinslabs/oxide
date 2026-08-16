// Regulatory query and the two ways userspace changes the domain in force:
// a whole rule table, and a country-code hint.
//
// The two differ in more than shape. A rule table is applied there and then,
// so a table that asks for what is already in force is refused as already
// set; a country hint is a request the arbitration may outrank, and being
// outranked is not an error the caller can act on.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use netlink::genetlink::attr;
use netlink::genetlink::family::GenlCtx;
use netlink::Nlmsghdr;
use syscall::errno::Errno;

use crate::reg::domain::{self, ALPHA2_WORLD};
use crate::reg::hint::{self, RegRequest, Treatment};
use crate::reg::rule::{FreqRange, PowerRule, RegRule};
use crate::reg::RegDomain;
use crate::uapi::attr as a;
use crate::uapi::cmd;
use crate::uapi::enums::{dfs_region, reg_initiator};
use crate::uapi::nested::reg_rule_attr as rra;
use crate::wiphy::{registry, Wiphy};

use super::{event, msg, resolve};

/// Rules one request may carry. A table longer than this is a caller that
/// has lost track of what it is sending.
pub const MAX_SUPP_REG_RULES: usize = 128;

/// The domain in force, either globally or on one radio. # C: O(N rules)
pub fn get(hdr: &Nlmsghdr, attrs: &[u8], ctx: GenlCtx) -> Vec<u8> {
    let wiphy = match msg::get_u32(attrs, a::WIPHY) {
        None => None,
        Some(_) => match resolve::wiphy(attrs, ctx.net_ns) {
            Ok(t) => Some(t.wiphy),
            Err(e) => return msg::error(hdr, e),
        },
    };
    let mut out = msg::start(hdr, cmd::GET_REG);
    put_domain(&mut out, wiphy.as_ref());
    msg::end(&mut out);
    out
}

/// The domain of every radio in the namespace. # C: O(N radios × N rules)
pub fn dump(hdr: &Nlmsghdr, attrs: &[u8], ctx: GenlCtx) -> Vec<u8> {
    let mut reply: Vec<u8> = Vec::new();
    registry::for_each(ctx.net_ns, |w| {
        if !resolve::dump_selects(attrs, w) { return; }
        let mut one = msg::start(hdr, cmd::GET_REG);
        put_domain(&mut one, Some(w));
        msg::end(&mut one);
        msg::push(&mut reply, one);
    });
    msg::push_done(&mut reply, hdr);
    reply
}

/// Write a domain out. A radio's own domain is reported with the radio's
/// index so a reader can tell which of several it belongs to. # C: O(N rules)
fn put_domain(out: &mut Vec<u8>, wiphy: Option<&Arc<Wiphy>>) {
    let regdom = wiphy.map_or_else(RegDomain::world, |w| w.regdom());
    // The country code goes out NUL-terminated, which is what a reader that
    // treats it as a string expects to find.
    let mut alpha2 = [0u8; 3];
    alpha2[..2].copy_from_slice(&regdom.alpha2);
    attr::put(out, a::REG_ALPHA2, &alpha2);
    if regdom.dfs_region != dfs_region::UNSET {
        msg::put_u8(out, a::DFS_REGION, regdom.dfs_region);
    }
    attr::put_u32(out, a::REG_TYPE, regdom.reg_type());
    let rules = attr::nest_start(out, a::REG_RULES);
    for (i, r) in regdom.rules.iter().enumerate() {
        let one = attr::nest_start(out, i as u16);
        attr::put_u32(out, rra::FLAGS, r.flags);
        attr::put_u32(out, rra::FREQ_RANGE_START, r.freq_range.start_khz);
        attr::put_u32(out, rra::FREQ_RANGE_END, r.freq_range.end_khz);
        attr::put_u32(out, rra::FREQ_RANGE_MAX_BW, r.freq_range.max_bandwidth_khz);
        attr::put_u32(out, rra::POWER_RULE_MAX_ANT_GAIN,
                      r.power_rule.max_antenna_gain_mbi as u32);
        attr::put_u32(out, rra::POWER_RULE_MAX_EIRP, r.power_rule.max_eirp_mbm as u32);
        attr::put_u32(out, rra::DFS_CAC_TIME, r.dfs_cac_ms);
        attr::nest_end(out, one);
    }
    attr::nest_end(out, rules);
    if let Some(w) = wiphy {
        attr::put_u32(out, a::WIPHY, w.index);
        if w.caps.self_managed_reg { msg::put_flag(out, a::WIPHY_SELF_MANAGED_REG); }
    }
}

/// Install a whole rule table. # C: O(N radios × N channels × N rules)
pub fn set(hdr: &Nlmsghdr, attrs: &[u8], ctx: GenlCtx) -> Vec<u8> {
    match set_inner(attrs, ctx) {
        Ok(()) => msg::ack(hdr),
        Err(e) => msg::error(hdr, e),
    }
}

/// The decision `set` makes.
///
/// A table asking for the code already in force is `EALREADY`: the caller
/// asked for a change and none happened, and a supplicant that read success
/// would wait for a change notification that never comes. # C: O(N rules)
fn set_inner(attrs: &[u8], ctx: GenlCtx) -> Result<(), Errno> {
    let raw = msg::get_bytes(attrs, a::REG_ALPHA2).ok_or(Errno::Einval)?;
    let alpha2 = domain::parse_alpha2(raw).ok_or(Errno::Einval)?;
    let nest = msg::get_bytes(attrs, a::REG_RULES).ok_or(Errno::Einval)?;
    let region = msg::get_u8(attrs, a::DFS_REGION).unwrap_or(dfs_region::UNSET);
    let region = if region <= dfs_region::MAX { region } else { dfs_region::UNSET };
    let rules = parse_rules(nest)?;
    let requested = RegDomain::new(alpha2, region, rules);
    apply_request(alpha2, reg_initiator::USER, &requested, ctx.net_ns)
}

/// Read a rule table out of its nest. # C: O(N rules)
fn parse_rules(nest: &[u8]) -> Result<Vec<RegRule>, Errno> {
    let mut out: Vec<RegRule> = Vec::new();
    for at in attr::parse(nest) {
        if out.len() >= MAX_SUPP_REG_RULES { return Err(Errno::Einval); }
        let body = at.payload;
        let start_khz = msg::get_u32(body, rra::FREQ_RANGE_START).ok_or(Errno::Einval)?;
        let end_khz = msg::get_u32(body, rra::FREQ_RANGE_END).ok_or(Errno::Einval)?;
        if end_khz <= start_khz { return Err(Errno::Einval); }
        out.push(RegRule {
            freq_range: FreqRange {
                start_khz, end_khz,
                max_bandwidth_khz: msg::get_u32(body, rra::FREQ_RANGE_MAX_BW).unwrap_or(0),
            },
            power_rule: PowerRule {
                max_antenna_gain_mbi: msg::get_u32(body, rra::POWER_RULE_MAX_ANT_GAIN)
                    .unwrap_or(0) as i32,
                max_eirp_mbm: msg::get_u32(body, rra::POWER_RULE_MAX_EIRP)
                    .ok_or(Errno::Einval)? as i32,
                max_psd_mbm_mhz: 0,
            },
            flags: msg::get_u32(body, rra::FLAGS).unwrap_or(0),
            dfs_cac_ms: msg::get_u32(body, rra::DFS_CAC_TIME).unwrap_or(0),
        });
    }
    if out.is_empty() { return Err(Errno::Einval); }
    Ok(out)
}

/// A country-code hint. # C: O(N radios × N channels)
pub fn req_set(hdr: &Nlmsghdr, attrs: &[u8], ctx: GenlCtx) -> Vec<u8> {
    match req_set_inner(attrs, ctx) {
        Ok(()) => msg::ack(hdr),
        Err(e) => msg::error(hdr, e),
    }
}

/// The decision `req_set` makes.
///
/// A hint that the arbitration outranks, or that asks for the domain already
/// in force, is still a hint that was heard: the caller is not told it made a
/// bad request, because it did not. Only a code that is not a country code at
/// all is refused. # C: O(N radios)
fn req_set_inner(attrs: &[u8], ctx: GenlCtx) -> Result<(), Errno> {
    let raw = msg::get_bytes(attrs, a::REG_ALPHA2).ok_or(Errno::Einval)?;
    let alpha2 = domain::parse_alpha2(raw).ok_or(Errno::Einval)?;
    if !domain::is_an_alpha2(alpha2) && alpha2 != ALPHA2_WORLD { return Err(Errno::Einval); }
    // A hint names a country and not a rule table; the world domain's rules
    // stand in until a table for that country arrives.
    let requested = RegDomain::new(alpha2, dfs_region::UNSET, RegDomain::world().rules);
    // A hint that loses the arbitration was still heard, so the caller is
    // told the request succeeded and reads the result back if it cares.
    match apply_request(alpha2, reg_initiator::USER, &requested, ctx.net_ns) {
        Err(Errno::Ealready) | Err(Errno::Einval) => Ok(()),
        other => other,
    }
}

/// Arbitrate a request against what is in force and, if it wins, put the
/// result in force on every radio in the namespace.
///
/// The arbitration is decided once, against the domain the namespace's first
/// radio holds: every radio in a namespace moves together, and deciding per
/// radio would let two of them disagree about the country. # C: O(N radios)
fn apply_request(alpha2: [u8; 2], initiator: u32, requested: &RegDomain, net_ns: u64)
    -> Result<(), Errno>
{
    let mut radios: Vec<Arc<Wiphy>> = Vec::new();
    registry::for_each(net_ns, |w| radios.push(w.clone()));
    let Some(first) = radios.first() else { return Err(Errno::Enodev); };

    let current = first.regdom();
    let new = RegRequest::new(alpha2, initiator);
    let last = RegRequest::new(current.alpha2, reg_initiator::CORE);
    let treatment = hint::treatment(current.alpha2, &last, &new, false);
    let Some(resolved) = hint::resolve(treatment, &current, requested) else {
        return Err(match treatment {
            Treatment::AlreadySet => Errno::Ealready,
            _ => Errno::Einval,
        });
    };
    for w in radios.iter() {
        // A radio that manages its own domain is told nothing: the whole
        // point of the flag is that the core's answer does not apply to it.
        if w.caps.self_managed_reg { continue; }
        w.with_state(|s| {
            s.regdom = resolved.clone();
            s.generation = s.generation.wrapping_add(1);
        });
        let _ = w.ops.set_regdom(w);
        event::reg_change(w, initiator);
    }
    Ok(())
}
