// Interface creation, query, change and removal, and the per-interface
// settings that do not belong to any other command group.
//
// Module manifest:
// - `emit`: one interface's description, shared by query, dump and creation.

extern crate alloc;

use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;

use netlink::genetlink::attr;
use netlink::genetlink::family::GenlCtx;
use netlink::Nlmsghdr;
use syscall::errno::Errno;

use crate::ops::NewIfaceParams;
use crate::uapi::attr as a;
use crate::uapi::enums::{feature_flags, ps_state, IfType};
use crate::uapi::nested::{self, mntr_flag};
use crate::uapi::cmd;
use crate::wdev::Wdev;
use crate::wiphy::{registry, Wiphy};

use super::{chandef, event, msg, resolve};

#[path = "iface_cmd/emit.rs"]
pub mod emit;

/// Highest monitor-capture flag this build knows.
const MNTR_FLAG_MAX: u16 = mntr_flag::MAX;
/// Cooked-frame capture is withdrawn: it cannot be combined with any other
/// capture selection and no driver here implements it.
const MNTR_FLAG_COOK: u32 = 1 << mntr_flag::COOK_FRAMES;
/// Active monitoring acknowledges frames, so it needs the radio's consent.
const MNTR_FLAG_ACTIVE: u32 = 1 << mntr_flag::ACTIVE;

/// One interface's description. # C: O(N interfaces)
pub fn get(hdr: &Nlmsghdr, attrs: &[u8], ctx: GenlCtx) -> Vec<u8> {
    let (wiphy, wdev) = match resolve::wdev(attrs, ctx.net_ns) {
        Ok(v) => v,
        Err(e) => return msg::error(hdr, e),
    };
    let mut out = msg::start(hdr, cmd::NEW_INTERFACE);
    emit::put(&mut out, &wiphy, &wdev);
    msg::end(&mut out);
    out
}

/// Every interface in the caller's namespace. # C: O(N interfaces)
pub fn dump(hdr: &Nlmsghdr, attrs: &[u8], ctx: GenlCtx) -> Vec<u8> {
    let mut reply: Vec<u8> = Vec::new();
    registry::for_each(ctx.net_ns, |w| {
        if !resolve::dump_selects(attrs, w) { return; }
        for wdev in w.wdevs() {
            let mut one = msg::start(hdr, cmd::NEW_INTERFACE);
            emit::put(&mut one, w, &wdev);
            msg::end(&mut one);
            msg::push(&mut reply, one);
        }
    });
    msg::push_done(&mut reply, hdr);
    reply
}

/// Create an interface. # C: O(N interfaces)
pub fn new(hdr: &Nlmsghdr, attrs: &[u8], ctx: GenlCtx) -> Vec<u8> {
    match new_inner(attrs, ctx) {
        Ok((wiphy, wdev)) => {
            let mut out = msg::start(hdr, cmd::NEW_INTERFACE);
            emit::put(&mut out, &wiphy, &wdev);
            msg::end(&mut out);
            event::new_interface(&wiphy, &wdev);
            out
        }
        Err(e) => msg::error(hdr, e),
    }
}

/// The decision `new` makes. The order is the contract: a request naming a
/// radio that does not exist is answered before its interface type is even
/// looked at, so a caller probing for support on an absent radio is told the
/// radio is absent. # C: O(N interfaces)
fn new_inner(attrs: &[u8], ctx: GenlCtx) -> Result<(Arc<Wiphy>, Arc<Wdev>), Errno> {
    let target = resolve::wiphy(attrs, ctx.net_ns)?;
    let wiphy = target.wiphy;
    let name = msg::get_str(attrs, a::IFNAME).ok_or(Errno::Einval)?.to_string();
    if name.is_empty() { return Err(Errno::Einval); }
    let iftype = iftype_of(attrs)?;
    let addr = address_request(&wiphy, attrs, iftype)?;
    let use_4addr = four_addr(attrs)?;
    if !wiphy.supports_iftype(iftype) { return Err(Errno::Eopnotsupp); }
    let mntr_flags = monitor_flags(&wiphy, attrs, iftype)?;
    // A name already in use anywhere would give userspace two interfaces it
    // cannot tell apart, and every later request naming it would reach an
    // arbitrary one of the two.
    if registry::lookup_wdev_by_name(&name).is_some() { return Err(Errno::Eexist); }

    let params = NewIfaceParams { name, iftype, addr, use_4addr, mntr_flags };
    let wdev = wiphy.ops.add_virtual_intf(&wiphy, &params)?;
    if let Some(v) = use_4addr { wdev.with(|w| w.use_4addr = v); }
    if mntr_flags != 0 { wdev.with(|w| w.mntr_flags = mntr_flags); }
    if msg::get_flag(attrs, a::SOCKET_OWNER) {
        wdev.with(|w| w.owner_portid = Some(ctx.portid));
    }
    wiphy.add_wdev(wdev.clone());
    Ok((wiphy, wdev))
}

/// Interface type a request asks for; absent means unspecified. # C: O(N attrs)
fn iftype_of(attrs: &[u8]) -> Result<IfType, Errno> {
    match msg::get_u32(attrs, a::IFTYPE) {
        None => Ok(IfType::Unspecified),
        Some(v) => IfType::from_u32(v).ok_or(Errno::Einval),
    }
}

/// Address a creation asks for. Only a type with no network device, or a
/// radio that says it can set an address at creation, may name one, and the
/// address must be one a station can hold. # C: O(1)
fn address_request(wiphy: &Arc<Wiphy>, attrs: &[u8], iftype: IfType)
    -> Result<Option<crate::ieee80211::MacAddr>, Errno>
{
    let Some(mac) = msg::get_mac(attrs, a::MAC) else { return Ok(None); };
    let allowed = !iftype.has_netdev()
        || wiphy.caps.features & feature_flags::MAC_ON_CREATE != 0;
    if !allowed { return Ok(None); }
    if !mac.is_unicast() { return Err(Errno::Eaddrnotavail); }
    Ok(Some(mac))
}

/// Whether four-address frames were asked for. No radio here advertises the
/// capability, so asking for it is refused rather than silently dropped.
/// # C: O(N attrs)
fn four_addr(attrs: &[u8]) -> Result<Option<bool>, Errno> {
    match msg::get_u8(attrs, a::_4ADDR) {
        None => Ok(None),
        Some(0) => Ok(Some(false)),
        Some(_) => Err(Errno::Eopnotsupp),
    }
}

/// Monitor-capture selection. The flags are a nest of flag attributes
/// numbered by the capture kind. # C: O(N flags)
fn monitor_flags(wiphy: &Arc<Wiphy>, attrs: &[u8], iftype: IfType) -> Result<u32, Errno> {
    let Some(nest) = msg::get_bytes(attrs, a::MNTR_FLAGS) else { return Ok(0); };
    if iftype != IfType::Monitor { return Err(Errno::Einval); }
    let mut flags = 0u32;
    for at in attr::parse(nest) {
        if at.ty >= 1 && at.ty <= MNTR_FLAG_MAX { flags |= 1u32 << at.ty; }
    }
    if flags & MNTR_FLAG_COOK != 0 { return Err(Errno::Eopnotsupp); }
    if flags & MNTR_FLAG_ACTIVE != 0
        && wiphy.caps.features & feature_flags::ACTIVE_MONITOR == 0 {
        return Err(Errno::Eopnotsupp);
    }
    Ok(flags)
}

/// Change an interface. # C: O(N interfaces)
pub fn set(hdr: &Nlmsghdr, attrs: &[u8], ctx: GenlCtx) -> Vec<u8> {
    match set_inner(attrs, ctx) {
        Ok(Some((wiphy, wdev))) => { event::new_interface(&wiphy, &wdev); msg::ack(hdr) }
        Ok(None) => msg::ack(hdr),
        Err(e) => msg::error(hdr, e),
    }
}

/// The decision `set` makes; reports the interface when something changed, so
/// a notification goes out only for a real change. # C: O(N interfaces)
fn set_inner(attrs: &[u8], ctx: GenlCtx)
    -> Result<Option<(Arc<Wiphy>, Arc<Wdev>)>, Errno>
{
    let (wiphy, wdev) = resolve::wdev(attrs, ctx.net_ns)?;
    let old = wdev.iftype();
    let new_type = match msg::get_u32(attrs, a::IFTYPE) {
        None => old,
        Some(v) => IfType::from_u32(v).ok_or(Errno::Einval)?,
    };
    let use_4addr = four_addr(attrs)?;
    let mntr_flags = monitor_flags(&wiphy, attrs, new_type)?;
    let changed = new_type != old || use_4addr.is_some() || mntr_flags != 0;
    if new_type != old {
        // A type with no network device is created, never converted into.
        if !new_type.has_netdev() || !old.has_netdev() { return Err(Errno::Eopnotsupp); }
        if old == IfType::ApVlan { return Err(Errno::Eopnotsupp); }
        if !wiphy.supports_iftype(new_type) { return Err(Errno::Eopnotsupp); }
        wiphy.ops.change_virtual_intf(&wiphy, &wdev, new_type)?;
        wdev.with(|w| { w.iftype = new_type; w.use_4addr = false; });
        wiphy.bump_generation();
    }
    if let Some(v) = use_4addr { wdev.with(|w| w.use_4addr = v); }
    if mntr_flags != 0 { wdev.with(|w| w.mntr_flags = mntr_flags); }
    Ok(if changed { Some((wiphy, wdev)) } else { None })
}

/// Destroy an interface. # C: O(N interfaces)
pub fn del(hdr: &Nlmsghdr, attrs: &[u8], ctx: GenlCtx) -> Vec<u8> {
    let (wiphy, wdev) = match resolve::wdev(attrs, ctx.net_ns) {
        Ok(v) => v,
        Err(e) => return msg::error(hdr, e),
    };
    if let Err(e) = wiphy.ops.del_virtual_intf(&wiphy, &wdev) { return msg::error(hdr, e); }
    wiphy.remove_wdev(wdev.identifier);
    event::del_interface(&wiphy, &wdev);
    msg::ack(hdr)
}

/// Turn power save on or off for one interface. # C: O(N interfaces)
pub fn set_power_save(hdr: &Nlmsghdr, attrs: &[u8], ctx: GenlCtx) -> Vec<u8> {
    match power_save_inner(attrs, ctx) {
        Ok(()) => msg::ack(hdr),
        Err(e) => msg::error(hdr, e),
    }
}

/// The decision `set_power_save` makes. A request for the state already in
/// force succeeds without reaching the driver. # C: O(N interfaces)
fn power_save_inner(attrs: &[u8], ctx: GenlCtx) -> Result<(), Errno> {
    let state = msg::get_u32(attrs, a::PS_STATE).ok_or(Errno::Einval)?;
    if state > ps_state::MAX { return Err(Errno::Einval); }
    let (wiphy, wdev) = resolve::wdev(attrs, ctx.net_ns)?;
    let want = state == ps_state::ENABLED;
    let (already, timeout) = wdev.with(|w| (w.ps == want, w.ps_timeout_ms));
    if already { return Ok(()); }
    wiphy.ops.set_power_mgmt(&wiphy, &wdev, want, timeout)?;
    wdev.with(|w| w.ps = want);
    Ok(())
}

/// Report an interface's power-save state. # C: O(N interfaces)
pub fn get_power_save(hdr: &Nlmsghdr, attrs: &[u8], ctx: GenlCtx) -> Vec<u8> {
    let (_wiphy, wdev) = match resolve::wdev(attrs, ctx.net_ns) {
        Ok(v) => v,
        Err(e) => return msg::error(hdr, e),
    };
    let on = wdev.with(|w| w.ps);
    let mut out = msg::start(hdr, cmd::GET_POWER_SAVE);
    attr::put_u32(&mut out, a::PS_STATE,
                  if on { ps_state::ENABLED } else { ps_state::DISABLED });
    msg::end(&mut out);
    out
}

/// Set the channel an interface with no association operates on. # C: O(N channels)
pub fn set_channel(hdr: &Nlmsghdr, attrs: &[u8], ctx: GenlCtx) -> Vec<u8> {
    match set_channel_inner(attrs, ctx) {
        Ok(()) => msg::ack(hdr),
        Err(e) => msg::error(hdr, e),
    }
}

/// The decision `set_channel` makes. # C: O(width × N rules)
fn set_channel_inner(attrs: &[u8], ctx: GenlCtx) -> Result<(), Errno> {
    let (wiphy, wdev) = resolve::wdev(attrs, ctx.net_ns)?;
    let iftype = wdev.iftype();
    // Only a type that has no association of its own takes a channel this
    // way; a client's channel follows the network it joined.
    if !matches!(iftype, IfType::Monitor | IfType::Ap | IfType::P2pGo | IfType::MeshPoint) {
        return Err(Errno::Eopnotsupp);
    }
    let def = chandef::parse(&wiphy, attrs)?;
    if !chandef::usable(&wiphy, &def) { return Err(Errno::Einval); }
    wiphy.ops.set_monitor_channel(&wiphy, &def)?;
    wdev.with(|w| w.chandef = Some(def));
    Ok(())
}

/// Configure connection-quality monitoring. # C: O(N interfaces)
pub fn set_cqm(hdr: &Nlmsghdr, attrs: &[u8], ctx: GenlCtx) -> Vec<u8> {
    match set_cqm_inner(attrs, ctx) {
        Ok(()) => msg::ack(hdr),
        Err(e) => msg::error(hdr, e),
    }
}

/// The decision `set_cqm` makes. A threshold must be a negative signal level
/// in dBm; zero disables the trigger. # C: O(N interfaces)
fn set_cqm_inner(attrs: &[u8], ctx: GenlCtx) -> Result<(), Errno> {
    let nest = msg::get_bytes(attrs, a::CQM).ok_or(Errno::Einval)?;
    let (_wiphy, wdev) = resolve::wdev(attrs, ctx.net_ns)?;
    let thold = msg::get_u32(nest, nested::cqm::RSSI_THOLD).map(|v| v as i32);
    let hyst = msg::get_u32(nest, nested::cqm::RSSI_HYST);
    if let (Some(thold), Some(hyst)) = (thold, hyst) {
        if thold > 0 { return Err(Errno::Einval); }
        if !wdev.iftype().is_client() { return Err(Errno::Eopnotsupp); }
        wdev.with(|w| {
            w.cqm.rssi_thold = thold;
            w.cqm.rssi_hyst = hyst;
            w.cqm.last_rssi_event = None;
        });
        return Ok(());
    }
    if let Some(count) = msg::get_u32(nest, nested::cqm::PKT_LOSS_EVENT) {
        if !wdev.iftype().is_client() { return Err(Errno::Eopnotsupp); }
        wdev.with(|w| w.cqm.beacon_loss_count = count);
        return Ok(());
    }
    Err(Errno::Einval)
}

