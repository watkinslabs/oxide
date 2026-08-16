// Scan trigger, abort, and the cached results.
//
// Module manifest:
// - `bss`: one cached network as a results dump reports it.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use netlink::genetlink::attr;
use netlink::genetlink::family::GenlCtx;
use netlink::Nlmsghdr;
use syscall::errno::Errno;

use crate::ieee80211::MAX_SSID_LEN;
use crate::scan::{ScanRequest, ScanSsid, ScanState};
use crate::uapi::attr as a;
use crate::uapi::cmd;
use crate::uapi::enums::{feature_flags, scan_flags, IfType};
use crate::wdev::Wdev;
use crate::wiphy::Wiphy;

use super::{event, msg, resolve};

#[path = "scan_cmd/bss.rs"]
pub mod bss;

/// Scan options that each need their own extended-feature advertisement.
const NEEDS_EXT_FEATURE: u32 = scan_flags::LOW_SPAN | scan_flags::LOW_POWER
    | scan_flags::HIGH_ACCURACY | scan_flags::FILS_MAX_CHANNEL_TIME
    | scan_flags::ACCEPT_BCAST_PROBE_RESP
    | scan_flags::OCE_PROBE_REQ_DEFERRAL_SUPPRESSION
    | scan_flags::OCE_PROBE_REQ_HIGH_TX_RATE | scan_flags::RANDOM_SN
    | scan_flags::MIN_PREQ_CONTENT | scan_flags::FREQ_KHZ
    | scan_flags::COLOCATED_6GHZ;

/// Start a scan. # C: O(N channels + N attrs)
pub fn trigger(hdr: &Nlmsghdr, attrs: &[u8], ctx: GenlCtx) -> Vec<u8> {
    match trigger_inner(attrs, ctx) {
        Ok((wiphy, wdev)) => { event::trigger_scan(&wiphy, &wdev); msg::ack(hdr) }
        Err(e) => msg::error(hdr, e),
    }
}

/// The decision `trigger` makes.
///
/// The order is the contract userspace branches on: a radio already scanning
/// is busy before any of the request's contents are looked at, so a caller
/// that got `EBUSY` knows to wait rather than to fix its request.
/// # C: O(N channels + N attrs)
fn trigger_inner(attrs: &[u8], ctx: GenlCtx) -> Result<(Arc<Wiphy>, Arc<Wdev>), Errno> {
    let (wiphy, wdev) = resolve::wdev(attrs, ctx.net_ns)?;
    let iftype = wdev.iftype();
    if matches!(iftype, IfType::Nan | IfType::NanData | IfType::Pd) {
        return Err(Errno::Eopnotsupp);
    }
    if wiphy.with_state(|s| s.scan.is_some()) { return Err(Errno::Ebusy); }

    let freqs = parse_freqs(&wiphy, attrs)?;
    let ssids = parse_ssids(&wiphy, attrs)?;
    let ie = msg::get_bytes(attrs, a::IE).unwrap_or(&[]).to_vec();
    if ie.len() > wiphy.caps.max_scan_ie_len as usize { return Err(Errno::Einval); }
    let flags = parse_flags(&wiphy, &wdev, attrs)?;
    let (mac_addr, mac_addr_mask) = randomised_address(attrs, flags)?;

    let request = ScanRequest {
        ssids, freqs, ie, flags, portid: ctx.portid, mac_addr, mac_addr_mask,
        duration_ms: msg::get_u16(attrs, a::MEASUREMENT_DURATION).unwrap_or(0),
        duration_mandatory: msg::get_flag(attrs, a::MEASUREMENT_DURATION_MANDATORY),
        start_ns: wiphy.with_state(|s| bss::reference_now(&s.bss)),
    };
    // The state is published before the driver is called so a scan the driver
    // completes synchronously still finds it; a driver that refuses takes it
    // straight back out, because a state left behind makes every later scan
    // report `EBUSY` for ever.
    wiphy.with_state(|s| s.scan = Some(ScanState { request: request.clone(), aborting: false }));
    if let Err(e) = wiphy.ops.scan(&wiphy, &wdev, &request) {
        wiphy.with_state(|s| s.scan = None);
        return Err(e);
    }
    Ok((wiphy, wdev))
}

/// Channels a request names. An empty list means every channel the radio
/// has; a frequency the radio has no channel for is refused rather than
/// silently dropped, because a caller that asked for one channel and got a
/// scan of another would report the wrong network. # C: O(N channels)
fn parse_freqs(wiphy: &Arc<Wiphy>, attrs: &[u8]) -> Result<Vec<u32>, Errno> {
    let Some(nest) = msg::get_bytes(attrs, a::SCAN_FREQUENCIES) else { return Ok(Vec::new()); };
    let mut out: Vec<u32> = Vec::new();
    for at in attr::parse(nest) {
        let Some(b) = at.payload.get(..4) else { return Err(Errno::Einval); };
        let freq = u32::from_ne_bytes([b[0], b[1], b[2], b[3]]);
        let chan = wiphy.channel(freq).ok_or(Errno::Einval)?;
        // A channel the domain disabled is dropped, not refused: a caller
        // sweeping a band should still scan the rest of it.
        if !chan.is_usable() { continue; }
        if !out.contains(&freq) { out.push(freq); }
    }
    if out.is_empty() { return Err(Errno::Einval); }
    Ok(out)
}

/// Networks a request probes for. # C: O(N ssids)
fn parse_ssids(wiphy: &Arc<Wiphy>, attrs: &[u8]) -> Result<Vec<ScanSsid>, Errno> {
    let Some(nest) = msg::get_bytes(attrs, a::SCAN_SSIDS) else { return Ok(Vec::new()); };
    let mut out: Vec<ScanSsid> = Vec::new();
    for at in attr::parse(nest) {
        if at.payload.len() > MAX_SSID_LEN { return Err(Errno::Einval); }
        out.push(ScanSsid(at.payload.to_vec()));
    }
    if out.len() > wiphy.caps.max_scan_ssids as usize { return Err(Errno::Einval); }
    Ok(out)
}

/// Scan options. A flag this build does not know is refused as unsupported
/// and not ignored: a caller that asked for a low-power scan and silently got
/// an ordinary one has been told something untrue. # C: O(1)
fn parse_flags(wiphy: &Arc<Wiphy>, wdev: &Arc<Wdev>, attrs: &[u8]) -> Result<u32, Errno> {
    let Some(flags) = msg::get_u32(attrs, a::SCAN_FLAGS) else { return Ok(0); };
    if flags & !scan_flags::KNOWN != 0 { return Err(Errno::Eopnotsupp); }
    let caps = &wiphy.caps;
    if flags & scan_flags::LOW_PRIORITY != 0
        && caps.features & feature_flags::LOW_PRIORITY_SCAN == 0 {
        return Err(Errno::Eopnotsupp);
    }
    // Every flag below needs an extended-feature advertisement that no radio
    // in this build makes, so asking for one promises behaviour nothing
    // implements and is refused rather than silently ignored.
    if flags & NEEDS_EXT_FEATURE != 0 { return Err(Errno::Eopnotsupp); }
    if flags & scan_flags::RANDOM_ADDR != 0 {
        if caps.features & feature_flags::SCAN_RANDOM_MAC_ADDR == 0 {
            return Err(Errno::Eopnotsupp);
        }
        // Randomising the address of a connected interface would break the
        // association it already has.
        if wdev.conn().connected { return Err(Errno::Eopnotsupp); }
    }
    Ok(flags)
}

/// The address pair a randomised scan sends from. Both halves are required
/// together, and every bit the mask fixes must already be set in the address.
/// # C: O(1)
fn randomised_address(attrs: &[u8], flags: u32)
    -> Result<(Option<crate::ieee80211::MacAddr>, Option<crate::ieee80211::MacAddr>), Errno>
{
    if flags & scan_flags::RANDOM_ADDR == 0 { return Ok((None, None)); }
    let addr = msg::get_mac(attrs, a::MAC).ok_or(Errno::Einval)?;
    let mask = msg::get_mac(attrs, a::MAC_MASK).ok_or(Errno::Einval)?;
    for i in 0..crate::ieee80211::ADDR_LEN {
        if addr.0[i] & !mask.0[i] != 0 { return Err(Errno::Einval); }
    }
    // The fixed half must name a station address: locally administered and
    // not a group address.
    if mask.0[0] & 0x03 != 0x03 { return Err(Errno::Einval); }
    if addr.0[0] & 0x03 != 0x02 { return Err(Errno::Einval); }
    Ok((Some(addr), Some(mask)))
}

/// Ask for a scan in progress to stop. # C: O(1)
pub fn abort(hdr: &Nlmsghdr, attrs: &[u8], ctx: GenlCtx) -> Vec<u8> {
    let (wiphy, wdev) = match resolve::wdev(attrs, ctx.net_ns) {
        Ok(v) => v,
        Err(e) => return msg::error(hdr, e),
    };
    if !wiphy.with_state(|s| s.scan.is_some()) { return msg::ack(hdr); }
    if let Err(e) = wiphy.ops.abort_scan(&wiphy, &wdev) { return msg::error(hdr, e); }
    wiphy.with_state(|s| { if let Some(sc) = s.scan.as_mut() { sc.aborting = true; } });
    msg::ack(hdr)
}

/// Every network the radio has heard, one message each. # C: O(N entries)
pub fn dump(hdr: &Nlmsghdr, attrs: &[u8], ctx: GenlCtx) -> Vec<u8> {
    let (wiphy, wdev) = match resolve::wdev(attrs, ctx.net_ns) {
        Ok(v) => v,
        Err(e) => return msg::error(hdr, e),
    };
    let (entries, generation, now) = wiphy.with_state(|s| {
        let now = bss::reference_now(&s.bss);
        s.bss.expire_now(now);
        (s.bss.snapshot(), s.bss.generation, now)
    });
    let mut reply: Vec<u8> = Vec::new();
    for entry in entries.iter() {
        let mut one = msg::start(hdr, cmd::NEW_SCAN_RESULTS);
        bss::put(&mut one, &wiphy, &wdev, entry, generation, now);
        msg::end(&mut one);
        msg::push(&mut reply, one);
    }
    msg::push_done(&mut reply, hdr);
    reply
}
