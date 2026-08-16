// Connect, disconnect, and the four raw management exchanges a supplicant
// that runs its own state machine drives directly.
//
// Module manifest:
// - `parse`: authentication types and security suites, shared with the
//   access-point group.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use netlink::genetlink::family::GenlCtx;
use netlink::Nlmsghdr;
use syscall::errno::Errno;

use crate::ieee80211::status::reason;
use crate::ieee80211::MacAddr;
use crate::ops::{AssocRequest, AuthRequest};
use crate::sme::ConnectParams;
use crate::uapi::attr as a;
use crate::uapi::cmd;
use crate::uapi::enums::auth_type;
use crate::wdev::Wdev;

use super::{msg, resolve};

#[path = "connect_cmd/parse.rs"]
pub mod parse;

/// Interface types that run the client-side management state machine.
const CLIENT_TYPES: [crate::uapi::enums::IfType; 2] =
    [crate::uapi::enums::IfType::Station, crate::uapi::enums::IfType::P2pClient];

/// Start a connection. # C: O(N attrs)
pub fn connect(hdr: &Nlmsghdr, attrs: &[u8], ctx: GenlCtx) -> Vec<u8> {
    match connect_inner(attrs, ctx) {
        Ok(()) => msg::ack(hdr),
        Err(e) => msg::error(hdr, e),
    }
}

/// The decision `connect` makes.
///
/// The checks run in the reference's order, which is not the order they read
/// in: the security suites are validated before the interface type, so a
/// connect naming a cipher the radio lacks is a bad argument even on an
/// interface that could never connect at all. # C: O(N attrs)
fn connect_inner(attrs: &[u8], ctx: GenlCtx) -> Result<(), Errno> {
    let (wiphy, wdev) = resolve::wdev(attrs, ctx.net_ns)?;
    let ssid = msg::get_bytes(attrs, a::SSID).unwrap_or(&[]);
    if ssid.is_empty() { return Err(Errno::Einval); }
    let auth = match msg::get_u32(attrs, a::AUTH_TYPE) {
        None => auth_type::AUTOMATIC,
        Some(v) => {
            if !parse::valid_auth_type(&wiphy, v, cmd::CONNECT) { return Err(Errno::Einval); }
            v
        }
    };
    let crypto = parse::crypto(&wiphy, attrs)?;
    if !CLIENT_TYPES.contains(&wdev.iftype()) { return Err(Errno::Eopnotsupp); }
    let mfp = parse::use_mfp(&wiphy, attrs)?;
    let freq = parse::pinned_freq(&wiphy, attrs, a::WIPHY_FREQ)?;
    let freq_hint = if freq.is_some() { None }
                    else { parse::pinned_freq(&wiphy, attrs, a::WIPHY_FREQ_HINT)? };

    let params = ConnectParams {
        ssid: ssid.to_vec(),
        bssid: msg::get_mac(attrs, a::MAC),
        bssid_hint: msg::get_mac(attrs, a::MAC_HINT),
        freq, freq_hint,
        auth_type: auth,
        privacy: msg::get_flag(attrs, a::PRIVACY),
        wpa_versions: crypto.wpa_versions,
        cipher_group: crypto.cipher_group,
        ciphers_pairwise: crypto.ciphers_pairwise,
        akm_suites: crypto.akm_suites,
        ie: msg::get_bytes(attrs, a::IE).unwrap_or(&[]).to_vec(),
        mfp,
        prev_bssid: msg::get_mac(attrs, a::PREV_BSSID),
        want_1x: msg::get_flag(attrs, a::WANT_1X_4WAY_HS),
        auto_auth: auth == auth_type::AUTOMATIC,
    };
    admissible(&wdev, &params)?;
    wiphy.ops.connect(&wiphy, &wdev, &params)?;
    if msg::get_flag(attrs, a::SOCKET_OWNER) {
        wdev.with(|w| w.owner_portid = Some(ctx.portid));
    }
    Ok(())
}

/// Whether an interface may start this attempt.
///
/// A second connect while one is live is refused rather than replacing it,
/// because the first has a terminal event userspace is still waiting for. A
/// reassociation is the exception, and only when it names the address it is
/// reassociating away from. # C: O(1)
fn admissible(wdev: &Arc<Wdev>, params: &ConnectParams) -> Result<(), Errno> {
    let conn = wdev.conn();
    if conn.can_connect() { return Ok(()); }
    if conn.connected {
        let Some(prev) = params.prev_bssid else { return Err(Errno::Ealready); };
        if conn.current_bssid != Some(prev) { return Err(Errno::Enotconn); }
        return Ok(());
    }
    Err(Errno::Ealready)
}

/// End a connection. # C: O(1)
pub fn disconnect(hdr: &Nlmsghdr, attrs: &[u8], ctx: GenlCtx) -> Vec<u8> {
    match disconnect_inner(attrs, ctx) {
        Ok(()) => msg::ack(hdr),
        Err(e) => msg::error(hdr, e),
    }
}

/// The decision `disconnect` makes. Disconnecting an interface that has no
/// connection succeeds and reaches no driver: the caller asked for a state
/// that already holds. # C: O(1)
fn disconnect_inner(attrs: &[u8], ctx: GenlCtx) -> Result<(), Errno> {
    let (wiphy, wdev) = resolve::wdev(attrs, ctx.net_ns)?;
    let reason = parse::reason_code(attrs, reason::DEAUTH_LEAVING)?;
    if !CLIENT_TYPES.contains(&wdev.iftype()) { return Err(Errno::Eopnotsupp); }
    let conn = wdev.conn();
    wdev.with(|w| w.owner_portid = None);
    if !conn.connected && conn.conn.is_none() { return Ok(()); }
    wiphy.ops.disconnect(&wiphy, &wdev, reason)
}

/// Send an authenticate. # C: O(N attrs)
pub fn authenticate(hdr: &Nlmsghdr, attrs: &[u8], ctx: GenlCtx) -> Vec<u8> {
    match authenticate_inner(attrs, ctx) {
        Ok(()) => msg::ack(hdr),
        Err(e) => msg::error(hdr, e),
    }
}

/// The decision `authenticate` makes. A request that only changes local
/// state puts no frame on the air and succeeds without reaching the driver.
/// # C: O(N attrs)
fn authenticate_inner(attrs: &[u8], ctx: GenlCtx) -> Result<(), Errno> {
    let (wiphy, wdev) = resolve::wdev(attrs, ctx.net_ns)?;
    let bssid = msg::get_mac(attrs, a::MAC).ok_or(Errno::Einval)?;
    let auth = msg::get_u32(attrs, a::AUTH_TYPE).ok_or(Errno::Einval)?;
    let ssid = msg::get_bytes(attrs, a::SSID).ok_or(Errno::Einval)?;
    let freq = msg::get_u32(attrs, a::WIPHY_FREQ).ok_or(Errno::Einval)?;
    if !CLIENT_TYPES.contains(&wdev.iftype()) { return Err(Errno::Eopnotsupp); }
    if wiphy.channel(freq).is_none() { return Err(Errno::Einval); }
    if !parse::valid_auth_type(&wiphy, auth, cmd::AUTHENTICATE) { return Err(Errno::Einval); }
    let auth_data = msg::get_bytes(attrs, a::AUTH_DATA);
    // The algorithms that carry their own exchange need the payload, and the
    // ones that do not must not be given one.
    let needs_data = matches!(auth, auth_type::SAE | auth_type::FILS_SK
        | auth_type::FILS_SK_PFS | auth_type::FILS_PK | auth_type::EPPKE
        | auth_type::IEEE8021X);
    if needs_data != auth_data.is_some() { return Err(Errno::Einval); }
    if msg::get_flag(attrs, a::LOCAL_STATE_CHANGE) { return Ok(()); }
    let req = AuthRequest {
        bssid, freq, ssid: ssid.to_vec(), auth_type: auth,
        ie: msg::get_bytes(attrs, a::IE).unwrap_or(&[]).to_vec(),
        auth_data: auth_data.unwrap_or(&[]).to_vec(),
        local_state_change: false,
    };
    wiphy.ops.auth(&wiphy, &wdev, &req)
}

/// Send an associate. # C: O(N attrs)
pub fn associate(hdr: &Nlmsghdr, attrs: &[u8], ctx: GenlCtx) -> Vec<u8> {
    match associate_inner(attrs, ctx) {
        Ok(()) => msg::ack(hdr),
        Err(e) => msg::error(hdr, e),
    }
}

/// The decision `associate` makes. # C: O(N attrs)
fn associate_inner(attrs: &[u8], ctx: GenlCtx) -> Result<(), Errno> {
    let (wiphy, wdev) = resolve::wdev(attrs, ctx.net_ns)?;
    let bssid = msg::get_mac(attrs, a::MAC).ok_or(Errno::Einval)?;
    let ssid = msg::get_bytes(attrs, a::SSID).ok_or(Errno::Einval)?;
    let freq = msg::get_u32(attrs, a::WIPHY_FREQ).ok_or(Errno::Einval)?;
    let crypto = parse::crypto(&wiphy, attrs)?;
    if !CLIENT_TYPES.contains(&wdev.iftype()) { return Err(Errno::Eopnotsupp); }
    if wiphy.channel(freq).is_none() { return Err(Errno::Einval); }
    let use_mfp = parse::use_mfp(&wiphy, attrs)?;
    let req = AssocRequest {
        bssid, freq, ssid: ssid.to_vec(),
        ie: msg::get_bytes(attrs, a::IE).unwrap_or(&[]).to_vec(),
        prev_bssid: msg::get_mac(attrs, a::PREV_BSSID),
        use_mfp,
        crypto_ciphers_pairwise: crypto.ciphers_pairwise,
        crypto_cipher_group: crypto.cipher_group,
        crypto_akm_suites: crypto.akm_suites,
    };
    wiphy.ops.assoc(&wiphy, &wdev, &req)
}

/// Send a deauthenticate. # C: O(N attrs)
pub fn deauthenticate(hdr: &Nlmsghdr, attrs: &[u8], ctx: GenlCtx) -> Vec<u8> {
    tear_down(hdr, attrs, ctx, true)
}

/// Send a disassociate. # C: O(N attrs)
pub fn disassociate(hdr: &Nlmsghdr, attrs: &[u8], ctx: GenlCtx) -> Vec<u8> {
    tear_down(hdr, attrs, ctx, false)
}

/// The two teardown exchanges, which differ only in the frame they send.
/// # C: O(N attrs)
fn tear_down(hdr: &Nlmsghdr, attrs: &[u8], ctx: GenlCtx, deauth: bool) -> Vec<u8> {
    match tear_down_inner(attrs, ctx, deauth) {
        Ok(()) => msg::ack(hdr),
        Err(e) => msg::error(hdr, e),
    }
}

/// The decision the two teardown exchanges make. # C: O(N attrs)
fn tear_down_inner(attrs: &[u8], ctx: GenlCtx, deauth: bool) -> Result<(), Errno> {
    let (wiphy, wdev) = resolve::wdev(attrs, ctx.net_ns)?;
    let peer: MacAddr = msg::get_mac(attrs, a::MAC).ok_or(Errno::Einval)?;
    if msg::get_u16(attrs, a::REASON_CODE).is_none() { return Err(Errno::Einval); }
    if !CLIENT_TYPES.contains(&wdev.iftype()) { return Err(Errno::Eopnotsupp); }
    let code = parse::reason_code(attrs, 0)?;
    let local = msg::get_flag(attrs, a::LOCAL_STATE_CHANGE);
    if deauth { wiphy.ops.deauth(&wiphy, &wdev, peer, code, local) }
    else { wiphy.ops.disassoc(&wiphy, &wdev, peer, code, local) }
}
