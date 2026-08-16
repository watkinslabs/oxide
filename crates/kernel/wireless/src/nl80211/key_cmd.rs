// Key installation, removal, query and default selection.
//
// Module manifest:
// - `parse`: the two request encodings a key arrives in.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use netlink::genetlink::attr;
use netlink::genetlink::family::GenlCtx;
use netlink::Nlmsghdr;
use syscall::errno::Errno;

use crate::ieee80211::MacAddr;
use crate::keys::{self, InstalledKey, KeyCaps, FIRST_BIGTK_IDX, LAST_BIGTK_IDX};
use crate::uapi::attr as a;
use crate::uapi::enums::{ext_feature, key_type, IfType};
use crate::uapi::nested::key as k;
use crate::uapi::{ciphers, cmd};
use crate::wdev::Wdev;
use crate::wiphy::Wiphy;

use super::{msg, resolve};

#[path = "key_cmd/parse.rs"]
pub mod parse;

/// What the radio permits, as the key rules need to see it.
///
/// Beacon protection is advertised two ways — one for a radio that protects
/// the beacons it sends and one for a radio that only validates the ones it
/// receives — and a client interface may use either. # C: O(N suites)
fn key_caps(wiphy: &Arc<Wiphy>, iftype: IfType) -> KeyCaps {
    let caps = &wiphy.caps;
    let mut beacon_protection = caps.has_ext_feature(ext_feature::BEACON_PROTECTION);
    if iftype.is_client() && caps.has_ext_feature(ext_feature::BEACON_PROTECTION_CLIENT) {
        beacon_protection = true;
    }
    KeyCaps {
        igtk: caps.cipher_suites.iter().any(|&c| ciphers::is_mgmt_cipher(c)),
        beacon_protection,
        ext_key_id: caps.has_ext_feature(ext_feature::EXT_KEY_ID),
        // No radio advertises a secured ad-hoc network here, so a group key
        // addressed to one peer has no configuration that would accept it.
        ibss_rsn: false,
    }
}

/// Whether an interface is in a state that admits a key. # C: O(1)
fn allowed(wdev: &Arc<Wdev>) -> Result<(), Errno> {
    let (iftype, connected) = wdev.with(|w| (w.iftype, w.conn.connected));
    keys::key_allowed(iftype, connected, false)
}

/// Report an installed key: its cipher, its index and its replay counter.
///
/// The key material is never reported. A query that returned it would hand
/// any process that can read netlink the network's key. # C: O(N peers)
pub fn get(hdr: &Nlmsghdr, attrs: &[u8], ctx: GenlCtx) -> Vec<u8> {
    let (wiphy, wdev) = match resolve::wdev(attrs, ctx.net_ns) {
        Ok(v) => v,
        Err(e) => return msg::error(hdr, e),
    };
    let idx = msg::get_u8(attrs, a::KEY_IDX).unwrap_or(0);
    let caps = key_caps(&wiphy, wdev.iftype());
    if (FIRST_BIGTK_IDX..=LAST_BIGTK_IDX).contains(&idx) && !caps.beacon_protection {
        return msg::error(hdr, Errno::Einval);
    }
    let peer = msg::get_mac(attrs, a::MAC);
    let pairwise = match msg::get_u32(attrs, a::KEY_TYPE) {
        None => peer.is_some(),
        Some(key_type::PAIRWISE) => true,
        Some(key_type::GROUP) => false,
        Some(_) => return msg::error(hdr, Errno::Einval),
    };
    if !pairwise && peer.is_some() && !caps.ibss_rsn {
        return msg::error(hdr, Errno::Enoent);
    }
    let found = wdev.with(|w| w.keys.get(idx, pairwise, peer).cloned());
    let Some(key) = found else { return msg::error(hdr, Errno::Enoent); };

    let mut out = msg::start(hdr, cmd::NEW_KEY);
    if let Some(ifindex) = wdev.ifindex() { attr::put_u32(&mut out, a::IFINDEX, ifindex); }
    msg::put_u64(&mut out, a::WDEV, wdev.identifier);
    msg::put_u8(&mut out, a::KEY_IDX, idx);
    if let Some(p) = peer { msg::put_mac(&mut out, a::MAC, p); }
    if let Some(seq) = &key.params.seq { attr::put(&mut out, a::KEY_SEQ, seq); }
    if key.params.cipher != 0 { attr::put_u32(&mut out, a::KEY_CIPHER, key.params.cipher); }
    let nest = attr::nest_start(&mut out, a::KEY);
    if let Some(seq) = &key.params.seq { attr::put(&mut out, k::SEQ, seq); }
    if key.params.cipher != 0 { attr::put_u32(&mut out, k::CIPHER, key.params.cipher); }
    msg::put_u8(&mut out, k::IDX, idx);
    attr::nest_end(&mut out, nest);
    msg::end(&mut out);
    out
}

/// Install a key. # C: O(N suites)
pub fn new(hdr: &Nlmsghdr, attrs: &[u8], ctx: GenlCtx) -> Vec<u8> {
    match new_inner(attrs, ctx) {
        Ok(()) => msg::ack(hdr),
        Err(e) => msg::error(hdr, e),
    }
}

/// The decision `new` makes. The whole errno ladder lives in the key rules,
/// which is why this reads as parse, ask, apply. # C: O(N suites)
fn new_inner(attrs: &[u8], ctx: GenlCtx) -> Result<(), Errno> {
    let (wiphy, wdev) = resolve::wdev(attrs, ctx.net_ns)?;
    let mut parsed = parse::key(attrs)?;
    if !parsed.has_key { return Err(Errno::Einval); }
    let peer = msg::get_mac(attrs, a::MAC);
    let pairwise = parse::is_pairwise(&parsed, peer.is_some())?;
    let idx = parsed.idx.ok_or(Errno::Einval)?;
    if !pairwise {
        if let Some(vlan) = msg::get_u16(attrs, a::VLAN_ID) { parsed.params.vlan_id = vlan; }
    }
    let iftype = wdev.iftype();
    keys::validate(key_caps(&wiphy, iftype), &wiphy.caps.cipher_suites, iftype,
                   &parsed.params, idx, pairwise, peer)?;
    allowed(&wdev)?;
    wiphy.ops.add_key(&wiphy, &wdev, idx, pairwise, peer, &parsed.params)?;
    wdev.with(|w| w.keys.install(InstalledKey {
        params: parsed.params.clone(), idx, pairwise, peer,
    }));
    Ok(())
}

/// Select a default key, or hand the transmit role to a key already there.
/// # C: O(1)
pub fn set(hdr: &Nlmsghdr, attrs: &[u8], ctx: GenlCtx) -> Vec<u8> {
    match set_inner(attrs, ctx) {
        Ok(()) => msg::ack(hdr),
        Err(e) => msg::error(hdr, e),
    }
}

/// The decision `set` makes. Only a default selection and the extended
/// key-id transmit handover are served; anything else would be an install,
/// which is a different command. # C: O(1)
fn set_inner(attrs: &[u8], ctx: GenlCtx) -> Result<(), Errno> {
    let (wiphy, wdev) = resolve::wdev(attrs, ctx.net_ns)?;
    let parsed = parse::key(attrs)?;
    let idx = parsed.idx.ok_or(Errno::Einval)?;
    let set_tx = parsed.params.mode == keys::key_mode::SET_TX;
    if !parsed.def && !parsed.defmgmt && !parsed.defbeacon && !set_tx {
        return Err(Errno::Einval);
    }
    if parsed.def {
        allowed(&wdev)?;
        wiphy.ops.set_default_key(&wiphy, &wdev, idx, parsed.def_uni, parsed.def_multi)?;
        return wdev.with(|w| w.keys.set_default(idx));
    }
    if parsed.defmgmt {
        allowed(&wdev)?;
        wiphy.ops.set_default_mgmt_key(&wiphy, &wdev, idx)?;
        return wdev.with(|w| w.keys.set_default_mgmt(idx));
    }
    if parsed.defbeacon {
        allowed(&wdev)?;
        // Beacon protection has no driver call of its own here; the key is
        // already installed and only the choice of which one signs changes.
        return wdev.with(|w| w.keys.set_default_beacon(idx));
    }
    // Handing the transmit role to an already-installed pairwise key is the
    // second half of an extended key-id rekey.
    if !wiphy.caps.has_ext_feature(ext_feature::EXT_KEY_ID) { return Err(Errno::Einval); }
    let peer: MacAddr = msg::get_mac(attrs, a::MAC).ok_or(Errno::Einval)?;
    if idx > 1 { return Err(Errno::Einval); }
    wiphy.ops.add_key(&wiphy, &wdev, idx, true, Some(peer), &parsed.params)
}

/// Remove a key. # C: O(N peers)
pub fn del(hdr: &Nlmsghdr, attrs: &[u8], ctx: GenlCtx) -> Vec<u8> {
    match del_inner(attrs, ctx) {
        Ok(()) => msg::ack(hdr),
        Err(e) => msg::error(hdr, e),
    }
}

/// The decision `del` makes. # C: O(N peers)
fn del_inner(attrs: &[u8], ctx: GenlCtx) -> Result<(), Errno> {
    let (wiphy, wdev) = resolve::wdev(attrs, ctx.net_ns)?;
    let parsed = parse::key(attrs)?;
    let peer = msg::get_mac(attrs, a::MAC);
    let pairwise = parse::is_pairwise(&parsed, peer.is_some())?;
    let idx = parsed.idx.ok_or(Errno::Einval)?;
    let caps = key_caps(&wiphy, wdev.iftype());
    if !keys::valid_key_idx(caps, idx, pairwise) { return Err(Errno::Einval); }
    allowed(&wdev)?;
    // A group key addressed to a peer only exists in a secured ad-hoc
    // network, so on any other radio there is nothing at that address.
    if !pairwise && peer.is_some() && !caps.ibss_rsn { return Err(Errno::Enoent); }
    wiphy.ops.del_key(&wiphy, &wdev, idx, pairwise, peer)?;
    wdev.with(|w| w.keys.remove(idx, pairwise, peer));
    Ok(())
}
