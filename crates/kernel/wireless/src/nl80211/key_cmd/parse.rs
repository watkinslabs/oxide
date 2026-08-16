// Reading one key out of a request.
//
// Two encodings are live and both must work. The modern one nests every field
// under a single key attribute; the older one spreads the same fields across
// the top level, and `wpa_supplicant` still sends that form for the wired-
// equivalent ciphers. A build that read only the nest would install no key at
// all for those.

extern crate alloc;

use netlink::genetlink::attr;
use syscall::errno::Errno;

use crate::keys::{KeyParams, FIRST_BIGTK_IDX, FIRST_IGTK_IDX, LAST_BIGTK_IDX, LAST_IGTK_IDX,
                  MAX_DATA_KEY_IDX};
use crate::uapi::attr as a;
use crate::uapi::enums::key_type;
use crate::uapi::nested::key as k;

use super::super::msg;

/// Highest index any key may occupy.
const MAX_KEY_IDX: u8 = LAST_BIGTK_IDX;

/// `NL80211_KEY_DEFAULT_TYPE_*` — which traffic a default key covers.
mod default_type {
    pub const UNICAST: u16 = 1;
    pub const MULTICAST: u16 = 2;
}

/// One key as a request states it.
#[derive(Clone, Debug, Default)]
pub struct KeyParse {
    pub params: KeyParams,
    /// Index the request named, if it named one.
    pub idx: Option<u8>,
    /// Key type the request named, if it named one.
    pub key_type: Option<u32>,
    /// Whether key material was supplied at all, which is not the same as
    /// supplying an empty key.
    pub has_key: bool,
    pub def: bool,
    pub defmgmt: bool,
    pub defbeacon: bool,
    /// Which traffic the default covers.
    pub def_uni: bool,
    pub def_multi: bool,
}

/// Read a key from whichever encoding the request used, then apply the rules
/// that hold across both. # C: O(N attrs)
pub fn key(attrs: &[u8]) -> Result<KeyParse, Errno> {
    let mut out = match msg::get_bytes(attrs, a::KEY) {
        Some(nest) => nested(nest)?,
        None => flat(attrs),
    };
    check(&mut out)?;
    Ok(out)
}

/// The modern encoding: every field inside one nest. # C: O(N attrs)
fn nested(nest: &[u8]) -> Result<KeyParse, Errno> {
    let mut out = KeyParse {
        def: msg::get_flag(nest, k::DEFAULT),
        defmgmt: msg::get_flag(nest, k::DEFAULT_MGMT),
        defbeacon: msg::get_flag(nest, k::DEFAULT_BEACON),
        idx: msg::get_u8(nest, k::IDX),
        key_type: msg::get_u32(nest, k::TYPE),
        ..Default::default()
    };
    defaults(&mut out);
    if let Some(data) = msg::get_bytes(nest, k::DATA) {
        out.params.key = data.to_vec();
        out.has_key = true;
    }
    if let Some(seq) = msg::get_bytes(nest, k::SEQ) { out.params.seq = Some(seq.to_vec()); }
    if let Some(c) = msg::get_u32(nest, k::CIPHER) { out.params.cipher = c; }
    if let Some(m) = msg::get_u8(nest, k::MODE) { out.params.mode = m as u32; }
    if let Some(types) = msg::get_bytes(nest, k::DEFAULT_TYPES) { default_types(&mut out, types); }
    Ok(out)
}

/// The older encoding: the same fields at the top level. # C: O(N attrs)
fn flat(attrs: &[u8]) -> KeyParse {
    let mut out = KeyParse {
        def: msg::get_flag(attrs, a::KEY_DEFAULT),
        defmgmt: msg::get_flag(attrs, a::KEY_DEFAULT_MGMT),
        defbeacon: false,
        idx: msg::get_u8(attrs, a::KEY_IDX),
        key_type: msg::get_u32(attrs, a::KEY_TYPE),
        ..Default::default()
    };
    defaults(&mut out);
    if let Some(data) = msg::get_bytes(attrs, a::KEY_DATA) {
        out.params.key = data.to_vec();
        out.has_key = true;
    }
    if let Some(seq) = msg::get_bytes(attrs, a::KEY_SEQ) { out.params.seq = Some(seq.to_vec()); }
    if let Some(c) = msg::get_u32(attrs, a::KEY_CIPHER) { out.params.cipher = c; }
    if let Some(types) = msg::get_bytes(attrs, a::KEY_DEFAULT_TYPES) {
        default_types(&mut out, types);
    }
    out
}

/// Which traffic a default flag implies it covers, before any explicit
/// statement overrides it. # C: O(1)
fn defaults(out: &mut KeyParse) {
    if out.def { out.def_uni = true; out.def_multi = true; }
    if out.defmgmt || out.defbeacon { out.def_multi = true; }
}

/// An explicit statement of which traffic a default covers. # C: O(N attrs)
fn default_types(out: &mut KeyParse, nest: &[u8]) {
    out.def_uni = attr::find(nest, default_type::UNICAST).is_some();
    out.def_multi = attr::find(nest, default_type::MULTICAST).is_some();
}

/// Rules that hold whichever encoding was used.
///
/// The index range depends on which default the key is: a management default
/// lives at 4 or 5 and a beacon default at 6 or 7, and putting one at a data
/// index would silently make it a data key. # C: O(1)
fn check(out: &mut KeyParse) -> Result<(), Errno> {
    let defaults = u8::from(out.def) + u8::from(out.defmgmt) + u8::from(out.defbeacon);
    if defaults > 1 { return Err(Errno::Einval); }
    if out.defmgmt || out.defbeacon {
        // A key that protects management frames or beacons is a group key by
        // construction; claiming it covers unicast traffic is meaningless.
        if out.def_uni || !out.def_multi { return Err(Errno::Einval); }
    }
    if let Some(idx) = out.idx {
        let ok = if out.defmgmt { (FIRST_IGTK_IDX..=LAST_IGTK_IDX).contains(&idx) }
                 else if out.defbeacon { (FIRST_BIGTK_IDX..=LAST_BIGTK_IDX).contains(&idx) }
                 else if out.def { idx <= MAX_DATA_KEY_IDX }
                 else { idx <= MAX_KEY_IDX };
        if !ok { return Err(Errno::Einval); }
    }
    Ok(())
}

/// Whether a request installs or removes a pairwise key, given what it said
/// and whether it named a peer. A request that named neither is a group key.
/// # C: O(1)
pub fn is_pairwise(parsed: &KeyParse, has_peer: bool) -> Result<bool, Errno> {
    match parsed.key_type {
        None => Ok(has_peer),
        Some(key_type::PAIRWISE) => Ok(true),
        Some(key_type::GROUP) => Ok(false),
        Some(_) => Err(Errno::Einval),
    }
}
