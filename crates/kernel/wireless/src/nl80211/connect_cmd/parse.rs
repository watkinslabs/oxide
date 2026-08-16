// The two pieces of request parsing the connect group shares with the
// access-point group: which authentication algorithms a radio will accept,
// and the security suites a request offers.
//
// Both are refusals with a specific errno that userspace branches on. A
// cipher the radio never advertised is a bad argument, not an unsupported
// operation: `wpa_supplicant` retries with a narrower proposal on the first
// and gives up on the second.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::uapi::attr as a;
use crate::uapi::cmd;
use crate::uapi::enums::{auth_type, feature_flags, mfp, wpa_version};
use crate::wiphy::Wiphy;

use super::super::msg;

/// Pairwise cipher suites one request may offer.
pub const MAX_NR_CIPHER_SUITES: usize = 5;
/// Authentication-and-key-management suites one request may offer.
pub const MAX_NR_AKM_SUITES: usize = 2;

/// The security suites a connect or an access-point start offers.
#[derive(Clone, Debug, Default)]
pub struct Crypto {
    pub ciphers_pairwise: Vec<u32>,
    pub cipher_group: Option<u32>,
    pub akm_suites: Vec<u32>,
    pub wpa_versions: u32,
    /// Whether the four-way handshake's controlled port is managed by
    /// userspace over netlink rather than by the data path.
    pub control_port: bool,
    pub control_port_ethertype: Option<u16>,
    pub control_port_no_encrypt: bool,
    pub control_port_over_nl80211: bool,
}

/// Read the security suites out of a request, refusing any the radio never
/// advertised. # C: O(N suites)
pub fn crypto(wiphy: &Arc<Wiphy>, attrs: &[u8]) -> Result<Crypto, Errno> {
    let mut out = Crypto {
        control_port: msg::get_flag(attrs, a::CONTROL_PORT),
        control_port_ethertype: msg::get_u16(attrs, a::CONTROL_PORT_ETHERTYPE),
        control_port_no_encrypt: msg::get_flag(attrs, a::CONTROL_PORT_NO_ENCRYPT),
        control_port_over_nl80211: msg::get_flag(attrs, a::CONTROL_PORT_OVER_NL80211),
        ..Default::default()
    };
    if let Some(raw) = msg::get_bytes(attrs, a::CIPHER_SUITES_PAIRWISE) {
        if raw.len() % 4 != 0 { return Err(Errno::Einval); }
        if raw.len() / 4 > MAX_NR_CIPHER_SUITES { return Err(Errno::Einval); }
        out.ciphers_pairwise = msg::get_u32_array(attrs, a::CIPHER_SUITES_PAIRWISE);
        for &c in out.ciphers_pairwise.iter() {
            if !wiphy.has_cipher(c) { return Err(Errno::Einval); }
        }
    }
    if let Some(group) = msg::get_u32(attrs, a::CIPHER_SUITE_GROUP) {
        if !wiphy.has_cipher(group) { return Err(Errno::Einval); }
        out.cipher_group = Some(group);
    }
    if let Some(v) = msg::get_u32(attrs, a::WPA_VERSIONS) {
        if v & !wpa_version::ALL != 0 { return Err(Errno::Einval); }
        out.wpa_versions = v;
    }
    if let Some(raw) = msg::get_bytes(attrs, a::AKM_SUITES) {
        if raw.len() % 4 != 0 { return Err(Errno::Einval); }
        if raw.len() / 4 > MAX_NR_AKM_SUITES { return Err(Errno::Einval); }
        out.akm_suites = msg::get_u32_array(attrs, a::AKM_SUITES);
    }
    Ok(out)
}

/// Whether a radio will accept an authentication type for a command.
///
/// The answer differs per command: the algorithms an access point may offer
/// are not the ones a client may ask for, and several need a capability the
/// radio has to have advertised. # C: O(1)
pub fn valid_auth_type(wiphy: &Arc<Wiphy>, ty: u32, command: u8) -> bool {
    if ty > auth_type::MAX { return false; }
    let sae_ok = wiphy.caps.features & feature_flags::SAE != 0;
    match command {
        cmd::AUTHENTICATE => match ty {
            auth_type::SAE => sae_ok,
            // No radio here advertises the offloads the remaining algorithms
            // need, so offering one would promise something nothing serves.
            auth_type::FILS_SK | auth_type::FILS_SK_PFS | auth_type::FILS_PK
                | auth_type::EPPKE | auth_type::IEEE8021X => false,
            _ => true,
        },
        cmd::CONNECT => match ty {
            auth_type::SAE => sae_ok,
            auth_type::FILS_SK | auth_type::FILS_SK_PFS | auth_type::FILS_PK
                | auth_type::EPPKE | auth_type::IEEE8021X => false,
            _ => true,
        },
        cmd::START_AP => !matches!(ty, auth_type::SAE | auth_type::FILS_SK
            | auth_type::FILS_SK_PFS | auth_type::FILS_PK),
        _ => false,
    }
}

/// The management-frame protection level a request demands. Absent means
/// none; the optional level needs the radio to have advertised it.
/// # C: O(1)
pub fn use_mfp(wiphy: &Arc<Wiphy>, attrs: &[u8]) -> Result<u32, Errno> {
    let Some(v) = msg::get_u32(attrs, a::USE_MFP) else { return Ok(mfp::NO); };
    if v > mfp::MAX { return Err(Errno::Einval); }
    if v == mfp::OPTIONAL
        && !wiphy.caps.has_ext_feature(crate::uapi::enums::ext_feature::MFP_OPTIONAL) {
        return Err(Errno::Eopnotsupp);
    }
    Ok(v)
}

/// Frequency a request pins, checked against the radio's channel list.
/// # C: O(N channels)
pub fn pinned_freq(wiphy: &Arc<Wiphy>, attrs: &[u8], ty: u16) -> Result<Option<u32>, Errno> {
    let Some(freq) = msg::get_u32(attrs, ty) else { return Ok(None); };
    if wiphy.channel(freq).is_none() { return Err(Errno::Einval); }
    Ok(Some(freq))
}

/// Reason code a teardown carries. Zero is reserved and never sent.
/// # C: O(N attrs)
pub fn reason_code(attrs: &[u8], default: u16) -> Result<u16, Errno> {
    let reason = msg::get_u16(attrs, a::REASON_CODE).unwrap_or(default);
    if reason == 0 { return Err(Errno::Einval); }
    Ok(reason)
}
