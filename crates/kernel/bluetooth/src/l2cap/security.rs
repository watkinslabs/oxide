//! The security decision: whether the link a channel wants to run over already
//! provides at least what the channel requires.
//!
//! A channel asking for more than its link provides must not be admitted. That
//! is the whole point of the per-channel level, so the decision is one named
//! function with no side effects, testable on its own.

use crate::hci::conn::Conn;
use crate::uapi::bt::{BT_SECURITY_FIPS, BT_SECURITY_LOW, BT_SECURITY_MEDIUM};
use crate::uapi::l2cap as u;

/// What a link currently provides.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct LinkSecurity {
    /// Level the link satisfies right now.
    pub level: u8,
    pub encrypted: bool,
    pub authenticated: bool,
    /// Encryption key size in bytes; meaningless while unencrypted.
    pub enc_key_size: u8,
}

impl LinkSecurity {
    /// Read the security a tracked link currently provides. # C: O(1)
    pub fn from_conn(c: &Conn) -> LinkSecurity {
        LinkSecurity {
            level: c.sec_level, encrypted: c.encrypted,
            authenticated: c.authenticated, enc_key_size: c.enc_key_size,
        }
    }
}

/// Why a channel may not be admitted onto a link.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Verdict {
    /// The link already provides what the channel requires.
    Sufficient,
    /// The link provides less than the channel requires; the level must be
    /// raised before the channel can open.
    Insufficient,
    /// The level is met but the encryption key is shorter than that level
    /// permits.
    KeySizeTooSmall,
}

/// Whether a provided level covers a required one. The levels are ordered, so
/// this is a comparison — with the lowest level satisfied by any link, since it
/// asks for nothing. # C: O(1)
pub fn level_sufficient(required: u8, provided: u8) -> bool {
    if required <= BT_SECURITY_LOW { return true; }
    provided >= required
}

/// Smallest encryption key a level accepts. Every level below the highest
/// shares one floor, chosen so a BR/EDR and an LE link are held to the same
/// standard; the highest level requires a full-width key. # C: O(1)
pub fn min_key_size(required: u8) -> u8 {
    if required == BT_SECURITY_FIPS { u::FIPS_ENC_KEY_SIZE } else { u::MIN_ENC_KEY_SIZE }
}

/// Whether the key in use is long enough for the level asked for. An
/// unencrypted link has no key size to check — the level check is what catches
/// it, and applying a key-size floor to a link with no key would refuse
/// channels that legitimately ask for nothing. # C: O(1)
pub fn key_size_sufficient(required: u8, link: &LinkSecurity) -> bool {
    if !link.encrypted { return true; }
    link.enc_key_size >= min_key_size(required)
}

/// Whether a channel requiring `required` may be admitted onto `link`.
/// # C: O(1)
pub fn admissible(required: u8, link: &LinkSecurity) -> Verdict {
    if !level_sufficient(required, link.level) { return Verdict::Insufficient; }
    if !key_size_sufficient(required, link) { return Verdict::KeySizeTooSmall; }
    Verdict::Sufficient
}

/// The credit-based connect result that reports a refusal. A channel asking for
/// the middle level wants encryption; anything above it wants an authenticated
/// pairing, and the two are distinct failures to the peer. # C: O(1)
pub fn le_refusal_result(verdict: Verdict, required: u8) -> u16 {
    match verdict {
        Verdict::Sufficient => u::CR_LE_SUCCESS,
        Verdict::KeySizeTooSmall => u::CR_LE_BAD_KEY_SIZE,
        Verdict::Insufficient => {
            if required == BT_SECURITY_MEDIUM { u::CR_LE_ENCRYPTION } else { u::CR_LE_AUTHENTICATION }
        }
    }
}

/// The BR/EDR connect result that reports a refusal. The BR/EDR enumeration has
/// one code for every security failure. # C: O(1)
pub fn bredr_refusal_result(verdict: Verdict) -> u16 {
    match verdict {
        Verdict::Sufficient => u::CR_SUCCESS,
        _ => u::CR_SEC_BLOCK,
    }
}

/// The level the legacy link-mode option asks for. The bits are cumulative and
/// the strongest one set wins; the highest level cannot be requested this way,
/// which is why setting its bit is refused rather than honoured. # C: O(1)
pub fn level_from_link_mode(lm: u32) -> Option<u8> {
    if lm & u::LM_FIPS != 0 { return None; }
    let mut level = BT_SECURITY_LOW;
    if lm & u::LM_AUTH != 0 { level = BT_SECURITY_LOW; }
    if lm & u::LM_ENCRYPT != 0 { level = BT_SECURITY_MEDIUM; }
    if lm & u::LM_SECURE != 0 { level = crate::uapi::bt::BT_SECURITY_HIGH; }
    Some(level)
}

/// The link-mode bits that describe a level, for reporting one back.
/// # C: O(1)
pub fn link_mode_from_level(level: u8) -> u32 {
    match level {
        BT_SECURITY_LOW => u::LM_AUTH,
        BT_SECURITY_MEDIUM => u::LM_AUTH | u::LM_ENCRYPT,
        crate::uapi::bt::BT_SECURITY_HIGH => u::LM_AUTH | u::LM_ENCRYPT | u::LM_SECURE,
        BT_SECURITY_FIPS => u::LM_AUTH | u::LM_ENCRYPT | u::LM_SECURE | u::LM_FIPS,
        _ => 0,
    }
}

#[cfg(test)]
#[path = "tests/security.rs"]
mod tests;
