//! Security levels: what a requirement asks for, what a key provides, and
//! whether a link already satisfies a request.
//!
//! The mapping is not a simple ordering of the requirement bits. A key is only
//! at the highest level if it both authenticates the peer and came from a
//! secure-connections exchange; a man-in-the-middle requirement alone caps it
//! one level lower whatever else the exchange negotiated.

use crate::uapi::bt::{BT_SECURITY_FIPS, BT_SECURITY_HIGH, BT_SECURITY_LOW, BT_SECURITY_MEDIUM};
use crate::uapi::smp::{
    SMP_AUTH_BONDING, SMP_AUTH_MITM, SMP_AUTH_NONE, SMP_AUTH_SC, SMP_ENC_KEY_SIZE,
    SMP_LTK_P256, SMP_LTK_P256_DEBUG, SMP_MAX_ENC_KEY_SIZE, SMP_MIN_ENC_KEY_SIZE,
};

/// Whether a stored long-term key may be re-used, or whether the caller wants
/// a fresh long-term key even though a short-term one is already encrypting.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum KeyPref {
    /// A short-term key encrypting the link is good enough.
    AllowStk,
    /// A short-term key is not, if a long-term one exists to replace it.
    UseLtk,
}

/// The level a set of authentication requirements asks for. # C: O(1)
pub fn authreq_to_seclevel(authreq: u8) -> u8 {
    if authreq & SMP_AUTH_MITM != 0 {
        if authreq & SMP_AUTH_SC != 0 { BT_SECURITY_FIPS } else { BT_SECURITY_HIGH }
    } else {
        BT_SECURITY_MEDIUM
    }
}

/// The requirements that ask for a level. Note the asymmetry with the reverse
/// mapping: asking for the highest level does not itself set the
/// secure-connections bit, which is negotiated separately. # C: O(1)
pub fn seclevel_to_authreq(sec_level: u8) -> u8 {
    match sec_level {
        BT_SECURITY_FIPS | BT_SECURITY_HIGH => SMP_AUTH_MITM | SMP_AUTH_BONDING,
        BT_SECURITY_MEDIUM => SMP_AUTH_BONDING,
        _ => SMP_AUTH_NONE,
    }
}

/// Whether a key type came from a secure-connections exchange. # C: O(1)
pub fn ltk_is_sc(key_type: u8) -> bool {
    key_type == SMP_LTK_P256 || key_type == SMP_LTK_P256_DEBUG
}

/// The level a stored key can support. # C: O(1)
pub fn ltk_sec_level(key_type: u8, authenticated: bool) -> u8 {
    if authenticated {
        if ltk_is_sc(key_type) { BT_SECURITY_FIPS } else { BT_SECURITY_HIGH }
    } else {
        BT_SECURITY_MEDIUM
    }
}

/// Validate the negotiated encryption key size against the level being
/// pursued and the controller's own limit.
///
/// The highest level admits only a full-width key: a shorter one would leave
/// the link at a strength the level's name does not describe. `Ok` carries the
/// size to use, `Err` the failure reason to send. # C: O(1)
pub fn check_enc_key_size(pending_level: u8, max_key_size: u8, controller_max: u8) -> Result<u8, u8> {
    if pending_level == BT_SECURITY_FIPS && max_key_size != SMP_MAX_ENC_KEY_SIZE {
        return Err(SMP_ENC_KEY_SIZE);
    }
    if max_key_size > controller_max || max_key_size < SMP_MIN_ENC_KEY_SIZE {
        return Err(SMP_ENC_KEY_SIZE);
    }
    Ok(max_key_size)
}

/// Whether a link already satisfies a requested level.
///
/// A link encrypted with a short-term key reports insufficient security when
/// the caller wants a long-term one and a long-term one exists, so the link is
/// re-encrypted with the stored key rather than left on the pairing key.
/// # C: O(1)
pub fn sufficient_security(
    current_level: u8,
    stk_encrypted: bool,
    have_ltk: bool,
    want: u8,
    pref: KeyPref,
) -> bool {
    if want == BT_SECURITY_LOW { return true; }
    if pref == KeyPref::UseLtk && stk_encrypted && have_ltk { return false; }
    current_level >= want
}
