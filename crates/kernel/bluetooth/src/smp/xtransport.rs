//! Cross-transport key derivation.
//!
//! A pairing on one transport produces a key for the other, so a device paired
//! over one radio need not be paired again over the second. Two generations
//! exist: the first keys the derivation on the key being converted, the second
//! keys it on a salt instead. Both sides must agree on which, and the second
//! is only used when both advertised it — deriving with the wrong one yields a
//! key neither side can use and no diagnostic beyond a failed encryption.

use crate::uapi::smp::SMP_KEY_LEN;
use super::crypto::{h6, h7};

/// Identifier mixed in when converting a long-term key, stored
/// least-significant-first.
pub const KEY_ID_TMP1: [u8; 4] = [0x31, 0x70, 0x6d, 0x74];
/// Identifier mixed in when converting a link key.
pub const KEY_ID_TMP2: [u8; 4] = [0x32, 0x70, 0x6d, 0x74];
/// Identifier selecting the low-energy to basic-rate direction.
pub const KEY_ID_LEBR: [u8; 4] = [0x72, 0x62, 0x65, 0x6c];
/// Identifier selecting the basic-rate to low-energy direction.
pub const KEY_ID_BRLE: [u8; 4] = [0x65, 0x6c, 0x72, 0x62];

/// The second-generation salt for an identifier: the four bytes followed by
/// zeros to a full block. # C: O(1)
pub fn ct2_salt(key_id: &[u8; 4]) -> [u8; SMP_KEY_LEN] {
    let mut salt = [0u8; SMP_KEY_LEN];
    salt[..key_id.len()].copy_from_slice(key_id);
    salt
}

/// Derive a basic-rate link key from a long-term key. # C: O(1)
pub fn ltk_to_link_key(ltk: &[u8; SMP_KEY_LEN], ct2: bool) -> [u8; SMP_KEY_LEN] {
    let tmp = if ct2 { h7(ltk, &ct2_salt(&KEY_ID_TMP1)) } else { h6(ltk, &KEY_ID_TMP1) };
    h6(&tmp, &KEY_ID_LEBR)
}

/// Derive a long-term key from a basic-rate link key. # C: O(1)
pub fn link_key_to_ltk(link_key: &[u8; SMP_KEY_LEN], ct2: bool) -> [u8; SMP_KEY_LEN] {
    let tmp = if ct2 { h7(link_key, &ct2_salt(&KEY_ID_TMP2)) } else { h6(link_key, &KEY_ID_TMP2) };
    h6(&tmp, &KEY_ID_BRLE)
}
