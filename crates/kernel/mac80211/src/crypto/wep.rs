// The wired-equivalent cipher. It is here because a network that offers
// nothing else is still a network a station must be able to join, and because
// the temporal-key cipher's payload transform is the same one — implemented
// once, used twice.

extern crate alloc;

use alloc::vec::Vec;

use super::{crc32, rc4, CryptoError, CryptoResult};
use crate::uapi::cipher_len;

/// Width of the per-frame initialisation vector.
pub const IV_LEN: usize = 3;
/// Shift of the key identifier in the octet after the vector.
pub const KEY_ID_SHIFT: u32 = 6;

/// Build the four-byte header: the vector, then the key identifier.
/// # C: O(1)
pub fn build_hdr(iv: u32, key_id: u8) -> [u8; cipher_len::WEP_IV] {
    [(iv & 0xff) as u8, ((iv >> 8) & 0xff) as u8, ((iv >> 16) & 0xff) as u8,
     key_id << KEY_ID_SHIFT]
}

/// Read the vector and key identifier back out. # C: O(1)
pub fn parse_hdr(h: &[u8]) -> CryptoResult<(u32, u8)> {
    let h = h.get(..cipher_len::WEP_IV).ok_or(CryptoError::TooShort)?;
    let iv = h[0] as u32 | ((h[1] as u32) << 8) | ((h[2] as u32) << 16);
    Ok((iv, h[3] >> KEY_ID_SHIFT))
}

/// The per-frame key: the vector prepended to the shared key. # C: O(len)
fn frame_key(iv: u32, key: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(IV_LEN + key.len());
    k.extend_from_slice(&build_hdr(iv, 0)[..IV_LEN]);
    k.extend_from_slice(key);
    k
}

/// Encrypt one frame body. # C: O(len)
pub fn encrypt(key: &[u8], iv: u32, key_id: u8, payload: &[u8]) -> CryptoResult<Vec<u8>> {
    if key.is_empty() { return Err(CryptoError::BadKey); }
    let mut out = Vec::with_capacity(cipher_len::WEP_IV + payload.len() + cipher_len::WEP_ICV);
    out.extend_from_slice(&build_hdr(iv, key_id));
    out.extend_from_slice(payload);
    out.extend_from_slice(&crc32::icv_bytes(payload));
    rc4::apply(&frame_key(iv, key), &mut out[cipher_len::WEP_IV..]);
    Ok(out)
}

/// Decrypt one frame body and verify its check value. # C: O(len)
pub fn decrypt(key: &[u8], data: &[u8]) -> CryptoResult<(u32, u8, Vec<u8>)> {
    if key.is_empty() { return Err(CryptoError::BadKey); }
    if data.len() < cipher_len::WEP_IV + cipher_len::WEP_ICV {
        return Err(CryptoError::TooShort);
    }
    let (iv, key_id) = parse_hdr(data)?;
    let mut body = data[cipher_len::WEP_IV..].to_vec();
    rc4::apply(&frame_key(iv, key), &mut body);
    let split = body.len() - cipher_len::WEP_ICV;
    if body[split..] != crc32::icv_bytes(&body[..split]) {
        return Err(CryptoError::IntegrityFailure);
    }
    body.truncate(split);
    Ok((iv, key_id, body))
}

/// Bytes this cipher adds to a frame. # C: O(1)
pub fn overhead() -> usize { cipher_len::WEP_IV + cipher_len::WEP_ICV }
