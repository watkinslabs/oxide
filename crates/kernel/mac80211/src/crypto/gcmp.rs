// Galois counter mode.
//
// The header is laid out exactly like the counter-mode one — same split of
// the packet number, same key-identifier octet — but the nonce is not: this
// cipher's initialisation vector is the transmitter address and the packet
// number with NO flags byte, so the two ciphers cannot share a nonce builder
// even though they share a header builder.

extern crate alloc;

use alloc::vec::Vec;

use aes::block::AesKey;
use aes::gcm;
use wireless::ieee80211::hdr::MacHeader;

use super::aad;
use super::ccmp::{EXT_IV, KEY_ID_SHIFT};
use super::pn::Pn;
use super::{CryptoError, CryptoResult};
use crate::uapi::cipher_len;

/// Build the eight-byte cipher header. # C: O(1)
pub fn build_hdr(pn: Pn, key_id: u8) -> [u8; cipher_len::GCMP_HDR] {
    let p = pn.to_bytes();
    [p[5], p[4], 0, EXT_IV | (key_id << KEY_ID_SHIFT), p[3], p[2], p[1], p[0]]
}

/// Read the packet number and key identifier back out. # C: O(1)
pub fn parse_hdr(h: &[u8]) -> CryptoResult<(Pn, u8)> { super::ccmp::parse_hdr(h) }

/// Encrypt one frame body. # C: O(len)
pub fn encrypt(key: &[u8], header: &MacHeader, pn: Pn, key_id: u8, payload: &[u8])
    -> CryptoResult<Vec<u8>>
{
    let aes = AesKey::new(key).ok_or(CryptoError::BadKey)?;
    let (extra, _tid) = aad::build(header);
    let iv = aad::gcm_iv(header, &pn.to_bytes());

    let mut out = Vec::with_capacity(cipher_len::GCMP_HDR + payload.len() + cipher_len::GCMP_MIC);
    out.extend_from_slice(&build_hdr(pn, key_id));
    out.extend_from_slice(payload);
    let mut tag = [0u8; cipher_len::GCMP_MIC];
    gcm::encrypt(&aes, &iv, &extra, &mut out[cipher_len::GCMP_HDR..], &mut tag)
        .map_err(|_| CryptoError::BadKey)?;
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Decrypt one frame body. Returns the packet number, the key identifier and
/// the plaintext; the replay decision belongs to the key that holds the
/// counters. # C: O(len)
pub fn decrypt(key: &[u8], header: &MacHeader, data: &[u8]) -> CryptoResult<(Pn, u8, Vec<u8>)> {
    let aes = AesKey::new(key).ok_or(CryptoError::BadKey)?;
    if data.len() < cipher_len::GCMP_HDR + cipher_len::GCMP_MIC {
        return Err(CryptoError::TooShort);
    }
    let (pn, key_id) = parse_hdr(data)?;
    let (extra, _tid) = aad::build(header);
    let iv = aad::gcm_iv(header, &pn.to_bytes());

    let ct_end = data.len() - cipher_len::GCMP_MIC;
    let mut tag = [0u8; cipher_len::GCMP_MIC];
    tag.copy_from_slice(&data[ct_end..]);
    let mut body = data[cipher_len::GCMP_HDR..ct_end].to_vec();
    gcm::decrypt(&aes, &iv, &extra, &mut body, &tag)
        .map_err(|_| CryptoError::IntegrityFailure)?;
    Ok((pn, key_id, body))
}

/// Bytes this cipher adds to a frame. # C: O(1)
pub fn overhead() -> usize { cipher_len::GCMP_HDR + cipher_len::GCMP_MIC }
