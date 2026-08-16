// Counter mode with cipher-block-chaining message authentication.
//
// The header this cipher writes is NOT the packet number in transmission
// order: the six bytes are split around the key-identifier octet and the two
// halves run in opposite directions. Every implementation that got this wrong
// produced frames the peer rejected with no diagnosis available, which is why
// the byte order lives in exactly two functions here and is pinned by a
// published test vector.

extern crate alloc;

use alloc::vec::Vec;

use aes::block::AesKey;
use aes::ccm;
use wireless::ieee80211::hdr::MacHeader;

use super::aad;
use super::pn::Pn;
use super::{CryptoError, CryptoResult};
use crate::uapi::cipher_len;

/// Bit in the key-identifier octet that marks the extended header. Every
/// frame this cipher produces sets it; a frame without it was produced by the
/// wired-equivalent cipher and must not be handed here.
pub const EXT_IV: u8 = 0x20;
/// Shift of the key identifier within its octet.
pub const KEY_ID_SHIFT: u32 = 6;

/// Build the eight-byte cipher header. # C: O(1)
pub fn build_hdr(pn: Pn, key_id: u8) -> [u8; cipher_len::CCMP_HDR] {
    let p = pn.to_bytes();
    [p[5], p[4], 0, EXT_IV | (key_id << KEY_ID_SHIFT), p[3], p[2], p[1], p[0]]
}

/// Read the packet number and key identifier back out of a cipher header.
/// # C: O(1)
pub fn parse_hdr(h: &[u8]) -> CryptoResult<(Pn, u8)> {
    let h = h.get(..cipher_len::CCMP_HDR).ok_or(CryptoError::TooShort)?;
    if h[3] & EXT_IV == 0 { return Err(CryptoError::NoExtIv); }
    let pn = [h[7], h[6], h[5], h[4], h[1], h[0]];
    Ok((Pn::from_bytes(&pn), h[3] >> KEY_ID_SHIFT))
}

/// Integrity-field width for a key of this length: the 256-bit variant keeps
/// the same header and doubles only the tag. # C: O(1)
pub fn mic_len(key_len: usize) -> usize {
    if key_len == 32 { cipher_len::CCMP_256_MIC } else { cipher_len::CCMP_MIC }
}

/// Encrypt one frame body. `header` is the frame's MAC header as parsed, and
/// `payload` is everything after it. What comes back is the cipher header,
/// the ciphertext and the integrity field, ready to sit where the payload
/// was. # C: O(len)
pub fn encrypt(key: &[u8], header: &MacHeader, pn: Pn, key_id: u8, payload: &[u8])
    -> CryptoResult<Vec<u8>>
{
    let aes = AesKey::new(key).ok_or(CryptoError::BadKey)?;
    let n = mic_len(key.len());
    let (extra, qos_tid) = aad::build(header);
    let nonce = aad::ccm_nonce(header, qos_tid, &pn.to_bytes());

    let mut out = Vec::with_capacity(cipher_len::CCMP_HDR + payload.len() + n);
    out.extend_from_slice(&build_hdr(pn, key_id));
    out.extend_from_slice(payload);
    let mut mic = [0u8; cipher_len::CCMP_256_MIC];
    let body = &mut out[cipher_len::CCMP_HDR..];
    ccm::encrypt(&aes, &nonce, &extra, body, &mut mic[..n])
        .map_err(|_| CryptoError::BadKey)?;
    out.extend_from_slice(&mic[..n]);
    Ok(out)
}

/// Decrypt one frame body in place of its ciphertext. Returns the packet
/// number the frame carried, the key identifier it named, and the plaintext.
/// The packet number is returned rather than checked here: the replay
/// decision needs the key's own counters, which this function does not hold.
/// # C: O(len)
pub fn decrypt(key: &[u8], header: &MacHeader, data: &[u8]) -> CryptoResult<(Pn, u8, Vec<u8>)> {
    let aes = AesKey::new(key).ok_or(CryptoError::BadKey)?;
    let n = mic_len(key.len());
    if data.len() < cipher_len::CCMP_HDR + n { return Err(CryptoError::TooShort); }
    let (pn, key_id) = parse_hdr(data)?;
    let (extra, qos_tid) = aad::build(header);
    let nonce = aad::ccm_nonce(header, qos_tid, &pn.to_bytes());

    let ct_end = data.len() - n;
    let mut body = data[cipher_len::CCMP_HDR..ct_end].to_vec();
    ccm::decrypt(&aes, &nonce, &extra, &mut body, &data[ct_end..])
        .map_err(|_| CryptoError::IntegrityFailure)?;
    Ok((pn, key_id, body))
}

/// Bytes this cipher adds to a frame of a given key length. # C: O(1)
pub fn overhead(key_len: usize) -> usize { cipher_len::CCMP_HDR + mic_len(key_len) }
