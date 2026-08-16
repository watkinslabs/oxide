// The temporal-key cipher: a per-frame key derived from the temporal key, the
// transmitter address and the sequence counter, then the stream cipher over
// the payload and its check value.
//
// The two-phase mixing exists so the expensive half depends only on the upper
// 32 bits of the counter and is recomputed once every 65536 frames rather
// than once per frame. The cheap half must run per frame: reusing a per-frame
// key is what the mixing was introduced to prevent.

extern crate alloc;

use alloc::vec::Vec;

use wireless::ieee80211::MacAddr;

use super::pn::Tsc;
use super::{crc32, rc4, CryptoError, CryptoResult};
use crate::uapi::{cipher_len, tkip_key};

/// Rounds of the first mixing phase.
const PHASE1_ROUNDS: usize = 8;
/// Words of intermediate key material the first phase produces.
const P1K_LEN: usize = 5;
/// Width of the per-frame key the second phase produces.
pub const RC4_KEY_LEN: usize = 16;
/// Bit in the key-identifier octet marking the extended counter.
pub const EXT_IV: u8 = 0x20;
/// Shift of the key identifier within its octet.
pub const KEY_ID_SHIFT: u32 = 6;

/// A two-byte-wide substitution table derived from the block cipher's own
/// table; the second half is the first half byte-swapped, which is why only
/// half is stored.
const SBOX: [u16; 256] = [
    0xC6A5, 0xF884, 0xEE99, 0xF68D, 0xFF0D, 0xD6BD, 0xDEB1, 0x9154,
    0x6050, 0x0203, 0xCEA9, 0x567D, 0xE719, 0xB562, 0x4DE6, 0xEC9A,
    0x8F45, 0x1F9D, 0x8940, 0xFA87, 0xEF15, 0xB2EB, 0x8EC9, 0xFB0B,
    0x41EC, 0xB367, 0x5FFD, 0x45EA, 0x23BF, 0x53F7, 0xE496, 0x9B5B,
    0x75C2, 0xE11C, 0x3DAE, 0x4C6A, 0x6C5A, 0x7E41, 0xF502, 0x834F,
    0x685C, 0x51F4, 0xD134, 0xF908, 0xE293, 0xAB73, 0x6253, 0x2A3F,
    0x080C, 0x9552, 0x4665, 0x9D5E, 0x3028, 0x37A1, 0x0A0F, 0x2FB5,
    0x0E09, 0x2436, 0x1B9B, 0xDF3D, 0xCD26, 0x4E69, 0x7FCD, 0xEA9F,
    0x121B, 0x1D9E, 0x5874, 0x342E, 0x362D, 0xDCB2, 0xB4EE, 0x5BFB,
    0xA4F6, 0x764D, 0xB761, 0x7DCE, 0x527B, 0xDD3E, 0x5E71, 0x1397,
    0xA6F5, 0xB968, 0x0000, 0xC12C, 0x4060, 0xE31F, 0x79C8, 0xB6ED,
    0xD4BE, 0x8D46, 0x67D9, 0x724B, 0x94DE, 0x98D4, 0xB0E8, 0x854A,
    0xBB6B, 0xC52A, 0x4FE5, 0xED16, 0x86C5, 0x9AD7, 0x6655, 0x1194,
    0x8ACF, 0xE910, 0x0406, 0xFE81, 0xA0F0, 0x7844, 0x25BA, 0x4BE3,
    0xA2F3, 0x5DFE, 0x80C0, 0x058A, 0x3FAD, 0x21BC, 0x7048, 0xF104,
    0x63DF, 0x77C1, 0xAF75, 0x4263, 0x2030, 0xE51A, 0xFD0E, 0xBF6D,
    0x814C, 0x1814, 0x2635, 0xC32F, 0xBEE1, 0x35A2, 0x88CC, 0x2E39,
    0x9357, 0x55F2, 0xFC82, 0x7A47, 0xC8AC, 0xBAE7, 0x322B, 0xE695,
    0xC0A0, 0x1998, 0x9ED1, 0xA37F, 0x4466, 0x547E, 0x3BAB, 0x0B83,
    0x8CCA, 0xC729, 0x6BD3, 0x283C, 0xA779, 0xBCE2, 0x161D, 0xAD76,
    0xDB3B, 0x6456, 0x744E, 0x141E, 0x92DB, 0x0C0A, 0x486C, 0xB8E4,
    0x9F5D, 0xBD6E, 0x43EF, 0xC4A6, 0x39A8, 0x31A4, 0xD337, 0xF28B,
    0xD532, 0x8B43, 0x6E59, 0xDAB7, 0x018C, 0xB164, 0x9CD2, 0x49E0,
    0xD8B4, 0xACFA, 0xF307, 0xCF25, 0xCAAF, 0xF48E, 0x47E9, 0x1018,
    0x6FD5, 0xF088, 0x4A6F, 0x5C72, 0x3824, 0x57F1, 0x73C7, 0x9751,
    0xCB23, 0xA17C, 0xE89C, 0x3E21, 0x96DD, 0x61DC, 0x0D86, 0x0F85,
    0xE090, 0x7C42, 0x71C4, 0xCCAA, 0x90D8, 0x0605, 0xF701, 0x1C12,
    0xC2A3, 0x6A5F, 0xAEF9, 0x69D0, 0x1791, 0x9958, 0x3A27, 0x27B9,
    0xD938, 0xEB13, 0x2BB3, 0x2233, 0xD2BB, 0xA970, 0x0789, 0x33A7,
    0x2DB6, 0x3C22, 0x1592, 0xC920, 0x8749, 0xAAFF, 0x5078, 0xA57A,
    0x038F, 0x59F8, 0x0980, 0x1A17, 0x65DA, 0xD731, 0x84C6, 0xD0B8,
    0x82C3, 0x29B0, 0x5A77, 0x1E11, 0x7BCB, 0xA8FC, 0x6DD6, 0x2C3A,
];

fn sbox(val: u16) -> u16 { SBOX[(val & 0xff) as usize] ^ SBOX[(val >> 8) as usize].swap_bytes() }
fn le16(b: &[u8]) -> u16 { u16::from_le_bytes([b[0], b[1]]) }

/// Intermediate key material, valid for one value of the counter's upper
/// half.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct P1k {
    words: [u16; P1K_LEN],
    /// Counter half this material was derived for; material derived for a
    /// different one produces a per-frame key the peer will not have.
    pub iv32: u32,
    pub valid: bool,
}

/// First mixing phase: temporal key, transmitter address and the counter's
/// upper half. # C: O(1)
pub fn phase1(tk: &[u8], ta: MacAddr, iv32: u32) -> P1k {
    let mut p = [0u16; P1K_LEN];
    p[0] = (iv32 & 0xffff) as u16;
    p[1] = (iv32 >> 16) as u16;
    p[2] = le16(&ta.0[0..2]);
    p[3] = le16(&ta.0[2..4]);
    p[4] = le16(&ta.0[4..6]);
    for i in 0..PHASE1_ROUNDS {
        let j = 2 * (i & 1);
        p[0] = p[0].wrapping_add(sbox(p[4] ^ le16(&tk[j..])));
        p[1] = p[1].wrapping_add(sbox(p[0] ^ le16(&tk[4 + j..])));
        p[2] = p[2].wrapping_add(sbox(p[1] ^ le16(&tk[8 + j..])));
        p[3] = p[3].wrapping_add(sbox(p[2] ^ le16(&tk[12 + j..])));
        p[4] = p[4].wrapping_add(sbox(p[3] ^ le16(&tk[j..]))).wrapping_add(i as u16);
    }
    P1k { words: p, iv32, valid: true }
}

/// Second mixing phase: the per-frame key, which begins with the three
/// counter bytes the header also carries. # C: O(1)
pub fn phase2(tk: &[u8], p1k: &P1k, iv16: u16) -> [u8; RC4_KEY_LEN] {
    let p = &p1k.words;
    let mut ppk = [p[0], p[1], p[2], p[3], p[4], p[4].wrapping_add(iv16)];
    ppk[0] = ppk[0].wrapping_add(sbox(ppk[5] ^ le16(&tk[0..])));
    ppk[1] = ppk[1].wrapping_add(sbox(ppk[0] ^ le16(&tk[2..])));
    ppk[2] = ppk[2].wrapping_add(sbox(ppk[1] ^ le16(&tk[4..])));
    ppk[3] = ppk[3].wrapping_add(sbox(ppk[2] ^ le16(&tk[6..])));
    ppk[4] = ppk[4].wrapping_add(sbox(ppk[3] ^ le16(&tk[8..])));
    ppk[5] = ppk[5].wrapping_add(sbox(ppk[4] ^ le16(&tk[10..])));
    ppk[0] = ppk[0].wrapping_add((ppk[5] ^ le16(&tk[12..])).rotate_right(1));
    ppk[1] = ppk[1].wrapping_add((ppk[0] ^ le16(&tk[14..])).rotate_right(1));
    ppk[2] = ppk[2].wrapping_add(ppk[1].rotate_right(1));
    ppk[3] = ppk[3].wrapping_add(ppk[2].rotate_right(1));
    ppk[4] = ppk[4].wrapping_add(ppk[3].rotate_right(1));
    ppk[5] = ppk[5].wrapping_add(ppk[4].rotate_right(1));

    let mut key = [0u8; RC4_KEY_LEN];
    key[0] = (iv16 >> 8) as u8;
    key[1] = (((iv16 >> 8) | 0x20) & 0x7f) as u8;
    key[2] = (iv16 & 0xff) as u8;
    key[3] = ((ppk[5] ^ le16(&tk[0..])) >> 1) as u8;
    for i in 0..6 { key[4 + i * 2..6 + i * 2].copy_from_slice(&ppk[i].to_le_bytes()); }
    key
}

/// Build the eight-byte cipher header. The first three bytes repeat the
/// counter's lower half in the same weakened form the per-frame key starts
/// with, which is part of the wire format and not a mistake. # C: O(1)
pub fn build_hdr(tsc: Tsc, key_id: u8) -> [u8; cipher_len::TKIP_IV] {
    let mut h = [0u8; cipher_len::TKIP_IV];
    h[0] = (tsc.iv16 >> 8) as u8;
    h[1] = (((tsc.iv16 >> 8) | 0x20) & 0x7f) as u8;
    h[2] = (tsc.iv16 & 0xff) as u8;
    h[3] = EXT_IV | (key_id << KEY_ID_SHIFT);
    h[4..8].copy_from_slice(&tsc.iv32.to_le_bytes());
    h
}

/// Read the counter and key identifier back out. # C: O(1)
pub fn parse_hdr(h: &[u8]) -> CryptoResult<(Tsc, u8)> {
    let h = h.get(..cipher_len::TKIP_IV).ok_or(CryptoError::TooShort)?;
    if h[3] & EXT_IV == 0 { return Err(CryptoError::NoExtIv); }
    let iv16 = ((h[0] as u16) << 8) | h[2] as u16;
    let iv32 = u32::from_le_bytes([h[4], h[5], h[6], h[7]]);
    Ok((Tsc { iv16, iv32 }, h[3] >> KEY_ID_SHIFT))
}

/// The encryption half of a temporal-key blob. # C: O(1)
pub fn encr_key(blob: &[u8]) -> Option<&[u8]> {
    blob.get(tkip_key::ENCR_OFFSET..tkip_key::ENCR_OFFSET + tkip_key::ENCR_LEN)
}
/// The integrity key a sender uses. # C: O(1)
pub fn tx_mic_key(blob: &[u8]) -> Option<&[u8]> {
    blob.get(tkip_key::TX_MIC_OFFSET..tkip_key::TX_MIC_OFFSET + tkip_key::MIC_LEN)
}
/// The integrity key a receiver checks with. # C: O(1)
pub fn rx_mic_key(blob: &[u8]) -> Option<&[u8]> {
    blob.get(tkip_key::RX_MIC_OFFSET..tkip_key::RX_MIC_OFFSET + tkip_key::MIC_LEN)
}

/// Encrypt one frame body: header, then the payload and its check value
/// under the per-frame key. # C: O(len)
pub fn encrypt(tk: &[u8], ta: MacAddr, tsc: Tsc, key_id: u8, payload: &[u8])
    -> CryptoResult<Vec<u8>>
{
    if tk.len() < tkip_key::ENCR_LEN { return Err(CryptoError::BadKey); }
    let p1k = phase1(tk, ta, tsc.iv32);
    let rc4key = phase2(tk, &p1k, tsc.iv16);
    let mut out = Vec::with_capacity(cipher_len::TKIP_IV + payload.len() + cipher_len::TKIP_ICV);
    out.extend_from_slice(&build_hdr(tsc, key_id));
    out.extend_from_slice(payload);
    out.extend_from_slice(&crc32::icv_bytes(payload));
    rc4::apply(&rc4key, &mut out[cipher_len::TKIP_IV..]);
    Ok(out)
}

/// Decrypt one frame body and verify its check value. Returns the counter the
/// frame carried, the key identifier it named, and the plaintext.
/// # C: O(len)
pub fn decrypt(tk: &[u8], ta: MacAddr, data: &[u8]) -> CryptoResult<(Tsc, u8, Vec<u8>)> {
    if tk.len() < tkip_key::ENCR_LEN { return Err(CryptoError::BadKey); }
    if data.len() < cipher_len::TKIP_IV + cipher_len::TKIP_ICV {
        return Err(CryptoError::TooShort);
    }
    let (tsc, key_id) = parse_hdr(data)?;
    let p1k = phase1(tk, ta, tsc.iv32);
    let rc4key = phase2(tk, &p1k, tsc.iv16);
    let mut body = data[cipher_len::TKIP_IV..].to_vec();
    rc4::apply(&rc4key, &mut body);
    let split = body.len() - cipher_len::TKIP_ICV;
    let want = crc32::icv_bytes(&body[..split]);
    if body[split..] != want { return Err(CryptoError::IntegrityFailure); }
    body.truncate(split);
    Ok((tsc, key_id, body))
}

/// Bytes this cipher adds to a frame, integrity code excluded — that is added
/// to the whole MSDU before fragmentation, not to each fragment. # C: O(1)
pub fn overhead() -> usize { cipher_len::TKIP_IV + cipher_len::TKIP_ICV }
