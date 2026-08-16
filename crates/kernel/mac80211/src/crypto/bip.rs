// Management-frame integrity: the element appended to a robust management
// frame and the code computed over it.
//
// The element is authenticated WITH ITS OWN INTEGRITY FIELD ZEROED and then
// the field is filled in — a verifier that forgets to zero it before
// recomputing rejects every frame, and one that authenticates the frame
// without the element at all accepts a frame whose sequence number an
// attacker replaced.

extern crate alloc;

use alloc::vec::Vec;

use aes::block::AesKey;
use aes::cmac;
use wireless::ieee80211::{fctl, hdr::MacHeader};

use super::pn::Pn;
use super::{CryptoError, CryptoResult};

/// Element identifier of the integrity element.
pub const EID_MMIE: u8 = 76;
/// Element body width for the 128-bit code: key identifier, sequence number,
/// and the code itself.
pub const MMIE_BODY_LEN: usize = 2 + 6 + 8;
/// Element body width for the 256-bit code.
pub const MMIE_BODY_LEN_256: usize = 2 + 6 + 16;
/// Additional authenticated data width: the masked frame-control word and
/// three addresses.
pub const AAD_LEN: usize = 2 + 18;
/// Bits masked out of the frame-control word before it is authenticated.
const MASK_CLEAR: u16 = fctl::FCTL_RETRY | fctl::FCTL_PM | fctl::FCTL_MOREDATA;

/// Code width a key of this length produces. # C: O(1)
pub fn mic_len(key_len: usize) -> usize { if key_len == 32 { 16 } else { 8 } }

/// Build the additional authenticated data. # C: O(1)
pub fn build_aad(header: &MacHeader) -> [u8; AAD_LEN] {
    let mut aad = [0u8; AAD_LEN];
    aad[0..2].copy_from_slice(&(header.frame_control & !MASK_CLEAR).to_le_bytes());
    aad[2..8].copy_from_slice(&header.addr1.0);
    aad[8..14].copy_from_slice(&header.addr2.map_or([0u8; 6], |a| a.0));
    aad[14..20].copy_from_slice(&header.addr3.map_or([0u8; 6], |a| a.0));
    aad
}

/// The element with a zeroed code, as it is authenticated. # C: O(1)
fn mmie_zeroed(key_id: u8, ipn: Pn, mic_len: usize) -> Vec<u8> {
    let mut e = Vec::with_capacity(2 + 8 + mic_len);
    e.push(EID_MMIE);
    e.push((8 + mic_len) as u8);
    e.extend_from_slice(&(key_id as u16).to_le_bytes());
    // The sequence number goes out least significant byte first, the opposite
    // order to the counter-mode ciphers' packet number.
    let p = ipn.to_bytes();
    e.extend_from_slice(&[p[5], p[4], p[3], p[2], p[1], p[0]]);
    e.resize(e.len() + mic_len, 0);
    e
}

/// Append the integrity element to a management frame body. `body` is
/// everything after the MAC header. Returns the element to append.
/// # C: O(len)
pub fn protect(key: &[u8], header: &MacHeader, body: &[u8], key_id: u8, ipn: Pn)
    -> CryptoResult<Vec<u8>>
{
    let aes = AesKey::new(key).ok_or(CryptoError::BadKey)?;
    let n = mic_len(key.len());
    let mut elem = mmie_zeroed(key_id, ipn, n);
    let aad = build_aad(header);

    let mut msg = Vec::with_capacity(AAD_LEN + body.len() + elem.len());
    msg.extend_from_slice(&aad);
    msg.extend_from_slice(body);
    msg.extend_from_slice(&elem);
    let mut mic = [0u8; 16];
    cmac::Cmac::with_key(aes.clone()).mac_into(&msg, &mut mic[..n]);
    let at = elem.len() - n;
    elem[at..].copy_from_slice(&mic[..n]);
    Ok(elem)
}

/// Verify a management frame that carries the element as its last bytes.
/// Returns the sequence number the frame carried, so the caller can apply its
/// replay rule. # C: O(len)
pub fn verify(key: &[u8], header: &MacHeader, body: &[u8]) -> CryptoResult<(Pn, u8)> {
    let aes = AesKey::new(key).ok_or(CryptoError::BadKey)?;
    let n = mic_len(key.len());
    let elem_len = 2 + 8 + n;
    if body.len() < elem_len { return Err(CryptoError::TooShort); }
    let split = body.len() - elem_len;
    let elem = &body[split..];
    if elem[0] != EID_MMIE || elem[1] as usize != 8 + n { return Err(CryptoError::BadKey); }
    let key_id = u16::from_le_bytes([elem[2], elem[3]]) as u8;
    let seq = &elem[4..10];
    let ipn = Pn::from_bytes(&[seq[5], seq[4], seq[3], seq[2], seq[1], seq[0]]);

    let mut msg = Vec::with_capacity(AAD_LEN + body.len());
    msg.extend_from_slice(&build_aad(header));
    msg.extend_from_slice(&body[..split]);
    msg.extend_from_slice(&mmie_zeroed(key_id, ipn, n));
    let mut want = [0u8; 16];
    cmac::Cmac::with_key(aes.clone()).mac_into(&msg, &mut want[..n]);
    if want[..n] != elem[10..] { return Err(CryptoError::IntegrityFailure); }
    Ok((ipn, key_id))
}
