// The encryption step of the transmit path.
//
// The protected bit is set by the SAME function that encrypts, and the
// integrity code the temporal-key cipher needs is added to the whole payload
// before fragmentation rather than to each fragment. Separating either from
// the other produces frames that look protected and are not, or fragments the
// peer reassembles into a frame whose integrity code covers the wrong bytes.

extern crate alloc;

use alloc::vec::Vec;

use wireless::ieee80211::{fctl, hdr::MacHeader, MacAddr};
use wireless::uapi::ciphers::cipher;

use crate::crypto::pn::Tsc;
use crate::crypto::{ccmp, gcmp, michael, tkip, wep, CryptoError, CryptoResult};
use crate::key::Key;

/// Set the protected bit in a frame's frame-control word. # C: O(1)
pub fn mark_protected(frame: &mut [u8]) {
    if frame.len() < 2 { return; }
    let fc = u16::from_le_bytes([frame[0], frame[1]]) | fctl::FCTL_PROTECTED;
    frame[0..2].copy_from_slice(&fc.to_le_bytes());
}

/// Add the temporal-key cipher's message integrity code to a payload, which
/// happens once per frame and BEFORE any fragmentation. # C: O(len)
pub fn add_michael_mic(key: &Key, header: &MacHeader, payload: &mut Vec<u8>)
    -> CryptoResult<()>
{
    if key.cipher != cipher::TKIP { return Ok(()); }
    let mic_key = tkip::tx_mic_key(&key.material).ok_or(CryptoError::BadKey)?;
    let mic = michael::michael_mic_hdr(mic_key, header, payload).ok_or(CryptoError::BadKey)?;
    payload.extend_from_slice(&mic);
    Ok(())
}

/// Encrypt one frame's payload under a key. The frame's own header must
/// already carry the protected bit — the additional authenticated data covers
/// it, so setting it afterwards produces a frame that fails its own integrity
/// check. # C: O(len)
pub fn encrypt_payload(key: &mut Key, key_idx: u8, header: &MacHeader, sa: MacAddr,
                       payload: &[u8]) -> CryptoResult<Vec<u8>> {
    if !key.may_transmit() { return Err(CryptoError::BadKey); }
    let out = match key.cipher {
        cipher::CCMP | cipher::CCMP_256 => {
            let pn = key.tx_pn.take().ok_or(CryptoError::BadKey)?;
            ccmp::encrypt(&key.material, header, pn, key_idx, payload)?
        }
        cipher::GCMP | cipher::GCMP_256 => {
            let pn = key.tx_pn.take().ok_or(CryptoError::BadKey)?;
            gcmp::encrypt(&key.material, header, pn, key_idx, payload)?
        }
        cipher::TKIP => {
            let pn = key.tx_pn.take().ok_or(CryptoError::BadKey)?;
            let tk = tkip::encr_key(&key.material).ok_or(CryptoError::BadKey)?;
            tkip::encrypt(tk, sa, Tsc::from_pn(pn), key_idx, payload)?
        }
        cipher::WEP40 | cipher::WEP104 => {
            let pn = key.tx_pn.take().ok_or(CryptoError::BadKey)?;
            wep::encrypt(&key.material, (pn.0 & 0xff_ffff) as u32, key_idx, payload)?
        }
        _ => return Err(CryptoError::BadKey),
    };
    key.tx_count += 1;
    Ok(out)
}

/// Build the whole protected frame: the header with its protected bit set,
/// then the cipher's output. # C: O(len)
pub fn protect_frame(key: &mut Key, key_idx: u8, header_bytes: &[u8], payload: &[u8],
                     sa: MacAddr) -> CryptoResult<Vec<u8>> {
    let mut hdr = header_bytes.to_vec();
    mark_protected(&mut hdr);
    let parsed = MacHeader::parse(&hdr).ok_or(CryptoError::TooShort)?;
    let mut body = payload.to_vec();
    add_michael_mic(key, &parsed, &mut body)?;
    let sealed = encrypt_payload(key, key_idx, &parsed, sa, &body)?;
    let mut out = Vec::with_capacity(hdr.len() + sealed.len());
    out.extend_from_slice(&hdr);
    out.extend_from_slice(&sealed);
    Ok(out)
}
