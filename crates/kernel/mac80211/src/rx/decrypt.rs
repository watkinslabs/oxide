// The decryption step of the receive chain.
//
// Two rules here are load-bearing and neither fails loudly when broken.
//
// The first: a frame that arrives UNPROTECTED on an interface that has keys
// must not be delivered as if it had been protected. An attacker can always
// send a frame with the protected bit clear; the only thing that makes that
// useless is refusing it.
//
// The second: the replay counter advances only AFTER the integrity check
// passes. Advancing it first lets an attacker replay a frame with a forged
// high packet number and push the counter past every genuine frame still in
// flight, which silently drops them all.

extern crate alloc;

use alloc::vec::Vec;

use wireless::ieee80211::{fctl, hdr::MacHeader};
use wireless::uapi::ciphers::cipher;

use crate::crypto::pn::{Pn, Tsc};
use crate::crypto::{ccmp, gcmp, michael, tkip, wep, CryptoError};
use crate::key::KeySet;
use crate::uapi::{cipher_len, tkip_key};

/// What came out of the decryption step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Decrypted {
    /// The frame was not protected and did not need to be.
    Plain,
    /// The frame was protected and here is its plaintext body.
    Ok { body: Vec<u8>, key_idx: u8 },
    /// The frame must be dropped.
    Drop(CryptoError),
    /// The frame failed its integrity code, which is reported upward as well
    /// as dropped: two of them in a minute mean the link is under attack and
    /// the network takes countermeasures.
    MicFailure { key_idx: u8 },
}

/// Whether a received DATA frame must be protected on this interface.
///
/// Management frames are deliberately not covered here. An unprotected robust
/// management frame on a protected link is not merely dropped: it is REPORTED
/// upward under its own event and the link is left alone, and a decision made
/// here would have thrown it away before anyone could report it. That
/// decision lives with the management dispatch. # C: O(1)
pub fn requires_protection(fc: u16, keys: &KeySet, _mfp: bool) -> bool {
    fctl::is_data(fc) && !fctl::is_nodata(fc) && keys.any()
}

/// Run the decryption step over one frame body. `body` is everything after
/// the MAC header. # C: O(len)
pub fn decrypt(keys: &mut KeySet, header: &MacHeader, body: &[u8], mfp: bool) -> Decrypted {
    let fc = header.frame_control;
    if !fctl::is_protected(fc) {
        if requires_protection(fc, keys, mfp) { return Decrypted::Drop(CryptoError::BadKey); }
        return Decrypted::Plain;
    }
    let Some(sender) = header.transmitter() else { return Decrypted::Drop(CryptoError::BadKey); };
    let unicast = !header.addr1.is_multicast();

    // The key index is in the same octet for every cipher this layer
    // installs, which is what makes selecting the key before knowing the
    // cipher possible at all.
    let Some(&id_octet) = body.get(3) else { return Decrypted::Drop(CryptoError::TooShort); };
    let hdr_idx = id_octet >> 6;

    let Some(key) = keys.rx_key(sender, unicast, hdr_idx) else {
        return Decrypted::Drop(CryptoError::BadKey);
    };
    let cipher_id = key.cipher;
    let material = key.material.clone();
    let tid = if fctl::is_data_qos(fc) { Some(header.tid()) } else { None };

    let (pn, key_idx, plain) = match cipher_id {
        cipher::CCMP | cipher::CCMP_256 => match ccmp::decrypt(&material, header, body) {
            Ok((pn, idx, body)) => (pn, idx, body),
            Err(e) => return Decrypted::Drop(e),
        },
        cipher::GCMP | cipher::GCMP_256 => match gcmp::decrypt(&material, header, body) {
            Ok((pn, idx, body)) => (pn, idx, body),
            Err(e) => return Decrypted::Drop(e),
        },
        cipher::TKIP => match tkip::decrypt(&material, sender, body) {
            Ok((tsc, idx, body)) => (tsc.to_pn(), idx, body),
            Err(e) => return Decrypted::Drop(e),
        },
        cipher::WEP40 | cipher::WEP104 => match wep::decrypt(&material, body) {
            // The wired-equivalent cipher has no replay counter at all; its
            // per-frame vector is not one and must not be treated as one.
            Ok((_iv, idx, body)) => return finish_wep(keys, idx, body),
            Err(e) => return Decrypted::Drop(e),
        },
        _ => return Decrypted::Drop(CryptoError::BadKey),
    };

    // Integrity passed; now, and only now, the replay counter may move.
    let Some(key) = keys.rx_key_mut(sender, unicast, hdr_idx) else {
        return Decrypted::Drop(CryptoError::BadKey);
    };
    if !key.rx_pn.accept(tid, pn) { return Decrypted::Drop(CryptoError::Replay); }
    key.rx_count += 1;

    if cipher_id == cipher::TKIP {
        // The temporal-key cipher's own check value covers the fragment; the
        // message integrity code covers the whole reassembled frame and is
        // verified once, here, over the payload it protects.
        let Some(mic_key) = tkip::rx_mic_key(&material) else {
            return Decrypted::Drop(CryptoError::BadKey);
        };
        if plain.len() < cipher_len::MICHAEL_MIC {
            return Decrypted::Drop(CryptoError::TooShort);
        }
        let split = plain.len() - cipher_len::MICHAEL_MIC;
        let Some(want) = michael::michael_mic_hdr(mic_key, header, &plain[..split]) else {
            return Decrypted::Drop(CryptoError::BadKey);
        };
        if want[..] != plain[split..] { return Decrypted::MicFailure { key_idx }; }
        return Decrypted::Ok { body: plain[..split].to_vec(), key_idx };
    }
    Decrypted::Ok { body: plain, key_idx }
}

fn finish_wep(keys: &mut KeySet, key_idx: u8, body: Vec<u8>) -> Decrypted {
    if let Some(key) = keys.get_mut(key_idx, false, None) { key.rx_count += 1; }
    Decrypted::Ok { body, key_idx }
}

/// The counter a temporal-key frame carried, for the failure report a message
/// integrity failure raises. # C: O(1)
pub fn tkip_tsc_bytes(body: &[u8]) -> Option<[u8; 6]> {
    let (tsc, _) = tkip::parse_hdr(body).ok()?;
    let pn = Tsc { iv16: tsc.iv16, iv32: tsc.iv32 }.to_pn();
    let b = Pn(pn.0).to_bytes();
    Some([b[5], b[4], b[3], b[2], b[1], b[0]])
}

/// Whether a key blob is the right width for the temporal-key cipher, which
/// takes three keys in one blob rather than one. # C: O(1)
pub fn tkip_blob_ok(material: &[u8]) -> bool { material.len() >= tkip_key::TOTAL_LEN }
