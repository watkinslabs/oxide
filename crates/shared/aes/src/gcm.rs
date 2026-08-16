// AES-GCM with a 12-byte IV and a 16-byte tag — the shape the 802.11 GCMP
// link cipher uses.
//
// With a 12-byte IV the pre-counter block J0 is IV || 00 00 00 01; the tag
// mask is the cipher applied to J0 and the keystream for the payload starts at
// J0 with the 32-bit counter incremented, i.e. counter value 2. The tag is
// GHASH(AAD-padded || C-padded || lengths) XOR that mask.

use crate::block::{AesKey, BLOCK_LEN};
use crate::ct;
use crate::ghash::Ghash;

/// IV length, bytes.
pub const IV_LEN: usize = 12;
/// Tag length, bytes.
pub const TAG_LEN: usize = BLOCK_LEN;

/// Longest plaintext GCM defines for one key/IV pair: 2^36 - 32 bytes.
const MAX_DATA: u64 = (1u64 << 36) - 32;
/// Longest AAD the length block can encode.
const MAX_AAD: u64 = u64::MAX / 8;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum GcmError {
    /// Payload or associated data exceeds what the length block encodes.
    TooLong,
    /// Tag did not verify; plaintext was not produced.
    AuthFailed,
}

fn inc32(ctr: &mut [u8; BLOCK_LEN]) {
    let n = u32::from_be_bytes([ctr[12], ctr[13], ctr[14], ctr[15]]).wrapping_add(1);
    ctr[12..].copy_from_slice(&n.to_be_bytes());
}

/// XOR `data` with the keystream starting at counter block `ctr` (which is
/// advanced before the first block).
fn ctr_xor(key: &AesKey, ctr: &mut [u8; BLOCK_LEN], data: &mut [u8]) {
    let mut off = 0;
    while off < data.len() {
        inc32(ctr);
        let mut ks = *ctr;
        key.encrypt_block(&mut ks);
        let n = core::cmp::min(BLOCK_LEN, data.len() - off);
        for i in 0..n { data[off + i] ^= ks[i]; }
        off += n;
    }
}

fn lengths_ok(aad: &[u8], data: &[u8]) -> bool {
    (data.len() as u64) <= MAX_DATA && (aad.len() as u64) <= MAX_AAD
}

fn subkey(key: &AesKey) -> [u8; BLOCK_LEN] {
    let mut h = [0u8; BLOCK_LEN];
    key.encrypt_block(&mut h);
    h
}

fn j0(iv: &[u8; IV_LEN]) -> [u8; BLOCK_LEN] {
    let mut b = [0u8; BLOCK_LEN];
    b[..IV_LEN].copy_from_slice(iv);
    b[BLOCK_LEN - 1] = 1;
    b
}

fn tag_of(key: &AesKey, iv: &[u8; IV_LEN], aad: &[u8], ct_buf: &[u8]) -> [u8; TAG_LEN] {
    let mut g = Ghash::new(&subkey(key));
    g.update_padded(aad);
    g.update_padded(ct_buf);
    g.update_lengths(aad.len() as u64, ct_buf.len() as u64);
    let mut t = g.finish();
    let mut mask = j0(iv);
    key.encrypt_block(&mut mask);
    for i in 0..TAG_LEN { t[i] ^= mask[i]; }
    t
}

/// Encrypt `data` in place and write the authentication tag.
/// # C: O(len(aad) + len(data))
pub fn encrypt(key: &AesKey, iv: &[u8; IV_LEN], aad: &[u8], data: &mut [u8],
               tag: &mut [u8; TAG_LEN]) -> Result<(), GcmError> {
    if !lengths_ok(aad, data) { return Err(GcmError::TooLong); }
    let mut ctr = j0(iv);
    ctr_xor(key, &mut ctr, data);
    *tag = tag_of(key, iv, aad, data);
    Ok(())
}

/// Verify `tag` over the ciphertext in `data`, and only then decrypt in place.
/// The tag covers the ciphertext, so a rejected message leaves `data` holding
/// the untouched ciphertext — no plaintext is ever produced for a forgery.
/// Comparison is constant time.
/// # C: O(len(aad) + len(data))
pub fn decrypt(key: &AesKey, iv: &[u8; IV_LEN], aad: &[u8], data: &mut [u8],
               tag: &[u8; TAG_LEN]) -> Result<(), GcmError> {
    if !lengths_ok(aad, data) { return Err(GcmError::TooLong); }
    let want = tag_of(key, iv, aad, data);
    if !ct::eq(&want, tag) { return Err(GcmError::AuthFailed); }
    let mut ctr = j0(iv);
    ctr_xor(key, &mut ctr, data);
    Ok(())
}

/// Tag over `aad` alone with an empty payload — the GMAC case, shared with
/// `cmac::gmac`.
/// # C: O(len(aad))
pub(crate) fn tag_empty_payload(key: &AesKey, iv: &[u8; IV_LEN], aad: &[u8]) -> [u8; TAG_LEN] {
    tag_of(key, iv, aad, &[])
}

/// AES-GMAC: the tag over `aad` with an empty payload. It is not a second
/// construction — it is this mode with nothing to encrypt, which is why it
/// lives here and not beside the other message authentication code.
/// # C: O(len(aad))
pub fn gmac(key: &AesKey, iv: &[u8; IV_LEN], aad: &[u8], out: &mut [u8; TAG_LEN]) {
    *out = tag_empty_payload(key, iv, aad);
}
