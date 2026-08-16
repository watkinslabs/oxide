// AES-CCM (counter with CBC-MAC) at L=2, which fixes the nonce at 13 bytes
// and the payload at 65535 bytes — the parameters the 802.11 CCMP link cipher
// uses. MIC length is caller-chosen, 8 or 16 bytes.
//
// The first MAC block B0 carries a flags byte, the nonce and the payload
// length; its flags are (AAD present ? 0x40 : 0) | ((M-2)/2) << 3 | (L-1).
// Associated data is prefixed with its length — two big-endian bytes below
// 65280, otherwise the escape 0xfffe followed by a 32-bit big-endian count —
// and both the AAD run and the payload run are zero-padded to a block
// boundary before entering the CBC-MAC. Keystream blocks A_i carry flags
// (L-1) with the block index in the trailing two bytes; A_0 masks the MIC and
// A_1 onward covers the payload.

use super::block::{AesKey, BLOCK_LEN};
use super::ct;

/// Nonce length at L=2, bytes.
pub const NONCE_LEN: usize = 13;
/// Short MIC length accepted by the link cipher, bytes.
pub const MIC_LEN_8: usize = 8;
/// Long MIC length accepted by the link cipher, bytes.
pub const MIC_LEN_16: usize = 16;

/// L parameter: payload length field width, bytes.
const L: usize = 2;
/// Longest payload L=2 can encode.
const MAX_DATA: usize = 0xffff;
/// AAD lengths at or above this use the 6-byte escape encoding.
const AAD_ESCAPE_AT: usize = 0xff00;
/// Escape marker introducing a 32-bit AAD length.
const AAD_ESCAPE: u16 = 0xfffe;
/// B0 flag bit set when associated data is present.
const FLAG_ADATA: u8 = 0x40;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CcmError {
    /// Nonce was not 13 bytes.
    BadNonce,
    /// MIC buffer was not 8 or 16 bytes.
    BadMicLen,
    /// Payload longer than the length field encodes.
    TooLong,
    /// MIC did not verify. Caller must discard the payload buffer.
    AuthFailed,
}

fn check(nonce: &[u8], mic_len: usize, data_len: usize) -> Result<(), CcmError> {
    if nonce.len() != NONCE_LEN { return Err(CcmError::BadNonce); }
    if mic_len != MIC_LEN_8 && mic_len != MIC_LEN_16 { return Err(CcmError::BadMicLen); }
    if data_len > MAX_DATA { return Err(CcmError::TooLong); }
    Ok(())
}

/// Counter block A_i.
fn ctr_block(nonce: &[u8], i: u16) -> [u8; BLOCK_LEN] {
    let mut b = [0u8; BLOCK_LEN];
    b[0] = (L - 1) as u8;
    b[1..1 + NONCE_LEN].copy_from_slice(nonce);
    b[BLOCK_LEN - 2..].copy_from_slice(&i.to_be_bytes());
    b
}

/// Running CBC-MAC over whole blocks.
struct CbcMac<'k> { key: &'k AesKey, x: [u8; BLOCK_LEN] }

impl<'k> CbcMac<'k> {
    fn new(key: &'k AesKey) -> Self { Self { key, x: [0u8; BLOCK_LEN] } }

    fn block(&mut self, b: &[u8; BLOCK_LEN]) {
        for i in 0..BLOCK_LEN { self.x[i] ^= b[i]; }
        self.key.encrypt_block(&mut self.x);
    }

    /// Absorb `data` preceded by `prefix`, zero-padding the run to a block
    /// boundary. `prefix` is at most 6 bytes, so it never spans two blocks.
    fn run(&mut self, prefix: &[u8], data: &[u8]) {
        let mut b = [0u8; BLOCK_LEN];
        let mut n = prefix.len();
        b[..n].copy_from_slice(prefix);
        let mut off = 0;
        while off < data.len() {
            let take = core::cmp::min(BLOCK_LEN - n, data.len() - off);
            b[n..n + take].copy_from_slice(&data[off..off + take]);
            n += take;
            off += take;
            if n == BLOCK_LEN { self.block(&b); b = [0u8; BLOCK_LEN]; n = 0; }
        }
        if n != 0 { self.block(&b); }
    }
}

/// Encode the AAD length prefix into `out`, returning its byte count.
fn aad_prefix(out: &mut [u8; 6], len: usize) -> usize {
    if len < AAD_ESCAPE_AT {
        out[..2].copy_from_slice(&(len as u16).to_be_bytes());
        2
    } else {
        out[..2].copy_from_slice(&AAD_ESCAPE.to_be_bytes());
        out[2..6].copy_from_slice(&(len as u32).to_be_bytes());
        6
    }
}

/// CBC-MAC of B0 || len(AAD)||AAD || payload, truncated to `mic_len`, then
/// masked with the A_0 keystream.
fn mic(key: &AesKey, nonce: &[u8], aad: &[u8], data: &[u8], mic_len: usize) -> [u8; BLOCK_LEN] {
    let mut b0 = [0u8; BLOCK_LEN];
    b0[0] = if aad.is_empty() { 0 } else { FLAG_ADATA }
          | (((mic_len - 2) / 2) as u8) << 3
          | (L - 1) as u8;
    b0[1..1 + NONCE_LEN].copy_from_slice(nonce);
    b0[BLOCK_LEN - 2..].copy_from_slice(&(data.len() as u16).to_be_bytes());

    let mut m = CbcMac::new(key);
    m.block(&b0);
    if !aad.is_empty() {
        let mut pfx = [0u8; 6];
        let n = aad_prefix(&mut pfx, aad.len());
        m.run(&pfx[..n], aad);
    }
    if !data.is_empty() { m.run(&[], data); }

    let mut s0 = ctr_block(nonce, 0);
    key.encrypt_block(&mut s0);
    let mut t = m.x;
    for i in 0..BLOCK_LEN { t[i] ^= s0[i]; }
    t
}

/// XOR the payload with the A_1.. keystream.
fn ctr_xor(key: &AesKey, nonce: &[u8], data: &mut [u8]) {
    let mut i: u16 = 1;
    let mut off = 0;
    while off < data.len() {
        let mut ks = ctr_block(nonce, i);
        key.encrypt_block(&mut ks);
        let n = core::cmp::min(BLOCK_LEN, data.len() - off);
        for j in 0..n { data[off + j] ^= ks[j]; }
        off += n;
        i = i.wrapping_add(1);
    }
}

/// Encrypt `data` in place and write the MIC. `nonce` is 13 bytes, `mic` is 8
/// or 16 bytes.
/// # C: O(len(aad) + len(data)) — two block-cipher passes over the payload
pub fn encrypt(key: &AesKey, nonce: &[u8], aad: &[u8], data: &mut [u8],
               mic_out: &mut [u8]) -> Result<(), CcmError> {
    check(nonce, mic_out.len(), data.len())?;
    let n = mic_out.len();
    let t = mic(key, nonce, aad, data, n);
    ctr_xor(key, nonce, data);
    mic_out.copy_from_slice(&t[..n]);
    Ok(())
}

/// Decrypt `data` in place and verify the MIC, constant time.
///
/// CCM authenticates the plaintext, so the payload must be decrypted before
/// the MIC can be computed: on `AuthFailed` the buffer holds unauthenticated
/// plaintext and the caller must discard it without acting on its contents.
/// # C: O(len(aad) + len(data))
pub fn decrypt(key: &AesKey, nonce: &[u8], aad: &[u8], data: &mut [u8],
               mic_in: &[u8]) -> Result<(), CcmError> {
    check(nonce, mic_in.len(), data.len())?;
    ctr_xor(key, nonce, data);
    let t = mic(key, nonce, aad, data, mic_in.len());
    if !ct::eq(&t[..mic_in.len()], mic_in) { return Err(CcmError::AuthFailed); }
    Ok(())
}
