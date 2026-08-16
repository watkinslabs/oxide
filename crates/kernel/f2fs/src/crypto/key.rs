//! The master key, and everything derived from it.
//!
//! A v2 master key is never used as a cipher key. It is used ONLY to key a
//! derivation function, and every subkey — the file key, the per-mode key, the
//! directory hash key, the inode hash key, and the key's own public identifier
//! — comes out of that one function under a different context byte. The byte
//! is what keeps them apart: two purposes sharing a context would derive the
//! same bytes, and knowledge of one subkey would hand over the other.
//!
//! A v1 master key has no such function. Its per-file key is the master key
//! enciphered block by block under the file's nonce, which is why a v1 key
//! must be at least as long as the key it derives, and why v1 can derive
//! nothing else — there is no second output to take.

use alloc::vec::Vec;

use aes::block::AesKey;
use crypt::HkdfSha512;

use super::uapi::*;
use super::FscryptError;

/// A master key held for derivation.
#[derive(Clone)]
pub struct MasterKey {
    raw: Vec<u8>,
    kdf: HkdfSha512,
}

impl MasterKey {
    /// Take a raw master key and prepare its derivation function.
    /// # C: O(len(raw))
    pub fn new(raw: &[u8]) -> Result<Self, FscryptError> {
        if raw.len() < MIN_KEY_SIZE || raw.len() > MAX_RAW_KEY_SIZE {
            return Err(FscryptError::BadKeySize(raw.len()));
        }
        // No salt: a master key is already pseudorandom, and there is nowhere
        // to persist a per-key salt.
        Ok(Self { raw: Vec::from(raw), kdf: HkdfSha512::extract(&[], raw) })
    }

    /// Bytes of key material. # C: O(1)
    pub fn size(&self) -> usize { self.raw.len() }

    /// The raw bytes, which only the older policy's derivation needs.
    /// # C: O(1)
    pub fn raw(&self) -> &[u8] { &self.raw }

    /// Derive `out` under `context`, with the info string given in pieces.
    ///
    /// Every derivation carries the same prefix and then the context byte, so
    /// no two purposes can produce the same output from one key.
    /// # C: O(len(out))
    pub fn expand(&self, context: u8, info: &[&[u8]], out: &mut [u8]) -> Result<(), FscryptError> {
        let mut parts: Vec<&[u8]> = Vec::with_capacity(2 + info.len());
        parts.push(HKDF_PREFIX);
        parts.push(core::slice::from_ref(&context));
        parts.extend_from_slice(info);
        if self.kdf.expand(&parts, out) { Ok(()) } else { Err(FscryptError::BadKeySize(out.len())) }
    }

    /// The key's public name: a hash of the key itself, so a v2 policy that
    /// names it cannot be satisfied by a different key.
    /// # C: O(1)
    pub fn identifier(&self) -> [u8; KEY_IDENTIFIER_SIZE] {
        let mut id = [0u8; KEY_IDENTIFIER_SIZE];
        let _ = self.expand(HKDF_KEY_IDENTIFIER, &[], &mut id);
        id
    }

    /// A 128-bit hash key derived under `context`.
    ///
    /// The derivation produces bytes; the hash wants two 64-bit words, read
    /// little-endian. Reading them the other way gives a self-consistent hash
    /// that disagrees with every other reader of the same volume.
    /// # C: O(1)
    pub fn siphash_key(&self, context: u8, info: &[&[u8]]) -> Result<siphash::Key, FscryptError> {
        let mut b = [0u8; 16];
        self.expand(context, info, &mut b)?;
        Ok(siphash::Key::from_bytes(&b))
    }
}

/// The per-file key of a v1 policy: the master key run through the block
/// cipher under the file's nonce, one block at a time.
///
/// The nonce is the KEY and the master key is the PLAINTEXT, which is the
/// reverse of what the names suggest. Swapping them derives a key that works
/// perfectly against itself and against nothing else.
/// # C: O(key_size)
pub fn v1_file_key(master: &[u8], nonce: &[u8; FILE_NONCE_SIZE], key_size: usize)
    -> Result<Vec<u8>, FscryptError> {
    if key_size % aes::AES_BLOCK_LEN != 0 || key_size > MAX_RAW_KEY_SIZE {
        return Err(FscryptError::BadKeySize(key_size));
    }
    // The older derivation cannot stretch: it produces exactly as many bytes
    // as it consumes, so a master key shorter than the derived key has no
    // material for the tail.
    if master.len() < key_size { return Err(FscryptError::KeyTooShort); }
    let cipher = AesKey::new(nonce).ok_or(FscryptError::BadKeySize(FILE_NONCE_SIZE))?;
    let mut out = Vec::with_capacity(key_size);
    for chunk in master[..key_size].chunks(aes::AES_BLOCK_LEN) {
        let mut b = [0u8; aes::AES_BLOCK_LEN];
        b.copy_from_slice(chunk);
        cipher.encrypt_block(&mut b);
        out.extend_from_slice(&b);
    }
    Ok(out)
}
