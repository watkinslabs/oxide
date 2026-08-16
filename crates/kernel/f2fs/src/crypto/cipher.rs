//! The ciphers a mode names, prepared once per inode.
//!
//! Two constructions carry file contents and one carries names:
//!
//! - The tweakable narrow-block mode, whose key is TWO cipher keys in one
//!   buffer and whose tweak is the IV.
//! - Chaining with an IV that is itself enciphered under a key derived by
//!   hashing the file key — so the IV is unpredictable without the key, which
//!   a bare block index is not.
//! - Chaining with ciphertext stealing, which keeps a name's exact length.
//!
//! Each is a different answer for the same bytes, and each decrypts its own
//! output perfectly, so picking the wrong one is invisible without a second
//! implementation to disagree with.

use aes::block::AesKey;
use aes::cbc;
use aes::xts::Xts;

use super::mode::Mode;
use super::uapi::*;
use super::FscryptError;

/// Bytes a contents request must be a multiple of.
pub const CONTENTS_ALIGNMENT: usize = 16;

/// A prepared cipher.
#[derive(Clone)]
pub enum Cipher {
    /// Tweakable narrow-block, for file contents.
    Xts(Xts),
    /// Chaining with an enciphered IV, for file contents.
    CbcEssiv { data: AesKey, essiv: aes::Aes256 },
    /// Chaining with ciphertext stealing, for names.
    Cts(AesKey),
}

impl Cipher {
    /// Prepare the cipher `mode` names from `key`, which must be exactly the
    /// mode's key size. # C: O(1)
    pub fn prepare(mode: Mode, key: &[u8]) -> Result<Self, FscryptError> {
        if key.len() != mode.key_size { return Err(FscryptError::BadKeySize(key.len())); }
        match mode.num {
            MODE_AES_256_XTS =>
                Xts::new(key).map(Cipher::Xts).map_err(|_| FscryptError::BadKeySize(key.len())),
            MODE_AES_128_CBC => {
                // The IV key is the digest of the file key, so a predictable
                // block index becomes an unpredictable IV.
                let salt = crypt::sha256::sha256(key);
                let data = AesKey::new(key).ok_or(FscryptError::BadKeySize(key.len()))?;
                Ok(Cipher::CbcEssiv { data, essiv: aes::Aes256::new(&salt) })
            }
            MODE_AES_256_CTS | MODE_AES_128_CTS =>
                AesKey::new(key).map(Cipher::Cts).ok_or(FscryptError::BadKeySize(key.len())),
            other => Err(FscryptError::UnsupportedMode(other)),
        }
    }

    /// Encrypt `buf` in place under `iv`. # C: O(len(buf))
    pub fn encrypt(&self, iv: &[u8; 16], buf: &mut [u8]) -> Result<(), FscryptError> {
        match self {
            Cipher::Xts(x) => x.encrypt(iv, buf).map_err(|_| FscryptError::BadLength(buf.len())),
            Cipher::CbcEssiv { data, essiv } => {
                let mut v = *iv;
                essiv.encrypt_block(&mut v);
                cbc::encrypt(data, &mut v, buf).map_err(|_| FscryptError::BadLength(buf.len()))
            }
            Cipher::Cts(k) =>
                cbc::cts_encrypt(k, iv, buf).map_err(|_| FscryptError::BadLength(buf.len())),
        }
    }

    /// Decrypt `buf` in place under `iv`. # C: O(len(buf))
    pub fn decrypt(&self, iv: &[u8; 16], buf: &mut [u8]) -> Result<(), FscryptError> {
        match self {
            Cipher::Xts(x) => x.decrypt(iv, buf).map_err(|_| FscryptError::BadLength(buf.len())),
            Cipher::CbcEssiv { data, essiv } => {
                let mut v = *iv;
                essiv.encrypt_block(&mut v);
                cbc::decrypt(data, &mut v, buf).map_err(|_| FscryptError::BadLength(buf.len()))
            }
            Cipher::Cts(k) =>
                cbc::cts_decrypt(k, iv, buf).map_err(|_| FscryptError::BadLength(buf.len())),
        }
    }
}
